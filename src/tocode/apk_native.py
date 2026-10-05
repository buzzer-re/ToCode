"""Native shared-object handling for APK exports.

Every ``.so`` found in the APK set is extracted to ``lib/<abi>/`` and, unless
``--no-native`` is given, decompiled with the regular ToCode pipeline
(``create_analyzer`` + ``export_binary``) into ``native/<abi>/<lib>/``. The
native work runs on a background thread so it overlaps with the DEX export;
one library failing never fails the APK export.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import multiprocessing
import os
from pathlib import Path
import queue as queue_mod
import re
import signal
import threading
import time
from typing import Any, Callable
import zipfile

from .backends.base import BackendRequest
from .errors import ToCodeError
from .naming import clean_path_component
from .progress import Progress


ELF_MAGIC = b"\x7fELF"
# A decompiler backend needs room to analyze a library (r2's ``aaa`` on a few MB
# of ARM code can reach a gigabyte). The native thread runs next to the DEX
# decompile pool, so it waits for this much free memory before starting the next
# library instead of competing for the last megabytes and getting the whole run
# OOM-killed. The DEX side finishing is what usually releases it.
DEFAULT_NATIVE_MIN_FREE_MB = 1024
NATIVE_MEMORY_POLL_SECONDS = 5.0
NATIVE_MEMORY_MAX_WAIT_SECONDS = 1800.0
# The nested export writes its own tocode.log; its lines are mirrored to the main
# output at this cadence so the terminal shows what the native side is doing.
NATIVE_LOG_TAIL_SECONDS = 0.5
NATIVE_HEARTBEAT_SECONDS = 20.0
_LOG_TIMESTAMP_RX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\s+")
_RENDER_TOTAL_RX = re.compile(r"Rendering and writing (\d+) functions")
# Per-function render lines: "export <name> 0x<addr> - <n> bytes done|failed: ...".
# The parent also logs a bare "export <name> 0x<addr> - <n> bytes" when it hands a
# function to a worker; only completed ones count toward the bar.
_FUNCTION_LINE_RX = re.compile(r"^export \S+ 0x[0-9a-f]+ - \d+ bytes (done|failed)")
_FUNCTION_START_RX = re.compile(r"^export \S+ 0x[0-9a-f]+ - \d+ bytes$")
KNOWN_ABIS = ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86", "mips", "mips64")


@dataclass(slots=True)
class NativeLib:
    abi: str
    name: str
    entry: str
    source_apk: str
    size: int
    sha256: str
    path: Path
    export_dir: Path | None = None
    backend: str | None = None
    decompiler: str | None = None
    function_count: int | None = None
    failure_count: int | None = None
    status: str = "pending"
    seconds: float | None = None
    # Package of the APK the library was extracted from (for the nested AGENTS.md).
    package: str = ""
    # Full provenance paragraph for the nested AGENTS.md; overrides the APK text
    # (used when the library comes from a .NET bundle, package, or assembly).
    origin: str | None = None

    @property
    def stem(self) -> str:
        return clean_path_component(Path(self.name).stem)

    def to_json(self, root: Path) -> dict[str, Any]:
        return {
            "abi": self.abi,
            "name": self.name,
            "entry": self.entry,
            "source_apk": self.source_apk,
            "size": self.size,
            "sha256": self.sha256,
            "path": _rel(self.path, root),
            "export_dir": _rel(self.export_dir, root),
            "backend": self.backend,
            "decompiler": self.decompiler,
            "function_count": self.function_count,
            "failure_count": self.failure_count,
            "status": self.status,
            "seconds": round(self.seconds, 1) if self.seconds is not None else None,
        }


@dataclass(slots=True)
class NativeOptions:
    backend: BackendRequest = "auto"
    analysis_command: str = "aaa"
    idadir: Path | None = None
    ida_domain_path: Path | None = None
    purge_cache: bool = False
    jobs: int | None = None
    tree: bool = False
    entropy: bool = False


def _rel(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def classify_native_entry(name: str, head: bytes) -> tuple[str, str] | None:
    """Return ``(abi, file name)`` when a zip entry is a shared object."""
    parts = name.split("/")
    leaf = parts[-1]
    if not leaf:
        return None
    is_so = leaf.endswith(".so") or ".so." in leaf
    if len(parts) >= 3 and parts[0] == "lib":
        if is_so or head.startswith(ELF_MAGIC):
            return parts[1], leaf
    if head.startswith(ELF_MAGIC) and (is_so or parts[0] in {"assets", "res"}):
        abi = next((part for part in parts if part in KNOWN_ABIS), "unknown")
        return abi, leaf
    return None


def native_lib_path(root: Path, abi: str, name: str) -> Path:
    return root / "lib" / clean_path_component(abi) / name


def native_export_dir(root: Path, lib: NativeLib) -> Path:
    return root / "native" / clean_path_component(lib.abi) / lib.stem


NativeExporter = Callable[[NativeLib, Path, Progress], tuple[str, str, int, int]]


def native_min_free_mb() -> int:
    """Free-memory floor before each native export (0 disables the wait)."""
    for name in ("TOCODE_NATIVE_MIN_FREE_MB", "TOCODE_APK_NATIVE_MIN_FREE_MB"):
        raw = os.environ.get(name, "").strip()
        if raw:
            try:
                return max(0, int(raw))
            except ValueError:
                continue
    return DEFAULT_NATIVE_MIN_FREE_MB


def describe_origin(lib: NativeLib) -> str:
    """Provenance paragraph for the nested export's AGENTS.md."""
    if lib.origin:
        return lib.origin
    package = f"`{lib.package}`" if lib.package else "an Android app"
    return (
        f"This is a decompiled native library from the {package} APK: "
        f"`{lib.name}` ({lib.abi}, `{lib.entry}` in `{lib.source_apk}`, "
        f"sha256 `{lib.sha256}`). "
        "The APK export that owns it is three directories up (`../../..`): its "
        "`exports.json` and `triage.json` list the Java `native` methods with the "
        "`Java_<package>_<Class>_<method>` JNI symbols this library is expected to "
        "export, `native-libs.json` lists the other libraries of the app, and "
        "`src/raw/<package>/` holds the decompiled Java that calls into this code."
    )


def run_native_export(
    lib: NativeLib, out_dir: Path, options: NativeOptions, progress: Progress
) -> tuple[str, str, int, int]:
    """Export one shared object with the regular binary pipeline."""
    from .analysis import create_analyzer
    from .exporter import export_binary

    with create_analyzer(
        lib.path,
        backend=options.backend,
        analysis_command=options.analysis_command,
        progress=progress,
        idadir=options.idadir,
        ida_domain_path=options.ida_domain_path,
        purge_cache=options.purge_cache,
    ) as analyzer:
        summary = export_binary(
            analyzer,
            out_dir=out_dir,
            progress=progress,
            jobs=options.jobs,
            tree=options.tree,
            entropy=options.entropy,
            origin=describe_origin(lib),
        )
        return (
            analyzer.backend_name,
            analyzer.decompiler_label,
            summary.function_count,
            len(summary.failed_functions),
        )


def _native_export_child(
    lib: NativeLib,
    out_dir: Path,
    options: NativeOptions,
    log_path: Path,
    result_queue: Any,
) -> None:
    """Entry point of the isolated per-library export process."""
    # Lead a process group of our own: the backend's worker pool (grandchildren
    # of the APK export) can then be killed as one unit if this process dies.
    if hasattr(os, "setsid"):
        try:
            os.setsid()
        except OSError:  # pragma: no cover - already a session leader
            pass
    progress = Progress(enabled=False)
    progress.set_log_path(log_path)
    _redirect_output(log_path)
    try:
        result = run_native_export(lib, out_dir, options, progress)
    except ToCodeError as exc:
        result_queue.put(("error", str(exc)))
    except BaseException as exc:  # pragma: no cover - backend crash isolation
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))
    else:
        result_queue.put(("ok", result))


_active_children: set[int] = set()
_active_lock = threading.Lock()


def kill_process_group(pid: int | None) -> None:
    """Kill the process group led by ``pid`` (no-op where unsupported).

    An OOM-killed or interrupted native child leaves its decompiler workers
    behind; they hold the multiprocessing resource tracker open and the APK
    export would then hang at exit waiting for it.
    """
    if pid is None or not hasattr(os, "killpg"):
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def terminate_active_native_children() -> None:
    with _active_lock:
        pids = list(_active_children)
    for pid in pids:
        kill_process_group(pid)


def collect_child_result(
    process: Any, result_queue: Any, *, poll_seconds: float = 1.0
) -> tuple[str, str, int, int]:
    """Wait for an isolated export process and turn its outcome into a result.

    A missing outcome means the child died without reporting: a negative exit
    code is a signal (the OOM killer, typically), which becomes a per-library
    ``ToCodeError`` instead of taking the APK export down. Whatever the child
    left running is killed with its process group.
    """
    outcome: tuple[str, Any] | None = None
    try:
        while True:
            try:
                outcome = result_queue.get(timeout=poll_seconds)
                break
            except queue_mod.Empty:
                if not process.is_alive():
                    break
    finally:
        process.join()
        if process.pid is not None:
            with _active_lock:
                _active_children.discard(process.pid)
    if outcome is None:
        kill_process_group(process.pid)
        code = process.exitcode
        if code is not None and code < 0:
            raise ToCodeError(
                f"export process was killed by signal {-code} "
                "(out of memory?); try -j 1 or --no-native"
            )
        raise ToCodeError(f"export process exited with code {code}")
    kind, payload = outcome
    if kind == "error":
        raise ToCodeError(str(payload))
    backend, decompiler, functions, failures = payload
    return (str(backend), str(decompiler), int(functions), int(failures))


def _redirect_output(log_path: Path) -> None:
    """Send the backend's own stdout/stderr chatter into the nested log."""
    try:
        handle = open(log_path, "ab", buffering=0)
        os.dup2(handle.fileno(), 1)
        os.dup2(handle.fileno(), 2)
    except OSError:  # pragma: no cover - keep the terminal if the log is unusable
        return


def default_native_exporter(options: NativeOptions) -> NativeExporter:
    """Run each library's export in its own process.

    A decompiler backend can use more memory than the host has (r2's ``aaa`` on
    a large library), and it may be OOM-killed or crash. In a child process that
    only fails that library; in-process it would take the whole APK export -- and
    the finished DEX work -- down with it.
    """

    def run(
        lib: NativeLib, out_dir: Path, progress: Progress
    ) -> tuple[str, str, int, int]:
        context = multiprocessing.get_context("spawn")
        result_queue: Any = context.Queue()
        process = context.Process(
            target=_native_export_child,
            args=(
                lib,
                out_dir,
                options,
                _need_log_path(progress, out_dir),
                result_queue,
            ),
            name=f"tocode-native-{lib.stem}",
        )
        process.start()
        if process.pid is not None:
            with _active_lock:
                _active_children.add(process.pid)
        return collect_child_result(process, result_queue)

    return run


def _need_log_path(progress: Progress, out_dir: Path) -> Path:
    return (
        progress.log_path if progress.log_path is not None else out_dir / "tocode.log"
    )


class NestedLogTail:
    """Mirror a nested export's ``tocode.log`` into the main progress.

    Per-function render lines drive a progress bar instead of being echoed
    (there are thousands); every other line is shown as ``native[lib]: ...``.
    """

    def __init__(
        self,
        log_path: Path,
        lib: NativeLib,
        progress: Progress,
        *,
        poll_seconds: float = NATIVE_LOG_TAIL_SECONDS,
    ) -> None:
        self.log_path = log_path
        self.lib = lib
        self.progress = progress
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._offset = 0
        self._bar_cm: Any = None
        self._bar: Any = None
        self.rendered = 0
        self.total: int | None = None
        self.last_line: str = "starting"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"tocode-native-tail-{self.lib.stem}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        self._drain()
        self._close_bar()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._drain()
            self._stop.wait(self.poll_seconds)

    def _drain(self) -> None:
        try:
            with self.log_path.open("rb") as handle:
                handle.seek(self._offset)
                chunk = handle.read()
        except OSError:
            return
        if not chunk:
            return
        # Only consume complete lines; keep a partial tail for the next poll.
        end = chunk.rfind(b"\n")
        if end < 0:
            return
        self._offset += end + 1
        for raw in chunk[: end + 1].decode("utf-8", errors="replace").splitlines():
            self._handle_line(_LOG_TIMESTAMP_RX.sub("", raw).rstrip())

    def _handle_line(self, line: str) -> None:
        if not line:
            return
        if _FUNCTION_LINE_RX.match(line):
            self.rendered += 1
            if self._bar is not None:
                self._bar.update(1)
            return
        if _FUNCTION_START_RX.match(line):
            return
        self.last_line = line
        total = _RENDER_TOTAL_RX.search(line)
        if total is not None:
            self.total = int(total.group(1))
            self._open_bar()
        self.progress.log(f"native[{self.lib.name}]: {line}")

    def _open_bar(self) -> None:
        if self._bar is not None or self.total is None:
            return
        self._bar_cm = self.progress.bar(
            total=self.total, desc=f"native {self.lib.name}", unit="fn"
        )
        self._bar = self._bar_cm.__enter__()
        if self.rendered:
            self._bar.update(self.rendered)

    def _close_bar(self) -> None:
        if self._bar_cm is not None:
            self._bar_cm.__exit__(None, None, None)
            self._bar_cm = None
            self._bar = None

    def status(self) -> str:
        if self.total:
            return f"{self.rendered}/{self.total} functions"
        return self.last_line


@dataclass
class NativeRunner:
    """Runs the native exports on a background thread."""

    libs: list[NativeLib]
    root: Path
    progress: Progress
    exporter: NativeExporter
    stop_event: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    errors: list[str] = field(default_factory=list)
    min_free_mb: int = 0
    available_memory: Callable[[], int | None] = lambda: None
    poll_seconds: float = NATIVE_MEMORY_POLL_SECONDS
    max_wait_seconds: float = NATIVE_MEMORY_MAX_WAIT_SECONDS
    mirror_logs: bool = True
    current: NativeLib | None = None
    waiting: tuple[NativeLib, int] | None = None
    current_started: float = 0.0
    current_tail: NestedLogTail | None = None

    def describe_current(self) -> str | None:
        """One line about what the native thread is doing right now."""
        waiting = self.waiting
        if waiting is not None:
            pending, available = waiting
            return (
                f"native: waiting for memory before {pending.name} ({pending.abi}): "
                f"{available} MB free, need {self.min_free_mb} MB "
                "(set TOCODE_NATIVE_MIN_FREE_MB to change)"
            )
        lib = self.current
        if lib is None:
            return None
        elapsed = time.monotonic() - self.current_started
        detail = self.current_tail.status() if self.current_tail else "running"
        done = sum(1 for item in self.libs if item.status == "done")
        finished = sum(1 for item in self.libs if item.status not in {"pending"})
        return (
            f"native: {lib.name} ({lib.abi}) {detail}, {elapsed:.0f}s elapsed; "
            f"{finished}/{len(self.libs)} libraries finished, {done} exported"
        )

    def start(self) -> None:
        self.thread = threading.Thread(
            target=self._run, name="tocode-native", daemon=True
        )
        self.thread.start()

    def join(self) -> None:
        if self.thread is not None:
            self.thread.join()

    def stop(self) -> None:
        self.stop_event.set()
        terminate_active_native_children()

    def _run(self) -> None:
        for lib in self.libs:
            if self.stop_event.is_set():
                lib.status = "skipped: interrupted"
                continue
            self._wait_for_memory(lib)
            if self.stop_event.is_set():
                lib.status = "skipped: interrupted"
                continue
            self._export_one(lib)

    def _wait_for_memory(self, lib: NativeLib) -> None:
        if self.min_free_mb <= 0:
            return
        waited = 0.0
        logged = False
        while not self.stop_event.is_set() and waited < self.max_wait_seconds:
            available = self.available_memory()
            if available is None or available >= self.min_free_mb:
                break
            self.waiting = (lib, available)
            if not logged:
                self.progress.log(
                    f"native: waiting for memory before {lib.name} ({lib.abi}): "
                    f"{available} MB free, need {self.min_free_mb} MB"
                )
                logged = True
            self.stop_event.wait(self.poll_seconds)
            waited += self.poll_seconds
        self.waiting = None
        if logged and not self.stop_event.is_set():
            self.progress.file_log(
                f"native: waited {waited:.0f}s for memory before {lib.name}"
            )

    def _export_one(self, lib: NativeLib) -> None:
        out_dir = native_export_dir(self.root, lib)
        lib.export_dir = out_dir
        log_path = out_dir / "tocode.log"
        child = Progress(enabled=False)
        child.set_log_path(log_path)
        self.progress.log(
            f"native: {lib.name} ({lib.abi}) export started -> "
            f"{_rel(out_dir, self.root)}"
        )
        started = time.monotonic()
        tail = NestedLogTail(log_path, lib, self.progress) if self.mirror_logs else None
        self.current = lib
        self.current_started = started
        self.current_tail = tail
        if tail is not None:
            tail.start()
        try:
            backend, decompiler, functions, failures = self.exporter(
                lib, out_dir, child
            )
        except ToCodeError as exc:
            lib.status = f"failed: {exc}"
        except Exception as exc:  # pragma: no cover - backend crash isolation
            lib.status = f"failed: {type(exc).__name__}: {exc}"
        else:
            lib.backend = backend
            lib.decompiler = decompiler
            lib.function_count = functions
            lib.failure_count = failures
            lib.status = "done"
        finally:
            if tail is not None:
                tail.stop()
            self.current = None
            self.current_tail = None
        lib.seconds = time.monotonic() - started
        if lib.status == "done":
            self.progress.log(
                f"native: {lib.name} ({lib.abi}) exported with {lib.backend} "
                f"in {lib.seconds:.1f}s: functions={lib.function_count} "
                f"failures={lib.failure_count}"
            )
        else:
            self.errors.append(f"{lib.abi}/{lib.name}: {lib.status}")
            self.progress.log(f"native: {lib.name} ({lib.abi}) {lib.status}")


def extract_native_libs(
    apks: list[Path], root: Path, *, sha256: Callable[[Path], str]
) -> list[NativeLib]:
    """Extract every shared object of the APK set to ``lib/<abi>/``."""
    libs: list[NativeLib] = []
    seen: set[tuple[str, str]] = set()
    for apk in apks:
        with zipfile.ZipFile(apk) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                with archive.open(info) as handle:
                    head = handle.read(4)
                classified = classify_native_entry(info.filename, head)
                if classified is None:
                    continue
                abi, name = classified
                if (abi, name) in seen:
                    continue
                seen.add((abi, name))
                target = native_lib_path(root, abi, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as sink:
                    while True:
                        chunk = source.read(1 << 20)
                        if not chunk:
                            break
                        sink.write(chunk)
                libs.append(
                    NativeLib(
                        abi=abi,
                        name=name,
                        entry=info.filename,
                        source_apk=apk.name,
                        size=info.file_size,
                        sha256=sha256(target),
                        path=target,
                    )
                )
    return libs


def native_libs_json(libs: list[NativeLib], root: Path) -> dict[str, Any]:
    return {
        "count": len(libs),
        "done": sum(1 for item in libs if item.status == "done"),
        "libs": [item.to_json(root) for item in libs],
    }
