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
    restart: bool = False
    binja_dir: Path | None = None


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
        binja_dir=options.binja_dir,
    ) as analyzer:
        summary = export_binary(
            analyzer,
            out_dir=out_dir,
            progress=progress,
            jobs=options.jobs,
            tree=options.tree,
            entropy=options.entropy,
            restart=options.restart,
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
    watch_parent()
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


PARENT_POLL_SECONDS = 1.0


def watch_parent(poll_seconds: float = PARENT_POLL_SECONDS) -> None:
    """Kill this process group when the parent ToCode process goes away.

    An isolated export leads its own process group (so Ctrl-C can kill it with
    its decompiler workers), which also means it outlives a parent killed from
    outside (``kill``, a closed terminal, the OOM killer) and keeps holding
    gigabytes. Polling the parent pid works on every POSIX system.
    """
    if not hasattr(os, "getppid") or not hasattr(os, "killpg"):
        return
    parent = os.getppid()

    def run() -> None:
        while True:
            time.sleep(poll_seconds)
            if os.getppid() != parent:
                try:
                    os.killpg(os.getpgrp(), signal.SIGKILL)
                except OSError:  # pragma: no cover - not a group leader
                    os._exit(1)

    threading.Thread(target=run, name="tocode-parent-watch", daemon=True).start()


class ExportKilledError(ToCodeError):
    """An isolated export process was killed by a signal (usually out of memory)."""


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
            raise ExportKilledError(
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
        echo: bool = True,
    ) -> None:
        self.log_path = log_path
        self.lib = lib
        self.progress = progress
        self.poll_seconds = poll_seconds
        # False: lines go to the main log file only and no bar is drawn; the
        # caller renders progress from ``rendered``/``total``/``last_line``.
        self.echo = echo
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
            if self.echo:
                self._open_bar()
        if self.echo:
            self.progress.log(f"native[{self.lib.name}]: {line}")
        else:
            self.progress.file_log(f"[{self.lib.name}] {line}")

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


# A file that just started has not loaded its binary yet: count this much free
# memory as already taken by it for this long when deciding to start another.
RAMP_SECONDS = 20.0


@dataclass(slots=True)
class RunningExport:
    lib: NativeLib
    started: float
    tail: NestedLogTail | None = None


@dataclass
class NativeRunner:
    """Runs the native exports on a background thread.

    Up to ``parallel`` exports run at once, each in its own process (the
    exporter blocks a thread per export). A new export starts only when a slot
    is free and the host has ``min_free_mb`` of free memory for it on top of
    what recently started exports have not claimed yet. An export killed by a
    signal (the OOM killer) while others ran beside it is retried once, alone;
    it resumes from its own checkpoint.
    """

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
    # Folder exports draw their own progress display: per-library lines and
    # the nested logs then go to the log file only.
    quiet: bool = False
    parallel: int = 1
    ramp_seconds: float = RAMP_SECONDS
    current: NativeLib | None = None
    waiting: tuple[NativeLib, int] | None = None
    current_started: float = 0.0
    current_tail: NestedLogTail | None = None
    _running: dict[str, RunningExport] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _changed: threading.Event = field(default_factory=threading.Event)
    _overlapped: set[str] = field(default_factory=set)
    _retries: set[str] = field(default_factory=set)
    _alone: set[str] = field(default_factory=set)
    _decisions: dict[str, bool] = field(default_factory=dict)

    def running(self) -> list[RunningExport]:
        """The exports running now, oldest first."""
        with self._lock:
            return sorted(self._running.values(), key=lambda item: item.started)

    def describe_current(self) -> str | None:
        """One line about what the native thread is doing right now."""
        waiting = self.waiting
        running = self.running()
        if waiting is not None and not running:
            pending, available = waiting
            return (
                f"native: waiting for memory before {pending.name} ({pending.abi}): "
                f"{available} MB free, need {self.min_free_mb} MB "
                "(set TOCODE_NATIVE_MIN_FREE_MB to change)"
            )
        if not running:
            return None
        done = sum(1 for item in self.libs if item.status == "done")
        finished = sum(1 for item in self.libs if item.status not in {"pending"})
        now = time.monotonic()
        parts = [
            f"{item.lib.name} ({item.lib.abi}) "
            f"{item.tail.status() if item.tail else 'running'}, "
            f"{now - item.started:.0f}s elapsed"
            for item in running
        ]
        return (
            f"native: {'; '.join(parts)}; "
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
        self._changed.set()
        terminate_active_native_children()

    def claim_retry(self, lib: NativeLib, exc: BaseException) -> bool:
        """Whether a failed export is retried alone (decided once per attempt).

        Only a kill by a signal while other exports ran beside it qualifies,
        and only once: alone, the export has the memory the others were holding.
        """
        with self._lock:
            decided = self._decisions.get(lib.entry)
            if decided is not None:
                return decided
            retry = (
                not self.stop_event.is_set()
                and isinstance(exc, ExportKilledError)
                and lib.entry in self._overlapped
                and lib.entry not in self._retries
            )
            if retry:
                self._retries.add(lib.entry)
                self._alone.add(lib.entry)
            self._decisions[lib.entry] = retry
            return retry

    def _run(self) -> None:
        queue = list(self.libs)
        threads: list[threading.Thread] = []
        while True:
            threads = [thread for thread in threads if thread.is_alive()]
            if self.stop_event.is_set():
                break
            with self._lock:
                running = len(self._running)
                queue[:0] = [lib for lib in self._requeued() if lib not in queue]
            if not queue:
                if running == 0:
                    break
                self._wait_for_change()
                continue
            lib = queue[0]
            with self._lock:
                alone_running = any(entry in self._alone for entry in self._running)
            if (
                running >= max(1, self.parallel)
                or alone_running
                or (lib.entry in self._alone and running > 0)
            ):
                self._wait_for_change()
                continue
            if not self._memory_allows(lib, running):
                continue
            if self.stop_event.is_set():
                break
            queue.pop(0)
            self._launch(lib, threads)
        for thread in threads:
            thread.join()
        for lib in self.libs:
            if lib.status == "pending":
                lib.status = "skipped: interrupted"

    def _requeued(self) -> list[NativeLib]:
        """Exports that failed and are claimed for a retry (caller holds the lock)."""
        return [
            lib
            for lib in self.libs
            if lib.entry in self._alone
            and lib.status == "pending"
            and lib.entry not in self._running
            and lib.seconds is not None
        ]

    def _wait_for_change(self) -> None:
        self._changed.wait(self.poll_seconds)
        self._changed.clear()

    def _memory_allows(self, lib: NativeLib, running: int) -> bool:
        """True when ``lib`` may start now; otherwise waits a little, returns False."""
        if self.min_free_mb <= 0:
            return True
        if running == 0:
            # Nothing else runs: wait for memory up to the limit, then go anyway.
            self._wait_for_memory(lib)
            return True
        now = time.monotonic()
        with self._lock:
            ramping = sum(
                1
                for item in self._running.values()
                if now - item.started < self.ramp_seconds
            )
        available = self.available_memory()
        if available is None or available >= self.min_free_mb * (1 + ramping):
            self.waiting = None
            return True
        self.waiting = (lib, available)
        self._wait_for_change()
        return False

    def _launch(self, lib: NativeLib, threads: list[threading.Thread]) -> None:
        self.waiting = None
        lib.status = "pending"
        out_dir = lib.export_dir or native_export_dir(self.root, lib)
        lib.export_dir = out_dir
        tail = (
            NestedLogTail(
                out_dir / "tocode.log", lib, self.progress, echo=not self.quiet
            )
            if self.mirror_logs
            else None
        )
        item = RunningExport(lib=lib, started=time.monotonic(), tail=tail)
        with self._lock:
            if self._running:
                self._overlapped.add(lib.entry)
                self._overlapped.update(self._running)
            self._running[lib.entry] = item
            self._decisions.pop(lib.entry, None)
            self.current = lib
            self.current_started = item.started
            self.current_tail = tail
        thread = threading.Thread(
            target=self._export_one,
            args=(item,),
            name=f"tocode-native-{lib.stem}",
            daemon=True,
        )
        threads.append(thread)
        thread.start()

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
                (self.progress.file_log if self.quiet else self.progress.log)(
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

    def _export_one(self, item: RunningExport) -> None:
        # Folder exports place each library themselves; APK/.NET use native/.
        lib = item.lib
        out_dir = lib.export_dir or native_export_dir(self.root, lib)
        child = Progress(enabled=False)
        child.set_log_path(out_dir / "tocode.log")
        say = self.progress.file_log if self.quiet else self.progress.log
        say(
            f"native: {lib.name} ({lib.abi}) export started -> "
            f"{_rel(out_dir, self.root)}"
        )
        tail = item.tail
        if tail is not None:
            tail.start()
        retry = False
        try:
            backend, decompiler, functions, failures = self.exporter(
                lib, out_dir, child
            )
        except ToCodeError as exc:
            retry = self.claim_retry(lib, exc)
            lib.status = "pending" if retry else f"failed: {exc}"
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
            lib.seconds = time.monotonic() - item.started
            with self._lock:
                self._running.pop(lib.entry, None)
                if self.current is lib:
                    self.current = None
                    self.current_tail = None
                if not retry:
                    self._alone.discard(lib.entry)
            self._changed.set()
        if retry:
            say(
                f"native: {lib.name} ({lib.abi}) was killed while other exports ran; "
                "retrying it alone"
            )
        elif lib.status == "done":
            say(
                f"native: {lib.name} ({lib.abi}) exported with {lib.backend} "
                f"in {lib.seconds:.1f}s: functions={lib.function_count} "
                f"failures={lib.failure_count}"
            )
        else:
            self.errors.append(f"{lib.abi}/{lib.name}: {lib.status}")
            say(f"native: {lib.name} ({lib.abi}) {lib.status}")


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
