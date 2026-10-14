"""Binary Ninja headless backend (the ``binaryninja`` Python API, in process).

Like the IDA backend it takes a file: a binary, or a Binary Ninja database
(``.bndb``). Analysis of a binary is cached as a ``.bndb`` keyed by the file's
SHA-256, so re-runs and parallel workers open the finished analysis instead of
repeating it. A ``.bndb`` given as input is opened as-is and never written.

The rendering is shared with the UI/RPyc backend (``BinjaSession``); this
session adds what is cheap only when the API is local: section bytes, full C
type definitions, and data cross-references with read/write direction.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
from typing import Any

from ..errors import BackendError
from ..progress import Progress
from .base import bootstrap_binja, is_binja_database
from .binja import BinjaSession


# Bump when a change to how the cached database is built makes old ones stale.
_BNDB_CACHE_VERSION = 1
MAX_TYPES = 50_000
MAX_REFS_PER_ADDRESS = 256
ANALYSIS_POLL_SECONDS = 0.5
# How long an aborted analysis may take to stop before the view is closed.
ABORT_WAIT_SECONDS = 10.0
SAVE_PROBE_TIMEOUT_SECONDS = 180.0


def cache_root() -> Path:
    explicit = os.environ.get("TOCODE_BINJA_CACHE_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "tocode" / "binja"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached_database(binary: Path) -> Path:
    return cache_root() / f"{_sha256(binary)}.v{_BNDB_CACHE_VERSION}.bndb"


def license_path() -> Path | None:
    """The license file named by ``--binja-license`` / ``TOCODE_BINJA_LICENSE``.

    Without one, Binary Ninja reads its own (``license.dat`` in its user folder).
    """
    value = os.environ.get("TOCODE_BINJA_LICENSE", "").strip()
    return Path(value).expanduser() if value else None


def _apply_license(bn: Any) -> None:
    """Hand the license file to the core before its first call validates one.

    The contents go straight to ``core_set_license``; they are never logged.
    Spawned workers inherit ``TOCODE_BINJA_LICENSE`` and apply it the same way.
    """
    path = license_path()
    if path is None:
        return
    try:
        data = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BackendError(
            f"cannot read the Binary Ninja license file {path}: {exc.strerror or exc}"
        ) from exc
    set_license = getattr(bn, "core_set_license", None)
    if not callable(set_license):
        raise BackendError(
            "this Binary Ninja API cannot take a license file (no core_set_license)"
        )
    set_license(data)


def import_binaryninja(binja_dir: Path | None = None) -> Any:
    bootstrap_binja(binja_dir)
    already_imported = "binaryninja" in sys.modules
    if importlib.util.find_spec("binaryninja") is None:
        raise BackendError(
            "the Binary Ninja Python API was not found; pass --binja-dir or set "
            "TOCODE_BINJA_DIR to the Binary Ninja install folder"
        )
    try:
        bn = importlib.import_module("binaryninja")
    except Exception as exc:  # noqa: BLE001 - core load failures are not ImportError
        raise BackendError(f"cannot import the Binary Ninja Python API: {exc}") from exc
    if not already_imported:
        # The core validates a license on its first call, not on import.
        _apply_license(bn)
    # Headless Binary Ninja logs analysis warnings to the terminal; failures
    # reach ToCode as exceptions, so keep the terminal to ToCode's own output.
    disable_log = getattr(bn, "disable_default_log", None)
    if callable(disable_log):
        try:
            disable_log()
        except Exception:  # noqa: BLE001
            pass
    return bn


def headless_problem(binja_dir: Path | None = None) -> str | None:
    """Why this process cannot use the Binary Ninja API, or None when it can.

    Imports the API and initializes the core, which is where a license that
    does not allow headless use is refused (before any file is opened).
    """
    try:
        bn = import_binaryninja(binja_dir)
    except BackendError as exc:
        return str(exc)
    check = getattr(bn, "core_product", None)
    if not callable(check):
        return None
    try:
        check()
    except Exception as exc:  # noqa: BLE001
        return f"Binary Ninja refused headless use: {exc}"
    return None


# Run in a child process: a core that cannot write databases may crash in
# BNCreateDatabase instead of returning False.
_SAVE_PROBE = """
import sys
from pathlib import Path
from tocode.backends.binja_headless import import_binaryninja

work = Path(sys.argv[2])
bn = import_binaryninja(Path(sys.argv[1]) if sys.argv[1] else None)
sample = work / "probe.bin"
sample.write_bytes(bytes(64))
view = bn.load(str(sample), update_analysis=False)
print("saved" if view.create_database(str(work / "probe.bndb")) else "refused")
"""


def _save_probe_marker(bn: Any) -> Path:
    try:
        identity = f"{bn.core_version()}-{bn.core_product()}"
    except Exception:  # noqa: BLE001
        identity = "unknown"
    return cache_root() / f"save-probe-{re.sub(r'[^A-Za-z0-9.]+', '-', identity)}.txt"


def can_create_databases(bn: Any, binja_dir: Path | None = None) -> bool:
    """Whether this Binary Ninja can write a ``.bndb`` without crashing.

    Some headless builds crash inside ``create_database`` (Binary Ninja 6.0
    Personal on Linux did on every save), which would take ToCode down with
    it. A child process tries once per core version and product; the answer
    is kept next to the database cache.
    """
    marker = _save_probe_marker(bn)
    try:
        cached = marker.read_text(encoding="utf-8").strip()
    except OSError:
        cached = ""
    if cached in ("ok", "fail"):
        return cached == "ok"
    with tempfile.TemporaryDirectory(prefix="tocode-binja-probe-") as work:
        try:
            result = subprocess.run(
                [sys.executable, "-c", _SAVE_PROBE, str(binja_dir or ""), work],
                capture_output=True,
                text=True,
                timeout=SAVE_PROBE_TIMEOUT_SECONDS,
            )
            works = (
                result.returncode == 0
                and result.stdout.strip().endswith("saved")
                and (Path(work) / "probe.bndb").is_file()
            )
        except (OSError, subprocess.TimeoutExpired):
            works = False
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("ok" if works else "fail", encoding="utf-8")
    except OSError:
        pass
    return works


def _peak_rss_mb() -> int | None:
    """This process's peak resident memory, in MB (None where unsupported)."""
    try:
        import resource
    except ImportError:  # Windows
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB, macOS bytes.
    return int(peak // (1024 * 1024) if sys.platform == "darwin" else peak // 1024)


def _show_analysis_progress(bar: Any, bv: Any) -> None:
    try:
        status = bv.analysis_progress
        count, total = int(status.count), int(status.total)
        phase = str(status).split(" (", 1)[0]
    except Exception:  # noqa: BLE001 - progress display is best effort
        return
    bar.set_description_str(f"binja {phase.lower()}", refresh=False)
    bar.total = total if total > 0 else None
    bar.n = min(count, total) if total > 0 else 0
    bar.refresh()


def _load(bn: Any, source: Path, *, update_analysis: bool) -> Any:
    try:
        bv = bn.load(str(source), update_analysis=update_analysis)
    except Exception as exc:  # noqa: BLE001
        hint = ""
        if "licen" in str(exc).lower():
            hint = " (headless use needs a Binary Ninja license that allows it)"
        raise BackendError(
            f"Binary Ninja could not open {source}: {exc}{hint}"
        ) from exc
    if bv is None:
        raise BackendError(f"Binary Ninja could not open {source}")
    if is_binja_database(source) and not list(getattr(bv, "segments", None) or ()):
        # A save that crashed leaves an empty file, which Binary Ninja opens as
        # a view with nothing mapped (and no functions) instead of failing.
        try:
            bv.file.close()
        except Exception:  # noqa: BLE001
            pass
        raise BackendError(
            f"Binary Ninja database {source} is empty or incomplete (no segments)"
        )
    return bv


class BinjaHeadlessSession(BinjaSession):
    """``BinjaSession`` over a view this process opened with ``binaryninja.load``."""

    backend_label = "Binary Ninja (headless)"
    # Workers reopen the cached .bndb in their own process.
    parallel_safe = True
    worker_backend = "binja-headless"

    def __init__(
        self,
        binary: Path,
        *,
        binja_dir: Path | None = None,
        db_path: Path | None = None,
        purge_cache: bool = False,
        save_cache: bool = True,
        progress: Progress | None = None,
    ) -> None:
        self.binary = Path(binary).resolve()
        self.binja_dir = binja_dir
        bn = import_binaryninja(binja_dir)
        self._progress = progress
        self._log = progress.log if progress is not None else (lambda _message: None)
        self._worker_memory_mb: int | None = None
        from_cache = False
        if db_path is not None:
            source = Path(db_path)
            self._cache_db: Path | None = source
            fresh = False
        elif is_binja_database(self.binary):
            source = self.binary
            self._cache_db = self.binary
            fresh = False
        else:
            cache = cached_database(self.binary) if save_cache else None
            if cache is not None and purge_cache:
                cache.unlink(missing_ok=True)
            if cache is not None and cache.is_file():
                source, fresh, from_cache = cache, False, True
                self._log(f"Opening cached Binary Ninja database {cache}")
            else:
                source, fresh = self.binary, True
            self._cache_db = cache
        # Analysis runs in analyze(), under the exporter's progress bar.
        try:
            bv = _load(bn, source, update_analysis=False)
        except BackendError:
            if not from_cache:
                raise
            # A cached database this Binary Ninja cannot read (an interrupted
            # save, or one written by another version): rebuild it from the
            # binary, keeping it if the binary cannot be opened either.
            bv = _load(bn, self.binary, update_analysis=False)
            self._log(f"Discarding unreadable cached Binary Ninja database {source}")
            source.unlink(missing_ok=True)
            fresh = True
        super().__init__(bv=bv, bn=bn)
        self._released = False
        self._fresh = fresh
        self._original = Path(str(bv.file.original_filename or self.binary))

    # -- lifecycle ----------------------------------------------------------

    def analyze(self) -> None:
        self._wait_for_analysis()
        if self._fresh and self._cache_db is not None:
            # Keep the finished analysis for re-runs and for parallel workers.
            if not can_create_databases(self._bn, self.binja_dir):
                self._log(
                    "This Binary Ninja cannot save databases headless; rendering "
                    "in this process without a .bndb"
                )
                self._render_without_database()
            else:
                self._save_database(self._cache_db)
            self._fresh = False
        # A worker that reopens the database holds about what this process
        # holds now; the exporter sizes the worker count with it.
        self._worker_memory_mb = _peak_rss_mb()

    def _save_database(self, target: Path) -> None:
        self._log(f"Saving Binary Ninja database {target}")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            saved = bool(self._bv.create_database(str(target)))
        except Exception:  # noqa: BLE001 - a cache is an optimisation
            saved = False
        if saved:
            self._log(f"Saved Binary Ninja database {target}")
            return
        self._log("Could not save the Binary Ninja database; rendering in this process")
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        self._render_without_database()

    def _render_without_database(self) -> None:
        """Without a .bndb, workers would each repeat the analysis: render
        serially against this view instead, like the UI/MCP/RPyc sessions."""
        self._cache_db = None
        self.parallel_safe = False
        self.worker_backend = "binja"

    def _wait_for_analysis(self) -> None:
        """``update_analysis_and_wait`` with Binary Ninja's own progress shown.

        A large binary analyzes for minutes inside one native call. It runs on
        a thread so this one can show ``analysis_progress`` and, on Ctrl-C,
        abort the analysis instead of waiting for the call to return.
        """
        done = threading.Event()
        failure: list[BaseException] = []

        def run() -> None:
            try:
                BinjaSession.analyze(self)
            except BaseException as exc:  # noqa: BLE001 - re-raised below
                failure.append(exc)
            finally:
                done.set()

        threading.Thread(target=run, name="tocode-binja-analysis", daemon=True).start()
        bar = (
            self._progress.new_bar(desc="binja analysis", unit="fn")
            if self._progress is not None
            else None
        )
        try:
            while not done.wait(ANALYSIS_POLL_SECONDS):
                if bar is not None:
                    _show_analysis_progress(bar, self._bv)
        except KeyboardInterrupt:
            abort = getattr(self._bv, "abort_analysis", None)
            if callable(abort):
                try:
                    abort()
                except Exception:  # noqa: BLE001
                    pass
            done.wait(ABORT_WAIT_SECONDS)
            raise
        finally:
            if bar is not None:
                bar.close()
        if failure:
            raise failure[0]

    def worker_memory_mb(self) -> int | None:
        """Memory one render worker needs: this process's peak after analysis."""
        return self._worker_memory_mb

    def close(self) -> None:
        bv = self._bv
        super().close()
        if self._released:
            return
        try:
            bv.file.close()
        except Exception:  # noqa: BLE001
            pass

    def prepare_parallel_workers(self) -> None:
        return None  # analyze() already saved the database workers open

    def release_parallel_resources(self) -> None:
        """Close the parent's view while workers render (each loads its own)."""
        if self._released:
            return
        self._disasm_cache.clear()
        self._decompile_cache.clear()
        try:
            self._bv.file.close()
        except Exception:  # noqa: BLE001
            pass
        self._released = True

    def restore_parallel_resources(self) -> None:
        if not self._released:
            return
        source = self._cache_db or self.binary
        self._bv = _load(self._bn, source, update_analysis=True)
        self._released = False

    def read_bytes(self, address: int, size: int) -> bytes | None:
        if self._released:
            # Workers rendered with their own views and the parent's view was
            # closed; reopen it for the section data written after rendering.
            self.restore_parallel_resources()
        return super().read_bytes(address, size)

    def database_path(self) -> Path | None:
        """The .bndb workers open (the input database or the analysis cache)."""
        return self._cache_db

    def _input_path(self) -> str:
        return str(
            self.binary if not is_binja_database(self.binary) else self._original
        )

    # -- local-only enrichments -----------------------------------------------

    def types(self) -> list[dict[str, Any]]:
        bn = self._bn
        try:
            from binaryninja.typeprinter import TypePrinter  # type: ignore[import-not-found]

            printer = TypePrinter.default
            container = self._bv.type_container
        except Exception:  # noqa: BLE001
            return []
        # Plain C names in the header, not Binary Ninja's backtick escaping.
        escaping = getattr(
            getattr(bn, "TokenEscapingType", None), "NoTokenEscapingType", None
        )
        options = {"escaping": escaping} if escaping is not None else {}
        kinds = {
            "StructureTypeClass": "struct",
            "EnumerationTypeClass": "enum",
            "NamedTypeReferenceClass": "typedef",
            "FunctionTypeClass": "func",
        }
        rows: list[dict[str, Any]] = []
        for index, (name, type_obj) in enumerate(self._bv.types.items()):
            if index >= MAX_TYPES:
                break
            try:
                lines = printer.get_type_lines(
                    type_obj, container, bn.QualifiedName(name), **options
                )
                c_decl = "\n".join(str(line) for line in lines)
            except Exception:  # noqa: BLE001
                c_decl = str(type_obj)
            type_class = str(getattr(type_obj.type_class, "name", type_obj.type_class))
            kind = kinds.get(type_class, "typedef")
            if kind == "struct" and getattr(type_obj, "type", None) is not None:
                if "Union" in str(getattr(type_obj, "type", "")):
                    kind = "union"
            width = int(getattr(type_obj, "width", 0) or 0)
            rows.append(
                {
                    "name": str(name),
                    "kind": kind,
                    "size": width or None,
                    "c_decl": c_decl,
                }
            )
        return rows

    def data_xrefs(self, addresses: Any) -> dict[int, list[tuple[int, bool]]]:
        store = getattr(self._bn.LowLevelILOperation, "LLIL_STORE", None)
        result: dict[int, list[tuple[int, bool]]] = {}
        for address in addresses:
            target = int(address)
            refs: list[tuple[int, bool]] = []
            try:
                for ref in self._bv.get_code_refs(target):
                    if len(refs) >= MAX_REFS_PER_ADDRESS:
                        break
                    write = False
                    function = getattr(ref, "function", None)
                    if function is not None and store is not None:
                        try:
                            llil = function.get_llil_at(ref.address)
                            write = llil is not None and llil.operation == store
                        except Exception:  # noqa: BLE001
                            write = False
                    refs.append((int(ref.address), write))
            except Exception:  # noqa: BLE001
                continue
            if refs:
                result[target] = refs
        return result
