"""Worker lifecycle for the MCP server.

Each open binary or database is a ``Handle``: one spawned worker process
(``worker.worker_main``) reached over a pipe. Calls to one handle are
serialized; calls to different handles run in parallel. A call that times out
kills the worker (with its process group); a worker that dies is reopened on
the next call. At most ``max_sessions`` workers stay alive: opening another
closes (and saves) the least recently used one. Idle workers close after
``idle_seconds``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import itertools
import multiprocessing
from pathlib import Path
import threading
import time
from typing import Any, Callable

from ..apk_native import _active_children, _active_lock, kill_process_group
from ..errors import ToCodeError
from . import targets as targets_module
from .targets import FolderTarget, Target

DEFAULT_MAX_SESSIONS = 4
DEFAULT_IDLE_SECONDS = 1800.0
DEFAULT_CALL_TIMEOUT = 300.0
# Opening analyzes a fresh binary from scratch: allow a long time.
DEFAULT_OPEN_TIMEOUT = 6 * 3600.0
CLOSE_TIMEOUT = 600.0
REAPER_SECONDS = 30.0


class SessionError(ToCodeError):
    pass


@dataclass
class Handle:
    target: Target
    process: Any = None
    conn: Any = None
    info: dict[str, Any] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    last_used: float = field(default_factory=time.monotonic)
    busy: bool = False
    note: str | None = None  # why the last worker went away
    pending_note: str | None = None  # told to the agent on the next result

    @property
    def alive(self) -> bool:
        return self.process is not None and self.process.is_alive()


class SessionManager:
    def __init__(
        self,
        *,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        idle_seconds: float = DEFAULT_IDLE_SECONDS,
        call_timeout: float = DEFAULT_CALL_TIMEOUT,
        open_timeout: float = DEFAULT_OPEN_TIMEOUT,
        worker_options: dict[str, Any] | None = None,
        log: Callable[[str], None] = lambda _message: None,
        log_dir: Path | None = None,
    ) -> None:
        self.max_sessions = max(1, max_sessions)
        self.idle_seconds = idle_seconds
        self.call_timeout = call_timeout
        self.open_timeout = open_timeout
        self.worker_options = dict(worker_options or {})
        self.log = log
        self.log_dir = log_dir
        self.handles: dict[str, Handle] = {}
        self.folders: dict[str, FolderTarget] = {}
        self._lock = threading.RLock()
        self._ids = itertools.count(1)
        self._stop = threading.Event()
        self._reaper = threading.Thread(
            target=self._reap_idle, name="tocode-mcp-reaper", daemon=True
        )
        self._reaper.start()

    # -- opening ----------------------------------------------------------------

    def open(
        self,
        path: str,
        *,
        database: str | None = None,
        backend: str | None = None,
    ) -> dict[str, Any]:
        resolved = targets_module.resolve(
            Path(path),
            database=Path(database) if database else None,
            backend=backend,
        )
        if isinstance(resolved, FolderTarget):
            with self._lock:
                resolved.name = self._unique(resolved.name, self.folders)
                self.folders[resolved.name] = resolved
            return resolved.describe()
        handle = self._adopt(resolved)
        self._ensure_worker(handle)
        return dict(handle.info)

    def _adopt(self, target: Target) -> Handle:
        with self._lock:
            for handle in self.handles.values():
                if (
                    handle.target.open_path == target.open_path
                    and handle.target.backend == target.backend
                ):
                    return handle  # already open: reuse the session
            target.name = self._unique(target.name, self.handles)
            handle = Handle(target=target)
            self.handles[target.name] = handle
            return handle

    def _unique(self, name: str, taken: dict[str, Any]) -> str:
        if name not in taken and name not in self.handles and name not in self.folders:
            return name
        for number in itertools.count(2):
            candidate = f"{name}#{number}"
            if candidate not in self.handles and candidate not in self.folders:
                return candidate
        raise AssertionError("unreachable")

    def handle(self, session: str) -> Handle:
        """A session by id, or a folder binary by relative path (opened on demand)."""
        with self._lock:
            if not session or session == "default":
                if len(self.handles) == 1:
                    return next(iter(self.handles.values()))
                raise SessionError(
                    "pass `session` (see `sessions`, or `open` a path first)"
                )
            handle = self.handles.get(session)
            if handle is not None:
                return handle
            folder_name, _, relpath = session.partition(":")
            candidates = (
                [(self.folders[folder_name], relpath)]
                if relpath and folder_name in self.folders
                else [(folder, session) for folder in self.folders.values()]
            )
        for folder, rel in candidates:
            export_dir = folder.binaries.get(rel)
            if export_dir is None:
                continue
            target = targets_module.export_target(
                export_dir, folder=folder.name, relpath=rel, name=f"{folder.name}:{rel}"
            )
            return self._adopt(target)
        raise SessionError(
            f"unknown session {session!r}; open sessions: "
            f"{', '.join(self.handles) or 'none'}; folders: {', '.join(self.folders) or 'none'}"
        )

    # -- calling --------------------------------------------------------------

    def call(
        self,
        session: str,
        op: str,
        args: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        handle = self.handle(session)
        with handle.lock:
            self._ensure_worker(handle)
            handle.busy = True
            try:
                result = self._roundtrip(handle, ("call", op, args or {}), timeout)
                if handle.pending_note and isinstance(result, dict):
                    result = {**result, "note": handle.pending_note}
                handle.pending_note = None
                return result
            finally:
                handle.busy = False
                handle.last_used = time.monotonic()

    def _roundtrip(self, handle: Handle, message: tuple, timeout: float | None) -> Any:
        request_id = next(self._ids)
        kind, *rest = message
        try:
            handle.conn.send((kind, request_id, *rest))
        except (OSError, BrokenPipeError) as exc:
            self._discard(handle, f"worker pipe closed: {exc}")
            raise SessionError(
                f"session {handle.target.name} lost its worker; retry the call"
            ) from exc
        limit = self.call_timeout if timeout is None else timeout
        deadline = time.monotonic() + limit if limit and limit > 0 else None
        while True:
            wait = (
                1.0
                if deadline is None
                else max(0.0, min(1.0, deadline - time.monotonic()))
            )
            try:
                ready = handle.conn.poll(wait)
            except (OSError, EOFError):
                ready = False
            if ready:
                try:
                    reply = handle.conn.recv()
                except (EOFError, OSError):
                    reply = None
                if reply is None:
                    break
                status, reply_id, payload = reply
                if reply_id != request_id:
                    continue  # a late answer to a call that timed out earlier
                if status == "ok":
                    return payload
                raise SessionError(str(payload))
            if not handle.alive:
                break
            if deadline is not None and time.monotonic() >= deadline:
                self._discard(handle, f"call timed out after {limit:.0f}s")
                raise SessionError(
                    f"{rest[0] if rest else kind} timed out after {limit:.0f}s; the "
                    f"session's worker was stopped (unsaved edits are lost) and "
                    "reopens on the next call"
                )
        code = handle.process.exitcode if handle.process is not None else None
        self._discard(handle, f"worker exited (code {code})")
        hint = (
            " (killed by a signal, out of memory?)"
            if code is not None and code < 0
            else ""
        )
        raise SessionError(
            f"session {handle.target.name}'s worker died during the call{hint}; "
            "it reopens on the next call (unsaved edits are lost)"
        )

    # -- worker lifecycle ---------------------------------------------------------

    def _ensure_worker(self, handle: Handle) -> None:
        if handle.alive and handle.conn is not None:
            return
        self._make_room(keep=handle)
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        log_path = self._log_path(handle.target)
        from .worker import worker_main

        process = context.Process(
            target=worker_main,
            args=(handle.target, child, log_path, self.worker_options),
            name=f"tocode-live-{handle.target.name}",
            daemon=False,
        )
        process.start()
        child.close()
        if process.pid is not None:
            with _active_lock:
                _active_children.add(process.pid)
        self.log(f"live: opening {handle.target.name} ({handle.target.open_path})")
        deadline = time.monotonic() + self.open_timeout
        while time.monotonic() < deadline:
            if parent.poll(1.0):
                try:
                    status, payload = parent.recv()
                except (EOFError, OSError):
                    break
                if status == "ready":
                    handle.process, handle.conn = process, parent
                    handle.info = dict(payload)
                    if handle.note:
                        handle.pending_note = f"reopened after: {handle.note}"
                        handle.info["note"] = handle.pending_note
                        handle.note = None
                    handle.last_used = time.monotonic()
                    return
                self._stop_process(process)
                raise SessionError(
                    f"could not open {handle.target.open_path}: {payload}"
                )
            if not process.is_alive():
                break
        self._stop_process(process)
        raise SessionError(
            f"could not open {handle.target.open_path}: the worker exited or timed "
            f"out (see {log_path})"
        )

    def _log_path(self, target: Target) -> Path:
        if target.export_dir is not None:
            return target.export_dir / ".tocode" / "live.log"
        base = self.log_dir or Path.home() / ".cache" / "tocode" / "live"
        return base / f"{target.name.replace('/', '_').replace(':', '_')}.log"

    def _make_room(self, *, keep: Handle) -> None:
        with self._lock:
            alive = [h for h in self.handles.values() if h.alive and h is not keep]
        while len(alive) >= self.max_sessions:
            idle = [h for h in alive if not h.busy]
            if not idle:
                raise SessionError(
                    f"all {self.max_sessions} sessions are busy; close one or raise "
                    "--max-sessions"
                )
            victim = min(idle, key=lambda h: h.last_used)
            self.log(f"live: closing {victim.target.name} to make room")
            self._retire(victim, "closed to make room for another session")
            alive.remove(victim)

    def close(self, session: str, *, save: bool = True) -> dict[str, Any]:
        handle = self.handle(session)
        result: dict[str, Any] = {"session": handle.target.name, "closed": True}
        with handle.lock:
            if handle.alive and handle.conn is not None:
                try:
                    result.update(
                        self._roundtrip(handle, ("close", save), CLOSE_TIMEOUT) or {}
                    )
                except SessionError as exc:
                    result["error"] = str(exc)
                self._discard(handle, "closed")
        with self._lock:
            self.handles.pop(handle.target.name, None)
        return result

    def _discard(self, handle: Handle, why: str) -> None:
        process = handle.process
        handle.process, handle.conn = None, None
        handle.note = why
        if process is not None:
            self._stop_process(process)

    def _stop_process(self, process: Any) -> None:
        process.join(timeout=5)
        if process.is_alive():
            kill_process_group(process.pid)
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
        if process.pid is not None:
            with _active_lock:
                _active_children.discard(process.pid)

    def _reap_idle(self) -> None:
        while not self._stop.wait(REAPER_SECONDS):
            if self.idle_seconds <= 0:
                continue
            now = time.monotonic()
            with self._lock:
                idle = [
                    h
                    for h in self.handles.values()
                    if h.alive and not h.busy and now - h.last_used > self.idle_seconds
                ]
            for handle in idle:
                self.log(f"live: closing idle session {handle.target.name}")
                self._retire(handle, "closed after being idle")

    def _retire(self, handle: Handle, why: str) -> None:
        """Save and stop a worker but keep the session: it reopens on demand."""
        try:
            with handle.lock:
                if handle.alive and handle.conn is not None:
                    self._roundtrip(handle, ("close", True), CLOSE_TIMEOUT)
                self._discard(handle, why)
        except SessionError:
            pass

    def describe(self) -> dict[str, Any]:
        with self._lock:
            return {
                "sessions": [
                    {
                        **h.target.describe(),
                        "alive": h.alive,
                        "idle_seconds": round(time.monotonic() - h.last_used),
                    }
                    for h in self.handles.values()
                ],
                "folders": [folder.describe() for folder in self.folders.values()],
                "max_sessions": self.max_sessions,
            }

    def shutdown(self) -> None:
        self._stop.set()
        for name in list(self.handles):
            try:
                self.close(name, save=True)
            except ToCodeError:
                continue
