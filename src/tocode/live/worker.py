"""The per-session worker process and the operations it serves.

A worker opens one binary or database with the regular backend stack
(``create_analyzer``), collects the inventory once, and then answers
operations sent by the supervisor over a pipe. It runs in its own process
group so a crash, an OOM kill, or a hung decompile only costs this session.
"""

from __future__ import annotations

import ast
from bisect import bisect_right
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
import importlib
import io
import json
import os
from pathlib import Path
import re
import traceback
from typing import Any, Callable

from ..errors import ToCodeError
from ..progress import Progress
from ..schema import ProgramAnalysis, Routine
from .targets import Target

_AUTO_NAME_RX = re.compile(
    r"(?:sub|fun|FUN|loc|j_sub|nullsub|qword|dword|word|byte|xmmword|ymmword|"
    r"off|unk|stru|asc|flt|dbl|data|DAT|PTR|LAB)_([0-9a-fA-F]+)"
)
# Operations that never need a fresh inventory first.
_NO_REFRESH = frozenset({"save", "status", "eval", "info", "refresh", "sync"})
MAX_TEXT = 200_000
MAX_READ = 64 * 1024
MAX_SEARCH_BYTES = 512 * 1024 * 1024
DEFAULT_LIMIT = 100


class OpError(ToCodeError):
    """A request the session cannot satisfy (bad target, unsupported, ...)."""


# --------------------------------------------------------------------------
# Process entry point
# --------------------------------------------------------------------------


def worker_main(
    target: Target,
    conn: Any,
    log_path: Path,
    options: dict[str, Any],
) -> None:
    from ..apk_native import _redirect_output, watch_parent

    if hasattr(os, "setsid"):
        try:
            os.setsid()
        except OSError:  # pragma: no cover - already a session leader
            pass
    watch_parent()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    _redirect_output(log_path)
    try:
        live = open_session(target, log_path=log_path, options=options)
    except BaseException as exc:  # noqa: BLE001 - report every open failure
        conn.send(("failed", f"{type(exc).__name__}: {exc}"))
        return
    conn.send(("ready", live.info()))
    while True:
        try:
            message = conn.recv()
        except (EOFError, OSError):
            break
        kind = message[0]
        if kind == "close":
            _, request_id, save = message
            try:
                result = live.close(save=bool(save))
            except BaseException as exc:  # noqa: BLE001
                conn.send(("error", request_id, f"{type(exc).__name__}: {exc}"))
            else:
                conn.send(("ok", request_id, result))
            break
        if kind != "call":
            continue
        _, request_id, op, args = message
        try:
            result = live.dispatch(op, args or {})
        except OpError as exc:
            conn.send(("error", request_id, str(exc)))
        except BaseException as exc:  # noqa: BLE001 - keep serving after a failure
            detail = traceback.format_exc(limit=6)
            live.log(f"live: {op} failed: {detail}")
            conn.send(("error", request_id, f"{type(exc).__name__}: {exc}"))
        else:
            conn.send(("ok", request_id, result))


def open_session(target: Target, *, log_path: Path, options: dict[str, Any]) -> Any:
    """The session class for the target's backend (.NET or a native backend)."""
    if target.backend == "dotnet":
        from .dotnet_live import DotnetLiveSession

        return DotnetLiveSession(
            target,
            log_path=log_path,
            allow_eval=bool(options.get("allow_eval", True)),
            allow_edits=bool(options.get("allow_edits", True)),
        )
    return LiveSession(target, log_path=log_path, **options)


def run_python(namespace: dict[str, Any], code: str) -> tuple[Any, str, str | None]:
    """Run an eval script: (last expression or `result`, output, traceback)."""
    namespace["result"] = None
    tree = ast.parse(code, mode="exec")
    tail = None
    last = tree.body[-1] if tree.body else None
    if isinstance(last, ast.Expr):
        tree.body.pop()
        tail = ast.Expression(last.value)
    output = io.StringIO()
    error = None
    value: Any = None
    with redirect_stdout(output), redirect_stderr(output):
        try:
            exec(compile(tree, "<eval>", "exec"), namespace)  # noqa: S102
            if tail is not None:
                value = eval(compile(tail, "<eval>", "eval"), namespace)  # noqa: S307
            else:
                value = namespace.get("result")
        except BaseException:  # noqa: BLE001 - the script's own failure
            error = traceback.format_exc(limit=8)
    return value, output.getvalue(), error


# --------------------------------------------------------------------------
# The session
# --------------------------------------------------------------------------


class LiveSession:
    def __init__(
        self,
        target: Target,
        *,
        log_path: Path,
        binja_dir: str | None = None,
        allow_eval: bool = True,
        allow_edits: bool = True,
    ) -> None:
        from ..analysis import create_analyzer
        from ..naming import build_name_book

        self.target = target
        self.allow_eval = allow_eval
        self.allow_edits = allow_edits
        self.progress = Progress(enabled=False, log_path=log_path)
        self.log(f"live: opening {target.open_path} ({target.backend})")
        self.analyzer = create_analyzer(
            target.open_path,
            backend=target.backend,  # type: ignore[arg-type]
            progress=self.progress,
            binja_dir=Path(binja_dir) if binja_dir else None,
        )
        self.session: Any = self.analyzer.session
        self.analysis: ProgramAnalysis = self.analyzer.collect()
        self.names = build_name_book(self.analysis)
        self.eval_namespace: dict[str, Any] | None = None
        # Addresses changed in this session that the next sync must re-render.
        self.dirty: set[int] = set()
        self.unknown_changes = False  # eval ran: sync must diff the inventory
        self.stale = False  # the inventory must be collected again before queries
        self.types_changed = False
        self.globals_changed = False
        self.functions_changed = False
        self.edit_ops: set[str] = set()
        self.assigned_names: dict[str, int] = {}
        self._build_indexes()
        self.ops: dict[str, Callable[[dict[str, Any]], Any]] = {
            "info": lambda _args: self.info(),
            "functions": self.op_functions,
            "function": self.op_function,
            "decompile": self.op_decompile,
            "disassemble": self.op_disassemble,
            "xrefs": self.op_xrefs,
            "strings": self.op_strings,
            "imports": self.op_imports,
            "exports": self.op_exports,
            "sections": self.op_sections,
            "types": self.op_types,
            "type": self.op_type,
            "read_bytes": self.op_read_bytes,
            "search": self.op_search,
            "lookup": self.op_lookup,
            "eval": self.op_eval,
            "save": lambda _args: self.save(),
            "refresh": lambda _args: self.refresh(),
            "status": lambda _args: self.status(),
        }
        self._register_extensions()
        from . import hooks

        # Edits made by eval scripts mark their functions for the next sync.
        self._hooks = hooks.install(self)
        self.log("live: session ready")

    # -- plumbing -------------------------------------------------------------

    def log(self, message: str) -> None:
        self.progress.file_log(message)

    def dispatch(self, op: str, args: dict[str, Any]) -> Any:
        handler = self.ops.get(op)
        if handler is None:
            raise OpError(f"unknown operation {op}")
        if self.stale and op not in self.edit_ops and op not in _NO_REFRESH:
            self.refresh()
        return handler(args)

    def _register_extensions(self) -> None:
        """Edit and sync operations live in their own modules."""
        for module in ("edits", "sync"):
            try:
                loaded = importlib.import_module(f"{__package__}.{module}")
            except ImportError:
                continue
            register = getattr(loaded, "register", None)
            if callable(register):
                register(self)

    @property
    def backend(self) -> str:
        return str(self.session.backend_name)

    def info(self) -> dict[str, Any]:
        binary = self.analysis.binary
        return {
            **self.target.describe(),
            "backend": self.backend,
            "backend_label": self.analyzer.backend_label,
            "decompiler": self.analyzer.decompiler_label,
            "arch": binary.arch,
            "bits": binary.bits,
            "format": binary.format_name,
            "os": binary.os_name,
            "image_base": hex(binary.image_base),
            "entrypoints": [hex(item) for item in binary.entrypoints],
            "functions": len(self.analysis.routines),
            "imports": len(self.analysis.imports),
            "exports": len(self.analysis.exports),
            "strings": len(self.analysis.strings),
            "types": len(self.analysis.types),
            "eval": self.allow_eval,
            "edits": self.allow_edits,
        }

    def status(self) -> dict[str, Any]:
        return {
            "pending_functions": sorted(hex(item) for item in self.dirty),
            "unknown_changes": self.unknown_changes,
        }

    def refresh(self) -> dict[str, Any]:
        """Collect the inventory again (after edits that add or rename things)."""
        from ..naming import build_name_book

        self.analyzer.analysis = None
        self.analysis = self.analyzer.collect()
        self.names = build_name_book(self.analysis)
        self._build_indexes()
        self.stale = False
        return {"functions": len(self.analysis.routines)}

    def reindex(self) -> None:
        """Names changed in place: rebuild the name book and lookups."""
        from ..naming import build_name_book

        self.names = build_name_book(self.analysis)
        self._build_indexes()

    def refresh_types(self) -> None:
        self.analysis.types = self.analyzer._types()

    def close(self, *, save: bool) -> dict[str, Any]:
        saved: dict[str, Any] = {"saved": False}
        if save and (self.dirty or self.unknown_changes or self._edited):
            saved = self.save()
        try:
            self.analyzer.close()
        except Exception:  # noqa: BLE001
            pass
        return saved

    _edited = False

    def save(self) -> dict[str, Any]:
        """Write the database to disk (edits survive the session)."""
        from . import edits

        return edits.save_database(self)

    # -- indexes and lookup ---------------------------------------------------

    def _build_indexes(self) -> None:
        routines = self.analysis.routines
        self._starts = sorted(routines)
        self._by_name: dict[str, int] = {}
        for address, routine in routines.items():
            self._by_name.setdefault(routine.name, address)
            self._by_name.setdefault(
                self.names.function_name(address, routine.name), address
            )
        for symbol in self.analysis.symbols:
            if symbol.name:
                self._by_name.setdefault(symbol.name, symbol.vaddr)
        for export in self.analysis.exports:
            self._by_name.setdefault(export.name, export.address)
        for address, item in self.analysis.imports.items():
            self._by_name.setdefault(item.name, address)
        # Names given in this session to addresses without a symbol yet.
        for name, address in self.assigned_names.items():
            self._by_name[name] = address
        self._lower = {name.lower(): address for name, address in self._by_name.items()}
        self._locations = _load_locations(self.target.export_dir)

    def resolve(self, value: Any, *, what: str = "target") -> int:
        if isinstance(value, int):
            return value
        if not isinstance(value, str) or not value.strip():
            raise OpError(f"{what} must be an address (0x...) or a name")
        text = value.strip()
        if re.fullmatch(r"0x[0-9a-fA-F]+", text):
            return int(text, 16)
        if text.isdigit():
            return int(text)
        if text in self._by_name:
            return self._by_name[text]
        if text.lower() in self._lower:
            return self._lower[text.lower()]
        # Auto-generated names carry their address (IDA, Ghidra, Binary Ninja).
        match = _AUTO_NAME_RX.fullmatch(text)
        if match:
            return int(match.group(1), 16)
        raise OpError(f"no function or symbol named {text!r}; try `lookup`")

    def routine_at(self, address: int) -> Routine | None:
        routines = self.analysis.routines
        if address in routines:
            return routines[address]
        index = bisect_right(self._starts, address) - 1
        if index >= 0:
            routine = routines[self._starts[index]]
            if routine.address <= address < routine.address + max(routine.size, 1):
                return routine
        return None

    def function_for(self, value: Any) -> Routine:
        address = self.resolve(value)
        routine = self.routine_at(address)
        if routine is None:
            raise OpError(f"no function at {hex(address)}")
        return routine

    def name_of(self, address: int) -> str:
        routine = self.analysis.routines.get(address)
        if routine is not None:
            return self.names.function_name(address, routine.name)
        item = self.analysis.imports.get(address)
        return item.name if item is not None else hex(address)

    # -- queries --------------------------------------------------------------

    def _routine_row(self, routine: Routine) -> dict[str, Any]:
        return {
            "address": hex(routine.address),
            "name": self.names.function_name(routine.address, routine.name),
            "size": routine.size,
            "signature": routine.signature,
            "kind": "import"
            if routine.imported
            else "library"
            if routine.library
            else "thunk"
            if routine.thunk
            else routine.code_kind,
            "callers": routine.indegree,
            "callees": routine.outdegree,
        }

    def op_functions(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        kind = args.get("kind") or "all"
        rows = []
        for address in self._starts:
            routine = self.analysis.routines[address]
            row = self._routine_row(routine)
            if kind != "all" and row["kind"] != kind:
                continue
            if pattern is not None and not pattern(row["name"]):
                continue
            rows.append(row)
        return _page(rows, args)

    def op_function(self, args: dict[str, Any]) -> dict[str, Any]:
        routine = self.function_for(args.get("target"))
        address = routine.address
        callees = self.analysis.callees.get(address, [])
        callers = self.analysis.callers.get(address, [])
        row = self._routine_row(routine)
        row.update(
            {
                "return_type": routine.return_type,
                "calltype": routine.calltype,
                "noreturn": routine.noreturn,
                "params": [{"name": n, "type": t} for n, t in routine.params],
                "locals": [{"name": n, "type": t} for n, t in routine.local_vars],
                "callers": [
                    {"address": hex(item), "name": self.name_of(item)}
                    for item in callers
                ],
                "callees": [
                    {"address": hex(item), "name": self.name_of(item)}
                    for item in callees
                ],
                "imports_called": self.analysis.import_calls.get(address, []),
                "source": {"file": routine.source_file, "line": routine.source_line}
                if routine.source_file
                else None,
                "export": self._locations.get(address),
            }
        )
        return row

    def op_decompile(self, args: dict[str, Any]) -> dict[str, Any]:
        from ..exporter import render_one_with_limits

        routine = self.function_for(args.get("target"))
        rendered = render_one_with_limits(
            self.session, self.analysis, routine, self.names
        )
        return {
            "address": hex(routine.address),
            "name": rendered.c_name,
            "prototype": rendered.prototype,
            "code": _clip(rendered.c_text),
            "error": rendered.failure.message if rendered.failure else None,
            "export": self._locations.get(routine.address),
        }

    def op_disassemble(self, args: dict[str, Any]) -> dict[str, Any]:
        routine = self.function_for(args.get("target"))
        text = self.session.disasm(routine.address)
        limit = int(args.get("max_lines") or 0)
        if limit > 0:
            lines = text.splitlines()
            text = "\n".join(lines[:limit]) + (
                f"\n... {len(lines) - limit} more lines" if len(lines) > limit else ""
            )
        return {
            "address": hex(routine.address),
            "name": self.name_of(routine.address),
            "disassembly": _clip(text),
        }

    def op_xrefs(self, args: dict[str, Any]) -> dict[str, Any]:
        address = self.resolve(args.get("target"))
        direction = args.get("direction") or "to"
        routine = self.analysis.routines.get(address)
        rows: list[dict[str, Any]] = []
        if direction == "from":
            if routine is None:
                raise OpError("xrefs from works on a function; use eval for data")
            for item in self.analysis.callees.get(address, []):
                rows.append(
                    {"to": hex(item), "name": self.name_of(item), "kind": "call"}
                )
            for name in self.analysis.import_calls.get(address, []):
                rows.append({"to": None, "name": name, "kind": "import call"})
            return {"target": hex(address), "direction": "from", "refs": rows}
        if routine is not None:
            for item in self.analysis.callers.get(address, []):
                rows.append(
                    {"from": hex(item), "function": self.name_of(item), "kind": "call"}
                )
        names = self._import_names_at(address)
        if names:
            # An import is called through its stub: name the real callers.
            for caller, called in sorted(self.analysis.import_calls.items()):
                if names & {_bare(name) for name in called}:
                    rows.append(
                        {
                            "from": hex(caller),
                            "function": self.name_of(caller),
                            "kind": "import call",
                        }
                    )
        seen = {row["from"] for row in rows}
        refs = self.analysis.data_xrefs.get(address)
        if refs is None:
            try:
                refs = self.session.data_xrefs([address]).get(address, [])
            except Exception:  # noqa: BLE001
                refs = []
        for source, write in refs or []:
            owner = self.routine_at(source)
            key = hex(source)
            if key in seen:
                continue
            rows.append(
                {
                    "from": key,
                    "function": self.name_of(owner.address) if owner else None,
                    "kind": "write" if write else "read",
                }
            )
        return {"target": hex(address), "direction": "to", "refs": rows}

    def _import_names_at(self, address: int) -> set[str]:
        """Import names behind an address: the import itself or its stub."""
        known = {_bare(item.name) for item in self.analysis.imports.values()}
        names: set[str] = set()
        imported = self.analysis.imports.get(address)
        if imported is not None:
            names.add(_bare(imported.name))
        stub = self.analysis.routines.get(address)
        if stub is not None and _bare(stub.name) in known:
            names.add(_bare(stub.name))
        return names

    def op_strings(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        rows = []
        for item in self.analysis.strings:
            if pattern is not None and not pattern(item.value):
                continue
            users = sorted(
                {
                    self.name_of(owner.address)
                    for source, _ in self.analysis.data_xrefs.get(item.vaddr, [])
                    if (owner := self.routine_at(source)) is not None
                }
            )
            rows.append(
                {
                    "address": hex(item.vaddr),
                    "value": item.value,
                    "kind": item.kind,
                    "used_by": users,
                }
            )
        return _page(rows, args)

    def op_imports(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        rows = [
            {"address": hex(address), "name": item.name, "library": item.dll}
            for address, item in sorted(self.analysis.imports.items())
            if pattern is None or pattern(item.name)
        ]
        return _page(rows, args)

    def op_exports(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        rows = [
            {"address": hex(item.address), "name": item.name, "kind": item.kind}
            for item in self.analysis.exports
            if pattern is None or pattern(item.name)
        ]
        return _page(rows, args)

    def op_sections(self, _args: dict[str, Any]) -> dict[str, Any]:
        return {
            "sections": [
                {
                    "name": segment.name,
                    "address": hex(segment.vaddr),
                    "size": max(segment.vsize, segment.size),
                    "perms": segment.perms,
                    "kind": segment.kind,
                }
                for segment in self.analysis.segments
            ]
        }

    def op_types(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        kind = args.get("kind")
        rows = [
            {"name": item.name, "kind": item.kind, "size": item.size}
            for item in self.analysis.types
            if (pattern is None or pattern(item.name))
            and (not kind or item.kind == kind)
        ]
        return _page(rows, args)

    def op_type(self, args: dict[str, Any]) -> dict[str, Any]:
        name = str(args.get("name") or "").strip()
        for item in self.analysis.types:
            if item.name == name:
                return {
                    "name": item.name,
                    "kind": item.kind,
                    "size": item.size,
                    "c_decl": item.c_decl,
                    "members": item.members,
                }
        raise OpError(f"no type named {name!r}; try `types` with a filter")

    def read(self, address: int, size: int) -> bytes:
        reader = getattr(self.session, "read_bytes", None)
        if callable(reader):
            data = reader(address, size)
            if data:
                return bytes(data)
        segment = self.analysis.segment_at(address)
        if segment is None or segment.size <= 0:
            return b""
        offset = address - segment.vaddr
        if offset >= segment.size:
            return b"\0" * size  # uninitialized (bss-like) memory
        path = self.analysis.binary.path
        try:
            with path.open("rb") as handle:
                handle.seek(segment.paddr + offset)
                return handle.read(min(size, segment.size - offset))
        except OSError:
            return b""

    def op_read_bytes(self, args: dict[str, Any]) -> dict[str, Any]:
        address = self.resolve(args.get("address"), what="address")
        size = max(1, min(int(args.get("size") or 64), MAX_READ))
        data = self.read(address, size)
        return {
            "address": hex(address),
            "size": len(data),
            "hex": data.hex(),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
        }

    def op_search(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = str(args.get("pattern") or "")
        kind = args.get("kind") or "text"
        limit = max(1, min(int(args.get("limit") or 50), 1000))
        if not pattern:
            raise OpError("search needs a pattern")
        if kind == "hex":
            try:
                needle = re.compile(re.escape(bytes.fromhex(pattern.replace(" ", ""))))
            except ValueError as exc:
                raise OpError(f"bad hex pattern: {exc}") from exc
        elif kind == "regex":
            needle = re.compile(pattern.encode("utf-8"))
        else:
            needle = re.compile(re.escape(pattern.encode("utf-8")))
        hits: list[dict[str, Any]] = []
        budget = MAX_SEARCH_BYTES
        for segment in self.analysis.segments:
            size = min(segment.size, budget)
            if size <= 0:
                continue
            budget -= size
            blob = self.read(segment.vaddr, size)
            for match in needle.finditer(blob):
                address = segment.vaddr + match.start()
                owner = self.routine_at(address)
                hits.append(
                    {
                        "address": hex(address),
                        "section": segment.name,
                        "function": self.name_of(owner.address) if owner else None,
                    }
                )
                if len(hits) >= limit:
                    return {
                        "pattern": pattern,
                        "kind": kind,
                        "hits": hits,
                        "truncated": True,
                    }
        return {"pattern": pattern, "kind": kind, "hits": hits, "truncated": False}

    def op_lookup(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("name") or "").strip().lower()
        if not query:
            raise OpError("lookup needs a name")
        limit = max(1, min(int(args.get("limit") or 50), 500))
        rows = []
        for name, address in sorted(self._by_name.items()):
            if query in name.lower():
                owner = self.routine_at(address)
                rows.append(
                    {
                        "name": name,
                        "address": hex(address),
                        "function": self.name_of(owner.address) if owner else None,
                    }
                )
                if len(rows) >= limit:
                    break
        return {"query": query, "matches": rows}

    # -- eval -------------------------------------------------------------------

    def touch(self, *addresses: Any) -> None:
        for value in addresses:
            self.dirty.add(self.resolve(value))

    def _namespace(self) -> dict[str, Any]:
        if self.eval_namespace is not None:
            return self.eval_namespace
        namespace: dict[str, Any] = {
            "__name__": "__tocode_eval__",
            "session": self.session,
            "analysis": self.analysis,
            "touch": self.touch,
            "resolve": self.resolve,
            "result": None,
        }
        backend = self.backend
        if backend == "ida":
            namespace["db"] = getattr(self.session, "_db", None)
            for module in (
                "idaapi",
                "idc",
                "idautils",
                "ida_funcs",
                "ida_name",
                "ida_typeinf",
                "ida_hexrays",
                "ida_bytes",
                "ida_xref",
                "ida_segment",
                "ida_nalt",
                "ida_lines",
                "ida_ua",
                "ida_loader",
            ):
                try:
                    namespace[module] = importlib.import_module(module)
                except Exception:  # noqa: BLE001 - optional modules
                    continue
        elif backend == "binja":
            namespace["bv"] = getattr(self.session, "_bv", None)
            namespace["bn"] = getattr(self.session, "_bn", None)
        elif backend == "r2":
            namespace["r2"] = self.session
        elif backend == "angr":
            namespace["project"] = getattr(self.session, "project", None)
        self.eval_namespace = namespace
        return namespace

    def op_eval(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.allow_eval:
            raise OpError("eval is disabled for this server (--no-eval / --read-only)")
        code = str(args.get("code") or "")
        language = args.get("language") or "python"
        if args.get("reset"):
            self.eval_namespace = None
        self.unknown_changes = True
        self._edited = True
        if language == "r2":
            command = getattr(self.session, "cmd", None)
            if not callable(command):
                raise OpError(
                    f"r2 commands need the r2 backend (this is {self.backend})"
                )
            return {"output": _clip(str(command(code)))}
        if language != "python":
            raise OpError("language must be python or r2")
        before = set(self.dirty)
        value, output, error = run_python(self._namespace(), code)
        return {
            "result": _jsonable(value),
            "stdout": _clip(output),
            "error": error,
            "touched": sorted(hex(item) for item in self.dirty - before),
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _bare(name: str) -> str:
    """`_printf`, `.printf`, `printf@@GLIBC_2.17` -> `printf`."""
    return name.split("@", 1)[0].lstrip("._")


def _load_locations(export_dir: Path | None) -> dict[int, dict[str, Any]]:
    """Where each function lives in the export (from function-index.json)."""
    if export_dir is None:
        return {}
    try:
        payload = json.loads((export_dir / "function-index.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    locations: dict[int, dict[str, Any]] = {}
    for row in payload.get("functions", []):
        try:
            address = int(str(row["address"]), 16)
        except (KeyError, ValueError):
            continue
        c = row.get("c") or {}
        asm = row.get("asm") or {}
        locations[address] = {
            "c": f"{_relative(c.get('path'), export_dir)}:{c.get('line_start')}-{c.get('line_end')}",
            "asm": f"{_relative(asm.get('path'), export_dir)}:{asm.get('line_start')}-{asm.get('line_end')}",
        }
    return locations


def _relative(path: Any, root: Path) -> str:
    if not path:
        return ""
    try:
        return Path(str(path)).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _matcher(pattern: Any) -> Callable[[str], bool] | None:
    if not pattern:
        return None
    text = str(pattern)
    try:
        compiled = re.compile(text, re.IGNORECASE)
    except re.error:
        lowered = text.lower()
        return lambda value: lowered in value.lower()
    return lambda value: compiled.search(value) is not None


def _page(rows: list[dict[str, Any]], args: dict[str, Any]) -> dict[str, Any]:
    offset = max(0, int(args.get("offset") or 0))
    limit = max(1, min(int(args.get("limit") or DEFAULT_LIMIT), 2000))
    page = rows[offset : offset + limit]
    result: dict[str, Any] = {"total": len(rows), "offset": offset, "items": page}
    if offset + limit < len(rows):
        result["next_offset"] = offset + limit
    return result


def _clip(text: str, limit: int = MAX_TEXT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... truncated ({len(text) - limit} more characters)"


def _jsonable(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return _clip(repr(value), 2000)
    if value is None or isinstance(value, (bool, int, float, str)):
        return _clip(value) if isinstance(value, str) else value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_READ]).hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): _jsonable(item, depth + 1)
            for key, item in list(value.items())[:2000]
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item, depth + 1) for item in list(value)[:2000]]
    if hasattr(value, "__dataclass_fields__"):
        try:
            return _jsonable(asdict(value), depth + 1)
        except TypeError:
            pass
    return _clip(repr(value), 2000)
