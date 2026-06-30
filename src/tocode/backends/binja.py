from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import BackendName
from ..errors import BackendError


# Functions a thunk/PLT stub typically forwards to; lets us classify support
# code that Binary Ninja did not flag itself.
_RUNTIME_NAMES = frozenset(
    {
        "_init",
        "_fini",
        "__libc_start_main",
        "__libc_csu_init",
        "__libc_csu_fini",
        "frame_dummy",
        "register_tm_clones",
        "deregister_tm_clones",
        "__do_global_dtors_aux",
    }
)


# -- headless (binja-headless / RPyc) helpers ------------------------------
#
# binja-headless exposes ``conn.root.binaryninja`` (the module), ``conn.root.bv``
# (the view that was focused when the server started), and ``conn.root.eval`` (a
# remote ``eval``). It has no view-enumeration call, so open views are listed by
# reaching ``binaryninjaui.UIContext`` through ``eval``. Active-context lookup is
# Qt-main-thread bound and returns ``None`` over a background RPyc thread, so the
# focused view is taken from ``conn.root.bv`` instead.


def connect_rpyc(host: str, port: int) -> Any:
    """Open an RPyc connection to a binja-headless service."""
    try:
        import rpyc  # type: ignore[import-untyped]
    except ImportError as exc:
        raise BackendError(
            "python package rpyc is not installed; it ships with ToCode, so "
            "reinstall ToCode to restore it"
        ) from exc
    try:
        # Analysis of a fresh binary can take a while; do not time out waiting on
        # a remote call.
        return rpyc.connect(host, port, config={"sync_request_timeout": None})
    except Exception as exc:  # noqa: BLE001
        raise BackendError(
            f"could not connect to binja-headless at {host}:{port}: {exc}"
        ) from exc


def binaryninja_module(conn: Any) -> Any:
    return conn.root.binaryninja


def focused_view(conn: Any) -> Any:
    """The view binja-headless exposed at startup (the focused one)."""
    raw = getattr(conn.root, "bv", None)
    try:
        # Older builds expose ``bv`` as a method; current ones as the view itself.
        return raw() if callable(raw) else raw
    except Exception:  # noqa: BLE001
        return None


def open_views(conn: Any) -> list[Any]:
    """Every open ``BinaryView``, via the Binary Ninja UI context.

    Deduplicated by (file, view type, base) so a file opened in several tabs is
    listed once.
    """
    try:
        ui = conn.root.eval("__import__('binaryninjaui')")
    except Exception as exc:  # noqa: BLE001
        raise BackendError(
            f"could not access the Binary Ninja UI to list views: {exc}"
        ) from exc
    try:
        contexts = list(ui.UIContext.allContexts())
    except Exception as exc:  # noqa: BLE001
        raise BackendError(f"could not enumerate Binary Ninja views: {exc}") from exc

    seen: set[tuple[str, str, int]] = set()
    views: list[Any] = []
    for ctx in contexts:
        try:
            tabs = list(ctx.getTabs())
        except Exception:  # noqa: BLE001
            continue
        for tab in tabs:
            frame = ctx.getViewFrameForTab(tab)
            if frame is None:
                continue
            data = None
            try:
                data = frame.getCurrentBinaryView()
            except Exception:  # noqa: BLE001
                data = None
            if data is None:
                try:
                    data = frame.getData()
                except Exception:  # noqa: BLE001
                    data = None
            if data is None:
                continue
            key = (
                view_source_path(data),
                str(getattr(data, "view_type", "") or ""),
                int(getattr(data, "start", 0) or 0),
            )
            if key in seen:
                continue
            seen.add(key)
            views.append(data)
    return views


def view_source_path(bv: Any) -> str:
    view_file = getattr(bv, "file", None)
    name = getattr(view_file, "filename", None) or getattr(
        view_file, "original_filename", None
    )
    return str(name) if name else ""


def describe_view(bv: Any) -> str:
    view_type = str(getattr(bv, "view_type", "") or "?")
    bits = int(getattr(bv, "address_size", 0) or 0) * 8
    path = view_source_path(bv) or "<unnamed>"
    try:
        functions = str(len(list(bv.functions)))
    except Exception:  # noqa: BLE001
        functions = "?"
    return f"{view_type} {bits}-bit  {path}  ({functions} functions)"


class BinjaSession:
    """DecompilerSession backed by Binary Ninja.

    One class serves two execution modes because both ultimately drive the
    ``binaryninja`` module against a live ``BinaryView``:

    * **In the Binary Ninja UI** -- constructed directly with the console's
      ``bv`` (``BinjaSession(bv=bv)``); ``binaryninja`` is imported locally.
    * **Headless via** `binja-headless <https://github.com/hugsy/binja-headless>`_
      -- :meth:`connect_headless` opens an RPyc connection to a running Binary
      Ninja and uses ``conn.root.binaryninja`` plus a live ``BinaryView`` (the
      focused one, a selected one, or each open one -- see the module-level
      :func:`focused_view` / :func:`open_views` helpers). Those are network
      proxies (netrefs), so the same attribute access works unchanged; this code
      only converts values to plain ``int``/``str`` eagerly to keep round-trips
      down.

    A live view and an RPyc connection cannot be pickled into a worker process,
    so this backend renders serially in the parent (``parallel_safe = False``
    and deliberately absent from ``exporter.TIMEOUT_WORKER_BACKENDS``).
    """

    backend_name: BackendName = "binja"
    backend_label = "Binary Ninja"
    decompiler_label = "Binary Ninja (Pseudo C)"
    analysis_command: str | None = None
    parallel_safe = False

    def __init__(self, *, bv: Any, bn: Any = None) -> None:
        if bv is None:
            raise BackendError("Binary Ninja backend requires a BinaryView")
        if bn is None:
            try:
                import binaryninja  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - requires a BN install
                raise BackendError(
                    "the binaryninja module is not importable; run this inside "
                    "Binary Ninja, or use the headless path via binja-headless"
                ) from exc
            bn = binaryninja
        self._bn = bn
        self._bv = bv
        self._conn: Any = None
        self._disasm_cache: dict[int, str] = {}
        self._decompile_cache: dict[int, str] = {}

    @classmethod
    def connect_headless(
        cls, host: str, port: int, *, path: Path | str | None = None
    ) -> "BinjaSession":
        """Attach to a running Binary Ninja over binja-headless (RPyc).

        Uses the focused view when the remote has one; otherwise loads ``path``
        remotely (the confirmed attach-else-load behavior). For selecting a
        specific view or iterating every open view, the CLI manages one
        connection itself with :func:`open_views` and injects each ``bv``.
        """
        conn = connect_rpyc(host, port)
        bn = conn.root.binaryninja
        bv = focused_view(conn)

        if bv is None:
            if path is None:
                conn.close()
                raise BackendError(
                    "the remote Binary Ninja has no open BinaryView and no binary "
                    "path was provided to load"
                )
            try:
                bv = bn.load(str(path))
            except Exception as exc:  # noqa: BLE001
                conn.close()
                raise BackendError(
                    f"remote Binary Ninja failed to load {path}: {exc}"
                ) from exc
            if bv is None:
                conn.close()
                raise BackendError(f"remote Binary Ninja could not load {path}")

        session = cls(bv=bv, bn=bn)
        session._conn = conn
        return session

    # -- lifecycle ---------------------------------------------------------

    def analyze(self) -> None:
        try:
            self._bv.update_analysis_and_wait()
        except Exception as exc:  # noqa: BLE001
            raise BackendError(f"Binary Ninja analysis failed: {exc}") from exc

    def close(self) -> None:
        self._disasm_cache.clear()
        self._decompile_cache.clear()
        conn = self._conn
        self._conn = None
        # Only tear down the RPyc connection we own. An injected UI ``bv`` stays
        # open -- the user still owns it in the GUI.
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def ensure_decompiler(self) -> None:
        # Binary Ninja always ships HLIL / Pseudo C; the only real failure mode
        # is an unusable view.
        if self._bv is None:
            raise BackendError("Binary Ninja BinaryView is not available")

    # -- binary metadata ---------------------------------------------------

    def info(self) -> dict[str, Any]:
        bv = self._bv
        arch = getattr(bv, "arch", None)
        arch_name = str(getattr(arch, "name", "") or "unknown")
        bits = int(getattr(bv, "address_size", 0) or 0) * 8
        platform = getattr(bv, "platform", None)
        os_name = "unknown"
        if platform is not None:
            pname = str(getattr(platform, "name", "") or "")
            if pname:
                os_name = pname.split("-", 1)[0]
        fmt = str(getattr(bv, "view_type", "") or "")
        return {
            "bin": {
                "arch": arch_name,
                "bits": bits,
                "baddr": int(getattr(bv, "start", 0) or 0),
                "os": os_name,
                "format": fmt,
                "class": fmt,
                "type": fmt,
            },
            "tocode": {"input_path": self._input_path()},
        }

    def entries(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[int] = set()
        entry_point = getattr(self._bv, "entry_point", None)
        if entry_point is not None:
            addr = int(entry_point)
            seen.add(addr)
            rows.append({"vaddr": addr})
        try:
            for func in self._bv.entry_functions or []:
                addr = int(func.start)
                if addr not in seen:
                    seen.add(addr)
                    rows.append({"vaddr": addr})
        except Exception:  # noqa: BLE001
            pass
        return rows

    def sections(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        sections = getattr(self._bv, "sections", {}) or {}
        items = sections.values() if hasattr(sections, "values") else sections
        for sec in items:
            start = int(getattr(sec, "start", 0) or 0)
            length = int(getattr(sec, "length", 0) or 0)
            rows.append(
                {
                    "name": str(getattr(sec, "name", "") or f"sec_{start:x}"),
                    "size": length,
                    "vsize": length,
                    "type": str(getattr(sec, "type", "") or ""),
                    "perm": self._perms_at(start),
                    "paddr": start,
                    "vaddr": start,
                }
            )
        return rows

    def imports(self) -> list[dict[str, Any]]:
        bn = self._bn
        rows: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for type_name in (
            "ImportedFunctionSymbol",
            "ImportAddressSymbol",
            "ImportedDataSymbol",
        ):
            symbol_type = getattr(bn.SymbolType, type_name, None)
            if symbol_type is None:
                continue
            for sym in self._bv.get_symbols_of_type(symbol_type) or []:
                addr = int(getattr(sym, "address", 0) or 0)
                name = self._symbol_name(sym)
                key = (addr, name)
                if not name or key in seen:
                    continue
                seen.add(key)
                lib = self._symbol_library(sym)
                rows.append(
                    {
                        "plt": addr,
                        "name": name,
                        "bind": lib,
                        "dll": lib,
                        "type": "import",
                        "delay": False,
                    }
                )
        return rows

    def exports(self) -> list[dict[str, Any]]:
        bn = self._bn
        rows: list[dict[str, Any]] = []
        seen: set[int] = set()
        global_bindings = {
            getattr(bn.SymbolBinding, name, None)
            for name in ("GlobalBinding", "WeakBinding")
        }
        global_bindings.discard(None)
        for type_name in ("FunctionSymbol", "DataSymbol"):
            symbol_type = getattr(bn.SymbolType, type_name, None)
            if symbol_type is None:
                continue
            for sym in self._bv.get_symbols_of_type(symbol_type) or []:
                if getattr(sym, "binding", None) not in global_bindings:
                    continue
                addr = int(getattr(sym, "address", 0) or 0)
                if addr in seen:
                    continue
                seen.add(addr)
                rows.append(
                    {
                        "name": self._symbol_name(sym),
                        "vaddr": addr,
                        "bind": "GLOBAL",
                        "type": "export",
                        "ordinal": getattr(sym, "ordinal", None),
                        "is_forwarder": False,
                        "forwarder_target": None,
                    }
                )
        return rows

    def symbols(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for sym in self._bv.get_symbols() or []:
            name = self._symbol_name(sym)
            addr = int(getattr(sym, "address", 0) or 0)
            kind = str(getattr(sym, "type", "") or "")
            rows.append(
                {
                    "name": name,
                    "flagname": name,
                    "realname": str(getattr(sym, "short_name", None) or name),
                    "size": 0,
                    "type": kind,
                    "vaddr": addr,
                    "paddr": addr,
                    "is_imported": "Import" in kind,
                }
            )
        return rows

    def relocations(self) -> list[dict[str, Any]]:
        # Binary Ninja exposes relocation ranges without symbol names or types in
        # a stable, cross-version way; the exporter tolerates an empty list.
        return []

    def strings(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in self._bv.get_strings() or []:
            start = int(getattr(item, "start", 0) or 0)
            try:
                value = str(item.value)
            except Exception:  # noqa: BLE001
                value = ""
            length = int(getattr(item, "length", 0) or len(value))
            rows.append(
                {
                    "vaddr": start,
                    "paddr": start,
                    "size": length,
                    "length": length,
                    "section": self._section_name_at(start),
                    "type": str(getattr(item, "type", "") or "ascii"),
                    "string": value,
                }
            )
        return rows

    def flags(self) -> list[dict[str, Any]]:
        # Binary Ninja has no radare2-style flag namespace; empty is tolerated.
        return []

    def functions(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for func in self._bv.functions or []:
            addr = int(func.start)
            name = str(getattr(func, "name", "") or f"sub_{addr:x}")
            symbol_type = str(getattr(getattr(func, "symbol", None), "type", "") or "")
            is_import = "Import" in symbol_type
            is_thunk = bool(getattr(func, "is_thunk", False)) or is_import
            params = self._params(func)
            local_vars = self._locals(func)
            row: dict[str, Any] = {
                "addr": addr,
                "name": name,
                "size": int(getattr(func, "total_bytes", 0) or 0),
                "signature": self._signature(func),
                "calltype": self._calltype(func),
                "noreturn": not bool(getattr(func, "can_return", True)),
                "stackframe": 0,
                "nlocals": len(local_vars),
                "nargs": len(params),
                "outdegree": self._degree(func, "callees"),
                "indegree": self._degree(func, "callers"),
                "is_library": is_import,
                "is_thunk": is_thunk,
                "source_kind": self._classify(
                    name, is_import=is_import, is_thunk=is_thunk
                ),
                "return_type": self._return_type(func),
                "params": params,
            }
            if local_vars:
                row["locals"] = local_vars
            rows.append(row)
        return rows

    def types(self) -> list[dict[str, Any]]:
        # Type recovery ships as an empty stub for v1; can be enriched from
        # bv.types in a follow-up.
        return []

    # -- per-function rendering --------------------------------------------

    def disasm(self, address: int) -> str:
        address = int(address)
        if address in self._disasm_cache:
            return self._disasm_cache[address]
        func = self._bv.get_function_at(address)
        lines: list[str] = []
        if func is not None:
            try:
                for tokens, insn_addr in func.instructions:
                    text = "".join(str(token) for token in tokens)
                    lines.append(f"0x{int(insn_addr):x}: {text}".rstrip())
            except Exception:  # noqa: BLE001
                pass
        rendered = "\n".join(lines)
        self._disasm_cache[address] = rendered
        return rendered

    def decompile(self, address: int) -> str:
        address = int(address)
        if address not in self._decompile_cache:
            func = self._bv.get_function_at(address)
            self._decompile_cache[address] = self._render_pseudo_c(func, address)
        return self._decompile_cache[address]

    def function_summary(self, address: int) -> str:
        address = int(address)
        func = self._bv.get_function_at(address)
        if func is None:
            return (
                f"signature: sub_{address:x}\naddress: 0x{address:x}\n"
                "args: 0\nlocals: 0"
            )
        params = self._params(func)
        local_vars = self._locals(func)
        signature = (
            self._signature(func)
            or str(getattr(func, "name", "") or "")
            or f"sub_{address:x}"
        )
        lines = [
            f"signature: {signature}",
            f"address: 0x{address:x}",
            f"size: {int(getattr(func, 'total_bytes', 0) or 0)} bytes",
            f"returns: {'no' if not getattr(func, 'can_return', True) else 'yes'}",
            f"callers: {self._degree(func, 'callers')}",
            f"callees: {self._degree(func, 'callees')}",
            f"args: {len(params)}",
            f"locals: {len(local_vars)}",
        ]
        return "\n".join(lines)

    # -- call graph / xrefs ------------------------------------------------

    def calls_from(
        self, address: int, imports, functions
    ) -> tuple[list[int], list[str]]:
        address = int(address)
        func = self._bv.get_function_at(address)
        if func is None:
            return [], []
        function_addrs = set(functions)
        edges: set[int] = set()
        imported: set[str] = set()
        for target in self._callee_addresses(func):
            if target == address:
                continue
            routine = functions.get(target)
            if target in function_addrs and not (
                routine is not None and getattr(routine, "imported", False)
            ):
                edges.add(target)
            else:
                name = self._resolve_name(target, imports, functions)
                if name:
                    imported.add(name)
        return sorted(edges), sorted(imported)

    def data_xrefs(self, addresses) -> dict[int, list[tuple[int, bool]]]:
        # Data cross-references ship as an empty stub for v1.
        return {}

    # -- helpers -----------------------------------------------------------

    def _input_path(self) -> str:
        view_file = getattr(self._bv, "file", None)
        filename = getattr(view_file, "filename", None) or getattr(
            view_file, "original_filename", None
        )
        return str(filename) if filename else ""

    def _perms_at(self, address: int) -> str:
        segment = None
        try:
            segment = self._bv.get_segment_at(int(address))
        except Exception:  # noqa: BLE001
            segment = None
        if segment is None:
            return "---"
        return "".join(
            [
                "r" if getattr(segment, "readable", False) else "-",
                "w" if getattr(segment, "writable", False) else "-",
                "x" if getattr(segment, "executable", False) else "-",
            ]
        )

    def _section_name_at(self, address: int) -> str:
        try:
            sections = self._bv.get_sections_at(int(address)) or []
        except Exception:  # noqa: BLE001
            return ""
        for sec in sections:
            name = getattr(sec, "name", None)
            if name:
                return str(name)
        return ""

    @staticmethod
    def _symbol_name(sym: Any) -> str:
        return str(getattr(sym, "short_name", None) or getattr(sym, "name", "") or "")

    @staticmethod
    def _symbol_library(sym: Any) -> str | None:
        namespace = getattr(sym, "namespace", None)
        name = getattr(namespace, "name", None)
        if isinstance(name, (list, tuple)):
            name = name[0] if name else None
        return str(name) if name else None

    def _params(self, func: Any) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        try:
            for var in func.parameter_vars or []:
                out.append(
                    {
                        "name": str(getattr(var, "name", "") or ""),
                        "type": self._type_str(getattr(var, "type", None)),
                    }
                )
        except Exception:  # noqa: BLE001
            pass
        return out

    def _locals(self, func: Any) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        try:
            param_ids = {self._var_id(v) for v in (func.parameter_vars or [])}
        except Exception:  # noqa: BLE001
            param_ids = set()
        try:
            for var in func.vars or []:
                if self._var_id(var) in param_ids:
                    continue
                out.append(
                    {
                        "name": str(getattr(var, "name", "") or ""),
                        "type": self._type_str(getattr(var, "type", None)),
                    }
                )
        except Exception:  # noqa: BLE001
            pass
        return out

    @staticmethod
    def _var_id(var: Any) -> Any:
        identifier = getattr(var, "identifier", None)
        if identifier is not None:
            return int(identifier)
        return str(getattr(var, "name", ""))

    @staticmethod
    def _type_str(type_obj: Any) -> str:
        if type_obj is None:
            return ""
        try:
            return str(type_obj).strip()
        except Exception:  # noqa: BLE001
            return ""

    def _return_type(self, func: Any) -> str | None:
        rt = getattr(func, "return_type", None)
        text = self._type_str(rt)
        return text or None

    def _signature(self, func: Any) -> str | None:
        # Build a plain C declaration ("ret name(args)") rather than relying on
        # str(func.type), which renders a function-pointer-ish form the
        # exporter's signature parser mishandles.
        try:
            ret = self._return_type(func) or "void"
            name = str(getattr(func, "name", "") or f"sub_{int(func.start):x}")
            params = self._params(func)
            parts = [
                f"{param['type']} {param['name']}".strip() for param in params
            ] or ["void"]
            return f"{ret} {name}({', '.join(parts)})"
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _calltype(func: Any) -> str | None:
        cc = getattr(func, "calling_convention", None)
        name = getattr(cc, "name", None)
        return str(name) if name else None

    @staticmethod
    def _degree(func: Any, attr: str) -> int:
        try:
            return len(list(getattr(func, attr) or []))
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _classify(name: str, *, is_import: bool, is_thunk: bool) -> str:
        if is_thunk:
            return "thunk"
        if is_import:
            return "library"
        lowered = (name or "").lower()
        if lowered in _RUNTIME_NAMES or lowered.startswith(
            ("__libc_csu_", "__scrt_", "_scrt_", "__crt", "_crt", "_global__sub_i_")
        ):
            return "runtime"
        return "app"

    def _callee_addresses(self, func: Any) -> set[int]:
        out: set[int] = set()
        try:
            for callee in func.callees or []:
                out.add(int(callee.start))
        except Exception:  # noqa: BLE001
            pass
        return out

    def _resolve_name(self, target: int, imports, functions) -> str:
        if target in imports:
            return imports[target].name
        routine = functions.get(target)
        if routine is not None and getattr(routine, "imported", False):
            return routine.name
        func = self._bv.get_function_at(int(target))
        if func is not None:
            return str(getattr(func, "name", "") or f"sub_{target:x}")
        return f"sub_{target:x}"

    def _render_pseudo_c(self, func: Any, address: int) -> str:
        bn = self._bn
        if func is None:
            return (
                f"int sub_{address:x}()\n{{\n"
                "    /* Binary Ninja: no function at this address */\n}\n"
            )
        # Thunks / external stubs may have no high-level IL; emit a prototype stub
        # so the exporter still gets a parseable declaration.
        try:
            if func.hlil is None:
                proto = self._signature(func) or f"int sub_{address:x}()"
                return f"{proto}\n{{\n    /* Binary Ninja: no high-level IL */\n}}\n"
        except Exception:  # noqa: BLE001
            pass

        settings = bn.DisassemblySettings()
        for option_name, value in (
            ("ShowAddress", False),
            ("WaitForIL", True),
        ):
            option = getattr(bn.DisassemblyOption, option_name, None)
            if option is not None:
                try:
                    settings.set_option(option, value)
                except Exception:  # noqa: BLE001
                    pass

        try:
            obj = self._language_representation(bn, settings)
            cursor = bn.LinearViewCursor(obj)
            body = self._collect_lines(cursor, func)
        except Exception as exc:  # noqa: BLE001
            proto = self._signature(func) or f"int sub_{address:x}()"
            return f"{proto}\n{{\n    /* Binary Ninja render failed: {exc} */\n}}\n"

        text = "\n".join(body).strip("\n")
        if not text:
            proto = self._signature(func) or f"int sub_{address:x}()"
            return f"{proto}\n{{\n}}\n"
        return text + "\n"

    def _language_representation(self, bn: Any, settings: Any) -> Any:
        view_object = bn.LinearViewObject
        # Prefer an explicit Pseudo C representation; fall back to the default
        # high-level representation on older API signatures.
        try:
            return view_object.language_representation(
                self._bv, settings, language="Pseudo C"
            )
        except TypeError:
            pass
        except Exception:  # noqa: BLE001
            pass
        return view_object.language_representation(self._bv, settings)

    def _collect_lines(self, cursor: Any, func: Any) -> list[str]:
        start = int(func.start)
        end = int(getattr(func, "highest_address", start) or start)
        cursor.seek_to_address(start)
        out: list[str] = []
        guard = 0
        while guard < 100000:
            guard += 1
            batch = self._bv.get_next_linear_disassembly_lines(cursor)
            if not batch:
                break
            stop = False
            for line in batch:
                contents = getattr(line, "contents", None)
                addr = int(getattr(contents, "address", 0) or 0)
                # Stop once the cursor walks past this function's body.
                if out and addr > end:
                    stop = True
                    break
                out.append(str(line))
            if stop:
                break
        return out
