from __future__ import annotations

from contextlib import contextmanager
import logging
from pathlib import Path
from typing import Any, Iterator

from .base import BackendName
from ..errors import BackendError


@contextmanager
def _quiet_angr_logs() -> Iterator[None]:
    """Suppress expected angr diagnostics while preserving ToCode output."""
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(previous)


try:
    with _quiet_angr_logs():
        import angr  # type: ignore[import-untyped]
        import angr.analyses.decompiler  # noqa: F401  # register the Decompiler analysis
except ImportError:  # pragma: no cover - optional backend
    angr = None  # type: ignore[assignment]

try:  # XRef typing lives in different places across angr versions
    with _quiet_angr_logs():
        from angr.knowledge_plugins.xrefs import XRefType as _xref_type_cls
except Exception:  # noqa: BLE001  # pragma: no cover
    _xref_type_cls = None  # type: ignore[assignment,misc]

# Keep XRefType defined (as Any) whether or not the optional import succeeded.
XRefType: Any = _xref_type_cls


_RUNTIME_NAMES = frozenset(
    {
        "_init",
        "_fini",
        "__libc_start_main",
        "__libc_csu_init",
        "__libc_csu_fini",
        "__gmon_start__",
        "frame_dummy",
        "register_tm_clones",
        "deregister_tm_clones",
        "__do_global_dtors_aux",
    }
)


class AngrSession:
    """DecompilerSession backed by angr.

    angr is a pure-Python backend (no external decompiler binary) used as a
    last-resort fallback when neither IDA nor radare2 is available. It produces
    the same export structure as the other backends; the pseudo-C quality is
    lower than Hex-Rays/r2ghidra, which is accepted.
    """

    backend_name: BackendName = "angr"
    backend_label = "angr"
    decompiler_label = "angr decompiler"
    # Re-running angr's CFG in every worker process is prohibitively expensive,
    # so v1 renders serially.
    parallel_safe = False

    def __init__(self, binary: Path, *, analysis_command: str | None = None) -> None:
        self.binary = Path(binary).resolve()
        self.analysis_command: str | None = analysis_command
        if angr is None:
            raise BackendError("python package angr is not installed")
        try:
            with _quiet_angr_logs():
                self.project: Any = angr.Project(
                    str(self.binary),
                    auto_load_libs=False,
                    load_options={"perform_relocations": True},
                )
        except Exception as exc:  # noqa: BLE001
            raise BackendError(f"angr failed to load {self.binary}: {exc}") from exc
        self._cfg: Any = None
        self._funcs: dict[int, Any] = {}
        self._disasm_cache: dict[int, str] = {}
        self._decompile_cache: dict[int, str] = {}

    # -- lifecycle ---------------------------------------------------------

    def analyze(self) -> None:
        try:
            with _quiet_angr_logs():
                self._cfg = self.project.analyses.CFGFast(
                    normalize=True, cross_references=True
                )
        except Exception as exc:  # noqa: BLE001
            raise BackendError(f"angr CFG construction failed: {exc}") from exc
        # Recover prototypes/arguments/variables so functions() and the
        # decompiler have signatures and locals to work with. Best-effort:
        # a failure here only degrades quality, not structure.
        try:
            with _quiet_angr_logs():
                self.project.analyses.CompleteCallingConventions(
                    recover_variables=True, cfg=self._cfg.model
                )
        except Exception:  # noqa: BLE001
            pass
        self._funcs = {
            int(func.addr): func for func in self.project.kb.functions.values()
        }

    def close(self) -> None:
        self._funcs.clear()
        self._disasm_cache.clear()
        self._decompile_cache.clear()
        self._cfg = None
        self.project = None

    def ensure_decompiler(self) -> None:
        if not hasattr(self.project.analyses, "Decompiler"):
            raise BackendError(
                "angr decompiler is unavailable; install a complete angr"
            )

    # -- binary metadata ---------------------------------------------------

    def info(self) -> dict[str, Any]:
        arch = self.project.arch
        mo = self.project.loader.main_object
        base = getattr(mo, "mapped_base", 0) or getattr(mo, "min_addr", 0) or 0
        fmt = type(mo).__name__
        return {
            "bin": {
                "arch": getattr(arch, "name", "unknown"),
                "bits": int(getattr(arch, "bits", 0) or 0),
                "baddr": int(base),
                "os": str(getattr(mo, "os", "unknown") or "unknown"),
                "format": fmt,
                "class": fmt,
                "type": fmt,
            },
            "tocode": {"input_path": str(self.binary)},
        }

    def entries(self) -> list[dict[str, Any]]:
        seen: dict[int, dict[str, Any]] = {}
        for vaddr in (
            getattr(self.project, "entry", None),
            getattr(self.project.loader.main_object, "entry", None),
        ):
            if vaddr is None:
                continue
            seen.setdefault(int(vaddr), {"vaddr": int(vaddr)})
        return list(seen.values())

    def sections(self) -> list[dict[str, Any]]:
        mo = self.project.loader.main_object
        containers = list(getattr(mo, "sections", []) or [])
        if not containers:
            containers = list(getattr(mo, "segments", []) or [])
        rows: list[dict[str, Any]] = []
        for item in containers:
            vaddr = int(getattr(item, "vaddr", 0) or 0)
            name = getattr(item, "name", None) or f"seg_{vaddr:x}"
            rows.append(
                {
                    "name": str(name),
                    "size": int(getattr(item, "filesize", 0) or 0),
                    "vsize": int(getattr(item, "memsize", 0) or 0),
                    "type": type(item).__name__,
                    "perm": self._perms(item),
                    "paddr": int(getattr(item, "offset", 0) or 0),
                    "vaddr": vaddr,
                }
            )
        return rows

    def imports(self) -> list[dict[str, Any]]:
        mo = self.project.loader.main_object
        rows: list[dict[str, Any]] = []
        for name, reloc in (getattr(mo, "imports", {}) or {}).items():
            address = int(
                getattr(reloc, "rebased_addr", 0) or getattr(reloc, "value", 0) or 0
            )
            if not address:
                continue
            symbol = getattr(reloc, "symbol", None)
            lib = getattr(symbol, "owner", None)
            lib_name = getattr(lib, "provides", None) or getattr(
                lib, "binary_basename", None
            )
            rows.append(
                {
                    "plt": address,
                    "name": str(name),
                    "bind": lib_name,
                    "dll": lib_name,
                    "type": "import",
                    "delay": False,
                }
            )
        return rows

    def exports(self) -> list[dict[str, Any]]:
        mo = self.project.loader.main_object
        rows: list[dict[str, Any]] = []
        for sym in getattr(mo, "symbols", []) or []:
            if not getattr(sym, "is_export", False):
                continue
            rows.append(
                {
                    "name": str(getattr(sym, "name", "") or ""),
                    "vaddr": int(getattr(sym, "rebased_addr", 0) or 0),
                    "bind": None,
                    "type": "export",
                    "ordinal": None,
                    "is_forwarder": False,
                    "forwarder_target": None,
                }
            )
        return rows

    def symbols(self) -> list[dict[str, Any]]:
        mo = self.project.loader.main_object
        rows: list[dict[str, Any]] = []
        for sym in getattr(mo, "symbols", []) or []:
            name = str(getattr(sym, "name", "") or "")
            rows.append(
                {
                    "name": name,
                    "flagname": name,
                    "realname": name,
                    "size": int(getattr(sym, "size", 0) or 0),
                    "type": str(getattr(sym, "type", "")),
                    "vaddr": int(getattr(sym, "rebased_addr", 0) or 0),
                    "paddr": int(getattr(sym, "relative_addr", 0) or 0),
                    "is_imported": bool(getattr(sym, "is_import", False)),
                }
            )
        return rows

    def relocations(self) -> list[dict[str, Any]]:
        mo = self.project.loader.main_object
        rows: list[dict[str, Any]] = []
        for reloc in getattr(mo, "relocs", []) or []:
            symbol = getattr(reloc, "symbol", None)
            name = getattr(symbol, "name", None) or ""
            rows.append(
                {
                    "name": str(name),
                    "type": type(reloc).__name__,
                    "vaddr": int(getattr(reloc, "rebased_addr", 0) or 0),
                    "paddr": int(getattr(reloc, "relative_addr", 0) or 0),
                    "is_ifunc": False,
                }
            )
        return rows

    def strings(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if self._cfg is None:
            return rows
        mo = self.project.loader.main_object
        memory_data = (
            getattr(getattr(self._cfg, "model", None), "memory_data", {}) or {}
        )
        for addr, md in memory_data.items():
            sort = str(getattr(md, "sort", "")).lower()
            if "string" not in sort:
                continue
            value = self._string_value(md)
            if not value:
                continue
            vaddr = int(getattr(md, "address", addr) or addr)
            section = mo.find_section_containing(vaddr) if mo else None
            rows.append(
                {
                    "vaddr": vaddr,
                    "paddr": vaddr,
                    "size": int(getattr(md, "size", len(value)) or len(value)),
                    "length": len(value),
                    "section": getattr(section, "name", "") or "",
                    "type": "ascii",
                    "string": value,
                }
            )
        return rows

    def flags(self) -> list[dict[str, Any]]:
        # angr has no flag namespace; the exporter tolerates an empty list.
        return []

    def functions(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for addr, func in self._funcs.items():
            name = func.name or f"sub_{addr:x}"
            is_plt = bool(getattr(func, "is_plt", False))
            is_sim = bool(getattr(func, "is_simprocedure", False))
            is_thunk = is_plt or is_sim
            nargs = self._arg_count(func)
            rows.append(
                {
                    "addr": addr,
                    "name": name,
                    "size": int(getattr(func, "size", 0) or 0),
                    "signature": self._signature(func),
                    "calltype": self._calltype(func),
                    "noreturn": not bool(getattr(func, "returning", True)),
                    "stackframe": 0,
                    "nlocals": 0,
                    "nargs": nargs,
                    "outdegree": 0,
                    "indegree": 0,
                    "is_library": is_plt,
                    "is_thunk": is_thunk,
                    "source_kind": self._classify(func, name, is_thunk=is_thunk),
                }
            )
        return rows

    # -- per-function rendering --------------------------------------------

    def disasm(self, address: int) -> str:
        address = int(address)
        if address not in self._disasm_cache:
            func = self._funcs.get(address)
            lines: list[str] = []
            if func is not None:
                for block in self._sorted_blocks(func):
                    try:
                        capstone = block.capstone
                    except Exception:  # noqa: BLE001
                        continue
                    for insn in getattr(capstone, "insns", []):
                        lines.append(
                            f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".rstrip()
                        )
            self._disasm_cache[address] = "\n".join(lines)
        return self._disasm_cache[address]

    def decompile(self, address: int) -> str:
        address = int(address)
        if address not in self._decompile_cache:
            self._decompile_cache[address] = self._decompile(address)
        return self._decompile_cache[address]

    def function_summary(self, address: int) -> str:
        address = int(address)
        func = self._funcs.get(address)
        if func is None:
            return f"signature: sub_{address:x}\naddress: 0x{address:x}"
        callgraph = getattr(self.project.kb.functions, "callgraph", None)
        callees = list(callgraph.successors(address)) if callgraph else []
        callers = list(callgraph.predecessors(address)) if callgraph else []
        signature = self._signature(func) or func.name or f"sub_{address:x}"
        lines = [
            f"signature: {signature}",
            f"address: 0x{address:x}",
            f"size: {int(getattr(func, 'size', 0) or 0)} bytes",
            f"returns: {'no' if not getattr(func, 'returning', True) else 'yes'}",
            f"callers: {len(callers)}",
            f"callees: {len(callees)}",
            f"args: {self._arg_count(func)}",
            "locals: 0",
        ]
        callee_names = [
            (self._funcs[c].name if c in self._funcs else f"sub_{c:x}")
            for c in callees[:8]
        ]
        if callee_names:
            lines.append(f"callee_names: {', '.join(callee_names)}")
        return "\n".join(lines)

    # -- call graph / xrefs ------------------------------------------------

    def calls_from(
        self, address: int, imports, functions
    ) -> tuple[list[int], list[str]]:
        address = int(address)
        func = self._funcs.get(address)
        if func is None:
            return [], []
        function_addrs = set(functions)
        edges: set[int] = set()
        imported: set[str] = set()
        for target in self._call_targets(func):
            if target == address:
                continue
            if target in function_addrs and not _is_imported(functions.get(target)):
                edges.add(target)
            else:
                name = self._resolve_name(target, imports, functions)
                if name:
                    imported.add(name)
        return sorted(edges), sorted(imported)

    def data_xrefs(self, addresses) -> dict[int, list[tuple[int, bool]]]:
        manager = getattr(self.project.kb, "xrefs", None)
        if manager is None:
            return {}
        result: dict[int, list[tuple[int, bool]]] = {}
        for address in addresses:
            target = int(address)
            try:
                refs = manager.get_xrefs_by_dst(target)
            except Exception:  # noqa: BLE001
                continue
            rows: list[tuple[int, bool]] = []
            for xref in refs or ():
                ins = getattr(xref, "ins_addr", None)
                if ins is None:
                    continue
                is_write = False
                if XRefType is not None:
                    is_write = getattr(xref, "type", None) == XRefType.Write
                rows.append((int(ins), bool(is_write)))
            if rows:
                result[target] = rows
        return result

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _perms(item: Any) -> str:
        return "".join(
            [
                "r" if getattr(item, "is_readable", False) else "-",
                "w" if getattr(item, "is_writable", False) else "-",
                "x" if getattr(item, "is_executable", False) else "-",
            ]
        )

    @staticmethod
    def _string_value(md: Any) -> str:
        content = getattr(md, "content", None)
        if isinstance(content, bytes):
            return content.split(b"\x00", 1)[0].decode("utf-8", "replace")
        text = getattr(md, "string", None)
        if isinstance(text, bytes):
            return text.split(b"\x00", 1)[0].decode("utf-8", "replace")
        return str(text) if text else ""

    @staticmethod
    def _sorted_blocks(func: Any) -> list[Any]:
        try:
            return sorted(func.blocks, key=lambda b: int(getattr(b, "addr", 0)))
        except Exception:  # noqa: BLE001
            return list(getattr(func, "blocks", []) or [])

    @staticmethod
    def _signature(func: Any) -> str | None:
        proto = getattr(func, "prototype", None)
        if proto is None:
            return None
        name = func.name or f"sub_{func.addr:x}"
        # Build a normal C declaration ("ret name(args)"). angr's
        # SimTypeFunction.c_repr(name=...) renders the function-pointer form
        # ("ret (name)(args)"), which the exporter's signature parser mangles.
        try:
            ret = proto.returnty.c_repr() if proto.returnty is not None else "void"
            arg_names = getattr(proto, "arg_names", None) or ()
            parts: list[str] = []
            for index, arg in enumerate(proto.args or ()):
                arg_name = arg_names[index] if index < len(arg_names) else None
                parts.append(arg.c_repr(name=arg_name) if arg_name else arg.c_repr())
            params = ", ".join(parts) if parts else "void"
            return f"{ret} {name}({params})"
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _calltype(func: Any) -> str | None:
        cc = getattr(func, "calling_convention", None)
        return type(cc).__name__ if cc is not None else None

    @staticmethod
    def _arg_count(func: Any) -> int:
        proto = getattr(func, "prototype", None)
        args = getattr(proto, "args", None) if proto is not None else None
        if args is not None:
            return len(args)
        try:
            return len(func.arguments or [])
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _classify(func: Any, name: str, *, is_thunk: bool) -> str:
        if is_thunk:
            return "thunk"
        if getattr(func, "is_syscall", False):
            return "runtime"
        lowered = (name or "").lower()
        if lowered in _RUNTIME_NAMES or lowered.startswith(
            ("__libc_csu_", "__scrt_", "_scrt_", "__crt", "_crt", "_global__sub_i_")
        ):
            return "runtime"
        return "app"

    def _call_targets(self, func: Any) -> set[int]:
        targets: set[int] = set()
        try:
            for site in func.get_call_sites():
                target = func.get_call_target(site)
                if target is not None:
                    targets.add(int(target))
        except Exception:  # noqa: BLE001
            pass
        callgraph = getattr(self.project.kb.functions, "callgraph", None)
        if callgraph is not None and callgraph.has_node(func.addr):
            for succ in callgraph.successors(func.addr):
                targets.add(int(succ))
        return targets

    def _resolve_name(self, target: int, imports, functions) -> str:
        if target in imports:
            return imports[target].name
        routine = functions.get(target)
        if routine is not None and getattr(routine, "imported", False):
            return routine.name
        func = self._funcs.get(target)
        if func is not None:
            return func.name or f"sub_{target:x}"
        return f"sub_{target:x}"

    def _decompile(self, address: int) -> str:
        func = self._funcs.get(address)
        prototype = (func and self._signature(func)) or f"int sub_{address:x}()"
        if func is None:
            return f"{prototype}\n{{\n    /* angr: unknown function */\n}}\n"
        try:
            with _quiet_angr_logs():
                dec = self.project.analyses.Decompiler(func, cfg=self._cfg.model)
            text = getattr(getattr(dec, "codegen", None), "text", None)
        except Exception:  # noqa: BLE001
            text = None
        text = _strip_leading_decls(text) if text else None
        if text:
            return text
        return f"{prototype}\n{{\n    /* angr: decompilation unavailable */\n}}\n"


def _is_imported(routine: Any) -> bool:
    return bool(getattr(routine, "imported", False)) if routine is not None else False


def _strip_leading_decls(text: str) -> str:
    """Return angr's output starting at the function definition.

    angr's decompiler prepends referenced globals (``extern ...;``),
    ``typedef``/``struct`` blocks, and ``// attributes:`` comments before the
    function. The exporter treats everything before the first ``{`` as the
    prototype, so we must start the text at the function signature. The function
    is the first top-level ``{`` whose preceding declaration contains ``(`` (a
    parameter list); leading type/global blocks have no ``(`` before their brace.
    """
    depth = 0
    segment_start = 0
    for index, char in enumerate(text):
        if char == "{":
            if depth == 0 and "(" in text[segment_start:index]:
                return text[segment_start:].lstrip()
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
            if depth == 0:
                segment_start = index + 1
        elif char == ";" and depth == 0:
            segment_start = index + 1
    return text
