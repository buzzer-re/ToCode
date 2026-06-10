from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import r2pipe  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    r2pipe = None

from .base import BackendName
from ..errors import BackendError, BackendJsonError


class R2Session:
    backend_name: BackendName = "r2"
    backend_label = "radare2"
    decompiler_label = "r2ghidra"
    parallel_safe = True

    def __init__(self, binary: Path, *, analysis_command: str = "aaa") -> None:
        self.binary = Path(binary).resolve()
        self.analysis_command: str | None = analysis_command
        if r2pipe is None:
            raise BackendError("python package r2pipe is not installed")
        try:
            self._pipe = r2pipe.open(
                str(self.binary),
                flags=[
                    "-2",
                    "-e",
                    "scr.color=0",
                    "-e",
                    "scr.interactive=false",
                    "-e",
                    "scr.utf8=0",
                    "-e",
                    "bin.relocs.apply=true",
                ],
            )
        except FileNotFoundError as exc:
            raise BackendError("radare2 executable r2 was not found in PATH") from exc
        self._pdfj: dict[int, dict[str, Any]] = {}
        self._pdf: dict[int, str] = {}
        self._pdg: dict[int, str] = {}
        self.cmd("e asm.comments=false")
        self.cmd("e anal.strings=true")
        self.cmd("e anal.types.constraint=true")

    def analyze(self) -> None:
        self.cmd(self.analysis_command or "aaa")

    def close(self) -> None:
        try:
            self._pipe.quit()
        except Exception:  # noqa: BLE001
            pass

    def cmd(self, command: str) -> str:
        try:
            value = self._pipe.cmd(command)
        except BrokenPipeError as exc:
            raise BackendError(f"radare2 terminated while running {command!r}") from exc
        except Exception as exc:  # noqa: BLE001
            raise BackendError(f"radare2 failed while running {command!r}") from exc
        return value if isinstance(value, str) else str(value)

    def cmdj(self, command: str):
        try:
            return self._pipe.cmdj(command)
        except ValueError as exc:
            raise BackendJsonError(
                f"radare2 returned invalid JSON for {command!r}"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise BackendError(f"radare2 JSON command failed: {command!r}") from exc

    def ensure_decompiler(self) -> None:
        help_text = self.cmd("pdg?")
        if "Unknown command" in help_text or "Missing plugin" in help_text:
            raise BackendError("r2ghidra is not available to radare2")
        if "Cannot find the sleigh home" in help_text:
            raise BackendError(
                "r2ghidra SLEIGH data is not available; install it with "
                "`r2pm -ci r2ghidra-sleigh`"
            )
        languages = self.cmd("pdgL").strip()
        if not languages:
            raise BackendError(
                "r2ghidra SLEIGH languages are not available; install them with "
                "`r2pm -ci r2ghidra-sleigh`"
            )

    def info(self) -> dict[str, Any]:
        return self.cmdj("ij") or {}

    def entries(self) -> list[dict[str, Any]]:
        return self.cmdj("iej") or []

    def sections(self) -> list[dict[str, Any]]:
        return self.cmdj("iSj") or []

    def imports(self) -> list[dict[str, Any]]:
        return self.cmdj("iij") or []

    def exports(self) -> list[dict[str, Any]]:
        return self.cmdj("iEj") or []

    def symbols(self) -> list[dict[str, Any]]:
        return self.cmdj("isj") or []

    def relocations(self) -> list[dict[str, Any]]:
        return self.cmdj("irj") or []

    def strings(self) -> list[dict[str, Any]]:
        return self.cmdj("izj") or []

    def flags(self) -> list[dict[str, Any]]:
        return self.cmdj("fj") or []

    def functions(self) -> list[dict[str, Any]]:
        return self.cmdj("aflj") or []

    def disasm(self, address: int) -> str:
        if address not in self._pdf:
            self._pdf[address] = self.cmd(f"pdf @ 0x{address:x}")
        return self._pdf[address]

    def decompile(self, address: int) -> str:
        if address not in self._pdg:
            self._pdg[address] = self.cmd(f"pdg @ 0x{address:x}")
        return self._pdg[address]

    def function_summary(self, address: int) -> str:
        return self.cmd(f"pdsf @ 0x{address:x}")

    def _disasm_json(self, address: int) -> dict[str, Any]:
        if address not in self._pdfj:
            self._pdfj[address] = self.cmdj(f"pdfj @ 0x{address:x}") or {}
        return self._pdfj[address]

    def data_xrefs(self, addresses) -> dict[int, list[tuple[int, bool]]]:
        result: dict[int, list[tuple[int, bool]]] = {}
        for address in addresses:
            target = int(address)
            rows = self.cmdj(f"axtj @ 0x{target:x}") or []
            refs: list[tuple[int, bool]] = []
            for row in rows:
                frm = row.get("from")
                if frm is None:
                    continue
                kind = str(row.get("type", "")).lower()
                perm = str(row.get("perm", "")).lower()
                is_write = "w" in perm or kind == "write"
                refs.append((int(frm), is_write))
            if refs:
                result[target] = refs
        return result

    def calls_from(
        self, address: int, imports, functions
    ) -> tuple[list[int], list[str]]:
        body = self._disasm_json(address)
        function_addrs = set(functions)
        edges: set[int] = set()
        imported: set[str] = set()
        for op in body.get("ops", []):
            op_type = str(op.get("type", ""))
            target = op.get("jump")
            refs = op.get("refs") or []
            if op_type == "call":
                direct = self._direct_call_target(target, refs)
                if direct is None:
                    continue
                if direct in function_addrs and direct != address:
                    edges.add(direct)
                else:
                    imported.add(self._import_name(refs, direct, imports, functions))
            elif op_type in {"jmp", "ujmp", "cjmp"} and isinstance(target, int):
                if target in function_addrs and target != address:
                    edges.add(target)
        return sorted(edges), sorted(name for name in imported if name)

    def _direct_call_target(
        self, target: Any, refs: list[dict[str, Any]]
    ) -> int | None:
        if isinstance(target, int):
            return target
        for ref in refs:
            if ref.get("type") == "CALL" and isinstance(ref.get("addr"), int):
                return int(ref["addr"])
        return None

    def _import_name(self, refs, target, imports, functions) -> str:
        if isinstance(target, int):
            if target in imports:
                return imports[target].name
            routine = functions.get(target)
            if routine is not None and routine.imported:
                return routine.name
        for ref in refs:
            if ref.get("type") != "CALL":
                continue
            ref_addr = ref.get("addr")
            if isinstance(ref_addr, int):
                if ref_addr in imports:
                    return imports[ref_addr].name
                routine = functions.get(ref_addr)
                if routine is not None and routine.imported:
                    return routine.name
            name = ref.get("name")
            if isinstance(name, str):
                return name
        return f"sub_{target:x}" if isinstance(target, int) else ""
