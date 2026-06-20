from __future__ import annotations

from pathlib import Path
import time
from typing import Any

from .backends.base import BackendRequest, DecompilerSession, choose_backend
from .backends.ida import IdaSession
from .backends.r2 import R2Session
from .cluster import describe_imports
from .progress import Progress
from .schema import (
    BinaryFacts,
    ExportEntry,
    FlagEntry,
    ImportEntry,
    ProgramAnalysis,
    RelocationEntry,
    Routine,
    Segment,
    StringEntry,
    SymbolEntry,
    TypeDef,
)


class BinaryAnalyzer:
    def __init__(
        self,
        binary: Path,
        *,
        session: DecompilerSession,
        progress: Progress | None = None,
    ) -> None:
        self.binary = Path(binary).resolve()
        self.session = session
        self.progress = progress or Progress()
        self.analysis: ProgramAnalysis | None = None
        self.analysis_seconds: float | None = None

    @property
    def backend_name(self) -> str:
        return self.session.backend_name

    @property
    def backend_label(self) -> str:
        return self.session.backend_label

    @property
    def decompiler_label(self) -> str:
        return self.session.decompiler_label

    @property
    def supports_parallel(self) -> bool:
        return self.session.parallel_safe

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "BinaryAnalyzer":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    def collect(self) -> ProgramAnalysis:
        started = time.monotonic()
        label = (
            self.session.analysis_command
            or f"{self.session.backend_label} auto-analysis"
        )
        self.progress.log(f"Analyzing with {label}")
        with self.progress.bar(total=17, desc="analyze", unit="step") as bar:
            self.session.analyze()
            bar.update(1)
            info = self.session.info()
            bar.update(1)
            entries = self.session.entries()
            bar.update(1)
            segments = [
                self._segment(row) for row in self.session.sections() if row.get("name")
            ]
            bar.update(1)
            imports = self._imports(self.session.imports())
            bar.update(1)
            exports = [self._export(row) for row in self.session.exports()]
            bar.update(1)
            symbols = [self._symbol(row) for row in self.session.symbols()]
            bar.update(1)
            relocations = [self._relocation(row) for row in self.session.relocations()]
            bar.update(1)
            strings = [self._string(row) for row in self.session.strings()]
            bar.update(1)
            flags = [self._flag(row) for row in self.session.flags()]
            bar.update(1)
            data_xrefs = self._data_xrefs(symbols, relocations, strings, flags)
            bar.update(1)
            routines = self._routines(self.session.functions(), imports, segments)
            bar.update(1)
            callees, callers, import_calls = self._call_graph(routines, imports)
            bar.update(1)
            roots = self._roots(routines, exports, callers, entries)
            bar.update(1)
            thunks = self._thunks(routines, callees, import_calls)
            bar.update(1)
            types = self._types()
            bar.update(1)
            self.session.ensure_decompiler()
            bar.update(1)

        for address in thunks:
            if address in routines:
                routines[address].thunk = True
        for address, targets in callees.items():
            if address in routines:
                routines[address].outdegree = len(targets)
        for address, sources in callers.items():
            if address in routines:
                routines[address].indegree = len(sources)

        analysis = ProgramAnalysis(
            binary=self._binary_facts(info, entries),
            segments=segments,
            routines=routines,
            imports=imports,
            exports=exports,
            symbols=symbols,
            relocations=relocations,
            strings=strings,
            flags=flags,
            callees=callees,
            callers=callers,
            import_calls=import_calls,
            roots=roots,
            thunks=thunks,
            data_xrefs=data_xrefs,
            types=types,
        )
        self.analysis = analysis
        self.analysis_seconds = time.monotonic() - started
        self.progress.log(
            f"Inventory: functions={len(routines)} imports={len(imports)} "
            f"sections={len(segments)} time={self.analysis_seconds:.2f}s"
        )
        return analysis

    def disasm(self, address: int) -> str:
        return self.session.disasm(address)

    def decompile(self, address: int) -> str:
        return self.session.decompile(address)

    def function_summary(self, address: int) -> str:
        return self.session.function_summary(address)

    def cluster_description_from_imports(self, members: list[int]) -> str:
        names: list[str] = []
        if self.analysis is not None:
            for address in members:
                names.extend(self.analysis.import_calls.get(address, []))
        return describe_imports(names)

    def prepare_parallel_workers(self) -> None:
        prepare = getattr(self.session, "prepare_parallel_workers", None)
        if callable(prepare):
            prepare()

    def release_parallel_resources(self) -> None:
        release = getattr(self.session, "release_parallel_resources", None)
        if callable(release):
            release()

    def restore_parallel_resources(self) -> None:
        restore = getattr(self.session, "restore_parallel_resources", None)
        if callable(restore):
            restore()

    def release_render_memory(self) -> None:
        release = getattr(self.session, "release_render_memory", None)
        if callable(release):
            release()

    def _binary_facts(
        self, info: dict[str, Any], entries: list[dict[str, Any]]
    ) -> BinaryFacts:
        binary = info.get("bin", {})
        tocode = info.get("tocode", {})
        source_path = self.binary
        if isinstance(tocode, dict):
            raw_path = _first_text(tocode, "input_path")
            if raw_path:
                candidate = Path(raw_path).expanduser()
                if candidate.is_file():
                    source_path = candidate.resolve()
        return BinaryFacts(
            path=source_path,
            arch=str(binary.get("arch", "unknown")),
            bits=int(binary.get("bits", 0) or 0),
            image_base=int(binary.get("baddr", 0) or 0),
            os_name=str(binary.get("os", "unknown")),
            format_name=str(binary.get("format", "unknown")),
            file_type=str(binary.get("class", binary.get("type", "unknown"))),
            entrypoints=[
                int(row.get("vaddr", 0))
                for row in entries
                if row.get("vaddr") is not None
            ],
        )

    def _imports(self, rows: list[dict[str, Any]]) -> dict[int, ImportEntry]:
        result: dict[int, ImportEntry] = {}
        for row in rows:
            address = int(row.get("plt", 0) or 0)
            if not address:
                continue
            result[address] = ImportEntry(
                name=str(row.get("name", f"imp_{address:x}")),
                address=address,
                bind=row.get("bind"),
                kind=row.get("type"),
                dll=_first_text(row, "dll", "libname", "library", "module", "bind"),
                delay=bool(row.get("delay", row.get("is_delay", False))),
            )
        return result

    def _routines(
        self,
        rows: list[dict[str, Any]],
        imports: dict[int, ImportEntry],
        segments: list[Segment],
    ) -> dict[int, Routine]:
        result: dict[int, Routine] = {}
        for row in rows:
            address = int(row.get("addr", row.get("offset", 0)) or 0)
            if not address:
                continue
            name = str(row.get("name", f"sub_{address:x}"))
            result[address] = Routine(
                address=address,
                name=name,
                size=int(row.get("size", 0) or 0),
                signature=row.get("signature"),
                calltype=row.get("calltype"),
                noreturn=bool(row.get("noreturn", False)),
                stack_size=int(row.get("stackframe", 0) or 0),
                locals_count=int(row.get("nlocals", 0) or 0),
                args_count=int(row.get("nargs", 0) or 0),
                outdegree=int(row.get("outdegree", 0) or 0),
                indegree=int(row.get("indegree", 0) or 0),
                imported=address in imports
                or name.startswith(("sym.imp.", "loc.imp.", "__imp_")),
                library=bool(row.get("is_library", False)),
                thunk=bool(row.get("is_thunk", False)),
                code_kind=str(row.get("source_kind", "app") or "app"),
                segment=self._segment_name(address, segments),
                source_file=_clean_text(row.get("source_file")),
                source_dir=_clean_text(row.get("source_dir")),
                source_line=_opt_int(row.get("source_line")),
                return_type=_clean_text(row.get("return_type")),
                params=_name_type_pairs(row.get("params")),
                local_vars=_name_type_pairs(row.get("locals")),
            )
        return result

    def _types(self) -> list[TypeDef]:
        collect = getattr(self.session, "types", None)
        if not callable(collect):
            return []
        try:
            rows = collect()
        except Exception:  # noqa: BLE001 - type recovery must never break analysis
            return []
        result: list[TypeDef] = []
        for row in rows or ():
            if not isinstance(row, dict):
                continue
            name = _clean_text(row.get("name"))
            c_decl = _clean_text(row.get("c_decl"))
            if not name or not c_decl:
                continue
            members = row.get("members")
            result.append(
                TypeDef(
                    name=name,
                    kind=str(row.get("kind", "type") or "type"),
                    size=_opt_int(row.get("size")),
                    c_decl=c_decl,
                    members=list(members) if isinstance(members, list) else [],
                    ordinal=_opt_int(row.get("ordinal")),
                )
            )
        return result

    def _data_xrefs(
        self,
        symbols: list[SymbolEntry],
        relocations: list[RelocationEntry],
        strings: list[StringEntry],
        flags: list[FlagEntry],
    ) -> dict[int, list[tuple[int, bool]]]:
        collect = getattr(self.session, "data_xrefs", None)
        if not callable(collect):
            return {}
        addresses: set[int] = set()
        addresses.update(item.vaddr for item in strings)
        addresses.update(item.vaddr for item in symbols if not item.imported)
        addresses.update(item.vaddr for item in relocations)
        addresses.update(item.offset for item in flags)
        if not addresses:
            return {}
        try:
            return collect(addresses)
        except Exception:  # noqa: BLE001
            return {}

    def _call_graph(
        self,
        routines: dict[int, Routine],
        imports: dict[int, ImportEntry],
    ) -> tuple[dict[int, list[int]], dict[int, list[int]], dict[int, list[str]]]:
        callees: dict[int, list[int]] = {address: [] for address in routines}
        callers: dict[int, list[int]] = {address: [] for address in routines}
        import_calls: dict[int, list[str]] = {address: [] for address in routines}
        for address, routine in routines.items():
            if routine.imported:
                continue
            targets, imported = self.session.calls_from(address, imports, routines)
            callees[address] = targets
            import_calls[address] = imported
            for target in targets:
                callers.setdefault(target, []).append(address)
        for values in callers.values():
            values.sort()
        return callees, callers, import_calls

    def _roots(
        self,
        routines: dict[int, Routine],
        exports: list[ExportEntry],
        callers: dict[int, list[int]],
        entries: list[dict[str, Any]],
    ) -> list[int]:
        roots: list[int] = []
        for row in entries:
            address = int(row.get("vaddr", 0) or 0)
            if address in routines and address not in roots:
                roots.append(address)
        for item in exports:
            if item.address in routines and item.address not in roots:
                roots.append(item.address)
        for address, routine in routines.items():
            if (
                not routine.imported
                and not callers.get(address)
                and address not in roots
            ):
                roots.append(address)
        return roots

    def _thunks(
        self,
        routines: dict[int, Routine],
        callees: dict[int, list[int]],
        import_calls: dict[int, list[str]],
    ) -> set[int]:
        result: set[int] = set()
        for address, routine in routines.items():
            if routine.imported:
                result.add(address)
                continue
            if routine.size <= 16:
                targets = callees.get(address, [])
                if (
                    len(targets) == 1
                    and routines.get(targets[0]) is not None
                    and routines[targets[0]].imported
                ):
                    result.add(address)
                if not targets and len(import_calls.get(address, [])) == 1:
                    result.add(address)
        return result

    def _segment_name(self, address: int, segments: list[Segment]) -> str | None:
        for segment in segments:
            end = segment.vaddr + max(segment.vsize, segment.size)
            if segment.vaddr <= address < end:
                return segment.name
        return None

    @staticmethod
    def _segment(row: dict[str, Any]) -> Segment:
        return Segment(
            name=str(row.get("name", "")),
            size=int(row.get("size", 0) or 0),
            vsize=int(row.get("vsize", 0) or 0),
            kind=str(row.get("type", "")),
            perms=str(row.get("perm", "----")),
            paddr=int(row.get("paddr", 0) or 0),
            vaddr=int(row.get("vaddr", 0) or 0),
        )

    @staticmethod
    def _export(row: dict[str, Any]) -> ExportEntry:
        forwarder_target = _first_text(
            row, "forwarder_target", "forwarder", "forwarder_name", "target"
        )
        return ExportEntry(
            name=str(row.get("name", "")),
            address=int(row.get("vaddr", 0) or 0),
            bind=row.get("bind"),
            kind=row.get("type"),
            ordinal=_first_int(row, "ordinal", "ord"),
            forwarder=bool(row.get("is_forwarder", False) or forwarder_target),
            forwarder_target=forwarder_target,
        )

    @staticmethod
    def _symbol(row: dict[str, Any]) -> SymbolEntry:
        return SymbolEntry(
            name=str(row.get("name", "")),
            flag_name=str(row.get("flagname", row.get("name", ""))),
            real_name=str(row.get("realname", row.get("name", ""))),
            size=int(row.get("size", 0) or 0),
            kind=str(row.get("type", "")),
            vaddr=int(row.get("vaddr", 0) or 0),
            paddr=int(row.get("paddr", 0) or 0),
            imported=bool(row.get("is_imported", False)),
        )

    @staticmethod
    def _relocation(row: dict[str, Any]) -> RelocationEntry:
        return RelocationEntry(
            name=str(row.get("name", "")),
            kind=str(row.get("type", "")),
            vaddr=int(row.get("vaddr", 0) or 0),
            paddr=int(row.get("paddr", 0) or 0),
            ifunc=bool(row.get("is_ifunc", False)),
        )

    @staticmethod
    def _string(row: dict[str, Any]) -> StringEntry:
        return StringEntry(
            vaddr=int(row.get("vaddr", 0) or 0),
            paddr=int(row.get("paddr", 0) or 0),
            size=int(row.get("size", 0) or 0),
            length=int(row.get("length", 0) or 0),
            segment=str(row.get("section", "")),
            kind=str(row.get("type", "")),
            value=str(row.get("string", "")),
        )

    @staticmethod
    def _flag(row: dict[str, Any]) -> FlagEntry:
        return FlagEntry(
            name=str(row.get("name", "")),
            offset=int(row.get("offset", 0) or 0),
            size=int(row.get("size", 0) or 0),
            real_name=row.get("realname"),
        )


def create_analyzer(
    binary: Path,
    *,
    backend: BackendRequest = "auto",
    analysis_command: str = "aaa",
    progress: Progress | None = None,
    idadir: Path | None = None,
    ida_domain_path: Path | None = None,
    purge_cache: bool = False,
) -> BinaryAnalyzer:
    choice = choose_backend(
        backend,
        input_path=binary,
        idadir=idadir,
        ida_domain_path=ida_domain_path,
    )
    if progress is not None:
        progress.log(f"Using {choice.selected.upper()} as backend.")
        # Log before constructing the session: opening (and, for a fresh binary,
        # loading) the IDA database happens inside the session constructor and can
        # take a while, so the user should see activity instead of a silent gap.
        progress.log(f"Loading {Path(binary).resolve()}")
    if choice.selected == "ida":
        return BinaryAnalyzer(
            binary,
            session=IdaSession(
                binary,
                idadir=idadir,
                ida_domain_path=ida_domain_path,
                purge_cache=purge_cache,
            ),
            progress=progress,
        )
    if choice.selected == "angr":
        # Imported lazily: pulling in angr is slow and noisy (it loads native
        # extensions at import time), so only do it when angr is the backend.
        from .backends.angr import AngrSession

        return BinaryAnalyzer(
            binary,
            session=AngrSession(binary),
            progress=progress,
        )
    return BinaryAnalyzer(
        binary,
        session=R2Session(binary, analysis_command=analysis_command),
        progress=progress,
    )


def _first_text(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _first_int(row: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _opt_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _name_type_pairs(value: Any) -> list[tuple[str, str]]:
    """Normalize a backend's params/locals list into (name, type) tuples."""
    pairs: list[tuple[str, str]] = []
    if not isinstance(value, list):
        return pairs
    for item in value:
        if isinstance(item, dict):
            name = str(item.get("name", "") or "")
            type_name = str(item.get("type", "") or "")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            name, type_name = str(item[0] or ""), str(item[1] or "")
        else:
            continue
        if type_name:
            pairs.append((name, type_name))
    return pairs
