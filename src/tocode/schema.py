from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Segment:
    name: str
    size: int
    vsize: int
    kind: str
    perms: str
    paddr: int
    vaddr: int
    entropy: float | None = None

    @property
    def readable(self) -> bool:
        return "r" in self.perms

    @property
    def writable(self) -> bool:
        return "w" in self.perms

    @property
    def executable(self) -> bool:
        return "x" in self.perms


@dataclass(slots=True)
class Routine:
    address: int
    name: str
    size: int
    signature: str | None
    calltype: str | None
    noreturn: bool
    stack_size: int
    locals_count: int
    args_count: int
    outdegree: int
    indegree: int
    imported: bool = False
    library: bool = False
    thunk: bool = False
    code_kind: str = "app"
    segment: str | None = None
    # Original source location, recovered from DWARF/IDA debug info when present.
    source_file: str | None = None
    source_dir: str | None = None
    source_line: int | None = None
    # Recovered prototype detail (types respected from the backend, not invented).
    return_type: str | None = None
    params: list[tuple[str, str]] = field(default_factory=list)
    local_vars: list[tuple[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class ImportEntry:
    name: str
    address: int
    bind: str | None = None
    kind: str | None = None
    dll: str | None = None
    delay: bool = False


@dataclass(slots=True)
class ExportEntry:
    name: str
    address: int
    bind: str | None = None
    kind: str | None = None
    ordinal: int | None = None
    forwarder: bool = False
    forwarder_target: str | None = None


@dataclass(slots=True)
class SymbolEntry:
    name: str
    flag_name: str
    real_name: str
    size: int
    kind: str
    vaddr: int
    paddr: int
    imported: bool


@dataclass(slots=True)
class RelocationEntry:
    name: str
    kind: str
    vaddr: int
    paddr: int
    ifunc: bool


@dataclass(slots=True)
class StringEntry:
    vaddr: int
    paddr: int
    size: int
    length: int
    segment: str
    kind: str
    value: str


@dataclass(slots=True)
class FlagEntry:
    name: str
    offset: int
    size: int
    real_name: str | None = None


@dataclass(slots=True)
class Cluster:
    root: int
    label: str
    summary: str
    members: list[int]
    folder: str = "app"
    # Source basename driving the output filename when grouped by source file
    # (e.g. "socket" -> socket.c/.asm/.summary). None falls back to cluster_<root>.
    file_base: str | None = None


@dataclass(slots=True)
class TypeDef:
    """A type the backend identified (struct/union/enum/typedef/base/func)."""

    name: str
    kind: str
    size: int | None
    c_decl: str
    members: list[dict] = field(default_factory=list)
    ordinal: int | None = None


@dataclass(slots=True)
class FunctionFailure:
    address: int
    name: str
    message: str


@dataclass(slots=True)
class FunctionRange:
    address: int
    name: str
    c_file: Path
    c_line_start: int
    c_line_end: int
    asm_file: Path
    asm_line_start: int
    asm_line_end: int
    arg_count: int | None = None
    local_count: int | None = None
    origin_file: str | None = None
    origin_line: int | None = None


@dataclass(slots=True)
class RenderedFunction:
    address: int
    c_name: str
    prototype: str
    c_text: str
    asm_text: str
    summary_text: str
    failure: FunctionFailure | None = None


@dataclass(slots=True)
class BinaryFacts:
    path: Path
    arch: str
    bits: int
    image_base: int
    os_name: str
    format_name: str
    file_type: str
    entrypoints: list[int]

    @property
    def pointer_size(self) -> int:
        if self.bits >= 64:
            return 8
        if self.bits >= 32:
            return 4
        if self.bits >= 16:
            return 2
        return 1


@dataclass(slots=True)
class ProgramAnalysis:
    binary: BinaryFacts
    segments: list[Segment]
    routines: dict[int, Routine]
    imports: dict[int, ImportEntry]
    exports: list[ExportEntry]
    symbols: list[SymbolEntry]
    relocations: list[RelocationEntry]
    strings: list[StringEntry]
    flags: list[FlagEntry]
    callees: dict[int, list[int]]
    callers: dict[int, list[int]]
    import_calls: dict[int, list[str]]
    roots: list[int]
    thunks: set[int]
    types: list[TypeDef] = field(default_factory=list)
    # Data address -> list of (referencing instruction address, is_write), taken
    # directly from the decompiler's cross-reference database during analysis.
    data_xrefs: dict[int, list[tuple[int, bool]]] = field(default_factory=dict)
    _app_cache: list[Routine] | None = field(default=None, init=False, repr=False)

    def segment_at(self, address: int) -> Segment | None:
        for segment in self.segments:
            end = segment.vaddr + max(segment.vsize, segment.size)
            if segment.vaddr <= address < end:
                return segment
        return None

    def app_routines(self) -> list[Routine]:
        if self._app_cache is None:
            self._app_cache = [
                routine
                for routine in self.routines.values()
                if not routine.imported
                and routine.code_kind == "app"
                and not routine.library
            ]
        return self._app_cache

    def support_routines(self) -> list[Routine]:
        return [
            routine
            for routine in self.routines.values()
            if not routine.imported and routine.code_kind != "app"
        ]


@dataclass(slots=True)
class ExportSummary:
    root_dir: Path
    raw_src_dir: Path
    tree_src_dir: Path | None
    include_dir: Path
    header_path: Path
    source_files: list[Path]
    tree_source_files: list[Path]
    asm_files: list[Path]
    summary_files: list[Path]
    function_count: int
    cluster_count: int
    failed_functions: list[FunctionFailure] = field(default_factory=list)
    function_index_path: Path | None = None
    tree_function_index_path: Path | None = None
    manifest_path: Path | None = None
    data_dir: Path | None = None
