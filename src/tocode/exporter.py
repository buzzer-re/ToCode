from __future__ import annotations

import atexit
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
import multiprocessing
import os
from pathlib import Path
from typing import Any

from .analysis import BinaryAnalyzer
from .backends.ida import IdaSession
from .backends.r2 import R2Session
from .cluster import cluster_routines
from .metadata import (
    cluster_graph_json,
    display_path,
    export_variables,
    exports_json,
    functions_json,
    imports_json,
    reachable_json,
    relocations_json,
    sections_json,
    strings_json,
    triage_json,
    write_json,
)
from .naming import (
    SHARED_CLUSTER_ID,
    NameBook,
    asm_file_name,
    build_name_book,
    c_file_name,
    clean_c_identifier,
    clean_path_component,
    default_output_name,
    normalize_source,
    summary_file_name,
)
from .parallel import choose_jobs, describe_jobs
from .progress import Progress
from .schema import (
    Cluster,
    ExportSummary,
    FunctionFailure,
    FunctionRange,
    ProgramAnalysis,
    RenderedFunction,
    Routine,
)


MAX_FUNCTIONS_PER_FILE = 50
FAST_CLUSTER_FUNCTIONS = 500
TINY_CLUSTER_FUNCTIONS = 2
TINY_CLUSTER_BYTES = 0x80
MERGED_CLUSTER_FUNCTIONS = 12
MERGED_CLUSTER_BYTES = 0x800
ASM_STUB_MAX_SIZE = 16

_WORKER_SESSION: Any = None
_WORKER_ANALYSIS: ProgramAnalysis | None = None
_WORKER_NAMES: NameBook | None = None


@dataclass(slots=True)
class ExportContext:
    analyzer: BinaryAnalyzer
    progress: Progress
    out_dir: Path | None
    jobs: int | None
    analysis: ProgramAnalysis | None = None
    root: Path | None = None
    raw_dir: Path | None = None
    include_dir: Path | None = None
    data_dir: Path | None = None
    header_name: str = ""
    header_path: Path | None = None
    names: NameBook | None = None
    clusters: list[Cluster] = field(default_factory=list)
    addresses: list[int] = field(default_factory=list)
    rendered: dict[int, RenderedFunction] = field(default_factory=dict)
    prototypes: dict[int, str] = field(default_factory=dict)
    failures: list[FunctionFailure] = field(default_factory=list)
    raw_ranges: list[FunctionRange] = field(default_factory=list)
    raw_sources: list[Path] = field(default_factory=list)
    asm_files: list[Path] = field(default_factory=list)
    summary_files: list[Path] = field(default_factory=list)
    function_index: Path | None = None
    manifest: Path | None = None
    worker_count: int = 1
    requested_jobs: int | None = None
    render_mode: str = "single"
    data_variable_count: int = 0


@dataclass(frozen=True, slots=True)
class WorkerSpec:
    backend: str
    binary: Path
    analysis_command: str | None
    idadir: Path | None = None
    ida_domain_path: Path | None = None


def export_binary(
    analyzer: BinaryAnalyzer,
    *,
    out_dir: Path | None = None,
    progress: Progress | None = None,
    jobs: int | None = None,
) -> ExportSummary:
    progress = progress or analyzer.progress
    context = ExportContext(
        analyzer=analyzer,
        progress=progress,
        out_dir=out_dir,
        jobs=jobs,
    )
    _prepare_tree(context)
    _cluster(context)
    _render(context)
    _write_raw(context)
    _write_metadata(context)
    return _summary(context)


def _prepare_tree(context: ExportContext) -> None:
    analysis = context.analyzer.analysis or context.analyzer.collect()
    root = _root_dir(analysis.binary.path, context.out_dir)
    raw_dir = root / "src" / "raw"
    include_dir = root / "include"
    data_dir = root / "data"
    raw_dir.mkdir(parents=True, exist_ok=True)
    include_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    context.analysis = analysis
    context.root = root
    context.raw_dir = raw_dir
    context.include_dir = include_dir
    context.data_dir = data_dir
    context.header_name = f"{clean_path_component(analysis.binary.path.stem)}.h"
    context.header_path = include_dir / context.header_name
    context.names = build_name_book(analysis)


def _cluster(context: ExportContext) -> None:
    analysis = _need(context.analysis)
    src_dir = _need(context.root) / "src"
    clusters = _build_clusters(analysis, context.analyzer)
    context.clusters = [cluster for cluster in clusters if cluster.members]
    context.addresses = [address for cluster in context.clusters for address in cluster.members]
    expected: list[Path] = []
    for cluster in context.clusters:
        expected.extend(_expected_paths(_need(context.raw_dir), cluster))
    _remove_stale_sources(src_dir, expected)


def _render(context: ExportContext) -> None:
    analysis = _need(context.analysis)
    names = _need(context.names)
    count = len(context.addresses)
    if context.analyzer.supports_parallel:
        context.requested_jobs = context.jobs
        context.worker_count = choose_jobs(
            function_count=count,
            analysis_seconds=context.analyzer.analysis_seconds,
            requested=context.jobs,
            backend=context.analyzer.backend_name,
        )
        context.render_mode = "process" if context.worker_count > 1 else "single"
        context.progress.log(
            describe_jobs(
                function_count=count,
                analysis_seconds=context.analyzer.analysis_seconds,
                requested=context.jobs,
                selected=context.worker_count,
                backend=context.analyzer.backend_name,
            )
        )
    else:
        context.worker_count = 1
        context.render_mode = "single"
        context.progress.log(f"render: single session ({context.analyzer.backend_label})")

    context.progress.log(
        f"render: {count} functions, {len(context.clusters)} clusters, {context.analyzer.decompiler_label}"
    )
    context.rendered = render_functions(
        analyzer=context.analyzer,
        analysis=analysis,
        addresses=context.addresses,
        names=names,
        progress=context.progress,
        worker_count=context.worker_count,
    )


def _write_raw(context: ExportContext) -> None:
    context.progress.log("write: source, asm, metadata")
    written = write_source_tree(
        analysis=_need(context.analysis),
        clusters=context.clusters,
        src_dir=_need(context.raw_dir),
        asm_dir=_need(context.raw_dir),
        summary_dir=_need(context.raw_dir),
        include_dir=_need(context.include_dir),
        header_name=context.header_name,
        rendered=context.rendered,
        prototypes=context.prototypes,
        write_support=True,
    )
    context.raw_sources = written["sources"]
    context.asm_files = written["asm"]
    context.summary_files = written["summaries"]
    context.failures = written["failures"]
    context.raw_ranges = written["ranges"]


def write_source_tree(
    *,
    analysis: ProgramAnalysis,
    clusters: list[Cluster],
    src_dir: Path,
    asm_dir: Path,
    summary_dir: Path,
    include_dir: Path,
    header_name: str,
    rendered: dict[int, RenderedFunction],
    prototypes: dict[int, str],
    write_support: bool,
) -> dict[str, Any]:
    sources: list[Path] = []
    asm_files: list[Path] = []
    summaries: list[Path] = []
    failures: list[FunctionFailure] = []
    ranges: list[FunctionRange] = []

    for cluster in clusters:
        c_path = _cluster_path(src_dir, cluster, c_file_name(cluster))
        asm_path = _cluster_path(asm_dir, cluster, asm_file_name(cluster))
        summary_path = _cluster_path(summary_dir, cluster, summary_file_name(cluster))
        c_path.parent.mkdir(parents=True, exist_ok=True)
        asm_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        include_path = Path(os.path.relpath(include_dir / header_name, c_path.parent)).as_posix()
        block = build_cluster_files(
            analysis=analysis,
            cluster=cluster,
            header_include=include_path,
            c_path=c_path,
            asm_path=asm_path,
            summary_path=summary_path,
            rendered=rendered,
            prototypes=prototypes,
        )
        c_path.write_text(block["c"], encoding="utf-8")
        sources.append(c_path.resolve())
        ranges.extend(block["ranges"])
        if write_support:
            asm_path.write_text(block["asm"], encoding="utf-8")
            summary_path.write_text(block["summary"], encoding="utf-8")
            asm_files.append(asm_path.resolve())
            summaries.append(summary_path.resolve())
            failures.extend(block["failures"])

    return {
        "sources": sources,
        "asm": asm_files,
        "summaries": summaries,
        "failures": failures,
        "ranges": ranges,
    }


def build_cluster_files(
    *,
    analysis: ProgramAnalysis,
    cluster: Cluster,
    header_include: str,
    c_path: Path,
    asm_path: Path,
    summary_path: Path,
    rendered: dict[int, RenderedFunction],
    prototypes: dict[int, str],
) -> dict[str, Any]:
    c_parts = [_c_preamble(cluster, header_include)]
    asm_parts = [_asm_preamble(cluster)]
    summary_parts = [_summary_preamble(cluster)]
    c_line = next_line(c_parts[0])
    asm_line = next_line(asm_parts[0])
    ranges: list[FunctionRange] = []
    failures: list[FunctionFailure] = []
    c_resolved = c_path.resolve()
    asm_resolved = asm_path.resolve()

    for address in cluster.members:
        routine = analysis.routines[address]
        item = rendered[address]
        prototypes[address] = item.prototype
        if item.failure is not None:
            failures.append(item.failure)
        asm_start = asm_line
        asm_end = asm_start + line_count(item.asm_text) - 1
        metadata = _function_metadata(
            routine=routine,
            rendered=item,
            c_path=c_path,
            asm_path=asm_path,
            c_start=c_line,
            c_end=c_line,
            asm_start=asm_start,
            asm_end=asm_end,
        )
        body = metadata + item.c_text
        c_start = c_line
        c_end = c_start + line_count(body) - 1
        metadata = _function_metadata(
            routine=routine,
            rendered=item,
            c_path=c_path,
            asm_path=asm_path,
            c_start=c_start,
            c_end=c_end,
            asm_start=asm_start,
            asm_end=asm_end,
        )
        body = metadata + item.c_text
        c_parts.append(body.rstrip() + "\n\n")
        asm_parts.append(item.asm_text.rstrip() + "\n\n")
        summary_parts.append(_summary_function(routine, summary_path, item.summary_text).rstrip() + "\n\n")
        ranges.append(
            FunctionRange(
                address=address,
                name=routine.name,
                c_file=c_resolved,
                c_line_start=c_start,
                c_line_end=c_end,
                asm_file=asm_resolved,
                asm_line_start=asm_start,
                asm_line_end=asm_end,
            )
        )
        c_line = c_end + 2
        asm_line = asm_end + 2

    return {"c": "".join(c_parts), "asm": "".join(asm_parts), "summary": "".join(summary_parts), "ranges": ranges, "failures": failures}


def render_functions(
    *,
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    addresses: list[int],
    names: NameBook,
    progress: Progress,
    worker_count: int,
) -> dict[int, RenderedFunction]:
    if worker_count <= 1:
        return _render_serial(analyzer, analysis, addresses, names, progress)
    try:
        return _render_parallel(analyzer, analysis, addresses, names, progress, worker_count)
    except Exception as exc:  # noqa: BLE001
        progress.log(f"warning: parallel export failed ({exc}); retrying with the primary session")
        return _render_serial(analyzer, analysis, addresses, names, progress)


def _render_serial(
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    addresses: list[int],
    names: NameBook,
    progress: Progress,
) -> dict[int, RenderedFunction]:
    output: dict[int, RenderedFunction] = {}
    with progress.bar(total=len(addresses), desc="exporting", unit="func") as bar:
        for address in addresses:
            output[address] = render_one(analyzer, analysis, analysis.routines[address], names)
            bar.update(1)
    return output


def _render_parallel(
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    addresses: list[int],
    names: NameBook,
    progress: Progress,
    worker_count: int,
) -> dict[int, RenderedFunction]:
    progress.log(f"jobs: opening {worker_count} workers for {len(addresses)} functions")
    analyzer.prepare_parallel_workers()
    spec = _worker_spec(analyzer)
    output: dict[int, RenderedFunction] = {}
    pending = set(addresses)
    with progress.bar(total=len(addresses), desc="exporting", unit="func") as bar:
        try:
            ctx = multiprocessing.get_context("spawn")
            with ProcessPoolExecutor(
                max_workers=worker_count,
                mp_context=ctx,
                initializer=_init_worker,
                initargs=(spec, analysis, names),
            ) as executor:
                futures = {executor.submit(_render_in_worker, address): address for address in addresses}
                for future in as_completed(futures):
                    address = futures[future]
                    result_address, result = future.result()
                    output[result_address] = result
                    pending.discard(address)
                    bar.update(1)
        except BrokenProcessPool as exc:
            progress.log(f"warning: worker process exited unexpectedly ({exc}); retrying remaining functions")
        for address in sorted(pending, key=addresses.index):
            output[address] = _render_isolated(spec, analysis, address, names)
            bar.update(1)
    return output


def _worker_spec(analyzer: BinaryAnalyzer) -> WorkerSpec:
    session = analyzer.session
    return WorkerSpec(
        backend=analyzer.backend_name,
        binary=analyzer.binary,
        analysis_command=getattr(session, "analysis_command", None),
        idadir=getattr(session, "idadir", None),
        ida_domain_path=getattr(session, "ida_domain_path", None),
    )


def _init_worker(spec: WorkerSpec, analysis: ProgramAnalysis, names: NameBook) -> None:
    global _WORKER_SESSION, _WORKER_ANALYSIS, _WORKER_NAMES
    _WORKER_SESSION = _open_worker(spec)
    _WORKER_ANALYSIS = analysis
    _WORKER_NAMES = names
    atexit.register(_close_worker)


def _open_worker(spec: WorkerSpec):
    if spec.backend == "ida":
        session = IdaSession(spec.binary, idadir=spec.idadir, ida_domain_path=spec.ida_domain_path)
    elif spec.backend == "r2":
        session = R2Session(spec.binary, analysis_command=spec.analysis_command or "aaa")
        session.analyze()
    else:
        raise RuntimeError(f"unsupported backend for worker: {spec.backend}")
    session.ensure_decompiler()
    return session


def _close_worker() -> None:
    global _WORKER_SESSION
    if _WORKER_SESSION is not None:
        try:
            _WORKER_SESSION.close()
        finally:
            _WORKER_SESSION = None


def _render_in_worker(address: int) -> tuple[int, RenderedFunction]:
    if _WORKER_SESSION is None or _WORKER_ANALYSIS is None or _WORKER_NAMES is None:
        raise RuntimeError("render worker was not initialized")
    routine = _WORKER_ANALYSIS.routines[address]
    return address, render_one(_WORKER_SESSION, _WORKER_ANALYSIS, routine, _WORKER_NAMES)


def _render_isolated(
    spec: WorkerSpec,
    analysis: ProgramAnalysis,
    address: int,
    names: NameBook,
) -> RenderedFunction:
    try:
        ctx = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(
            max_workers=1,
            mp_context=ctx,
            initializer=_init_worker,
            initargs=(spec, analysis, names),
        ) as executor:
            _address, result = executor.submit(_render_in_worker, address).result()
            return result
    except Exception as exc:  # noqa: BLE001
        return _failure_stub(analysis, address, names, exc)


def render_one(session_like, analysis: ProgramAnalysis, routine: Routine, names: NameBook) -> RenderedFunction:
    try:
        disasm = session_like.disasm(routine.address).rstrip()
        summary = session_like.function_summary(routine.address).rstrip()
        if routine.size <= ASM_STUB_MAX_SIZE:
            prototype = fallback_prototype(routine, analysis.binary.pointer_size, names)
            c_text = asm_stub(routine, prototype)
        else:
            source = normalize_source(session_like.decompile(routine.address), names)
            if not source:
                raise RuntimeError("decompiler returned empty output")
            prototype = extract_prototype(source) or fallback_prototype(routine, analysis.binary.pointer_size, names)
            c_text = annotate_source(source, routine)
        failure = None
    except Exception as exc:  # noqa: BLE001
        prototype = fallback_prototype(routine, analysis.binary.pointer_size, names)
        c_text = failure_stub(routine, prototype)
        disasm = ""
        summary = ""
        failure = FunctionFailure(routine.address, routine.name, str(exc))
    return RenderedFunction(
        address=routine.address,
        c_name=extract_name(prototype) or clean_c_identifier(routine.name),
        prototype=prototype,
        c_text=c_text,
        asm_text=asm_function(routine, disasm),
        summary_text=summary,
        failure=failure,
    )


def _failure_stub(
    analysis: ProgramAnalysis,
    address: int,
    names: NameBook,
    exc: BaseException,
) -> RenderedFunction:
    routine = analysis.routines[address]
    prototype = fallback_prototype(routine, analysis.binary.pointer_size, names)
    return RenderedFunction(
        address=address,
        c_name=extract_name(prototype) or clean_c_identifier(routine.name),
        prototype=prototype,
        c_text=failure_stub(routine, prototype),
        asm_text=asm_function(routine, ""),
        summary_text="",
        failure=FunctionFailure(address, routine.name, str(exc)),
    )


def fallback_prototype(routine: Routine, pointer_size: int, names: NameBook) -> str:
    signature = (routine.signature or "").strip().rstrip(";")
    parsed = parse_signature(signature) if signature else None
    if parsed is not None:
        return parsed
    default = "undefined8" if pointer_size >= 8 else "undefined4"
    return f"{default} {names.function_name(routine.address, routine.name)}()"


def import_prototype(name: str, pointer_size: int) -> str:
    default = "undefined8" if pointer_size >= 8 else "undefined4"
    return f"{default} {clean_c_identifier(name)}()"


def parse_signature(signature: str) -> str | None:
    before, sep, after = signature.partition("(")
    if not sep:
        return None
    before = before.rstrip()
    if not before:
        return None
    name_start = len(before)
    while name_start > 0 and before[name_start - 1] not in {" ", "\t"}:
        name_start -= 1
    ret = before[:name_start].rstrip()
    raw_name = before[name_start:].strip()
    if not raw_name:
        return None
    pointer_prefix = "*" * (len(raw_name) - len(raw_name.lstrip("*")))
    name = clean_c_identifier(raw_name.lstrip("*"))
    ret = (ret + " " + pointer_prefix).strip() if ret else "undefined8"
    params = after.rsplit(")", 1)[0].strip()
    return f"{ret} {name}({params})" if params else f"{ret} {name}()"


def extract_prototype(source: str) -> str | None:
    before, sep, _after = source.partition("{")
    if not sep:
        return None
    text = " ".join(line.strip() for line in before.splitlines() if line.strip()).strip()
    return text or None


def extract_name(prototype: str) -> str | None:
    before, sep, _after = prototype.partition("(")
    if not sep:
        return None
    parts = before.rstrip().split()
    return parts[-1].lstrip("*") if parts else None


def annotate_source(source: str, routine: Routine) -> str:
    marker = f"\n    /* {routine.name} @ 0x{routine.address:x}; recovered address annotation. */\n"
    brace = source.find("{")
    if brace == -1:
        return f"/* {routine.name} @ 0x{routine.address:x} */\n{source}"
    return source[: brace + 1] + marker + source[brace + 1 :]


def asm_stub(routine: Routine, prototype: str) -> str:
    lines = [
        prototype,
        "{",
        f"    /* {routine.name} @ 0x{routine.address:x}; short routine, inspect paired ASM. */",
    ]
    if not prototype.startswith("void "):
        lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines)


def failure_stub(routine: Routine, prototype: str) -> str:
    lines = [
        prototype,
        "{",
        f"    /* export failed for {routine.name} @ 0x{routine.address:x}; see export-manifest.json. */",
    ]
    if not prototype.startswith("void "):
        lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines)


def asm_function(routine: Routine, disasm: str) -> str:
    return "\n".join([f"; Function: {routine.name} @ 0x{routine.address:x}", disasm.strip() or "; <no disassembly available>"])


def _summary_function(routine: Routine, path: Path, text: str) -> str:
    lines = [
        f"; Function: {routine.name} @ 0x{routine.address:x}",
        f"; Summary file: {display_path(path)}",
        "; Summary generator: ToCode",
    ]
    lines.append(text.strip() if text.strip() else "; <no summary available>")
    return "\n".join(lines)


def _write_metadata(context: ExportContext) -> None:
    analysis = _need(context.analysis)
    root = _need(context.root)
    header = _need(context.header_path)
    names = _need(context.names)
    header.write_text(build_header(analysis, context.prototypes, names), encoding="utf-8")
    context.data_variable_count = export_variables(analysis, root, context.raw_ranges)
    context.function_index = write_function_index(root, context.raw_ranges)
    stale = root / ("function-index-" + "ll" + "m.json")
    if stale.exists():
        stale.unlink()
    write_json(root / "sections.json", sections_json(analysis))
    write_json(root / "strings.json", strings_json(analysis, context.raw_ranges))
    write_json(root / "imports.json", imports_json(analysis))
    write_json(root / "exports.json", exports_json(analysis))
    write_json(root / "relocations.json", relocations_json(analysis))
    write_json(
        root / "functions.json",
        functions_json(
            analysis,
            context.raw_ranges,
            context.prototypes,
            names.functions,
        ),
    )
    reachable = reachable_json(analysis)
    write_json(root / "reachable.json", reachable)
    write_json(root / "cluster-graph.json", cluster_graph_json(analysis, context.clusters, context.raw_ranges))
    write_json(root / "triage.json", triage_json(analysis, context.clusters, context.raw_ranges, reachable))
    write_project_json(context)
    (root / "AGENTS.md").write_text(build_export_agents(analysis, context.header_name), encoding="utf-8")
    context.manifest = write_manifest(context)


def build_header(analysis: ProgramAnalysis, prototypes: dict[int, str], names: NameBook) -> str:
    lines = [
        "#pragma once",
        "",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef uint8_t byte;",
        "typedef uint16_t word;",
        "typedef uint32_t dword;",
        "typedef uint64_t qword;",
        "typedef uint8_t undefined;",
        "typedef uint8_t undefined1;",
        "typedef uint16_t undefined2;",
        "typedef uint32_t undefined4;",
        "typedef uint64_t undefined8;",
        "typedef void (*code)(void);",
        "",
        "typedef unsigned char uchar;",
        "typedef unsigned short ushort;",
        "typedef unsigned int uint;",
        "typedef unsigned long ulong;",
        "typedef unsigned long long ulonglong;",
        "typedef signed char sbyte;",
        "",
        "/* Generated by ToCode. */",
        f"/* Source binary: {analysis.binary.path} */",
        "",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "",
        "/* Internal functions */",
    ]
    for address in sorted(prototypes):
        routine = analysis.routines.get(address)
        if routine is not None and not routine.imported:
            lines.append(f"{prototypes[address]}; /* 0x{address:x} */")
    imports = [
        f"{import_prototype(names.import_name(address, item.name), analysis.binary.pointer_size)}; /* 0x{address:x} */"
        for address, item in sorted(analysis.imports.items())
    ]
    if imports:
        lines.extend(["", "/* Imported functions */", *imports])
    lines.extend(["", "#ifdef __cplusplus", "}", "#endif", ""])
    return "\n".join(lines)


def write_function_index(root: Path, ranges: list[FunctionRange], *, file_name: str = "function-index.json") -> Path:
    path = root / file_name
    write_json(
        path,
        {
            "schema_version": 2,
            "functions": [
                {
                    "address": f"0x{item.address:x}",
                    "name": item.name,
                    "c": {
                        "path": str(item.c_file),
                        "line_start": item.c_line_start,
                        "line_end": item.c_line_end,
                    },
                    "asm": {
                        "path": str(item.asm_file),
                        "line_start": item.asm_line_start,
                        "line_end": item.asm_line_end,
                    },
                }
                for item in ranges
            ],
        },
    )
    return path


def write_project_json(context: ExportContext) -> None:
    analysis = _need(context.analysis)
    root = _need(context.root)
    write_json(
        root / "project.json",
        {
            "binary": str(analysis.binary.path),
            "backend": context.analyzer.backend_name,
            "decompiler": context.analyzer.decompiler_label,
            "root_dir": str(root.resolve()),
            "src_dir": str(_need(context.raw_dir).resolve()),
            "raw_src_dir": str(_need(context.raw_dir).resolve()),
            "include_dir": str(_need(context.include_dir).resolve()),
            "data_dir": str(_need(context.data_dir).resolve()),
            "header": str(_need(context.header_path).resolve()),
            "agents": str((root / "AGENTS.md").resolve()),
            "source_files": [str(item) for item in context.raw_sources],
            "summary_files": [str(item) for item in context.summary_files],
            "asm_files": [str(item) for item in context.asm_files],
            "function_index": str(_need(context.function_index).resolve()),
            "function_count": len(context.raw_ranges),
            "cluster_count": len(context.clusters),
            "failure_count": len(context.failures),
            "requested_worker_count": context.requested_jobs if context.requested_jobs is not None else "auto",
            "worker_count": context.worker_count,
            "parallel_mode": context.render_mode,
        },
    )


def write_manifest(context: ExportContext) -> Path:
    analysis = _need(context.analysis)
    root = _need(context.root)
    path = root / "export-manifest.json"
    write_json(
        path,
        {
            "schema_version": 2,
            "binary": str(analysis.binary.path),
            "backend": context.analyzer.backend_name,
            "decompiler": context.analyzer.decompiler_label,
            "format": analysis.binary.format_name,
            "arch": analysis.binary.arch,
            "bits": analysis.binary.bits,
            "entrypoints": [f"0x{item:x}" for item in analysis.binary.entrypoints],
            "header": str(_need(context.header_path).resolve()),
            "source_files": [str(item) for item in context.raw_sources],
            "raw_source_files": [str(item) for item in context.raw_sources],
            "asm_files": [str(item) for item in context.asm_files],
            "summary_files": [str(item) for item in context.summary_files],
            "function_index": str(_need(context.function_index).resolve()),
            "raw_src_dir": str(_need(context.raw_dir).resolve()),
            "cluster_count": len(context.clusters),
            "function_count": len(context.raw_ranges),
            "data_variable_count": context.data_variable_count,
            "failure_count": len(context.failures),
            "requested_worker_count": context.requested_jobs if context.requested_jobs is not None else "auto",
            "worker_count": context.worker_count,
            "parallel_mode": context.render_mode,
            "agents": str((root / "AGENTS.md").resolve()),
            "triage": str((root / "triage.json").resolve()),
            "imports": str((root / "imports.json").resolve()),
            "exports": str((root / "exports.json").resolve()),
            "reachable": str((root / "reachable.json").resolve()),
            "cluster_graph": str((root / "cluster-graph.json").resolve()),
            "variables_interesting": str((root / "data" / "variables_interesting.json").resolve()),
            "failures": [
                {"address": f"0x{item.address:x}", "name": item.name, "error": item.message}
                for item in context.failures
            ],
        },
    )
    return path


def build_export_agents(analysis: ProgramAnalysis, header_name: str) -> str:
    section_files = sorted(
        [
            f"`data/{clean_path_component(section.name)}.bin`"
            for section in analysis.segments
            if max(section.vsize, section.size) > 0 and section.size > 0
        ],
        key=lambda item: (item != "`data/text.bin`", item),
    )
    examples = ", ".join(section_files[:8])
    if len(section_files) > 8:
        examples += ", ..."
    lines = [
        "# AGENTS",
        "",
        "You are working inside a ToCode binary export.",
        "Treat the recovered source, assembly, metadata, and raw section data as evidence for reverse engineering.",
        "",
        "## Mission",
        "",
        "Discover what this software does and write a factual markdown report named `REPORT.md` in the project root.",
        "Do not refactor or modify the generated export except for that report.",
        "Use subagents only for narrow evidence-gathering tasks such as strings, entrypoint paths, or one cluster family.",
        "",
        "## Files",
        "",
        "- `src/raw/*.summary`: compact function summaries grouped with each clustered source file.",
        "- `src/raw/*.c`: raw decompiled C-like output from the selected backend.",
        "- `src/raw/*.asm`: disassembly grouped with the matching raw source clusters.",
        f"- `include/{header_name}`: recovered prototypes and common typedefs.",
        f"- `data/*.bin`: raw section payloads from the original binary. Example files: {examples or '`data/*.bin`'}",
        "- `data/variables.json`: section manifest plus recovered strings, symbols, relocations, and data labels.",
        "- `data/variables_interesting.json`: globals and pointers worth checking early.",
        "- `triage.json`: first-read summary with entry clusters, strings of interest, and packing/evasion hints.",
        "- `imports.json` and `exports.json`: structured import/export tables.",
        "- `reachable.json`: entrypoint/export reachability depths and unreachable count.",
        "- `cluster-graph.json`: inter-cluster call graph.",
        "- `functions.json`: per-function caller/callee relationships, prototypes, source ranges, and ASM ranges.",
        "- `function-index.json`: exact raw source and ASM line mappings for each exported function.",
        "- `sections.json`, `strings.json`, and `relocations.json`: layout and reference metadata.",
        "- `project.json` and `export-manifest.json`: top-level export paths and artifact inventory.",
        "",
        "## Working Style",
        "",
        "- Start with `triage.json`, `imports.json`, `strings.json`, and `src/raw/*.summary`.",
        "- Use `functions.json` and `function-index.json` to open only the function line ranges you need.",
        "- Read ASM when decompiled output is ambiguous, short, indirect, or contradicted by metadata.",
        "- Treat recovered names and types as hints, not ground truth.",
        "- Cite file paths, function names, addresses, and line numbers for every major claim.",
        "- Be explicit about uncertainty and unresolved symbols.",
        "",
    ]
    return "\n".join(lines)


def _build_clusters(analysis: ProgramAnalysis, analyzer: BinaryAnalyzer) -> list[Cluster]:
    app = analysis.app_routines()
    if len(app) >= FAST_CLUSTER_FUNCTIONS:
        clusters = _fast_clusters(analysis)
    else:
        clusters = cluster_routines(
            addresses=[item.address for item in app],
            roots=analysis.roots,
            callees=analysis.callees,
            callers=analysis.callers,
            thunks=analysis.thunks,
        )
        for cluster in clusters:
            if cluster.root == SHARED_CLUSTER_ID:
                cluster.summary = "Shared utility functions"
                continue
            routine = analysis.routines.get(cluster.root)
            if routine is not None:
                cluster.label = routine.name
            cluster.summary = analyzer.cluster_description_from_imports(cluster.members)
    return _normalize_clusters(analysis, clusters) + _support_clusters(analysis)


def _fast_clusters(analysis: ProgramAnalysis) -> list[Cluster]:
    by_segment: dict[str, list[int]] = {}
    for routine in analysis.app_routines():
        by_segment.setdefault(clean_path_component(routine.segment or "misc"), []).append(routine.address)
    clusters: list[Cluster] = []
    for segment, members in sorted(by_segment.items()):
        members.sort()
        for index, chunk in enumerate(_chunks(members, MAX_FUNCTIONS_PER_FILE)):
            label = segment if len(members) <= MAX_FUNCTIONS_PER_FILE else f"{segment}_{index}"
            clusters.append(
                Cluster(
                    root=chunk[0],
                    label=label,
                    summary=f"Fast export chunk from section {segment}",
                    members=list(chunk),
                )
            )
    return clusters


def _support_clusters(analysis: ProgramAnalysis) -> list[Cluster]:
    grouped: dict[tuple[str, str], list[int]] = {}
    for routine in analysis.support_routines():
        folder = clean_path_component(routine.code_kind or "support")
        segment = clean_path_component(routine.segment or "misc")
        grouped.setdefault((folder, segment), []).append(routine.address)
    clusters: list[Cluster] = []
    for (folder, segment), members in sorted(grouped.items()):
        members.sort()
        for index, chunk in enumerate(_chunks(members, MAX_FUNCTIONS_PER_FILE)):
            label = f"{folder}_{segment}"
            if len(members) > MAX_FUNCTIONS_PER_FILE:
                label = f"{label}_{index}"
            clusters.append(
                Cluster(
                    root=chunk[0],
                    label=label,
                    summary=f"{folder} functions from section {segment}",
                    members=list(chunk),
                    folder=folder,
                )
            )
    return clusters


def _normalize_clusters(analysis: ProgramAnalysis, clusters: list[Cluster]) -> list[Cluster]:
    split: list[Cluster] = []
    for cluster in clusters:
        if len(cluster.members) <= MAX_FUNCTIONS_PER_FILE:
            split.append(cluster)
            continue
        for index, chunk in enumerate(_chunks(cluster.members, MAX_FUNCTIONS_PER_FILE)):
            split.append(
                Cluster(
                    root=chunk[0],
                    label=f"{cluster.label}_{index}",
                    summary=f"{cluster.summary} (part {index + 1})" if cluster.summary else "",
                    members=list(chunk),
                    folder=cluster.folder,
                )
            )
    return _coalesce_small(analysis, split)


def _coalesce_small(analysis: ProgramAnalysis, clusters: list[Cluster]) -> list[Cluster]:
    output: list[Cluster] = []
    pending: list[int] = []
    pending_root: int | None = None
    pending_bytes = 0
    for cluster in clusters:
        size = sum(max(analysis.routines[address].size, 1) for address in cluster.members if address in analysis.routines)
        mergeable = (
            cluster.root != SHARED_CLUSTER_ID
            and len(cluster.members) <= TINY_CLUSTER_FUNCTIONS
            and size <= TINY_CLUSTER_BYTES
        )
        if not mergeable:
            _flush_small(output, pending, pending_root)
            pending = []
            pending_root = None
            pending_bytes = 0
            output.append(cluster)
            continue
        if pending and (
            len(pending) + len(cluster.members) > MERGED_CLUSTER_FUNCTIONS
            or pending_bytes + size > MERGED_CLUSTER_BYTES
        ):
            _flush_small(output, pending, pending_root)
            pending = []
            pending_root = None
            pending_bytes = 0
        if pending_root is None:
            pending_root = cluster.root
        pending.extend(cluster.members)
        pending_bytes += size
    _flush_small(output, pending, pending_root)
    return output


def _flush_small(output: list[Cluster], members: list[int], root: int | None) -> None:
    if not members:
        return
    cluster_root = root if root is not None else SHARED_CLUSTER_ID
    output.append(
        Cluster(
            root=cluster_root,
            label=f"cluster_{cluster_root:016x}",
            summary="Merged small export clusters",
            members=list(members),
        )
    )


def _c_preamble(cluster: Cluster, header_include: str) -> str:
    lines = [
        "/* Generated by ToCode. */",
        "/* Cluster: utils */" if cluster.root == SHARED_CLUSTER_ID else f"/* Cluster root: {cluster.label} (0x{cluster.root:x}) */",
    ]
    if cluster.summary:
        lines.append(f"/* Description: {cluster.summary} */")
    lines.extend([f'#include "{header_include}"', ""])
    return "\n".join(lines)


def _asm_preamble(cluster: Cluster) -> str:
    lines = [
        "; Generated by ToCode.",
        "; Cluster: utils" if cluster.root == SHARED_CLUSTER_ID else f"; Cluster root: {cluster.label} (0x{cluster.root:x})",
    ]
    if cluster.summary:
        lines.append(f"; Description: {cluster.summary}")
    lines.append("")
    return "\n".join(lines)


def _summary_preamble(cluster: Cluster) -> str:
    lines = [
        "; Generated by ToCode.",
        "; Cluster: utils" if cluster.root == SHARED_CLUSTER_ID else f"; Cluster root: {cluster.label} (0x{cluster.root:x})",
    ]
    if cluster.summary:
        lines.append(f"; Description: {cluster.summary}")
    lines.extend(["; Summary source: backend function summaries", ""])
    return "\n".join(lines)


def _function_metadata(
    *,
    routine: Routine,
    rendered: RenderedFunction,
    c_path: Path,
    asm_path: Path,
    c_start: int,
    c_end: int,
    asm_start: int,
    asm_end: int,
) -> str:
    return "\n".join(
        [
            "/* metadata:",
            f" * address: 0x{routine.address:x}",
            f" * original_name: {routine.name}",
            f" * c_name: {rendered.c_name}",
            f" * source_file: {display_path(c_path)}",
            f" * line_start: {c_start}",
            f" * line_end: {c_end}",
            f" * asm_file: {display_path(asm_path)}",
            f" * asm_line_start: {asm_start}",
            f" * asm_line_end: {asm_end}",
            " */",
            "",
        ]
    )


def _root_dir(binary: Path, out_dir: Path | None) -> Path:
    if out_dir is not None:
        path = Path(out_dir).expanduser()
        return path.resolve() if path.is_absolute() else (binary.parent / path).resolve()
    default_root = os.environ.get("TOCODE_DEFAULT_OUT_ROOT", "").strip()
    if default_root:
        return (Path(default_root).expanduser().resolve() / default_output_name(binary)).resolve()
    return (binary.parent / default_output_name(binary)).resolve()


def _cluster_path(root: Path, cluster: Cluster, file_name: str) -> Path:
    return root / clean_path_component(cluster.folder or "app") / file_name


def _expected_paths(root: Path, cluster: Cluster) -> list[Path]:
    return [
        _cluster_path(root, cluster, c_file_name(cluster)),
        _cluster_path(root, cluster, asm_file_name(cluster)),
        _cluster_path(root, cluster, summary_file_name(cluster)),
    ]


def _remove_stale_sources(src_dir: Path, expected: list[Path]) -> None:
    allowed = {path.resolve() for path in expected}
    if not src_dir.exists():
        return
    for path in src_dir.rglob("*"):
        if path.is_file() and path.suffix in {".c", ".asm", ".summary"} and path.resolve() not in allowed:
            path.unlink()
    _remove_empty_dirs(src_dir)


def _remove_empty_dirs(path: Path) -> None:
    for child in path.iterdir():
        if child.is_dir():
            _remove_empty_dirs(child)
    if path != path.parent and not any(path.iterdir()):
        try:
            path.rmdir()
        except OSError:
            pass


def _summary(context: ExportContext) -> ExportSummary:
    return ExportSummary(
        root_dir=_need(context.root).resolve(),
        raw_src_dir=_need(context.raw_dir).resolve(),
        include_dir=_need(context.include_dir).resolve(),
        header_path=_need(context.header_path).resolve(),
        source_files=context.raw_sources,
        asm_files=context.asm_files,
        summary_files=context.summary_files,
        function_count=len(context.raw_ranges),
        cluster_count=len(context.clusters),
        failed_functions=context.failures,
        function_index_path=_need(context.function_index).resolve(),
        manifest_path=_need(context.manifest).resolve(),
        data_dir=_need(context.data_dir).resolve(),
    )


def _need(value):
    if value is None:
        raise RuntimeError("export context is incomplete")
    return value


def _chunks(values: list[int], size: int):
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def line_count(text: str) -> int:
    return max(1, len(text.splitlines()))


def next_line(text: str) -> int:
    return line_count(text) + 1
