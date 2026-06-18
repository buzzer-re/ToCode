from __future__ import annotations

import atexit
from contextlib import nullcontext
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any

from . import __version__
from .analysis import BinaryAnalyzer
from .backends.base import is_ida_database
from .backends.ida import IdaSession
from .backends.ida import _cache_root as _ida_cache_root
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
    write_text_atomic,
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
from .parallel import available_memory_mb, choose_jobs, describe_jobs
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
TREE_CALLING_CONVENTION_RX = re.compile(
    r"\b__(?:cdecl|fastcall|stdcall|thiscall|usercall|userpurge|noreturn)\b"
)
TREE_SPOILS_RX = re.compile(r"\s*__spoils<[^>]*>")
TREE_SPACE_RX = re.compile(r"[ \t]{2,}")
TREE_REGISTER_RX = re.compile(r"@<([^>]+)>")
TREE_VERSIONED_IMPORT_RX = re.compile(
    r"\b([A-Za-z_]\w*)__(?:GLIBC(?:XX)?|CXXABI)_[0-9][A-Za-z0-9_]*\b"
)

_WORKER_SESSION: Any = None
_WORKER_ANALYSIS: ProgramAnalysis | None = None
_WORKER_NAMES: NameBook | None = None
_TREE_WORKER_ANALYSIS: ProgramAnalysis | None = None
_TREE_WORKER_RENDERED: dict[int, RenderedFunction] | None = None
_TREE_WORKER_RAW_RANGES: dict[int, FunctionRange] | None = None
CHECKPOINT_SCHEMA_VERSION = 1


@dataclass(slots=True)
class CheckpointStore:
    root: Path
    cache_id: str
    progress: Progress
    restart: bool = False

    @property
    def state_dir(self) -> Path:
        return self.root / ".tocode"

    @property
    def rendered_dir(self) -> Path:
        return self.state_dir / "rendered"

    @property
    def state_path(self) -> Path:
        return self.state_dir / "checkpoint.json"

    def start(self, *, binary: Path, backend: str, address_count: int) -> None:
        if self.restart and self.state_dir.exists():
            shutil.rmtree(self.state_dir)
            self.progress.log("Checkpoint: discarded previous state (--restart)")
        existing = self._read_state()
        if existing is None and self.state_dir.exists():
            shutil.rmtree(self.state_dir)
            self.progress.log("Checkpoint: existing state is invalid; starting fresh")
        if existing is not None and existing.get("cache_id") != self.cache_id:
            shutil.rmtree(self.state_dir)
            existing = None
            self.progress.log(
                "Checkpoint: existing state does not match this export; starting fresh"
            )
        self.rendered_dir.mkdir(parents=True, exist_ok=True)
        completed = self.completed_addresses()
        status = "resuming" if existing is not None and completed else "started"
        self._write_state(
            {
                "schema_version": CHECKPOINT_SCHEMA_VERSION,
                "status": status,
                "cache_id": self.cache_id,
                "binary": str(binary),
                "backend": backend,
                "function_count": address_count,
                "completed": [f"0x{item:x}" for item in completed],
            }
        )
        if completed:
            self.progress.log(
                f"Checkpoint: resuming with {len(completed)}/{address_count} cached functions"
            )
        else:
            self.progress.log("Checkpoint: started")

    def load(self, address: int) -> RenderedFunction | None:
        path = self._rendered_path(address)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        try:
            if payload.get("cache_id") != self.cache_id:
                return None
            return _rendered_from_json(payload["rendered"])
        except (KeyError, TypeError, ValueError):
            return None

    def save(self, rendered: RenderedFunction) -> None:
        payload = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "cache_id": self.cache_id,
            "rendered": _rendered_to_json(rendered),
        }
        write_text_atomic(
            self._rendered_path(rendered.address),
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
        )

    def mark_interrupted(self) -> None:
        self._refresh_completed(status="interrupted")

    def mark_failed(self) -> None:
        self._refresh_completed(status="failed")

    def complete(self) -> None:
        if self.state_dir.exists():
            shutil.rmtree(self.state_dir)
        self.progress.log("Checkpoint: complete; removed saved state")

    def completed_addresses(self) -> list[int]:
        if not self.rendered_dir.is_dir():
            return []
        values: list[int] = []
        for path in self.rendered_dir.glob("*.json"):
            try:
                values.append(int(path.stem, 16))
            except ValueError:
                continue
        return sorted(values)

    def _refresh_completed(self, *, status: str) -> None:
        state = self._read_state() or {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "cache_id": self.cache_id,
        }
        state["status"] = status
        state["completed"] = [f"0x{item:x}" for item in self.completed_addresses()]
        self._write_state(state)

    def _read_state(self) -> dict[str, Any] | None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
            return None
        return payload if isinstance(payload, dict) else None

    def _write_state(self, payload: dict[str, Any]) -> None:
        write_text_atomic(
            self.state_path,
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
        )

    def _rendered_path(self, address: int) -> Path:
        return self.rendered_dir / f"{address:016x}.json"


def _rendered_to_json(item: RenderedFunction) -> dict[str, Any]:
    return {
        "address": item.address,
        "c_name": item.c_name,
        "prototype": item.prototype,
        "c_text": item.c_text,
        "asm_text": item.asm_text,
        "summary_text": item.summary_text,
        "failure": None
        if item.failure is None
        else {
            "address": item.failure.address,
            "name": item.failure.name,
            "message": item.failure.message,
        },
    }


def _rendered_from_json(payload: dict[str, Any]) -> RenderedFunction:
    failure_payload = payload.get("failure")
    failure = (
        None
        if failure_payload is None
        else FunctionFailure(
            address=int(failure_payload["address"]),
            name=str(failure_payload["name"]),
            message=str(failure_payload["message"]),
        )
    )
    return RenderedFunction(
        address=int(payload["address"]),
        c_name=str(payload["c_name"]),
        prototype=str(payload["prototype"]),
        c_text=str(payload["c_text"]),
        asm_text=str(payload["asm_text"]),
        summary_text=str(payload["summary_text"]),
        failure=failure,
    )


def _all_cached(checkpoint: CheckpointStore | None, addresses: list[int]) -> bool:
    return checkpoint is not None and all(
        checkpoint.load(address) is not None for address in addresses
    )


@dataclass(slots=True)
class ExportContext:
    analyzer: BinaryAnalyzer
    progress: Progress
    out_dir: Path | None
    jobs: int | None
    tree_enabled: bool
    entropy_enabled: bool = False
    restart: bool = False
    analysis: ProgramAnalysis | None = None
    root: Path | None = None
    raw_dir: Path | None = None
    tree_dir: Path | None = None
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
    tree_ranges: list[FunctionRange] = field(default_factory=list)
    raw_sources: list[Path] = field(default_factory=list)
    tree_sources: list[Path] = field(default_factory=list)
    asm_files: list[Path] = field(default_factory=list)
    summary_files: list[Path] = field(default_factory=list)
    function_index: Path | None = None
    tree_index: Path | None = None
    manifest: Path | None = None
    ida_database: Path | None = None
    worker_count: int = 1
    requested_jobs: int | None = None
    render_mode: str = "single"
    data_variable_count: int = 0
    checkpoint: CheckpointStore | None = None


@dataclass(frozen=True, slots=True)
class WorkerSpec:
    backend: str
    binary: Path
    analysis_command: str | None
    idadir: Path | None = None
    ida_domain_path: Path | None = None
    db_path: Path | None = None
    copy_db: bool = True


@dataclass(frozen=True, slots=True)
class TreeBuildJob:
    index: int
    cluster: Cluster
    tree_path: Path
    raw_path: Path
    include_path: str


def export_binary(
    analyzer: BinaryAnalyzer,
    *,
    out_dir: Path | None = None,
    progress: Progress | None = None,
    jobs: int | None = None,
    tree: bool = False,
    entropy: bool = False,
    restart: bool = False,
) -> ExportSummary:
    progress = progress or analyzer.progress
    context = ExportContext(
        analyzer=analyzer,
        progress=progress,
        out_dir=out_dir,
        jobs=jobs,
        tree_enabled=tree,
        entropy_enabled=entropy,
        restart=restart,
    )
    try:
        _prepare_tree(context)
        _cluster(context)
        _prepare_checkpoint(context)
        if tree:
            _render(context)
            _write_raw(context)
            _write_tree(context)
        else:
            _render_and_write_raw(context)
        _write_metadata(context)
    except KeyboardInterrupt:
        if context.checkpoint is not None:
            context.checkpoint.mark_interrupted()
        context.progress.log("Export interrupted; rerun the same command to resume.")
        raise
    except Exception:
        if context.checkpoint is not None:
            context.checkpoint.mark_failed()
        context.progress.log(
            "Export failed; rerun the same command to resume after fixing the issue."
        )
        raise
    if context.checkpoint is not None:
        context.checkpoint.complete()
    return _summary(context)


def _prepare_tree(context: ExportContext) -> None:
    root = _root_dir(context.analyzer.binary, context.out_dir)
    if context.progress.log_path is None:
        context.progress.set_log_path(root / "tocode.log")
    context.progress.log("Export run started")
    analysis = context.analyzer.analysis or context.analyzer.collect()
    raw_dir = root / "src" / "raw"
    tree_dir = root / "src" / "tree"
    include_dir = root / "include"
    data_dir = root / "data"
    raw_dir.mkdir(parents=True, exist_ok=True)
    if context.tree_enabled:
        tree_dir.mkdir(parents=True, exist_ok=True)
    include_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    context.analysis = analysis
    context.root = root
    context.raw_dir = raw_dir
    context.tree_dir = tree_dir if context.tree_enabled else None
    context.include_dir = include_dir
    context.data_dir = data_dir
    context.header_name = f"{clean_path_component(analysis.binary.path.stem)}.h"
    context.header_path = include_dir / context.header_name
    context.names = build_name_book(analysis)


def _prepare_checkpoint(context: ExportContext) -> None:
    analysis = _need(context.analysis)
    root = _need(context.root)
    cache_id = _checkpoint_cache_id(context)
    checkpoint = CheckpointStore(
        root=root,
        cache_id=cache_id,
        progress=context.progress,
        restart=context.restart,
    )
    checkpoint.start(
        binary=analysis.binary.path,
        backend=context.analyzer.backend_name,
        address_count=len(context.addresses),
    )
    context.checkpoint = checkpoint


def _checkpoint_cache_id(context: ExportContext) -> str:
    analysis = _need(context.analysis)
    payload = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "tocode_version": __version__,
        "binary": _binary_fingerprint(analysis.binary.path),
        "backend": context.analyzer.backend_name,
        "decompiler": context.analyzer.decompiler_label,
        "analysis_command": getattr(context.analyzer.session, "analysis_command", None),
        "tree": context.tree_enabled,
        "entropy": context.entropy_enabled,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def _binary_fingerprint(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
    except OSError:
        return {"path": str(path.resolve()), "missing": True}
    return {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _cluster(context: ExportContext) -> None:
    analysis = _need(context.analysis)
    src_dir = _need(context.root) / "src"
    clusters = _build_clusters(analysis, context.analyzer)
    context.clusters = [cluster for cluster in clusters if cluster.members]
    context.addresses = [
        address for cluster in context.clusters for address in cluster.members
    ]
    expected: list[Path] = []
    for cluster in context.clusters:
        expected.extend(_expected_paths(_need(context.raw_dir), cluster))
        if context.tree_enabled:
            expected.append(
                _cluster_path(_need(context.tree_dir), cluster, c_file_name(cluster))
            )
    _remove_stale_sources(src_dir, expected)


def _render(context: ExportContext) -> None:
    _select_render_workers(context)
    analysis = _need(context.analysis)
    names = _need(context.names)
    count = len(context.addresses)

    context.progress.log(
        f"Rendering {count} functions in {len(context.clusters)} clusters with {context.analyzer.decompiler_label}"
    )
    context.rendered = render_functions(
        analyzer=context.analyzer,
        analysis=analysis,
        addresses=context.addresses,
        names=names,
        progress=context.progress,
        worker_count=context.worker_count,
        checkpoint=context.checkpoint,
    )


def _select_render_workers(context: ExportContext) -> None:
    count = len(context.addresses)
    if context.analyzer.supports_parallel:
        context.requested_jobs = context.jobs
        is_ida = context.analyzer.backend_name == "ida"
        context.worker_count = choose_jobs(
            function_count=count,
            analysis_seconds=context.analyzer.analysis_seconds,
            requested=context.jobs,
            backend=context.analyzer.backend_name,
            available_memory_mb=available_memory_mb() if is_ida else None,
            database_size_mb=_worker_database_size_mb(context.analyzer)
            if is_ida
            else None,
        )
        context.render_mode = "process" if context.worker_count > 1 else "single"
        if is_ida and context.jobs is not None and context.worker_count < context.jobs:
            context.progress.log(
                f"Note: limiting to {context.worker_count} worker(s) instead of the "
                f"requested {context.jobs} to fit available memory "
                f"(each IDA worker loads the whole database; override with "
                f"TOCODE_IDA_WORKER_MEMORY_MB)."
            )
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
        context.progress.log(
            f"Rendering with one {context.analyzer.backend_label} session"
        )


def _render_and_write_raw(context: ExportContext) -> None:
    _select_render_workers(context)
    if context.render_mode == "single":
        context.render_mode = "stream"
    elif context.worker_count > 1:
        context.render_mode = "stream-process"
    analysis = _need(context.analysis)
    names = _need(context.names)
    context.progress.log(
        f"Rendering and writing {len(context.addresses)} functions in {len(context.clusters)} clusters with {context.analyzer.decompiler_label}"
    )
    written = render_and_write_source_tree(
        analyzer=context.analyzer,
        analysis=analysis,
        clusters=context.clusters,
        src_dir=_need(context.raw_dir),
        asm_dir=_need(context.raw_dir),
        summary_dir=_need(context.raw_dir),
        include_dir=_need(context.include_dir),
        header_name=context.header_name,
        names=names,
        prototypes=context.prototypes,
        progress=context.progress,
        worker_count=context.worker_count,
        checkpoint=context.checkpoint,
    )
    context.raw_sources = written["sources"]
    context.asm_files = written["asm"]
    context.summary_files = written["summaries"]
    context.failures = written["failures"]
    context.raw_ranges = written["ranges"]


def _write_raw(context: ExportContext) -> None:
    context.progress.log("Writing raw source, assembly, and summaries")
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
        progress=context.progress,
    )
    context.raw_sources = written["sources"]
    context.asm_files = written["asm"]
    context.summary_files = written["summaries"]
    context.failures = written["failures"]
    context.raw_ranges = written["ranges"]


def _write_tree(context: ExportContext) -> None:
    context.progress.log("Writing tree-sitter friendly source")
    worker_count = choose_jobs(
        function_count=len(context.clusters),
        analysis_seconds=0.0,
        requested=context.jobs,
        backend="tree",
    )
    if worker_count > 1:
        context.progress.log(
            f"Opening {worker_count} tree workers for {len(context.clusters)} clusters"
        )
    written = write_tree_sources(
        analysis=_need(context.analysis),
        clusters=context.clusters,
        src_dir=_need(context.tree_dir),
        raw_dir=_need(context.raw_dir),
        include_dir=_need(context.include_dir),
        rendered=context.rendered,
        raw_ranges=context.raw_ranges,
        progress=context.progress,
        worker_count=worker_count,
    )
    context.tree_sources = written["sources"]
    context.tree_ranges = written["ranges"]


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
    progress: Progress | None = None,
) -> dict[str, Any]:
    sources: list[Path] = []
    asm_files: list[Path] = []
    summaries: list[Path] = []
    failures: list[FunctionFailure] = []
    ranges: list[FunctionRange] = []

    bar_context = (
        progress.bar(total=len(clusters), desc="writing raw", unit="cluster")
        if progress
        else nullcontext()
    )
    with bar_context as bar:
        for cluster in clusters:
            c_path = _cluster_path(src_dir, cluster, c_file_name(cluster))
            asm_path = _cluster_path(asm_dir, cluster, asm_file_name(cluster))
            summary_path = _cluster_path(
                summary_dir, cluster, summary_file_name(cluster)
            )
            c_path.parent.mkdir(parents=True, exist_ok=True)
            asm_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            include_path = Path(
                os.path.relpath(include_dir / header_name, c_path.parent)
            ).as_posix()
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
            write_text_atomic(c_path, block["c"])
            sources.append(c_path.resolve())
            ranges.extend(block["ranges"])
            if write_support:
                write_text_atomic(asm_path, block["asm"])
                write_text_atomic(summary_path, block["summary"])
                asm_files.append(asm_path.resolve())
                summaries.append(summary_path.resolve())
                failures.extend(block["failures"])
            if bar is not None:
                bar.update(1)

    return {
        "sources": sources,
        "asm": asm_files,
        "summaries": summaries,
        "failures": failures,
        "ranges": ranges,
    }


def render_and_write_source_tree(
    *,
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    clusters: list[Cluster],
    src_dir: Path,
    asm_dir: Path,
    summary_dir: Path,
    include_dir: Path,
    header_name: str,
    names: NameBook,
    prototypes: dict[int, str],
    progress: Progress | None = None,
    worker_count: int = 1,
    checkpoint: CheckpointStore | None = None,
) -> dict[str, Any]:
    addresses = [address for cluster in clusters for address in cluster.members]
    if worker_count > 1 and not _all_cached(checkpoint, addresses):
        try:
            return render_and_write_source_tree_parallel(
                analyzer=analyzer,
                analysis=analysis,
                clusters=clusters,
                src_dir=src_dir,
                asm_dir=asm_dir,
                summary_dir=summary_dir,
                include_dir=include_dir,
                header_name=header_name,
                names=names,
                prototypes=prototypes,
                progress=progress,
                worker_count=worker_count,
                checkpoint=checkpoint,
            )
        except Exception as exc:  # noqa: BLE001
            analyzer.restore_parallel_resources()
            if progress is not None:
                progress.log(
                    f"Warning: streaming workers failed ({exc}); retrying with the primary session"
                )

    sources: list[Path] = []
    asm_files: list[Path] = []
    summaries: list[Path] = []
    failures: list[FunctionFailure] = []
    ranges: list[FunctionRange] = []
    total = sum(len(cluster.members) for cluster in clusters)

    bar_context = (
        progress.bar(total=total, desc="exporting", unit="func")
        if progress
        else nullcontext()
    )
    with bar_context as bar:
        for cluster in clusters:
            c_path = _cluster_path(src_dir, cluster, c_file_name(cluster))
            asm_path = _cluster_path(asm_dir, cluster, asm_file_name(cluster))
            summary_path = _cluster_path(
                summary_dir, cluster, summary_file_name(cluster)
            )
            c_path.parent.mkdir(parents=True, exist_ok=True)
            asm_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            include_path = Path(
                os.path.relpath(include_dir / header_name, c_path.parent)
            ).as_posix()
            rendered: dict[int, RenderedFunction] = {}
            for address in cluster.members:
                rendered[address] = render_with_checkpoint(
                    analyzer,
                    analysis,
                    address,
                    names,
                    checkpoint=checkpoint,
                    progress=progress,
                )
                if bar is not None:
                    bar.update(1)
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
            write_text_atomic(c_path, block["c"])
            write_text_atomic(asm_path, block["asm"])
            write_text_atomic(summary_path, block["summary"])
            sources.append(c_path.resolve())
            asm_files.append(asm_path.resolve())
            summaries.append(summary_path.resolve())
            ranges.extend(block["ranges"])
            failures.extend(block["failures"])
            release_memory = getattr(analyzer, "release_render_memory", None)
            if callable(release_memory):
                release_memory()

    return {
        "sources": sources,
        "asm": asm_files,
        "summaries": summaries,
        "failures": failures,
        "ranges": ranges,
    }


def render_and_write_source_tree_parallel(
    *,
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    clusters: list[Cluster],
    src_dir: Path,
    asm_dir: Path,
    summary_dir: Path,
    include_dir: Path,
    header_name: str,
    names: NameBook,
    prototypes: dict[int, str],
    progress: Progress | None,
    worker_count: int,
    checkpoint: CheckpointStore | None = None,
) -> dict[str, Any]:
    total = sum(len(cluster.members) for cluster in clusters)
    if progress is not None:
        progress.log(f"Opening {worker_count} streaming workers for {total} functions")
        progress.log("Preparing IDA worker database copies")
    analyzer.prepare_parallel_workers()
    spec = _worker_spec(analyzer, copy_db=worker_count > 1)
    if progress is not None:
        progress.log("Closing parent backend session before workers open")
    analyzer.release_parallel_resources()
    if progress is not None:
        progress.log(
            "Starting streaming worker processes; opening IDA databases may take a while"
        )

    sources: list[Path] = []
    asm_files: list[Path] = []
    summaries: list[Path] = []
    failures: list[FunctionFailure] = []
    ranges: list[FunctionRange] = []

    ctx = multiprocessing.get_context("spawn")
    bar_context = (
        progress.bar(total=total, desc="exporting", unit="func")
        if progress
        else nullcontext()
    )
    with bar_context as bar:
        with ProcessPoolExecutor(
            max_workers=worker_count,
            mp_context=ctx,
            initializer=_init_worker,
            initargs=(spec, analysis, names),
        ) as executor:
            _wait_for_streaming_workers(
                executor=executor,
                worker_count=worker_count,
                progress=progress,
            )
            for cluster in clusters:
                rendered: dict[int, RenderedFunction] = {}
                missing: list[int] = []
                for address in cluster.members:
                    cached = (
                        checkpoint.load(address) if checkpoint is not None else None
                    )
                    if cached is None:
                        missing.append(address)
                        if progress is not None:
                            routine = analysis.routines[address]
                            progress.file_log(f"export {routine.name} 0x{address:x}")
                    else:
                        rendered[address] = cached
                        if progress is not None:
                            routine = analysis.routines[address]
                            progress.file_log(
                                f"export {routine.name} 0x{address:x} cached"
                            )
                        if bar is not None:
                            bar.update(1)
                futures = {
                    executor.submit(_render_in_worker, address): address
                    for address in missing
                }
                for future in as_completed(futures):
                    result_address, result = future.result()
                    rendered[result_address] = result
                    record_render_result(
                        result,
                        analysis,
                        checkpoint=checkpoint,
                        progress=progress,
                    )
                    if bar is not None:
                        bar.update(1)
                block = _write_rendered_cluster(
                    analysis=analysis,
                    cluster=cluster,
                    src_dir=src_dir,
                    asm_dir=asm_dir,
                    summary_dir=summary_dir,
                    include_dir=include_dir,
                    header_name=header_name,
                    rendered=rendered,
                    prototypes=prototypes,
                )
                sources.append(block["source"])
                asm_files.append(block["asm_file"])
                summaries.append(block["summary_file"])
                ranges.extend(block["ranges"])
                failures.extend(block["failures"])

    return {
        "sources": sources,
        "asm": asm_files,
        "summaries": summaries,
        "failures": failures,
        "ranges": ranges,
    }


def _wait_for_streaming_workers(
    *,
    executor: ProcessPoolExecutor,
    worker_count: int,
    progress: Progress | None,
) -> None:
    ready_futures = [executor.submit(_worker_ready) for _ in range(worker_count)]
    bar_context = (
        progress.bar(total=worker_count, desc="opening workers", unit="worker")
        if progress
        else nullcontext()
    )
    pids: set[int] = set()
    with bar_context as bar:
        for future in as_completed(ready_futures):
            pids.add(future.result())
            if bar is not None:
                bar.update(1)
    if progress is not None:
        pid_text = ", ".join(str(pid) for pid in sorted(pids))
        progress.log(f"Streaming workers ready: {pid_text}")


def _write_rendered_cluster(
    *,
    analysis: ProgramAnalysis,
    cluster: Cluster,
    src_dir: Path,
    asm_dir: Path,
    summary_dir: Path,
    include_dir: Path,
    header_name: str,
    rendered: dict[int, RenderedFunction],
    prototypes: dict[int, str],
) -> dict[str, Any]:
    c_path = _cluster_path(src_dir, cluster, c_file_name(cluster))
    asm_path = _cluster_path(asm_dir, cluster, asm_file_name(cluster))
    summary_path = _cluster_path(summary_dir, cluster, summary_file_name(cluster))
    c_path.parent.mkdir(parents=True, exist_ok=True)
    asm_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    include_path = Path(
        os.path.relpath(include_dir / header_name, c_path.parent)
    ).as_posix()
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
    write_text_atomic(c_path, block["c"])
    write_text_atomic(asm_path, block["asm"])
    write_text_atomic(summary_path, block["summary"])
    return {
        "source": c_path.resolve(),
        "asm_file": asm_path.resolve(),
        "summary_file": summary_path.resolve(),
        "ranges": block["ranges"],
        "failures": block["failures"],
    }


def write_tree_sources(
    *,
    analysis: ProgramAnalysis,
    clusters: list[Cluster],
    src_dir: Path,
    raw_dir: Path,
    include_dir: Path,
    rendered: dict[int, RenderedFunction],
    raw_ranges: list[FunctionRange],
    progress: Progress | None = None,
    worker_count: int = 1,
) -> dict[str, Any]:
    sources: list[Path] = []
    ranges: list[FunctionRange] = []
    raw_range_by_address = {item.address: item for item in raw_ranges}
    tree_header = include_dir / "tocode_tree.h"
    write_text_atomic(tree_header, build_tree_header(analysis))
    jobs = build_tree_jobs(
        clusters=clusters,
        src_dir=src_dir,
        raw_dir=raw_dir,
        tree_header=tree_header,
    )

    worker_count = max(1, min(worker_count, len(jobs) or 1))
    if worker_count > 1:
        try:
            return write_tree_sources_parallel(
                analysis=analysis,
                jobs=jobs,
                rendered=rendered,
                raw_ranges=raw_range_by_address,
                progress=progress,
                worker_count=worker_count,
            )
        except Exception as exc:  # noqa: BLE001
            if progress:
                progress.log(
                    f"Warning: tree writer workers failed ({exc}); retrying in-process"
                )

    bar_context = (
        progress.bar(total=len(jobs), desc="writing tree", unit="cluster")
        if progress
        else nullcontext()
    )
    with bar_context as bar:
        for job in jobs:
            block = build_tree_cluster_file(
                analysis=analysis,
                cluster=job.cluster,
                include_path=job.include_path,
                tree_path=job.tree_path,
                raw_path=job.raw_path,
                rendered=rendered,
                raw_ranges=raw_range_by_address,
            )
            write_text_atomic(job.tree_path, block["c"])
            sources.append(job.tree_path.resolve())
            ranges.extend(block["ranges"])
            if bar is not None:
                bar.update(1)

    return {"sources": sources, "ranges": ranges}


def build_tree_jobs(
    *,
    clusters: list[Cluster],
    src_dir: Path,
    raw_dir: Path,
    tree_header: Path,
) -> list[TreeBuildJob]:
    jobs: list[TreeBuildJob] = []
    for index, cluster in enumerate(clusters):
        tree_path = _cluster_path(src_dir, cluster, c_file_name(cluster))
        raw_path = _cluster_path(raw_dir, cluster, c_file_name(cluster))
        tree_path.parent.mkdir(parents=True, exist_ok=True)
        include_path = Path(os.path.relpath(tree_header, tree_path.parent)).as_posix()
        jobs.append(
            TreeBuildJob(
                index=index,
                cluster=cluster,
                tree_path=tree_path,
                raw_path=raw_path,
                include_path=include_path,
            )
        )
    return jobs


def write_tree_sources_parallel(
    *,
    analysis: ProgramAnalysis,
    jobs: list[TreeBuildJob],
    rendered: dict[int, RenderedFunction],
    raw_ranges: dict[int, FunctionRange],
    progress: Progress | None,
    worker_count: int,
) -> dict[str, Any]:
    results: dict[int, tuple[Path, str, list[FunctionRange]]] = {}
    ctx = multiprocessing.get_context("spawn")
    bar_context = (
        progress.bar(total=len(jobs), desc="writing tree", unit="cluster")
        if progress
        else nullcontext()
    )
    with bar_context as bar:
        with ProcessPoolExecutor(
            max_workers=worker_count,
            mp_context=ctx,
            initializer=_init_tree_worker,
            initargs=(analysis, rendered, raw_ranges),
        ) as executor:
            futures = {
                executor.submit(_build_tree_in_worker, job): job.index for job in jobs
            }
            for future in as_completed(futures):
                index, tree_path, c_text, cluster_ranges = future.result()
                results[index] = (tree_path, c_text, cluster_ranges)
                if bar is not None:
                    bar.update(1)

    sources: list[Path] = []
    ranges: list[FunctionRange] = []
    for index in sorted(results):
        tree_path, c_text, cluster_ranges = results[index]
        write_text_atomic(tree_path, c_text)
        sources.append(tree_path.resolve())
        ranges.extend(cluster_ranges)
    return {"sources": sources, "ranges": ranges}


def _init_tree_worker(
    analysis: ProgramAnalysis,
    rendered: dict[int, RenderedFunction],
    raw_ranges: dict[int, FunctionRange],
) -> None:
    global _TREE_WORKER_ANALYSIS, _TREE_WORKER_RENDERED, _TREE_WORKER_RAW_RANGES
    _TREE_WORKER_ANALYSIS = analysis
    _TREE_WORKER_RENDERED = rendered
    _TREE_WORKER_RAW_RANGES = raw_ranges


def _build_tree_in_worker(
    job: TreeBuildJob,
) -> tuple[int, Path, str, list[FunctionRange]]:
    if (
        _TREE_WORKER_ANALYSIS is None
        or _TREE_WORKER_RENDERED is None
        or _TREE_WORKER_RAW_RANGES is None
    ):
        raise RuntimeError("tree writer worker was not initialized")
    block = build_tree_cluster_file(
        analysis=_TREE_WORKER_ANALYSIS,
        cluster=job.cluster,
        include_path=job.include_path,
        tree_path=job.tree_path,
        raw_path=job.raw_path,
        rendered=_TREE_WORKER_RENDERED,
        raw_ranges=_TREE_WORKER_RAW_RANGES,
    )
    return job.index, job.tree_path, block["c"], block["ranges"]


def build_tree_cluster_file(
    *,
    analysis: ProgramAnalysis,
    cluster: Cluster,
    include_path: str,
    tree_path: Path,
    raw_path: Path,
    rendered: dict[int, RenderedFunction],
    raw_ranges: dict[int, FunctionRange],
) -> dict[str, Any]:
    c_parts = [_tree_preamble(cluster, include_path)]
    c_line = next_line(c_parts[0])
    ranges: list[FunctionRange] = []
    tree_resolved = tree_path.resolve()
    raw_resolved = raw_path.resolve()

    for address in cluster.members:
        routine = analysis.routines[address]
        item = rendered[address]
        tree_body = tree_safe_function(item.c_text, fallback_name=item.c_name)
        metadata = _tree_function_metadata(routine=routine, raw_path=raw_path)
        body = metadata + tree_body
        start = c_line
        end = start + line_count(body) - 1
        raw_range = raw_ranges.get(address)
        c_parts.append(body.rstrip() + "\n\n")
        ranges.append(
            FunctionRange(
                address=address,
                name=routine.name,
                c_file=tree_resolved,
                c_line_start=start,
                c_line_end=end,
                asm_file=raw_range.asm_file
                if raw_range is not None
                else raw_resolved.with_suffix(".asm"),
                asm_line_start=raw_range.asm_line_start if raw_range is not None else 1,
                asm_line_end=raw_range.asm_line_end if raw_range is not None else 1,
                arg_count=raw_range.arg_count if raw_range is not None else None,
                local_count=raw_range.local_count if raw_range is not None else None,
            )
        )
        c_line = end + 2

    return {"c": "".join(c_parts), "ranges": ranges}


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
        summary_parts.append(
            _summary_function(routine, summary_path, item.summary_text).rstrip()
            + "\n\n"
        )
        arg_count, local_count = _counts_from_summary(item.summary_text)
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
                arg_count=arg_count,
                local_count=local_count,
            )
        )
        c_line = c_end + 2
        asm_line = asm_end + 2

    return {
        "c": "".join(c_parts),
        "asm": "".join(asm_parts),
        "summary": "".join(summary_parts),
        "ranges": ranges,
        "failures": failures,
    }


def _counts_from_summary(summary_text: str) -> tuple[int | None, int | None]:
    """Recover the argument and local counts the backend reported in a summary.

    The decompiler computes these while rendering, so reading them back from the
    summary avoids re-deriving them (which, for IDA, would mean decompiling every
    function a second time during inventory). Returns ``(None, None)`` when the
    summary does not carry the fields, so callers can fall back to inventory data.
    """
    args: int | None = None
    locals_: int | None = None
    for line in summary_text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        label = key.strip()
        if label == "args":
            args = _safe_int(value)
        elif label == "locals":
            locals_ = _safe_int(value)
    return args, locals_


def _safe_int(value: str) -> int | None:
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return None


def render_with_checkpoint(
    session_like,
    analysis: ProgramAnalysis,
    address: int,
    names: NameBook,
    *,
    checkpoint: CheckpointStore | None,
    progress: Progress | None,
) -> RenderedFunction:
    routine = analysis.routines[address]
    cached = checkpoint.load(address) if checkpoint is not None else None
    if cached is not None:
        if progress is not None:
            progress.file_log(f"export {routine.name} 0x{address:x} cached")
        return cached
    if progress is not None:
        progress.file_log(f"export {routine.name} 0x{address:x}")
    rendered = render_one(session_like, analysis, routine, names)
    record_render_result(
        rendered,
        analysis,
        checkpoint=checkpoint,
        progress=progress,
    )
    return rendered


def record_render_result(
    rendered: RenderedFunction,
    analysis: ProgramAnalysis,
    *,
    checkpoint: CheckpointStore | None,
    progress: Progress | None,
) -> None:
    if checkpoint is not None:
        checkpoint.save(rendered)
    if progress is None:
        return
    routine = analysis.routines.get(rendered.address)
    name = routine.name if routine is not None else rendered.c_name
    prefix = f"export {name} 0x{rendered.address:x}"
    if rendered.failure is None:
        progress.file_log(f"{prefix} done")
    else:
        progress.file_log(f"{prefix} failed: {rendered.failure.message}")


def render_functions(
    *,
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    addresses: list[int],
    names: NameBook,
    progress: Progress,
    worker_count: int,
    checkpoint: CheckpointStore | None = None,
) -> dict[int, RenderedFunction]:
    if worker_count <= 1 or _all_cached(checkpoint, addresses):
        return _render_serial(
            analyzer, analysis, addresses, names, progress, checkpoint=checkpoint
        )
    try:
        return _render_parallel(
            analyzer,
            analysis,
            addresses,
            names,
            progress,
            worker_count,
            checkpoint=checkpoint,
        )
    except Exception as exc:  # noqa: BLE001
        analyzer.restore_parallel_resources()
        progress.log(
            f"Warning: parallel export failed ({exc}); retrying with the primary session"
        )
        return _render_serial(
            analyzer, analysis, addresses, names, progress, checkpoint=checkpoint
        )


def _render_serial(
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    addresses: list[int],
    names: NameBook,
    progress: Progress,
    *,
    checkpoint: CheckpointStore | None = None,
) -> dict[int, RenderedFunction]:
    output: dict[int, RenderedFunction] = {}
    with progress.bar(total=len(addresses), desc="exporting", unit="func") as bar:
        for address in addresses:
            output[address] = render_with_checkpoint(
                analyzer,
                analysis,
                address,
                names,
                checkpoint=checkpoint,
                progress=progress,
            )
            bar.update(1)
    return output


def _render_parallel(
    analyzer: BinaryAnalyzer,
    analysis: ProgramAnalysis,
    addresses: list[int],
    names: NameBook,
    progress: Progress,
    worker_count: int,
    *,
    checkpoint: CheckpointStore | None = None,
) -> dict[int, RenderedFunction]:
    progress.log(f"Opening {worker_count} workers for {len(addresses)} functions")
    analyzer.prepare_parallel_workers()
    spec = _worker_spec(analyzer, copy_db=worker_count > 1)
    analyzer.release_parallel_resources()
    output: dict[int, RenderedFunction] = {}
    missing: list[int] = []
    for address in addresses:
        cached = checkpoint.load(address) if checkpoint is not None else None
        if cached is None:
            missing.append(address)
            routine = analysis.routines[address]
            progress.file_log(f"export {routine.name} 0x{address:x}")
        else:
            output[address] = cached
            routine = analysis.routines[address]
            progress.file_log(f"export {routine.name} 0x{address:x} cached")
    pending = set(missing)
    with progress.bar(total=len(addresses), desc="exporting", unit="func") as bar:
        for _address in output:
            bar.update(1)
        try:
            ctx = multiprocessing.get_context("spawn")
            with ProcessPoolExecutor(
                max_workers=worker_count,
                mp_context=ctx,
                initializer=_init_worker,
                initargs=(spec, analysis, names),
            ) as executor:
                futures = {
                    executor.submit(_render_in_worker, address): address
                    for address in missing
                }
                for future in as_completed(futures):
                    address = futures[future]
                    result_address, result = future.result()
                    output[result_address] = result
                    pending.discard(address)
                    record_render_result(
                        result,
                        analysis,
                        checkpoint=checkpoint,
                        progress=progress,
                    )
                    bar.update(1)
        except BrokenProcessPool as exc:
            progress.log(
                f"Warning: worker process exited unexpectedly ({exc}); retrying remaining functions"
            )
        for address in sorted(pending, key=addresses.index):
            output[address] = _render_isolated(spec, analysis, address, names)
            record_render_result(
                output[address],
                analysis,
                checkpoint=checkpoint,
                progress=progress,
            )
            bar.update(1)
    return output


def _worker_spec(analyzer: BinaryAnalyzer, *, copy_db: bool = True) -> WorkerSpec:
    session = analyzer.session
    return WorkerSpec(
        backend=analyzer.backend_name,
        binary=analyzer.binary,
        analysis_command=getattr(session, "analysis_command", None),
        idadir=getattr(session, "idadir", None),
        ida_domain_path=getattr(session, "ida_domain_path", None),
        db_path=_session_database_path(session),
        copy_db=copy_db,
    )


def _worker_database_size_mb(analyzer: BinaryAnalyzer) -> int | None:
    """On-disk size (MiB) of the database each worker will load, if known.

    Used to size the per-worker memory budget so that a very large database
    (such as a kernel `.i64`) does not spawn more workers than RAM can hold.
    """
    session = analyzer.session
    candidate = getattr(session, "_cache_db", None)
    if candidate is None:
        binary = getattr(session, "binary", None)
        if binary is not None and is_ida_database(Path(binary)):
            candidate = binary
    if candidate is None:
        return None
    try:
        size = Path(candidate).stat().st_size
    except OSError:
        return None
    return max(1, size // (1024 * 1024))


def _session_database_path(session: object) -> Path | None:
    database_path = getattr(session, "database_path", None)
    if callable(database_path):
        return database_path()
    return getattr(session, "_cache_db", None)


def _init_worker(spec: WorkerSpec, analysis: ProgramAnalysis, names: NameBook) -> None:
    global _WORKER_SESSION, _WORKER_ANALYSIS, _WORKER_NAMES
    _WORKER_SESSION = _open_worker(spec)
    _WORKER_ANALYSIS = analysis
    _WORKER_NAMES = names
    atexit.register(_close_worker)


def _open_worker(spec: WorkerSpec):
    session: Any
    if spec.backend == "ida":
        # When a single worker renders, it can open the prepared database in place
        # instead of duplicating it. Copying a large database (e.g. a kernel `.i64`)
        # is only needed so that concurrent workers do not share one IDA lock, and a
        # copy on RAM-backed temp storage would otherwise exhaust memory.
        if spec.db_path is not None and spec.copy_db:
            worker_db = _copy_worker_database(spec.db_path)
            open_db: Path | None = worker_db
        else:
            worker_db = None
            open_db = spec.db_path
        try:
            session = IdaSession(
                spec.binary,
                idadir=spec.idadir,
                ida_domain_path=spec.ida_domain_path,
                db_path=open_db,
                needs_analysis=False if open_db is not None else None,
            )
        except Exception:
            if worker_db is not None:
                worker_db.unlink(missing_ok=True)
            raise
        if worker_db is not None:
            setattr(session, "_tocode_worker_db_copy", worker_db)
    elif spec.backend == "r2":
        session = R2Session(
            spec.binary, analysis_command=spec.analysis_command or "aaa"
        )
        session.analyze()
    elif spec.backend == "angr":
        # Imported lazily so non-angr exports never pay angr's slow, noisy
        # native-extension import at startup.
        from .backends.angr import AngrSession

        session = AngrSession(spec.binary)
        session.analyze()
    else:
        raise RuntimeError(f"unsupported backend for worker: {spec.backend}")
    session.ensure_decompiler()
    return session


def _copy_worker_database(db_path: Path) -> Path:
    # Place worker copies on durable, on-disk storage rather than the default
    # system temp dir, which is frequently RAM-backed (tmpfs). Copying a
    # multi-gigabyte IDA database into tmpfs would pin that memory and OOM-kill
    # the export. The on-disk page cache used here is reclaimable under pressure.
    copy_dir = _worker_copy_dir(db_path)
    fd, name = tempfile.mkstemp(
        prefix="tocode-ida-worker-", suffix=db_path.suffix, dir=str(copy_dir)
    )
    os.close(fd)
    target = Path(name)
    shutil.copy2(db_path, target)
    return target


def _worker_copy_dir(db_path: Path) -> Path:
    explicit = os.environ.get("TOCODE_WORKER_TMP_DIR", "").strip()
    if explicit:
        candidate = Path(explicit).expanduser()
    else:
        candidate = _ida_cache_root() / "workers"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except OSError:
        # Fall back to the directory that already holds the source database; it is
        # on the same (on-disk) filesystem as the data we are copying.
        return db_path.parent


def _close_worker() -> None:
    global _WORKER_SESSION
    if _WORKER_SESSION is not None:
        worker_db = getattr(_WORKER_SESSION, "_tocode_worker_db_copy", None)
        try:
            _WORKER_SESSION.close()
        finally:
            if worker_db is not None:
                Path(worker_db).unlink(missing_ok=True)
            _WORKER_SESSION = None


def _render_in_worker(address: int) -> tuple[int, RenderedFunction]:
    if _WORKER_SESSION is None or _WORKER_ANALYSIS is None or _WORKER_NAMES is None:
        raise RuntimeError("render worker was not initialized")
    routine = _WORKER_ANALYSIS.routines[address]
    result = render_one(_WORKER_SESSION, _WORKER_ANALYSIS, routine, _WORKER_NAMES)
    release_memory = getattr(_WORKER_SESSION, "release_render_memory", None)
    if callable(release_memory):
        release_memory()
    return address, result


def _worker_ready() -> int:
    if _WORKER_SESSION is None:
        raise RuntimeError("render worker was not initialized")
    return os.getpid()


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


def render_one(
    session_like, analysis: ProgramAnalysis, routine: Routine, names: NameBook
) -> RenderedFunction:
    try:
        disasm = session_like.disasm(routine.address).rstrip()
        summary = session_like.function_summary(routine.address).rstrip()
        if routine.thunk:
            prototype = fallback_prototype(routine, analysis.binary.pointer_size, names)
            c_text = asm_stub(routine, prototype)
        else:
            source = normalize_source(session_like.decompile(routine.address), names)
            if not source:
                raise RuntimeError("decompiler returned empty output")
            prototype = extract_prototype(source) or fallback_prototype(
                routine, analysis.binary.pointer_size, names
            )
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
    function_name = names.function_name(routine.address, routine.name)
    parsed = (
        parse_signature(signature, fallback_name=function_name) if signature else None
    )
    if parsed is not None:
        return parsed
    default = "undefined8" if pointer_size >= 8 else "undefined4"
    return f"{default} {function_name}()"


def import_prototype(name: str, pointer_size: int) -> str:
    default = "undefined8" if pointer_size >= 8 else "undefined4"
    return f"{default} {clean_c_identifier(name)}()"


def parse_signature(signature: str, *, fallback_name: str | None = None) -> str | None:
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
    params = after.rsplit(")", 1)[0].strip()
    if not ret and fallback_name is not None:
        ret = clean_c_identifier(raw_name)
        name = clean_c_identifier(fallback_name)
    else:
        ret = (ret + " " + pointer_prefix).strip() if ret else "undefined8"
    return f"{ret} {name}({params})" if params else f"{ret} {name}()"


def extract_prototype(source: str) -> str | None:
    before, sep, _after = source.partition("{")
    if not sep:
        return None
    text = " ".join(
        line.strip() for line in before.splitlines() if line.strip()
    ).strip()
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
    return "\n".join(
        [
            f"; Function: {routine.name} @ 0x{routine.address:x}",
            disasm.strip() or "; <no disassembly available>",
        ]
    )


def tree_safe_function(source: str, *, fallback_name: str) -> str:
    text = source.strip()
    if "{" not in text:
        return f"tocode_word {clean_c_identifier(fallback_name)}(void)\n{{\n    return 0;\n}}"

    replacements = [
        ("unsigned __int128", "unsigned long long"),
        ("signed __int128", "long long"),
        ("__int128", "long long"),
        ("unsigned __int64", "unsigned long long"),
        ("signed __int64", "long long"),
        ("__int64", "long long"),
        ("unsigned __int32", "unsigned int"),
        ("signed __int32", "int"),
        ("__int32", "int"),
        ("unsigned __int16", "unsigned short"),
        ("signed __int16", "short"),
        ("__int16", "short"),
        ("unsigned __int8", "unsigned char"),
        ("signed __int8", "signed char"),
        ("__int8", "char"),
        ("_BOOL1", "bool"),
        ("_BOOL2", "bool"),
        ("_BOOL4", "bool"),
        ("_BYTE", "uint8_t"),
        ("_WORD", "uint16_t"),
        ("_DWORD", "uint32_t"),
        ("_QWORD", "uint64_t"),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    text = TREE_CALLING_CONVENTION_RX.sub("", text)
    text = TREE_SPOILS_RX.sub("", text)
    text = re.sub(r"\b__(?:pure|hidden|unused|noreturn)\b", "", text)
    text = re.sub(r"\b([0-9]+)i64\b", r"\1LL", text)
    text = re.sub(r"\b(0x[0-9A-Fa-f]+)i64\b", r"\1LL", text)
    text = re.sub(r"\b__PAIR\d+__\s*\(", "tocode_pair(", text)
    text = TREE_REGISTER_RX.sub(_tree_register_name, text)
    text = TREE_VERSIONED_IMPORT_RX.sub(r"\1", text)
    text = re.sub(r"\bnullptr\b", "NULL", text)
    text = TREE_SPACE_RX.sub(" ", text)
    return text.strip()


def _tree_register_name(match: re.Match[str]) -> str:
    return "_" + clean_c_identifier(match.group(1))


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

    # Cheap cleanups of stale artifacts; not worth a progress step.
    if not context.tree_enabled:
        stale_tree_index = root / "function-index-tree.json"
        if stale_tree_index.exists():
            stale_tree_index.unlink()
        stale_tree_header = _need(context.include_dir) / "tocode_tree.h"
        if stale_tree_header.exists():
            stale_tree_header.unlink()
    stale = root / ("function-index-" + "ll" + "m.json")
    if stale.exists():
        stale.unlink()

    shared: dict[str, Any] = {}

    def write_header() -> None:
        write_text_atomic(header, build_header(analysis, context.prototypes, names))

    def write_variables() -> None:
        context.data_variable_count = export_variables(
            analysis, root, entropy=context.entropy_enabled
        )

    def write_indexes() -> None:
        context.function_index = write_function_index(root, context.raw_ranges)
        context.tree_index = (
            write_function_index(
                root, context.tree_ranges, file_name="function-index-tree.json"
            )
            if context.tree_enabled
            else None
        )

    def write_functions() -> None:
        write_json(
            root / "functions.json",
            functions_json(
                analysis,
                context.raw_ranges,
                context.prototypes,
                names.functions,
                tree_ranges=context.tree_ranges,
            ),
        )

    def write_reachable() -> None:
        reachable = reachable_json(analysis)
        shared["reachable"] = reachable
        write_json(root / "reachable.json", reachable)

    def write_triage() -> None:
        write_json(
            root / "triage.json",
            triage_json(
                analysis,
                context.clusters,
                context.raw_ranges,
                shared["reachable"],
                entropy=context.entropy_enabled,
            ),
        )

    def publish_database() -> None:
        context.ida_database = publish_backend_database(context)

    def write_docs() -> None:
        write_text_atomic(
            root / "AGENTS.md",
            build_export_agents(
                analysis, context.header_name, tree_enabled=context.tree_enabled
            ),
        )
        write_text_atomic(root / "CLAUDE.md", "@./AGENTS.md\n")

    steps: list[tuple[str, Any]] = [
        ("header", write_header),
        ("data variables", write_variables),
        ("function index", write_indexes),
        (
            "sections.json",
            lambda: write_json(
                root / "sections.json",
                sections_json(analysis, entropy=context.entropy_enabled),
            ),
        ),
        (
            "strings.json",
            lambda: write_json(root / "strings.json", strings_json(analysis)),
        ),
        (
            "imports.json",
            lambda: write_json(root / "imports.json", imports_json(analysis)),
        ),
        (
            "exports.json",
            lambda: write_json(root / "exports.json", exports_json(analysis)),
        ),
        (
            "relocations.json",
            lambda: write_json(root / "relocations.json", relocations_json(analysis)),
        ),
        ("functions.json", write_functions),
        ("reachable.json", write_reachable),
        (
            "cluster-graph.json",
            lambda: write_json(
                root / "cluster-graph.json",
                cluster_graph_json(analysis, context.clusters, context.raw_ranges),
            ),
        ),
        ("triage.json", write_triage),
        ("backend database", publish_database),
        ("project.json", lambda: write_project_json(context)),
        ("AGENTS.md", write_docs),
        ("export-manifest.json", lambda: _set_manifest(context)),
    ]

    context.progress.log(f"Writing metadata and indexes ({len(steps)} steps)")
    with context.progress.bar(total=len(steps), desc="metadata", unit="step") as bar:
        for label, run in steps:
            _set_bar_description(bar, f"metadata: {label}")
            run()
            bar.update(1)


def _set_manifest(context: ExportContext) -> None:
    context.manifest = write_manifest(context)


def _set_bar_description(bar: Any, text: str) -> None:
    setter = getattr(bar, "set_description", None)
    if not callable(setter):
        return
    try:
        setter(text, refresh=False)
    except Exception:  # noqa: BLE001
        pass


def publish_backend_database(context: ExportContext) -> Path | None:
    session = getattr(context.analyzer, "session", None)
    database_path = getattr(session, "database_path", None)
    if not callable(database_path):
        return None
    source = database_path()
    if source is None or not source.is_file():
        return None
    analysis = _need(context.analysis)
    root = _need(context.root)
    suffix = source.suffix.lower()
    target = root / f"{clean_path_component(analysis.binary.path.stem)}{suffix}"
    if source.resolve() != target.resolve():
        _copy_file_with_progress(
            source, target, context.progress, desc="saving database"
        )
    context.progress.log(f"Saved IDA database to {target}")
    return target.resolve()


def _copy_file_with_progress(
    source: Path, target: Path, progress: Progress, *, desc: str
) -> None:
    # A database (kernel `.i64`) can be multiple gigabytes; copy in chunks with a
    # byte progress bar so the export does not appear stuck during the copy.
    try:
        size = source.stat().st_size
    except OSError:
        size = 0
    chunk_size = 8 * 1024 * 1024
    with (
        progress.bar(total=size, desc=desc, unit="B", unit_scale=True) as bar,
        source.open("rb") as src,
        target.open("wb") as dst,
    ):
        while True:
            buffer = src.read(chunk_size)
            if not buffer:
                break
            dst.write(buffer)
            bar.update(len(buffer))
    shutil.copystat(source, target)


def build_header(
    analysis: ProgramAnalysis, prototypes: dict[int, str], names: NameBook
) -> str:
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


def build_tree_header(analysis: ProgramAnalysis) -> str:
    default_return = "uint64_t" if analysis.binary.pointer_size >= 8 else "uint32_t"
    lines = [
        "#pragma once",
        "",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#include <string.h>",
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
        f"typedef {default_return} tocode_word;",
        "",
        "extern uintptr_t tocode_unknown;",
        "",
    ]
    return "\n".join(lines)


def write_function_index(
    root: Path, ranges: list[FunctionRange], *, file_name: str = "function-index.json"
) -> Path:
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
            "tree_src_dir": str(context.tree_dir.resolve())
            if context.tree_dir is not None
            else None,
            "include_dir": str(_need(context.include_dir).resolve()),
            "data_dir": str(_need(context.data_dir).resolve()),
            "header": str(_need(context.header_path).resolve()),
            "agents": str((root / "AGENTS.md").resolve()),
            "claude": str((root / "CLAUDE.md").resolve()),
            "log": str((root / "tocode.log").resolve()),
            "ida_database": str(context.ida_database)
            if context.ida_database is not None
            else None,
            "source_files": [str(item) for item in context.raw_sources],
            "tree_source_files": [str(item) for item in context.tree_sources],
            "summary_files": [str(item) for item in context.summary_files],
            "asm_files": [str(item) for item in context.asm_files],
            "function_index": str(_need(context.function_index).resolve()),
            "tree_function_index": str(context.tree_index.resolve())
            if context.tree_index is not None
            else None,
            "function_count": len(context.raw_ranges),
            "cluster_count": len(context.clusters),
            "failure_count": len(context.failures),
            "requested_worker_count": context.requested_jobs
            if context.requested_jobs is not None
            else "auto",
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
            "ida_database": str(context.ida_database)
            if context.ida_database is not None
            else None,
            "source_files": [str(item) for item in context.raw_sources],
            "raw_source_files": [str(item) for item in context.raw_sources],
            "tree_source_files": [str(item) for item in context.tree_sources],
            "asm_files": [str(item) for item in context.asm_files],
            "summary_files": [str(item) for item in context.summary_files],
            "function_index": str(_need(context.function_index).resolve()),
            "tree_function_index": str(context.tree_index.resolve())
            if context.tree_index is not None
            else None,
            "raw_src_dir": str(_need(context.raw_dir).resolve()),
            "tree_src_dir": str(context.tree_dir.resolve())
            if context.tree_dir is not None
            else None,
            "cluster_count": len(context.clusters),
            "function_count": len(context.raw_ranges),
            "data_variable_count": context.data_variable_count,
            "failure_count": len(context.failures),
            "requested_worker_count": context.requested_jobs
            if context.requested_jobs is not None
            else "auto",
            "worker_count": context.worker_count,
            "parallel_mode": context.render_mode,
            "agents": str((root / "AGENTS.md").resolve()),
            "claude": str((root / "CLAUDE.md").resolve()),
            "log": str((root / "tocode.log").resolve()),
            "triage": str((root / "triage.json").resolve()),
            "imports": str((root / "imports.json").resolve()),
            "exports": str((root / "exports.json").resolve()),
            "reachable": str((root / "reachable.json").resolve()),
            "cluster_graph": str((root / "cluster-graph.json").resolve()),
            "variables_interesting": str(
                (root / "data" / "variables_interesting.json").resolve()
            ),
            "failures": [
                {
                    "address": f"0x{item.address:x}",
                    "name": item.name,
                    "error": item.message,
                }
                for item in context.failures
            ],
        },
    )
    return path


def build_export_agents(
    analysis: ProgramAnalysis, header_name: str, *, tree_enabled: bool = True
) -> str:
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
        "Reverse the binary, answer user questions, or serve as an oracle/helper to the user regarding this recovered source code.",
        "Write a report only when the user asks for one; otherwise keep findings focused on the question or task at hand.",
        "Do not refactor or modify the generated export unless the user explicitly asks for edits.",
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
        "- `triage.json`: first-read summary with entry clusters, sections, counts, and strings of interest.",
        "- `imports.json` and `exports.json`: structured import/export tables.",
        "- `reachable.json`: entrypoint/export reachability depths and unreachable count.",
        "- `cluster-graph.json`: inter-cluster call graph.",
        "- `functions.json`: per-function caller/callee relationships, prototypes, source ranges, and ASM ranges.",
        "- `function-index.json`: exact raw source and ASM line mappings for each exported function.",
        "- `sections.json`, `strings.json`, and `relocations.json`: layout and reference metadata.",
        "- `project.json` and `export-manifest.json`: top-level export paths and artifact inventory.",
        "- `tocode.log`: export, checkpoint, resume, and per-function render history.",
        "- `CLAUDE.md`: Claude entrypoint that references `AGENTS.md`.",
        "- `<binary>.i64` or `<binary>.idb`: exported IDA database when the IDA backend was used.",
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
    if tree_enabled:
        lines.insert(
            lines.index(
                "- `src/raw/*.summary`: compact function summaries grouped with each clustered source file."
            ),
            "- `src/tree/*.c`: scanner-friendly C normalized for tree-sitter and Semgrep. Use this for automated source scanning.",
        )
        lines.insert(
            lines.index(
                "- `sections.json`, `strings.json`, and `relocations.json`: layout and reference metadata."
            ),
            "- `function-index-tree.json`: exact scanner-source line mappings for each exported function.",
        )
    return "\n".join(lines)


def _build_clusters(
    analysis: ProgramAnalysis, analyzer: BinaryAnalyzer
) -> list[Cluster]:
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
        by_segment.setdefault(
            clean_path_component(routine.segment or "misc"), []
        ).append(routine.address)
    clusters: list[Cluster] = []
    for segment, members in sorted(by_segment.items()):
        members.sort()
        for index, chunk in enumerate(_chunks(members, MAX_FUNCTIONS_PER_FILE)):
            label = (
                segment
                if len(members) <= MAX_FUNCTIONS_PER_FILE
                else f"{segment}_{index}"
            )
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


def _normalize_clusters(
    analysis: ProgramAnalysis, clusters: list[Cluster]
) -> list[Cluster]:
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
                    summary=f"{cluster.summary} (part {index + 1})"
                    if cluster.summary
                    else "",
                    members=list(chunk),
                    folder=cluster.folder,
                )
            )
    return _coalesce_small(analysis, split)


def _coalesce_small(
    analysis: ProgramAnalysis, clusters: list[Cluster]
) -> list[Cluster]:
    output: list[Cluster] = []
    pending: list[int] = []
    pending_root: int | None = None
    pending_bytes = 0
    for cluster in clusters:
        size = sum(
            max(analysis.routines[address].size, 1)
            for address in cluster.members
            if address in analysis.routines
        )
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
        "/* Cluster: utils */"
        if cluster.root == SHARED_CLUSTER_ID
        else f"/* Cluster root: {cluster.label} (0x{cluster.root:x}) */",
    ]
    if cluster.summary:
        lines.append(f"/* Description: {cluster.summary} */")
    lines.extend([f'#include "{header_include}"', ""])
    return "\n".join(lines)


def _asm_preamble(cluster: Cluster) -> str:
    lines = [
        "; Generated by ToCode.",
        "; Cluster: utils"
        if cluster.root == SHARED_CLUSTER_ID
        else f"; Cluster root: {cluster.label} (0x{cluster.root:x})",
    ]
    if cluster.summary:
        lines.append(f"; Description: {cluster.summary}")
    lines.append("")
    return "\n".join(lines)


def _summary_preamble(cluster: Cluster) -> str:
    lines = [
        "; Generated by ToCode.",
        "; Cluster: utils"
        if cluster.root == SHARED_CLUSTER_ID
        else f"; Cluster root: {cluster.label} (0x{cluster.root:x})",
    ]
    if cluster.summary:
        lines.append(f"; Description: {cluster.summary}")
    lines.extend(["; Summary source: backend function summaries", ""])
    return "\n".join(lines)


def _tree_preamble(cluster: Cluster, include_path: str) -> str:
    lines = [
        "/* Generated by ToCode for C parsers and source scanners. */",
        "/* Scanner source: normalized from src/raw; use raw and ASM for final evidence. */",
        "/* Cluster: utils */"
        if cluster.root == SHARED_CLUSTER_ID
        else f"/* Cluster root: {cluster.label} (0x{cluster.root:x}) */",
    ]
    if cluster.summary:
        lines.append(f"/* Description: {cluster.summary} */")
    lines.extend([f'#include "{include_path}"', ""])
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


def _tree_function_metadata(*, routine: Routine, raw_path: Path) -> str:
    return "\n".join(
        [
            "/* tocode-tree:",
            f" * address: 0x{routine.address:x}",
            f" * original_name: {routine.name}",
            f" * raw_source: {display_path(raw_path)}",
            " */",
            "",
        ]
    )


def _root_dir(binary: Path, out_dir: Path | None) -> Path:
    if out_dir is not None:
        path = Path(out_dir).expanduser()
        return (
            path.resolve() if path.is_absolute() else (binary.parent / path).resolve()
        )
    default_root = os.environ.get("TOCODE_DEFAULT_OUT_ROOT", "").strip()
    if default_root:
        return (
            Path(default_root).expanduser().resolve() / default_output_name(binary)
        ).resolve()
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
        if (
            path.is_file()
            and path.suffix in {".c", ".asm", ".summary"}
            and path.resolve() not in allowed
        ):
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
        tree_src_dir=context.tree_dir.resolve()
        if context.tree_dir is not None
        else None,
        include_dir=_need(context.include_dir).resolve(),
        header_path=_need(context.header_path).resolve(),
        source_files=context.raw_sources,
        tree_source_files=context.tree_sources,
        asm_files=context.asm_files,
        summary_files=context.summary_files,
        function_count=len(context.raw_ranges),
        cluster_count=len(context.clusters),
        failed_functions=context.failures,
        function_index_path=_need(context.function_index).resolve(),
        tree_function_index_path=context.tree_index.resolve()
        if context.tree_index is not None
        else None,
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
