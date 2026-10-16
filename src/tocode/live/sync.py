"""``sync``: update an export from its database, like an incremental rebuild.

1. Read what the export says (functions.json, types.json, the function index,
   the file layout in ``.tocode/sync/manifest.json``).
2. Collect the database's inventory again and diff: functions added,
   removed, renamed or retyped; types changed; globals renamed.
3. Decide what to re-render: edits made in this session, the diff, and what
   they affect (callers of renamed/retyped functions, functions whose code
   mentions a changed type or an old global name).
4. Keep every existing function in its file; put a new one next to a caller
   (or callee), else in ``discovered.c``.
5. Re-render, rewrite only the files whose content changed, and rewrite the
   JSON and headers. Untouched source files keep their bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any

from ..metadata import write_text_atomic
from ..naming import SHARED_CLUSTER_ID, asm_file_name, c_file_name, summary_file_name
from ..schema import Cluster, FunctionRange, RenderedFunction
from .. import syncstate
from .worker import OpError

if TYPE_CHECKING:
    from .worker import LiveSession

DISCOVERED = "discovered"
_PREAMBLE_ROOT_RX = re.compile(r"/\* Cluster root: (.*) \(0x([0-9a-fA-F]+)\) \*/")
_PREAMBLE_DESC_RX = re.compile(r"/\* Description: (.*) \*/")
_CLUSTER_FILE_RX = re.compile(r"^cluster_([0-9a-f]{16})\.c$")


def register(live: "LiveSession") -> None:
    live.ops["sync"] = lambda args: sync(live, args)
    live.ops["export"] = lambda args: export(live, args)


# --------------------------------------------------------------------------
# What the export says
# --------------------------------------------------------------------------


@dataclass
class DiskState:
    root: Path
    functions: dict[int, dict[str, Any]] = field(default_factory=dict)
    ranges: dict[int, FunctionRange] = field(default_factory=dict)
    tree_ranges: dict[int, FunctionRange] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    variables: dict[int, str] = field(default_factory=dict)
    clusters: list[Cluster] = field(default_factory=list)
    tree: bool = False
    entropy: bool = False
    origin: str | None = None
    origin_known: bool = False
    database: str | None = None

    @classmethod
    def load(cls, root: Path) -> "DiskState":
        state = cls(root=root)
        for row in _read(root / "functions.json").get("functions", []):
            address = _hex(row.get("address"))
            if address is not None:
                state.functions[address] = row
        state.ranges = _ranges(root, root / "function-index.json", state.functions)
        state.tree_ranges = _ranges(
            root, root / "function-index-tree.json", state.functions
        )
        for row in _read(root / "types.json").get("types", []):
            if row.get("name"):
                state.types[str(row["name"])] = str(row.get("c_decl") or "")
        variables = _read(root / "data" / "variables.json").get("variables", {})
        if isinstance(variables, dict):
            for name, row in variables.items():
                address = _hex((row or {}).get("va"))
                if address is not None:
                    state.variables[address] = str(name)
        project = _read(root / "project.json")
        state.database = project.get("ida_database")
        state.tree = bool(project.get("tree_src_dir"))
        manifest = syncstate.read_manifest(root)
        if manifest is not None:
            state.clusters = [
                syncstate.cluster_from_json(item)
                for item in manifest.get("clusters", [])
            ]
            state.tree = bool(manifest.get("tree"))
            state.entropy = bool(manifest.get("entropy"))
            state.origin = manifest.get("origin")
            state.origin_known = True
        else:
            state.clusters = _clusters_from_files(root, state.ranges)
        return state


def _read(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _hex(value: Any) -> int | None:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def _local_path(root: Path, recorded: Any) -> Path:
    """A path the index recorded, re-rooted if the export has been moved."""
    path = Path(str(recorded or ""))
    try:
        path.resolve().relative_to(root.resolve())
        return path
    except ValueError:
        parts = path.parts
        if "src" in parts:
            return root.joinpath(*parts[parts.index("src") :])
        return root / path.name


def _ranges(
    root: Path, index: Path, functions: dict[int, dict[str, Any]]
) -> dict[int, FunctionRange]:
    result: dict[int, FunctionRange] = {}
    for row in _read(index).get("functions", []):
        address = _hex(row.get("address"))
        if address is None:
            continue
        c = row.get("c") or {}
        asm = row.get("asm") or {}
        info = functions.get(address, {})
        origin = row.get("origin") or {}
        result[address] = FunctionRange(
            address=address,
            name=str(row.get("name") or info.get("name") or f"sub_{address:x}"),
            c_file=_local_path(root, c.get("path")).resolve(),
            c_line_start=int(c.get("line_start") or 0),
            c_line_end=int(c.get("line_end") or 0),
            asm_file=_local_path(root, asm.get("path")).resolve(),
            asm_line_start=int(asm.get("line_start") or 0),
            asm_line_end=int(asm.get("line_end") or 0),
            arg_count=info.get("nargs"),
            local_count=info.get("nlocals"),
            origin_file=origin.get("file"),
            origin_line=origin.get("line"),
        )
    return result


def _clusters_from_files(root: Path, ranges: dict[int, FunctionRange]) -> list[Cluster]:
    """The file layout of an export made before sync manifests existed."""
    raw = (root / "src" / "raw").resolve()
    by_file: dict[Path, list[FunctionRange]] = {}
    for item in ranges.values():
        by_file.setdefault(item.c_file, []).append(item)
    clusters: list[Cluster] = []
    for path, members in sorted(by_file.items()):
        members.sort(key=lambda item: item.c_line_start)
        try:
            folder = path.parent.relative_to(raw).as_posix()
        except ValueError:
            folder = "app"
        root_address, label, summary = members[0].address, "", ""
        try:
            head = path.read_text(encoding="utf-8", errors="replace").split("\n", 6)
        except OSError:
            head = []
        for line in head:
            if (match := _PREAMBLE_ROOT_RX.match(line)) is not None:
                label, root_address = match.group(1), int(match.group(2), 16)
            elif (match := _PREAMBLE_DESC_RX.match(line)) is not None:
                summary = match.group(1)
        file_base = None
        if path.name == "utils.c":
            root_address = SHARED_CLUSTER_ID
        elif (match := _CLUSTER_FILE_RX.match(path.name)) is not None:
            root_address = int(match.group(1), 16)
        else:
            file_base = path.stem
        clusters.append(
            Cluster(
                root=root_address,
                label=label,
                summary=summary,
                members=[item.address for item in members],
                folder=folder or "app",
                file_base=file_base,
            )
        )
    return clusters


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------


def sync(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    from ..exporter import _build_clusters, render_one_with_limits

    root = live.target.export_dir
    if root is None:
        raise OpError("this session has no export folder; call `export` first")
    started = time.monotonic()
    mode = str(args.get("mode") or "auto")
    forced = {live.resolve(item) for item in args.get("addresses") or []}
    disk = DiskState.load(root)
    _forget_decompilations(live)
    live.refresh()
    analysis = live.analysis
    names = live.names

    wanted = {
        a
        for cluster in _build_clusters(analysis, live.analyzer)
        for a in cluster.members
    }
    wanted = {a for a in wanted if a in analysis.routines}
    old = set(disk.ranges)
    added = sorted(wanted - old)
    removed = sorted(old - wanted)
    common = wanted & old

    renamed: list[dict[str, Any]] = []
    retyped: list[str] = []
    dirty: set[int] = set()
    old_tokens: set[str] = set()
    for address in sorted(common):
        routine = analysis.routines[address]
        row = disk.functions.get(address, {})
        if row and row.get("name") != routine.name:
            renamed.append(
                {"address": hex(address), "old": row.get("name"), "new": routine.name}
            )
            old_tokens.add(str(row.get("name")))
            dirty.add(address)
            dirty.update(analysis.callers.get(address, []))
        if row and _shape(row) != _routine_shape(routine):
            retyped.append(hex(address))
            dirty.add(address)
            dirty.update(analysis.callers.get(address, []))

    new_types = {item.name: item.c_decl for item in analysis.types}
    types_added = sorted(set(new_types) - set(disk.types))
    types_removed = sorted(set(disk.types) - set(new_types))
    types_modified = sorted(
        name
        for name in set(new_types) & set(disk.types)
        if new_types[name] != disk.types[name]
    )
    changed_types = types_added + types_removed + types_modified
    renamed_globals = _renamed_globals(disk, analysis)
    tokens = set(changed_types) | set(renamed_globals) | old_tokens
    if tokens:
        dirty.update(_mentions(disk, tokens))
        for address in common:
            routine = analysis.routines[address]
            used = " ".join(t for _, t in routine.params + routine.local_vars)
            if any(
                re.search(rf"\b{re.escape(token)}\b", used) for token in changed_types
            ):
                dirty.add(address)

    # A function appearing or vanishing changes how its callers decompile
    # (a named call instead of a raw address, or the reverse).
    for address in added:
        dirty.update(analysis.callers.get(address, []))
    for address in removed:
        for caller in disk.functions.get(address, {}).get("callers") or []:
            if (value := _hex(caller)) is not None:
                dirty.add(value)

    dirty |= live.dirty | forced
    if mode == "full":
        dirty |= wanted
    dirty = (dirty & wanted) | set(added)

    clusters, membership_changed = _place(disk.clusters, removed, added, analysis)
    fresh: dict[int, RenderedFunction] = {}
    for address in sorted(dirty):
        fresh[address] = render_one_with_limits(
            live.session, analysis, analysis.routines[address], names
        )
    changed = sorted(
        address
        for address, item in fresh.items()
        if (old_item := syncstate.load_render(root, address)) is None
        or not _same(old_item, item)
    )

    touched = [
        cluster
        for cluster in clusters
        if id(cluster) in membership_changed
        or any(a in changed for a in cluster.members)
    ]
    # Files being rewritten need every member's render: the kept one when the
    # function did not change, a new one for exports made without kept renders.
    rendered: dict[int, RenderedFunction] = dict(fresh)
    for cluster in touched:
        for address in cluster.members:
            if address in rendered:
                continue
            kept = syncstate.load_render(root, address)
            if kept is None:
                kept = render_one_with_limits(
                    live.session, analysis, analysis.routines[address], names
                )
                fresh[address] = kept
            rendered[address] = kept

    written = _rewrite(live, root, disk, clusters, touched, rendered, removed)
    _write_all_metadata(live, root, disk, clusters, rendered, written)
    for address, item in fresh.items():
        syncstate.save_render(root, item)
    for address in removed:
        syncstate.drop_render(root, address)
    syncstate.write_manifest(
        root,
        clusters=clusters,
        backend=live.analyzer.backend_name,
        decompiler=live.analyzer.decompiler_label,
        tree=disk.tree,
        entropy=disk.entropy,
        origin=disk.origin,
    )
    links = _refresh_folder_links(live, root) if touched or added or removed else None

    saved: dict[str, Any] | None = None
    if live._edited:
        saved = live.save()
    live.dirty.clear()
    live.unknown_changes = live.types_changed = live.globals_changed = False
    live.functions_changed = False
    live._locations = _reload_locations(root)
    report = {
        "export_dir": str(root),
        "mode": mode,
        "added": [_brief(live, a) for a in added],
        "removed": [hex(a) for a in removed],
        "renamed": renamed,
        "retyped": retyped,
        "types_added": types_added,
        "types_removed": types_removed,
        "types_modified": types_modified,
        "globals_renamed": renamed_globals,
        "rerendered": len(fresh),
        "changed": [_brief(live, a) for a in changed],
        "files_rewritten": sorted(_rel(root, path) for path in written["files"]),
        "files_removed": sorted(_rel(root, path) for path in written["removed"]),
        "failures": [
            {"address": hex(item.address), "error": item.failure.message}
            for item in fresh.values()
            if item.failure is not None
        ],
        "folder_links": links,
        "database": saved,
        "seconds": round(time.monotonic() - started, 2),
    }
    _log(root, report)
    return report


def _shape(row: dict[str, Any]) -> tuple:
    return (
        row.get("return_type"),
        tuple((p.get("name"), p.get("type")) for p in row.get("params") or []),
        tuple((p.get("name"), p.get("type")) for p in row.get("locals") or []),
        row.get("size"),
    )


def _routine_shape(routine: Any) -> tuple:
    return (
        routine.return_type,
        tuple(routine.params),
        tuple(routine.local_vars),
        routine.size,
    )


def _same(left: RenderedFunction, right: RenderedFunction) -> bool:
    return (
        left.c_text == right.c_text
        and left.asm_text == right.asm_text
        and left.summary_text == right.summary_text
        and left.prototype == right.prototype
    )


def _renamed_globals(disk: DiskState, analysis: Any) -> list[str]:
    """Old names of globals whose name changed (as data/variables.json names them)."""
    from ..metadata import variables_document

    current: dict[int, str] = {}
    for name, row in variables_document(analysis).items():
        address = _hex(row.get("va"))
        if address is not None:
            current[address] = name
    return sorted(
        name
        for address, name in disk.variables.items()
        if address in current and current[address] != name
    )


def _mentions(disk: DiskState, tokens: set[str]) -> set[int]:
    """Functions whose exported C mentions any of ``tokens`` as a whole word."""
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(t) for t in sorted(tokens) if t) + r")\b"
    )
    hits: set[int] = set()
    by_file: dict[Path, list[FunctionRange]] = {}
    for item in disk.ranges.values():
        by_file.setdefault(item.c_file, []).append(item)
    for path, items in by_file.items():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for item in items:
            text = "\n".join(lines[max(0, item.c_line_start - 1) : item.c_line_end])
            if pattern.search(text):
                hits.add(item.address)
    return hits


def _place(
    clusters: list[Cluster], removed: list[int], added: list[int], analysis: Any
) -> tuple[list[Cluster], set[int]]:
    """Existing functions keep their file; new ones join a caller's file."""
    gone = set(removed)
    changed: set[int] = set()
    result: list[Cluster] = []
    home: dict[int, Cluster] = {}
    for cluster in clusters:
        members = [a for a in cluster.members if a not in gone]
        copy = Cluster(
            root=cluster.root,
            label=cluster.label,
            summary=cluster.summary,
            members=members,
            folder=cluster.folder,
            file_base=cluster.file_base,
        )
        if len(members) != len(cluster.members):
            changed.add(id(copy))
        result.append(copy)
        for address in members:
            home[address] = copy
    discovered = next((c for c in result if c.file_base == DISCOVERED), None)
    pending = list(added)
    # Several passes so a chain of new functions follows its first placed caller.
    for _ in range(3):
        left = []
        for address in pending:
            neighbours = list(analysis.callers.get(address, [])) + list(
                analysis.callees.get(address, [])
            )
            target = next((home[n] for n in neighbours if n in home), None)
            if target is None:
                left.append(address)
                continue
            target.members.append(address)
            home[address] = target
            changed.add(id(target))
        if len(left) == len(pending):
            break
        pending = left
    if pending:
        if discovered is None:
            discovered = Cluster(
                root=pending[0],
                label=DISCOVERED,
                summary="Functions found after the export (added by sync)",
                members=[],
                folder="app",
                file_base=DISCOVERED,
            )
            result.append(discovered)
        discovered.members.extend(pending)
        changed.add(id(discovered))
    return result, changed


def _rewrite(
    live: "LiveSession",
    root: Path,
    disk: DiskState,
    clusters: list[Cluster],
    touched: list[Cluster],
    rendered: dict[int, RenderedFunction],
    removed: list[int],
) -> dict[str, Any]:
    from ..exporter import _cluster_path, build_cluster_files, write_tree_sources

    raw_dir = root / "src" / "raw"
    include_dir = root / "include"
    header_name = _header_name(live)
    files: list[Path] = []
    gone: list[Path] = []
    ranges: dict[int, FunctionRange] = {}
    prototypes: dict[int, str] = {}
    failures: list[Any] = []
    for cluster in touched:
        c_path = _cluster_path(raw_dir, cluster, c_file_name(cluster))
        asm_path = _cluster_path(raw_dir, cluster, asm_file_name(cluster))
        summary_path = _cluster_path(raw_dir, cluster, summary_file_name(cluster))
        if not cluster.members:
            for path in (c_path, asm_path, summary_path):
                if path.exists():
                    path.unlink()
                    gone.append(path)
            continue
        c_path.parent.mkdir(parents=True, exist_ok=True)
        include = Path(
            os.path.relpath(include_dir / header_name, c_path.parent)
        ).as_posix()
        block = build_cluster_files(
            analysis=live.analysis,
            cluster=cluster,
            header_include=include,
            c_path=c_path,
            asm_path=asm_path,
            summary_path=summary_path,
            rendered=rendered,
            prototypes=prototypes,
        )
        for path, text in (
            (c_path, block["c"]),
            (asm_path, block["asm"]),
            (summary_path, block["summary"]),
        ):
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                write_text_atomic(path, text)
                files.append(path)
        for item in block["ranges"]:
            ranges[item.address] = item
        failures.extend(block["failures"])
    tree_ranges: dict[int, FunctionRange] = {}
    live_touched = [cluster for cluster in touched if cluster.members]
    if disk.tree and live_touched:
        all_ranges = {**disk.ranges, **ranges}
        written = write_tree_sources(
            analysis=live.analysis,
            clusters=live_touched,
            src_dir=root / "src" / "tree",
            raw_dir=raw_dir,
            include_dir=include_dir,
            rendered=rendered,
            raw_ranges=list(all_ranges.values()),
        )
        files.extend(written["sources"])
        for item in written["ranges"]:
            tree_ranges[item.address] = item
    return {
        "files": files,
        "removed": gone,
        "ranges": ranges,
        "tree_ranges": tree_ranges,
        "failures": failures,
    }


def _header_name(live: "LiveSession") -> str:
    from ..naming import clean_path_component

    return f"{clean_path_component(live.analysis.binary.path.stem)}.h"


def _write_all_metadata(
    live: "LiveSession",
    root: Path,
    disk: DiskState,
    clusters: list[Cluster],
    rendered: dict[int, RenderedFunction],
    written: dict[str, Any],
) -> None:
    from ..exporter import ExportContext, _cluster_path, _write_metadata

    raw_dir = root / "src" / "raw"
    order = [a for cluster in clusters for a in cluster.members]
    ranges = {**disk.ranges, **written["ranges"]}
    tree_ranges = {**disk.tree_ranges, **written["tree_ranges"]}
    prototypes: dict[int, str] = {}
    failures = []
    for address in order:
        item = rendered.get(address)
        if item is not None:
            prototypes[address] = item.prototype
            if item.failure is not None:
                failures.append(item.failure)
        else:
            row = disk.functions.get(address, {})
            prototypes[address] = str(row.get("prototype") or "")
    header_name = _header_name(live)
    context = ExportContext(
        analyzer=live.analyzer,
        progress=live.progress,
        out_dir=root,
        jobs=None,
        tree_enabled=disk.tree,
        entropy_enabled=disk.entropy,
        origin=disk.origin,
    )
    context.analysis = live.analysis
    context.root = root
    context.raw_dir = raw_dir
    context.tree_dir = root / "src" / "tree" if disk.tree else None
    context.include_dir = root / "include"
    context.data_dir = root / "data"
    context.header_name = header_name
    context.header_path = context.include_dir / header_name
    context.names = live.names
    context.clusters = [cluster for cluster in clusters if cluster.members]
    context.addresses = order
    context.prototypes = prototypes
    context.failures = failures
    context.raw_ranges = [ranges[a] for a in order if a in ranges]
    context.tree_ranges = [tree_ranges[a] for a in order if a in tree_ranges]
    files = [
        _cluster_path(raw_dir, cluster, c_file_name(cluster))
        for cluster in context.clusters
    ]
    context.raw_sources = [path.resolve() for path in files]
    context.asm_files = [
        _cluster_path(raw_dir, cluster, asm_file_name(cluster)).resolve()
        for cluster in context.clusters
    ]
    context.summary_files = [
        _cluster_path(raw_dir, cluster, summary_file_name(cluster)).resolve()
        for cluster in context.clusters
    ]
    context.ida_database = live.target.database or (
        Path(disk.database) if disk.database else None
    )
    # Keep what the export run chose; a sync renders in one process.
    previous = _read(root / "project.json")
    context.worker_count = int(previous.get("worker_count") or 1)
    requested = previous.get("requested_worker_count")
    context.requested_jobs = requested if isinstance(requested, int) else None
    context.render_mode = str(previous.get("parallel_mode") or "single")
    _write_metadata(context, publish=False, docs=disk.origin_known)


def _refresh_folder_links(live: "LiveSession", root: Path) -> dict[str, Any] | None:
    """Inside a folder export, rejoin the cross-binary links (and annotations)."""
    master = next((p for p in root.parents if (p / ".tocode-folder").is_dir()), None)
    if master is None:
        return None
    project = _read(master / "project.json")
    source = project.get("input")
    if not source or not Path(str(source)).is_dir():
        return {"refreshed": False, "reason": "the folder's input is gone"}
    from ..apk_native import NativeOptions
    from ..folder import FolderOptions, export_folder
    from ..progress import Progress

    options = project.get("options") or {}
    summary = export_folder(
        Path(str(source)),
        options=FolderOptions(
            out_dir=master,
            only=list(options.get("only") or []),
            exclude=list(options.get("exclude") or []),
            include_framework=bool(options.get("include_framework")),
            native=bool(options.get("native", True)),
            managed=bool(options.get("managed", True)),
            links_only=True,
            native_options=NativeOptions(
                backend=options.get("backend") or "auto",
                tree=bool(options.get("tree")),
                entropy=bool(options.get("entropy")),
            ),
        ),
        progress=Progress(enabled=False),
    )
    return {"refreshed": True, "folder": str(master), "mapped": summary.mapped}


def _brief(live: "LiveSession", address: int) -> dict[str, Any]:
    return {"address": hex(address), "name": live.name_of(address)}


def _rel(root: Path, path: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _reload_locations(root: Path) -> dict[int, dict[str, Any]]:
    from .worker import _load_locations

    return _load_locations(root)


def _log(root: Path, report: dict[str, Any]) -> None:
    path = syncstate.sync_dir(root) / "sync-log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        **{k: report[k] for k in report if k != "changed"},
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def _forget_decompilations(live: "LiveSession") -> None:
    """Edits made by scripts may not have invalidated decompiler caches."""
    if live.backend == "ida":
        try:
            import ida_hexrays  # type: ignore[import-not-found]

            ida_hexrays.clear_cached_cfuncs()
        except Exception:  # noqa: BLE001
            pass
    for attribute in ("_decompile_cache", "_disasm_cache", "_locals_cache"):
        cache = getattr(live.session, attribute, None)
        if isinstance(cache, dict):
            cache.clear()


# --------------------------------------------------------------------------
# Export (a session opened on a plain binary)
# --------------------------------------------------------------------------


def export(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    from ..exporter import export_binary
    from ..naming import default_output_name

    if live.target.export_dir is not None and not args.get("out_dir"):
        raise OpError(
            f"this session already has an export at {live.target.export_dir}; use `sync`"
        )
    out = Path(str(args.get("out_dir") or "")) if args.get("out_dir") else None
    if out is None:
        out = live.target.binary.parent / default_output_name(live.target.binary)
    previous = os.environ.get("TOCODE_FUNCTION_TIMEOUT_SECONDS")
    # Render in this process, against the live session (no worker copies).
    os.environ["TOCODE_FUNCTION_TIMEOUT_SECONDS"] = "0"
    try:
        summary = export_binary(
            live.analyzer, out_dir=out, progress=live.progress, jobs=1
        )
    finally:
        if previous is None:
            os.environ.pop("TOCODE_FUNCTION_TIMEOUT_SECONDS", None)
        else:
            os.environ["TOCODE_FUNCTION_TIMEOUT_SECONDS"] = previous
    live.target.export_dir = summary.root_dir
    live._locations = _reload_locations(summary.root_dir)
    live.dirty.clear()
    return {
        "export_dir": str(summary.root_dir),
        "functions": summary.function_count,
        "clusters": summary.cluster_count,
        "failures": len(summary.failed_functions),
    }
