"""``sync`` for .NET exports: rewrite the types the edits touched.

The export keeps one ``.cs``/``.il`` pair per top-level type, so a sync
re-decompiles exactly the stale types from the patched assemblies, applies
the text edits (local renames, comments), moves the files of renamed types,
and rewrites the JSON documents with the export's own writers. Every other
file keeps its bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any

from ..metadata import write_json, write_text_atomic
from .worker import OpError

if TYPE_CHECKING:
    from .dotnet_live import DotnetLiveSession


def register(live: "DotnetLiveSession") -> None:
    live.ops["sync"] = lambda args: sync(live, args)
    live.ops["export"] = lambda args: export(live, args)


# --------------------------------------------------------------------------
# The export's current layout
# --------------------------------------------------------------------------


@dataclass
class Layout:
    # (assembly index, type token) -> {"cs_path": Path, "il_path": Path}
    types: dict[tuple[int, int], dict[str, Any]] = field(default_factory=dict)
    # (assembly index, method token) -> (cs_start, cs_end, il_start, il_end)
    methods: dict[tuple[int, int], tuple[Any, Any, Any, Any]] = field(
        default_factory=dict
    )


def disk_layout(live: "DotnetLiveSession") -> Layout:
    cached = live._layout
    if cached is not None:
        return cached
    layout = Layout()
    root = live.target.export_dir
    if root is None:
        return layout
    index = {info.name: info.index for info in live.session.assemblies}
    for row in _rows(root / "types.json", "types"):
        assembly = index.get(str(row.get("assembly")))
        if assembly is None or not row.get("cs_file"):
            continue
        layout.types[(assembly, int(str(row["token"]), 16))] = {
            "cs_path": (root / row["cs_file"]).resolve(),
            "il_path": (root / row["il_file"]).resolve()
            if row.get("il_file")
            else None,
        }
    for row in _rows(root / "functions.json", "functions"):
        assembly = index.get(str(row.get("assembly")))
        if assembly is None or not row.get("token"):
            continue
        layout.methods[(assembly, int(str(row["token"]), 16))] = (
            row.get("source_line_start"),
            row.get("source_line_end"),
            row.get("asm_line_start"),
            row.get("asm_line_end"),
        )
    live._layout = layout
    return layout


def _rows(path: Path, key: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = payload.get(key, [])
    return [row for row in rows if isinstance(row, dict)]


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------


def sync(live: "DotnetLiveSession", args: dict[str, Any]) -> dict[str, Any]:
    from ..backends.dotnet import WorkItem, decompile_item
    from ..dotnet import (
        DotnetContext,
        DotnetExportOptions,
        _assign_paths,
        assign_type_ranges,
        type_texts,
    )
    from . import dotnet_edits

    root = live.target.export_dir
    if root is None:
        raise OpError("this session has no export folder; call `export` first")
    started = time.monotonic()
    written_assemblies = live.reload()
    session = live.session
    layout = disk_layout(live)
    mode = str(args.get("mode") or "auto")
    tops = {
        (asm, token)
        for (asm, token), record in session.types.items()
        if record.declaring_type is None
        and not (record.name == "<Module>" and not record.methods and not record.fields)
    }
    dirty = set(live.dirty)
    for item in args.get("addresses") or []:
        dirty.add(live.top_level(live.resolve(item)))
    if mode == "full":
        dirty |= tops
    dirty &= tops

    raw_dir = root / "src" / "raw"
    context = DotnetContext(
        input_path=live.target.open_path,
        options=DotnetExportOptions(
            out_dir=root,
            include_framework=bool(live._project().get("include_framework")),
        ),
        progress=live.progress,
    )
    context.found = live.found
    context.session = session
    context.root = root
    context.raw_dir = raw_dir
    context.data_dir = root / "data"
    _assign_paths(context)  # where each type belongs under its current name

    # Untouched types keep their file even if numbering would now differ.
    claimed = {session.types[key].cs_path for key in dirty}
    for key in tops - dirty:
        old = layout.types.get(key)
        if old is None:
            dirty.add(key)  # a type the export never had
        elif old["cs_path"] in claimed and session.types[key].cs_path != old["cs_path"]:
            dirty.add(key)  # its file was taken by a renamed type
        else:
            for nested in session.nested_types(key[0], key[1]):
                nested.cs_path, nested.il_path = old["cs_path"], old["il_path"]
    for method in session.methods:
        if (method.assembly, _top(session, method)) in dirty:
            continue
        span = layout.methods.get((method.assembly, method.token))
        if span is not None:
            method.cs_start, method.cs_end, method.il_start, method.il_end = span

    rewritten: list[Path] = []
    moved: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    for key in sorted(dirty):
        asm, token = key
        record = session.types[key]
        result = decompile_item(WorkItem(asm, live.assembly_path(asm), token))
        cs_text, il_text, offset = type_texts(session, record, result)
        if result.cs is not None:
            cs_text, result.cs_ranges = dotnet_edits.apply_text_edits(
                live, asm, cs_text, result.cs_ranges, offset
            )
        if record.error:
            failures.append({"type": record.reflection_name, "error": record.error})
        old = layout.types.get(key)
        if old is not None and old["cs_path"] != record.cs_path:
            for path in (old["cs_path"], old["il_path"]):
                if path is not None and Path(path).exists():
                    Path(path).unlink()
            moved.append(
                {"from": _rel(root, old["cs_path"]), "to": _rel(root, record.cs_path)}
            )
        for path, text in ((record.cs_path, cs_text), (record.il_path, il_text)):
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                write_text_atomic(path, text)
                rewritten.append(path)
        assign_type_ranges(session, record, result, cs_text, il_text, offset)

    _write_documents(live, context)
    links = None
    if rewritten or moved:
        from .sync import _refresh_folder_links

        links = _refresh_folder_links(live, root)  # type: ignore[arg-type]
    live.edits.synced = len(live.edits.entries)
    live.edits.save()
    live.dirty.clear()
    live._layout = None
    live._locations = None
    live._words = None
    live._edited = False
    report = {
        "export_dir": str(root),
        "mode": mode,
        "rerendered": len(dirty),
        "changed": sorted(session.types[key].reflection_name for key in dirty),
        "files_rewritten": sorted(_rel(root, path) for path in rewritten),
        "moved": moved,
        "patched": written_assemblies,
        "edits": len(live.edits.entries),
        "failures": failures,
        "folder_links": links,
        "seconds": round(time.monotonic() - started, 2),
    }
    log = root / ".tocode" / "sync" / "sync-log.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), **report}) + "\n"
        )
    return report


def _top(session: Any, method: Any) -> int:
    record = session.types.get((method.assembly, method.type_token))
    if record is None:
        return method.type_token
    return int(record.top_level or record.token)


def _write_documents(live: "DotnetLiveSession", context: Any) -> None:
    """The export's JSON documents, rewritten from the live inventory."""
    from .. import dotnet_metadata as meta
    from ..dotnet import _write_metadata

    root = context.root
    _write_metadata(context)
    try:
        libs = json.loads((root / "native-libs.json").read_text("utf-8")).get(
            "libs", []
        )
    except (OSError, ValueError):
        libs = []
    write_json(
        root / "triage.json",
        meta.triage_json(context.session, context.found, context.reachable, libs),
    )
    sources = sorted(
        {
            str(record.cs_path)
            for record in context.session.types.values()
            if record.cs_path is not None
        }
        | {str(p) for p in (root / "src" / "raw").rglob("Properties/AssemblyInfo.cs")}
    )
    il_files = sorted(
        {
            str(record.il_path)
            for record in context.session.types.values()
            if record.il_path is not None
        }
        | {str(p) for p in (root / "src" / "raw").rglob("Properties/Manifest.il")}
    )
    for name in ("project.json", "export-manifest.json"):
        path = root / name
        try:
            document = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        document.update(
            {
                "source_files": sources,
                "il_files": il_files,
                "asm_files": il_files,
                "function_count": len(context.session.methods),
                "type_count": len(context.session.types),
            }
        )
        write_json(path, document)


def _rel(root: Path, path: Any) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------
# Export (a session opened on a plain assembly)
# --------------------------------------------------------------------------


def export(live: "DotnetLiveSession", args: dict[str, Any]) -> dict[str, Any]:
    from ..dotnet import DotnetExportOptions, export_dotnet

    if live.target.export_dir is not None and not args.get("out_dir"):
        raise OpError(
            f"this session already has an export at {live.target.export_dir}; use `sync`"
        )
    out = Path(str(args["out_dir"])) if args.get("out_dir") else None
    summary = export_dotnet(
        live.target.open_path,
        options=DotnetExportOptions(out_dir=out, native=False),
        progress=live.progress,
    )
    live.target.export_dir = summary.root_dir
    live._layout = None
    live._locations = None
    report: dict[str, Any] = {
        "export_dir": str(summary.root_dir),
        "types": summary.type_count,
    }
    if live.edits.entries:
        # Edits made before the export: bring them in.
        live.edits.synced = 0
        report["sync"] = sync(live, {"mode": "full"})
    return report
