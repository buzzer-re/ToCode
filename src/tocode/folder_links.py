"""Join the folder's link facts to the per-binary exports.

The linker tables give, for every bound import, the defining file and the
export's link-time address (or .NET MethodDef token). Here that address is
moved into the backend's address space (``image_base`` delta, checked against
exported names), mapped to the exported function that contains it, and
written out with file and line ranges:

- ``mappings.json`` at the top of the folder export;
- ``imports.json`` / ``functions.json`` / ``exports.json`` of each export
  (``libraries``, ``link``, ``import_links``, ``imported_by``);
- ``tocode-link:`` comments in the importer's decompiled source.

Everything is recomputed from scratch on each run, so it is idempotent and
picks up exports that finished since the last run.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

from .links.analyze import FolderLinks
from .links.bind import LINK_BOUND, SymbolLink
from .links.inventory import Inventory
from .links.names import c_tokens, link_key
from .metadata import write_json
from .progress import Progress

LABEL_WIDTH = 40
BAR_FORMAT = (
    "{desc} {bar:24} {n_fmt}/{total_fmt} {unit_label}{postfix} [{elapsed}<{remaining}]"
)

MAX_CALL_SITES = 16
MAX_IMPORTED_BY = 32
MIN_NAME_CONFIRMATIONS = 3


@dataclass(slots=True)
class FunctionRow:
    address: int
    size: int
    name: str
    source_file: str | None  # master-relative
    line_start: int | None
    line_end: int | None
    asm_file: str | None
    asm_line_start: int | None
    asm_line_end: int | None
    token: int | None = None

    def location(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}" if self.token is None else None,
            "token": f"0x{self.token:08x}" if self.token is not None else None,
            "name": self.name,
            "source_file": self.source_file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "asm_file": self.asm_file,
            "asm_line_start": self.asm_line_start,
            "asm_line_end": self.asm_line_end,
        }


@dataclass
class ExportIndex:
    relpath: str
    export_dir: Path
    rows: list[FunctionRow]
    starts: list[int] = field(default_factory=list)
    by_token: dict[int, FunctionRow] = field(default_factory=dict)
    by_key: dict[str, list[FunctionRow]] = field(default_factory=dict)
    backend_base: int | None = None
    delta: int = 0
    delta_source: str = "none"
    confirmed: int = 0
    checked: int = 0

    def __post_init__(self) -> None:
        self.rows.sort(key=lambda row: row.address)
        self.starts = [row.address for row in self.rows]
        for row in self.rows:
            if row.token is not None:
                self.by_token[row.token] = row
            self.by_key.setdefault(link_key(row.name), []).append(row)

    def containing(self, address: int) -> FunctionRow | None:
        index = bisect_right(self.starts, address) - 1
        if index < 0:
            return None
        row = self.rows[index]
        if row.address == address or address < row.address + max(row.size, 1):
            return row
        return None


@dataclass
class LinkResult:
    mapped: int = 0
    bound: int = 0
    annotated_lines: int = 0
    mappings_path: Path | None = None
    address_spaces: dict[str, Any] = field(default_factory=dict)


def _available(job_export_dir: Path) -> bool:
    return (job_export_dir / "export-manifest.json").is_file() and (
        job_export_dir / "functions.json"
    ).is_file()


def _rel_to(master: Path, export_dir: Path, value: Any) -> str | None:
    if not value:
        return None
    path = Path(str(value))
    if not path.is_absolute():
        path = export_dir / path
    try:
        return path.resolve().relative_to(master.resolve()).as_posix()
    except (ValueError, OSError):
        return str(value)


def _int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.rsplit("!", 1)[-1]
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return None
    return None


def load_index(
    master: Path, relpath: str, export_dir: Path, cache_dir: Path
) -> ExportIndex | None:
    manifest = export_dir / "export-manifest.json"
    functions = export_dir / "functions.json"
    try:
        stamp = f"{functions.stat().st_mtime_ns}:{functions.stat().st_size}:{manifest.stat().st_mtime_ns}"
    except OSError:
        return None
    cache = cache_dir / (hashlib.sha1(relpath.encode()).hexdigest()[:16] + ".json")
    rows: list[FunctionRow] | None = None
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if cached.get("stamp") == stamp:
            rows = [FunctionRow(*item) for item in cached["rows"]]
    except (OSError, ValueError, TypeError, KeyError):
        rows = None
    if rows is None:
        try:
            payload = json.loads(functions.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        rows = []
        for item in payload.get("functions", []):
            token = _int(item.get("token")) if item.get("token") else None
            address = _int(item.get("address"))
            if address is None:
                address = token or 0
            rows.append(
                FunctionRow(
                    address=address,
                    size=int(item.get("size") or 0),
                    name=str(item.get("name") or ""),
                    source_file=_rel_to(master, export_dir, item.get("source_file")),
                    line_start=item.get("source_line_start"),
                    line_end=item.get("source_line_end"),
                    asm_file=_rel_to(master, export_dir, item.get("asm_file")),
                    asm_line_start=item.get("asm_line_start"),
                    asm_line_end=item.get("asm_line_end"),
                    token=token,
                )
            )
        del payload
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(
            json.dumps(
                {
                    "stamp": stamp,
                    "rows": [
                        [
                            row.address,
                            row.size,
                            row.name,
                            row.source_file,
                            row.line_start,
                            row.line_end,
                            row.asm_file,
                            row.asm_line_start,
                            row.asm_line_end,
                            row.token,
                        ]
                        for row in rows
                    ],
                }  # fmt: skip
            ),
            encoding="utf-8",
        )
    index = ExportIndex(relpath=relpath, export_dir=export_dir, rows=rows)
    try:
        project = json.loads((export_dir / "project.json").read_text(encoding="utf-8"))
        index.backend_base = _int(project.get("image_base"))
    except (OSError, ValueError, AttributeError):
        index.backend_base = None
    return index


def choose_delta(
    index: ExportIndex, link_base: int, exports: list[tuple[str, int]]
) -> None:
    """Pick the link-time -> backend address delta best confirmed by names."""
    candidates: dict[int, str] = {0: "identity"}
    if index.backend_base is not None:
        candidates.setdefault(index.backend_base - link_base, "image_base")
    diffs: Counter[int] = Counter()
    for name, address in exports:
        for row in index.by_key.get(link_key(name), [])[:4]:
            diffs[row.address - address] += 1
    if diffs:
        delta, count = diffs.most_common(1)[0]
        if count >= MIN_NAME_CONFIRMATIONS:
            candidates.setdefault(delta, "export names")
    best = (-1, 0, "none")
    checked = 0
    for delta, source in candidates.items():
        confirmed = 0
        checked = 0
        for name, address in exports:
            rows = index.by_key.get(link_key(name))
            if not rows:
                continue
            checked += 1
            if any(row.address == address + delta for row in rows):
                confirmed += 1
        if confirmed > best[0] or (confirmed == best[0] and source == "image_base"):
            best = (confirmed, delta, source)
    index.confirmed, index.delta, index.delta_source = best[0], best[1], best[2]
    index.checked = checked
    if index.confirmed <= 0 and index.backend_base is not None:
        index.delta = index.backend_base - link_base
        index.delta_source = "image_base (unconfirmed)"


def link_exports(
    master: Path,
    inventory: Inventory,
    links: FolderLinks,
    jobs: list[Any],
    *,
    progress: Progress | None = None,
) -> LinkResult:
    from .folder_annotate import Annotation, annotate_file

    result = LinkResult()
    cache_dir = master / ".tocode-folder" / "index"
    job_by_path = {job.relpath: job for job in jobs}
    indexes: dict[str, ExportIndex | None] = {}

    def index_for(relpath: str) -> ExportIndex | None:
        if relpath in indexes:
            return indexes[relpath]
        job = job_by_path.get(relpath)
        index = None
        if job is not None and _available(job.export_dir):
            index = load_index(master, relpath, job.export_dir, cache_dir)
            facts = inventory.folder.facts(relpath)
            if index is not None and facts is not None and facts.format != "dotnet":
                exports = [
                    (item.name, item.address)
                    for item in facts.exports
                    if item.address is not None and item.kind != "absolute"
                ]
                choose_delta(index, facts.image_base, exports)
                result.address_spaces[relpath] = {
                    "link_base": f"0x{facts.image_base:x}",
                    "backend_base": f"0x{index.backend_base:x}"
                    if index.backend_base is not None
                    else None,
                    "delta": f"{'-' if index.delta < 0 else ''}0x{abs(index.delta):x}",
                    "source": index.delta_source,
                    "confirmed_by_export_names": index.confirmed,
                    "export_names_found": index.checked,
                }
        indexes[relpath] = index
        return index

    def export_dir(relpath: str | None) -> str | None:
        job = job_by_path.get(relpath or "")
        if job is None:
            return None
        return _rel_to(master, master, job.export_dir)

    def target_status(relpath: str) -> str:
        job = job_by_path.get(relpath)
        if job is None:
            return "not_exported"
        if job.status == "done":
            return "decompiled" if _available(job.export_dir) else "export_missing"
        return job.status

    # 1. Each bound link -> the defining function in the target's export.
    rows_out: list[dict[str, Any]] = []
    importer_sites: dict[str, list[tuple[SymbolLink, dict[str, Any]]]] = {}
    imported_by: dict[str, dict[int, list[dict[str, Any]]]] = {}
    for link in links.links:
        row = link.to_json()
        if link.target is not None:
            row["target_export_dir"] = export_dir(link.target)
            row["target_status"] = target_status(link.target)
        target_row: FunctionRow | None = None
        if link.status == LINK_BOUND and link.target is not None:
            result.bound += 1
            index = index_for(link.target)
            if index is not None:
                if link.token is not None:
                    target_row = index.by_token.get(link.token)
                elif link.address is not None:
                    target_row = index.containing(link.address + index.delta)
                    if target_row is None:
                        row["target_status"] = "not_in_a_function"
        if target_row is not None:
            row["target_function"] = target_row.location()
            result.mapped += 1
        rows_out.append(row)
        importer_sites.setdefault(link.importer, []).append((link, row))
        if target_row is not None:
            imported_by.setdefault(link.target or "", {}).setdefault(
                target_row.address, []
            ).append(row)

    # 2. Call sites in the importers, enrichment, comments.
    annotated = 0
    bar = (
        progress.new_bar(
            total=len(importer_sites),
            desc=f"{'linking':<{LABEL_WIDTH}}",
            disable=None,
            bar_format=BAR_FORMAT.replace("{unit_label}", "binaries"),
        )
        if progress is not None
        else None
    )
    for importer, pairs in importer_sites.items():
        if bar is not None:
            bar.update(1)
        index = index_for(importer)
        job = job_by_path.get(importer)
        if index is None or job is None or job.status.startswith("duplicate"):
            continue
        aliases: dict[int, set[str]] = {}
        callers = _call_sites(importer, index, pairs, inventory, aliases)
        for link, row in pairs:
            sites = callers.get(id(link), [])
            if sites:
                row["call_site_count"] = len(sites)
                row["call_sites"] = [site.location() for site in sites[:MAX_CALL_SITES]]
        annotations: list[Annotation] = []
        for link, row in pairs:
            target_fn = row.get("target_function")
            if link.status != LINK_BOUND or link.target is None:
                continue
            note = _note(link, row)
            for site in callers.get(id(link), []):
                if site.source_file and site.line_start and site.line_end:
                    annotations.append(
                        Annotation(
                            source_file=site.source_file,
                            line_start=site.line_start,
                            line_end=site.line_end,
                            tokens=c_tokens(
                                link.symbol
                                if link.kind != "pinvoke"
                                else (link.owner or link.symbol),
                                link.version,
                            )
                            + sorted(aliases.get(id(link), ())),
                            text=note,
                        )
                    )
            del target_fn
        by_file: dict[str, list[Annotation]] = {}
        for item in annotations:
            by_file.setdefault(item.source_file, []).append(item)
        for relfile, items in by_file.items():
            annotated += annotate_file(master / relfile, items)
        _enrich_importer(
            master, job.export_dir, importer, pairs, links, export_dir, callers
        )
    result.annotated_lines = annotated
    if bar is not None:
        bar.close()

    for target, by_address in imported_by.items():
        job = job_by_path.get(target)
        if job is None or not _available(job.export_dir):
            continue
        _enrich_target(job.export_dir, by_address, indexes.get(target))

    path = master / "mappings.json"
    statuses = Counter(row["status"] for row in rows_out)
    write_json(
        path,
        {
            "schema_version": 1,
            "summary": {
                "imports": len(rows_out),
                "bound_in_folder": result.bound,
                "mapped_to_function": result.mapped,
                "by_status": dict(sorted(statuses.items())),
                "annotated_source_lines": annotated,
            },
            "address_spaces": result.address_spaces,
            "links": rows_out,
        },
    )
    result.mappings_path = path
    if progress is not None:
        progress.log(
            f"Links: {result.bound} imports bound inside the folder, {result.mapped} mapped "
            f"to a decompiled function, {annotated} source lines annotated (mappings.json)"
        )
    return result


def _note(link: SymbolLink, row: dict[str, Any]) -> str:
    target = row.get("target_function") or {}
    where = row.get("target_export_dir") or link.target
    if target.get("source_file") and target.get("line_start"):
        return f"{link.symbol} -> {target['source_file']}:{target['line_start']}-{target['line_end']}"
    if target:
        place = target.get("address") or target.get("token")
        return f"{link.symbol} -> {where} {target.get('name')} @ {place} (no source lines in that export)"
    return f"{link.symbol} -> {where} ({row.get('target_status', 'not decompiled')})"


def _call_sites(
    importer, index: ExportIndex, pairs, inventory, aliases: dict[int, set[str]]
) -> dict[int, list[FunctionRow]]:
    """Importer functions that call each linked import.

    ``aliases`` collects the identifiers the backend uses for each import
    (from slot matches), so the source annotation can find the call line.
    """
    facts = inventory.folder.facts(importer)
    result: dict[int, list[FunctionRow]] = {}
    if facts is not None and facts.format == "dotnet":
        for link, _row in pairs:
            sites = [
                index.by_token[token]
                for token in (link.callers or [])
                if token in index.by_token
            ]
            if sites:
                result[id(link)] = sites
        return result
    by_key: dict[str, list[SymbolLink]] = {}
    by_slot: dict[int, SymbolLink] = {}
    for link, _row in pairs:
        by_key.setdefault(link_key(link.symbol), []).append(link)
        if link.slot is not None:
            by_slot[link.slot] = link
    # The backend may name an import differently (ordinal imports, renamed
    # slots); its imports.json address is the same pointer slot the linker
    # tables give, which ties the backend's name to the link.
    if by_slot:
        imports = _load_json(index.export_dir / "imports.json") or {}
        for group in imports.get("imports", []):
            for item in group.get("functions", []) if isinstance(group, dict) else []:
                address = _int(item.get("address")) if isinstance(item, dict) else None
                link = (
                    by_slot.get(address - index.delta) if address is not None else None
                )
                if link is not None:
                    backend_name = str(item.get("name") or "")
                    key = link_key(backend_name)
                    if link not in by_key.setdefault(key, []):
                        by_key[key].append(link)
                    aliases.setdefault(id(link), set()).update({backend_name, key})
    try:
        payload = json.loads(
            (index.export_dir / "functions.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return result
    functions = payload.get("functions", [])
    stubs: dict[int, str] = {}
    for item in functions:
        key = link_key(str(item.get("name") or ""))
        address = _int(item.get("address"))
        if key in by_key and address is not None and (item.get("size") or 0) <= 64:
            stubs[address] = key
    rows_by_address = {row.address: row for row in index.rows}
    for item in functions:
        address = _int(item.get("address"))
        if address is None or address in stubs:
            continue
        keys = {link_key(str(name)) for name in item.get("callees_imports") or []}
        for callee in item.get("callees") or []:
            target = _int(callee)
            if target in stubs:
                keys.add(stubs[target])
        row = rows_by_address.get(address)
        if row is None:
            continue
        for key in keys:
            for link in by_key.get(key, []):
                result.setdefault(id(link), []).append(row)
    return result


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _compact_link(row: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "symbol",
        "library",
        "status",
        "resolution",
        "target",
        "target_export_dir",
        "target_status",
        "export",
        "target_va",
        "target_token",
        "target_function",
    )
    return {key: row[key] for key in keys if row.get(key) is not None}


def _enrich_importer(
    master,
    export_dir_path: Path,
    importer,
    pairs,
    links: FolderLinks,
    export_dir,
    callers,
) -> None:
    imports_path = export_dir_path / "imports.json"
    payload = _load_json(imports_path)
    if payload is not None:
        edges = []
        for edge in links.resolution.edges:
            if edge.source != importer:
                continue
            row = edge.to_json()
            row["to_export_dir"] = export_dir(edge.target) if edge.target else None
            edges.append(row)
        payload["libraries"] = edges
        by_key: dict[str, list[dict[str, Any]]] = {}
        for link, row in pairs:
            by_key.setdefault(link_key(link.symbol), []).append(row)
        for group in payload.get("imports", []):
            for item in group.get("functions", []) if isinstance(group, dict) else []:
                if not isinstance(item, dict):
                    continue
                item.pop("link", None)
                name = str(item.get("name") or "")
                matches = by_key.get(link_key(name))
                if matches is None and "::" not in name and " " in name:
                    # .NET full names: "RetType Ns.Type::Member(Args)"
                    member = name.split(" ", 1)[1].split("(", 1)[0]
                    matches = by_key.get(link_key(member))
                if matches:
                    item["link"] = (
                        _compact_link(matches[0])
                        if len(matches) == 1
                        else [_compact_link(row) for row in matches[:8]]
                    )
        write_json(imports_path, payload)
    functions_path = export_dir_path / "functions.json"
    links_by_row: dict[int, list[dict[str, Any]]] = {}
    for link, row in pairs:
        for site in callers.get(id(link), []):
            target = row.get("target_function") or {}
            links_by_row.setdefault(site.address, []).append(
                {
                    "symbol": link.symbol,
                    "target": link.target,
                    "status": row.get("target_status")
                    if link.status == LINK_BOUND
                    else link.status,
                    "source_file": target.get("source_file"),
                    "line_start": target.get("line_start"),
                    "line_end": target.get("line_end"),
                }
            )
    payload = _load_json(functions_path)
    if payload is None:
        return
    changed = False
    for item in payload.get("functions", []):
        if "import_links" in item:
            del item["import_links"]
            changed = True
        address = (
            _int(item.get("address"))
            if not item.get("token")
            else _int(item.get("token"))
        )
        rows = links_by_row.get(address or -1)
        if rows:
            item["import_links"] = rows
            changed = True
    if changed:
        write_json(functions_path, payload)


def _enrich_target(
    export_dir_path: Path,
    by_address: dict[int, list[dict[str, Any]]],
    index: ExportIndex | None,
) -> None:
    functions_path = export_dir_path / "functions.json"
    payload = _load_json(functions_path)
    if payload is None:
        return
    for item in payload.get("functions", []):
        item.pop("imported_by", None)
        item.pop("imported_by_count", None)
        address = (
            _int(item.get("token")) if item.get("token") else _int(item.get("address"))
        )
        rows = by_address.get(address if address is not None else -1)
        if not rows:
            continue
        item["imported_by_count"] = len(rows)
        item["imported_by"] = [
            {
                "importer": row["importer"],
                "symbol": row["symbol"],
                "call_site_count": row.get("call_site_count", 0),
                "call_sites": row.get("call_sites", [])[:4],
            }
            for row in rows[:MAX_IMPORTED_BY]
        ]
    write_json(functions_path, payload)
    exports_path = export_dir_path / "exports.json"
    exports = _load_json(exports_path)
    if exports is None:
        return
    counts: Counter[str] = Counter()
    for rows in by_address.values():
        for row in rows:
            counts[link_key(str(row.get("export") or row["symbol"]))] += 1
    for item in exports.get("exports", []):
        if isinstance(item, dict):
            item.pop("imported_by_count", None)
            count = counts.get(link_key(str(item.get("name") or "")))
            if count:
                item["imported_by_count"] = count
    write_json(exports_path, exports)
