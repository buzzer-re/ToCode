from __future__ import annotations

from collections import deque
import math
from pathlib import Path
import re
from typing import Any

from .naming import SHARED_CLUSTER_ID, c_file_name, clean_path_component
from .schema import Cluster, FunctionRange, ProgramAnalysis, Segment, StringEntry


def display_path(path: Path) -> str:
    parts = path.parts
    for marker in ("src", "include", "data"):
        if marker in parts:
            return Path(*parts[parts.index(marker) :]).as_posix()
    return path.as_posix()


def imports_json(analysis: ProgramAnalysis) -> dict[str, object]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for address, item in sorted(analysis.imports.items()):
        dll = item.dll or item.bind or "unknown"
        grouped.setdefault(dll, []).append(
            {"name": item.name, "address": f"0x{address:x}", "delay": item.delay}
        )
    return {
        "imports": [
            {"dll": dll, "functions": functions}
            for dll, functions in sorted(
                grouped.items(), key=lambda value: value[0].lower()
            )
        ],
    }


def exports_json(analysis: ProgramAnalysis) -> dict[str, object]:
    return {
        "exports": [
            {
                "ordinal": item.ordinal,
                "name": item.name,
                "address": f"0x{item.address:x}",
                "is_forwarder": item.forwarder
                or inferred_forwarder(analysis, item) is not None,
                "forwarder_target": item.forwarder_target
                or inferred_forwarder(analysis, item),
            }
            for item in sorted(
                analysis.exports,
                key=lambda item: (
                    item.ordinal if item.ordinal is not None else 1 << 30,
                    item.name,
                    item.address,
                ),
            )
        ]
    }


def sections_json(analysis: ProgramAnalysis) -> dict[str, object]:
    return {
        "sections": [
            {
                "name": item.name,
                "vaddr": f"0x{item.vaddr:x}",
                "paddr": f"0x{item.paddr:x}",
                "size": item.size,
                "vsize": item.vsize,
                "type": item.kind,
                "permissions": item.perms,
                "rwx": item.readable and item.writable and item.executable,
                "entropy": section_entropy(analysis, item),
            }
            for item in analysis.segments
        ]
    }


def relocations_json(analysis: ProgramAnalysis) -> dict[str, object]:
    return {
        "relocations": [
            {
                "name": item.name,
                "type": item.kind,
                "vaddr": f"0x{item.vaddr:x}",
                "paddr": f"0x{item.paddr:x}",
                "is_ifunc": item.ifunc,
            }
            for item in analysis.relocations
        ]
    }


def strings_json(
    analysis: ProgramAnalysis, ranges: list[FunctionRange]
) -> dict[str, object]:
    xrefs = string_xrefs(analysis.strings, ranges)
    return {
        "strings": [
            {
                "vaddr": f"0x{item.vaddr:x}",
                "paddr": f"0x{item.paddr:x}",
                "size": item.size,
                "length": item.length,
                "section": item.segment,
                "type": item.kind,
                "value": item.value,
                "xrefs": xrefs.get(item.vaddr, []),
            }
            for item in analysis.strings
        ]
    }


def functions_json(
    analysis: ProgramAnalysis,
    ranges: list[FunctionRange],
    prototypes: dict[int, str],
    c_names: dict[int, str],
    tree_ranges: list[FunctionRange] | None = None,
) -> dict[str, object]:
    range_map = {item.address: item for item in ranges}
    tree_map = {item.address: item for item in (tree_ranges or [])}
    reachable = set(reachable_depths(analysis))
    rows: list[dict[str, object]] = []
    for address, routine in sorted(analysis.routines.items()):
        if routine.imported:
            continue
        raw_range = range_map.get(address)
        tree_range = tree_map.get(address)
        callees = analysis.callees.get(address, [])
        callers = analysis.callers.get(address, [])
        rows.append(
            {
                "address": f"0x{address:x}",
                "name": routine.name,
                "c_name": c_names.get(address, routine.name),
                "prototype": prototypes.get(address),
                "size": routine.size,
                "nargs": routine.args_count,
                "nlocals": routine.locals_count,
                "stackframe": routine.stack_size,
                "callees": [f"0x{item:x}" for item in callees],
                "callee_names": [
                    analysis.routines[item].name
                    for item in callees
                    if item in analysis.routines
                ],
                "callees_imports": analysis.import_calls.get(address, []),
                "callee_count": len(set(callees)),
                "callers": [f"0x{item:x}" for item in callers],
                "caller_count": len(set(callers)),
                "dead_code": address not in reachable,
                "source_file": str(raw_range.c_file) if raw_range else None,
                "source_line_start": raw_range.c_line_start if raw_range else None,
                "source_line_end": raw_range.c_line_end if raw_range else None,
                "tree_source_file": str(tree_range.c_file) if tree_range else None,
                "tree_source_line_start": tree_range.c_line_start
                if tree_range
                else None,
                "tree_source_line_end": tree_range.c_line_end if tree_range else None,
                "asm_file": str(raw_range.asm_file) if raw_range else None,
                "asm_line_start": raw_range.asm_line_start if raw_range else None,
                "asm_line_end": raw_range.asm_line_end if raw_range else None,
            }
        )
    return {"functions": rows}


def reachable_json(analysis: ProgramAnalysis) -> dict[str, object]:
    depths = reachable_depths(analysis)
    internal = [item for item in analysis.routines.values() if not item.imported]
    return {
        "reachable": [
            {
                "address": f"0x{address:x}",
                "name": analysis.routines[address].name,
                "depth": depth,
            }
            for address, depth in sorted(
                depths.items(), key=lambda item: (item[1], item[0])
            )
        ],
        "unreachable_count": sum(1 for item in internal if item.address not in depths),
    }


def reachable_depths(analysis: ProgramAnalysis) -> dict[int, int]:
    seeds = [
        address for address in entry_seeds(analysis) if address in analysis.routines
    ]
    if not seeds:
        seeds = [address for address in analysis.roots if address in analysis.routines]
    depths: dict[int, int] = {}
    queue: deque[tuple[int, int]] = deque((address, 0) for address in seeds)
    while queue:
        address, depth = queue.popleft()
        old = depths.get(address)
        if old is not None and old <= depth:
            continue
        depths[address] = depth
        for callee in analysis.callees.get(address, []):
            if callee in analysis.routines and not analysis.routines[callee].imported:
                queue.append((callee, depth + 1))
    return depths


def cluster_graph_json(
    analysis: ProgramAnalysis,
    clusters: list[Cluster],
    ranges: list[FunctionRange],
) -> dict[str, object]:
    cluster_by_func: dict[int, Cluster] = {}
    for cluster in clusters:
        for address in cluster.members:
            cluster_by_func[address] = cluster
    file_by_root = {item.address: item.c_file for item in ranges}
    outgoing: dict[str, set[str]] = {}
    incoming: dict[str, set[str]] = {}
    for address, cluster in cluster_by_func.items():
        source = cluster_id(cluster)
        outgoing.setdefault(source, set())
        incoming.setdefault(source, set())
        for callee in analysis.callees.get(address, []):
            target_cluster = cluster_by_func.get(callee)
            if target_cluster is None or target_cluster is cluster:
                continue
            target = cluster_id(target_cluster)
            outgoing[source].add(target)
            incoming.setdefault(target, set()).add(source)
    return {
        "clusters": [
            {
                "id": cluster_id(cluster),
                "file": display_path(
                    file_by_root.get(cluster.root, Path(c_file_name(cluster)))
                ),
                "root_function": cluster.label,
                "calls_clusters": sorted(outgoing.get(cluster_id(cluster), set())),
                "called_by_clusters": sorted(incoming.get(cluster_id(cluster), set())),
            }
            for cluster in clusters
        ]
    }


def triage_json(
    analysis: ProgramAnalysis,
    clusters: list[Cluster],
    ranges: list[FunctionRange],
    reachable_doc: dict[str, object],
) -> dict[str, object]:
    reachable_rows = reachable_doc.get("reachable", [])
    return {
        "binary_type": binary_type(analysis),
        "arch": analysis.binary.arch,
        "bits": analysis.binary.bits,
        "compiler": guess_compiler(analysis),
        "packed": guess_packed(analysis),
        "entry_clusters": entry_clusters(analysis, clusters, ranges),
        "sections": triage_sections(analysis),
        "rwx_sections": triage_sections(analysis, rwx_only=True),
        "export_count": len(analysis.exports),
        "import_count": len(analysis.imports),
        "strings_of_interest": interesting_strings(analysis)[:50],
        "reachable_count": len(reachable_rows)
        if isinstance(reachable_rows, list)
        else 0,
        "unreachable_count": reachable_doc.get("unreachable_count", 0),
    }


def entry_clusters(
    analysis: ProgramAnalysis,
    clusters: list[Cluster],
    ranges: list[FunctionRange],
) -> list[dict[str, object]]:
    ranges_by_address = {item.address: item for item in ranges}
    cluster_by_address = {
        address: cluster for cluster in clusters for address in cluster.members
    }
    rows: list[dict[str, object]] = []
    for address in entry_seeds(analysis):
        routine = analysis.routines.get(address)
        if routine is None:
            continue
        row_range = ranges_by_address.get(address)
        rows.append(
            {
                "name": routine.name,
                "address": f"0x{address:x}",
                "cluster": display_path(row_range.c_file)
                if row_range
                else (
                    c_file_name(cluster_by_address[address])
                    if address in cluster_by_address
                    else None
                ),
                "line": row_range.c_line_start if row_range else None,
            }
        )
    return rows


def export_variables(
    analysis: ProgramAnalysis, root: Path, ranges: list[FunctionRange]
) -> int:
    data_dir = root / "data"
    sections: list[dict[str, object]] = []
    with analysis.binary.path.open("rb") as handle:
        for segment in analysis.segments:
            if max(segment.vsize, segment.size) <= 0:
                continue
            file_name = None
            if segment.size > 0:
                file_name = f"{clean_path_component(segment.name)}.bin"
                handle.seek(segment.paddr)
                blob = handle.read(segment.size)
                (data_dir / file_name).write_bytes(blob)
                if blob:
                    segment.entropy = round(shannon_entropy(blob), 6)
            sections.append(
                {
                    "name": segment.name,
                    "file": file_name,
                    "va": f"0x{segment.vaddr:x}",
                    "size": segment.vsize,
                    "file_size": segment.size,
                    "permissions": segment.perms,
                    "entropy": section_entropy(analysis, segment),
                }
            )
    variables = variables_document(analysis, ranges)
    write_json(
        data_dir / "variables.json", {"sections": sections, "variables": variables}
    )
    write_json(
        data_dir / "variables_interesting.json",
        interesting_variables(analysis, variables),
    )
    return len(variables)


def variables_document(
    analysis: ProgramAnalysis, ranges: list[FunctionRange]
) -> dict[str, dict[str, object]]:
    variables: dict[str, dict[str, object]] = {}
    seen: set[int] = set()
    data_segments = [
        segment
        for segment in analysis.segments
        if segment.readable
        and not segment.executable
        and max(segment.vsize, segment.size) > 0
    ]

    def containing(address: int) -> Segment | None:
        for segment in data_segments:
            end = segment.vaddr + max(segment.vsize, segment.size)
            if segment.vaddr <= address < end:
                return segment
        return None

    def unique(base: str, address: int) -> str:
        return base if base not in variables else f"{base}_{address:x}"

    for string in analysis.strings:
        segment = containing(string.vaddr)
        if segment is None:
            continue
        label = unique(
            f"str_{clean_path_component(string.value[:32] or f'{string.vaddr:x}')}_{string.vaddr:x}",
            string.vaddr,
        )
        variables[label] = {
            "section": segment.name,
            "offset": string.vaddr - segment.vaddr,
            "size": string.size,
            "end": string.vaddr - segment.vaddr + string.size,
            "va": f"0x{string.vaddr:x}",
            "type": "char[]" if string.kind == "ascii" else "wchar_t[]",
            "string_type": string.kind,
            "value": string.value,
        }
        seen.add(string.vaddr)

    for symbol in analysis.symbols:
        if symbol.imported or symbol.vaddr in seen or symbol.kind == "FUNC":
            continue
        segment = containing(symbol.vaddr)
        if segment is None:
            continue
        label = unique(
            clean_path_component(symbol.real_name or symbol.name), symbol.vaddr
        )
        variables[label] = {
            "section": segment.name,
            "offset": symbol.vaddr - segment.vaddr,
            "size": symbol.size,
            "end": symbol.vaddr - segment.vaddr + symbol.size,
            "va": f"0x{symbol.vaddr:x}",
            "type": "uint8_t" if symbol.size == 1 else "uint8_t[]",
            "symbol_type": symbol.kind,
        }
        seen.add(symbol.vaddr)

    for relocation in analysis.relocations:
        if relocation.vaddr in seen:
            continue
        segment = containing(relocation.vaddr)
        if segment is None:
            continue
        label = unique(
            f"reloc_{clean_path_component(relocation.name)}", relocation.vaddr
        )
        variables[label] = {
            "section": segment.name,
            "offset": relocation.vaddr - segment.vaddr,
            "size": analysis.binary.pointer_size,
            "end": relocation.vaddr - segment.vaddr + analysis.binary.pointer_size,
            "va": f"0x{relocation.vaddr:x}",
            "type": "void*",
            "relocation_type": relocation.kind,
        }
        seen.add(relocation.vaddr)

    for flag in analysis.flags:
        if flag.offset in seen or not flag.name.startswith(
            ("obj.", "data.", "str.", "reloc.", "vtable.")
        ):
            continue
        segment = containing(flag.offset)
        if segment is None:
            continue
        label = unique(clean_path_component(flag.real_name or flag.name), flag.offset)
        variables[label] = {
            "section": segment.name,
            "offset": flag.offset - segment.vaddr,
            "size": flag.size,
            "end": flag.offset - segment.vaddr + flag.size,
            "va": f"0x{flag.offset:x}",
            "type": "uint8_t[]" if flag.size != 1 else "uint8_t",
            "flag": flag.name,
        }
        seen.add(flag.offset)

    add_variable_xrefs(variables, ranges)
    return dict(sorted(variables.items()))


def source_lines(ranges: list[FunctionRange]) -> list[dict[str, Any]]:
    cache: dict[Path, list[str]] = {}
    rows: list[dict[str, Any]] = []
    for item in ranges:
        if item.c_file not in cache:
            try:
                cache[item.c_file] = item.c_file.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                cache[item.c_file] = []
        for line_number in range(item.c_line_start, item.c_line_end + 1):
            index = line_number - 1
            if 0 <= index < len(cache[item.c_file]):
                rows.append(
                    {
                        "address": item.address,
                        "function": item.name,
                        "path": str(item.c_file),
                        "line": line_number,
                        "text": cache[item.c_file][index],
                    }
                )
    return rows


def string_xrefs(
    strings: list[StringEntry], ranges: list[FunctionRange]
) -> dict[int, list[dict[str, object]]]:
    lines = source_lines(ranges)
    result: dict[int, list[dict[str, object]]] = {}
    for item in strings:
        needles = string_needles(item.value)
        found: list[dict[str, object]] = []
        seen: set[tuple[int, int, str]] = set()
        for line in lines:
            if not any(needle in str(line["text"]) for needle in needles):
                continue
            key = (int(line["address"]), int(line["line"]), str(line["path"]))
            if key in seen:
                continue
            seen.add(key)
            found.append(
                {
                    "function": line["function"],
                    "address": f"0x{int(line['address']):x}",
                    "cluster": display_path(Path(str(line["path"]))),
                    "line": line["line"],
                }
            )
        result[item.vaddr] = found
    return result


def add_variable_xrefs(
    variables: dict[str, dict[str, object]], ranges: list[FunctionRange]
) -> None:
    lines = source_lines(ranges)
    for name, variable in variables.items():
        needles = {name}
        value = variable.get("value")
        if isinstance(value, str) and len(value) >= 4:
            needles.update(string_needles(value))
        flag = variable.get("flag")
        if isinstance(flag, str):
            needles.add(flag)
        xrefs: list[dict[str, object]] = []
        seen: set[tuple[int, bool]] = set()
        for line in lines:
            text = str(line["text"])
            if not any(needle and needle in text for needle in needles):
                continue
            key = (int(line["address"]), looks_written(text))
            if key in seen:
                continue
            seen.add(key)
            xrefs.append(
                {
                    "function": line["function"],
                    "address": f"0x{int(line['address']):x}",
                    "access": "write" if key[1] else "read",
                }
            )
        variable["xrefs"] = xrefs


def string_needles(value: str) -> list[str]:
    text = value.strip()
    if len(text) < 4:
        return []
    escaped = text.encode("unicode_escape").decode("ascii")
    return [
        item
        for item in {text, escaped, escaped.replace("\\\\", "\\")}
        if len(item) >= 4
    ]


def interesting_variables(
    analysis: ProgramAnalysis, variables: dict[str, dict[str, object]]
) -> dict[str, object]:
    known_strings = {item.value for item in analysis.strings}
    result: dict[str, dict[str, object]] = {}
    for name, variable in variables.items():
        size = _int_value(variable.get("size"), 0)
        type_name = str(variable.get("type", ""))
        xrefs = variable.get("xrefs")
        xref_rows = xrefs if isinstance(xrefs, list) else []
        writers = [
            row
            for row in xref_rows
            if isinstance(row, dict) and row.get("access") == "write"
        ]
        value = variable.get("value")
        reasons: list[str] = []
        if "[]" in type_name and size > 16:
            reasons.append("large_byte_array")
        if isinstance(value, str) and value not in known_strings:
            reasons.append("string_not_in_strings_json")
        if (
            "void*" in type_name
            or "code" in type_name.lower()
            or "relocation_type" in variable
        ):
            reasons.append("function_pointer_or_relocation")
        if len({row.get("address") for row in writers}) > 1:
            reasons.append("multiple_writers")
        if reasons:
            row = dict(variable)
            row["reasons"] = reasons
            result[name] = row
    return {"variables": result}


def interesting_strings(analysis: ProgramAnalysis) -> list[dict[str, object]]:
    pattern = re.compile(
        r"(https?://|\\\\|\\[A-Za-z0-9_. -]+\\|[A-Za-z]:\\|"
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b|"
        r"HKEY_|SOFTWARE\\|SYSTEM\\|\.exe\b|\.dll\b|\.ini\b|%[sdx])",
        re.IGNORECASE,
    )
    return [
        {"value": item.value, "address": f"0x{item.vaddr:x}"}
        for item in analysis.strings
        if pattern.search(item.value)
    ]


def entry_seeds(analysis: ProgramAnalysis) -> list[int]:
    seeds: list[int] = []
    for address in analysis.binary.entrypoints:
        if address not in seeds:
            seeds.append(address)
    for item in analysis.exports:
        if item.address and item.address not in seeds:
            seeds.append(item.address)
    return seeds


def inferred_forwarder(analysis: ProgramAnalysis, export: object) -> str | None:
    address = getattr(export, "address", 0)
    if not isinstance(address, int):
        return None
    segment = analysis.segment_at(address)
    if segment is not None and segment.executable:
        return None
    for item in analysis.strings:
        if item.vaddr <= address < item.vaddr + max(item.size, 1) and looks_forwarded(
            item.value
        ):
            return item.value
    return None


def looks_forwarded(value: str) -> bool:
    return bool(
        re.match(
            r"^[A-Za-z0-9_.-]+\.dll(?:\.[A-Za-z0-9_?$@.-]+)+$",
            value.strip(),
            re.IGNORECASE,
        )
    )


def triage_sections(
    analysis: ProgramAnalysis, *, rwx_only: bool = False
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for item in analysis.segments:
        rwx = item.readable and item.writable and item.executable
        if rwx_only and not rwx:
            continue
        rows.append(
            {
                "name": item.name,
                "entropy": section_entropy(analysis, item),
                "perms": item.perms,
                "size": item.size,
                "rwx": rwx,
            }
        )
    return rows


def _int_value(value: object, default: int = 0) -> int:
    if not isinstance(value, str | bytes | bytearray | int | float):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def binary_type(analysis: ProgramAnalysis) -> str:
    text = f"{analysis.binary.file_type} {analysis.binary.format_name} {analysis.binary.path.suffix}".lower()
    if "dll" in text or analysis.binary.path.suffix.lower() == ".dll":
        return "DLL"
    if "pe" in text or analysis.binary.os_name.lower().startswith("windows"):
        return "EXE"
    return analysis.binary.file_type or "unknown"


def guess_compiler(analysis: ProgramAnalysis) -> str | None:
    names = " ".join(item.name for item in analysis.imports.values()).lower()
    strings = " ".join(item.value for item in analysis.strings[:500]).lower()
    if any(
        token in names or token in strings
        for token in ("msvcrt", "ucrtbase", "vcruntime", "__security_check_cookie")
    ):
        return "MSVC"
    if "libgcc" in strings or "__gxx" in names:
        return "GCC/MinGW"
    return None


def guess_packed(analysis: ProgramAnalysis) -> bool:
    executable = [segment for segment in analysis.segments if segment.executable]
    return bool(
        [
            segment
            for segment in executable
            if (section_entropy(analysis, segment) or 0.0) >= 7.2
        ]
        and len(analysis.imports) <= 5
    )


def looks_written(line: str) -> bool:
    return bool(re.search(r"(?<![=!<>])=(?!=)", line) or "++" in line or "--" in line)


def section_entropy(analysis: ProgramAnalysis, segment: Segment) -> float | None:
    if segment.entropy is not None:
        return segment.entropy
    if segment.size <= 0:
        return None
    try:
        with analysis.binary.path.open("rb") as handle:
            handle.seek(segment.paddr)
            blob = handle.read(segment.size)
    except OSError:
        return None
    if not blob:
        return None
    segment.entropy = round(shannon_entropy(blob), 6)
    return segment.entropy


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def cluster_id(cluster: Cluster) -> str:
    return (
        "utils" if cluster.root == SHARED_CLUSTER_ID else f"cluster_{cluster.root:016x}"
    )


def write_json(path: Path, payload: dict[str, object]) -> None:
    import json

    path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
