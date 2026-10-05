"""JSON metadata documents for .NET exports.

Shapes follow ``metadata.py``/``apk_metadata.py`` wherever a native or Android
concept has a .NET equivalent (functions, function-index, strings, imports,
exports, sections, reachable, triage), so tooling that reads other ToCode
exports keeps working. .NET-only facts live in ``assemblies.json``,
``types.json``, ``namespace-graph.json``, ``resources.json`` and
``container.json``. Big per-row documents are generators for
``apk_metadata.write_json_rows``.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
import re
from typing import Any, Iterable, Iterator

from .apk_metadata import INTERESTING_STRING_TIERS
from .backends.dotnet import (
    AssemblyInfo,
    DotnetInput,
    DotnetSession,
    MethodInfo,
    TypeInfo,
)

# External API families worth surfacing first when triaging a .NET binary.
SUSPICIOUS_API_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "dynamic code loading / reflection",
        re.compile(
            r"System\.Reflection\.Assembly::(Load|LoadFrom|LoadFile|UnsafeLoadFrom)\b|"
            # CreateInstance<T>() is what the compiler emits for `new T()`.
            r"System\.AppDomain::(Load|ExecuteAssembly)|System\.Activator::CreateInstance(?!<)|"
            r"System\.Reflection\.MethodBase::Invoke|System\.Type::InvokeMember|"
            r"System\.Reflection\.Emit\.|AssemblyLoadContext::Load"
        ),
    ),
    ("process execution", re.compile(r"System\.Diagnostics\.Process::Start")),
    (
        "network",
        re.compile(
            r"System\.Net\.(Http\.HttpClient|WebClient|WebRequest|Sockets\.|Dns::|"
            r"HttpWebRequest|WebSockets\.)"
        ),
    ),
    ("cryptography", re.compile(r"System\.Security\.Cryptography\.")),
    ("registry", re.compile(r"Microsoft\.Win32\.Registry")),
    (
        "native interop",
        re.compile(
            r"System\.Runtime\.InteropServices\.(Marshal::(GetDelegateForFunctionPointer|"
            r"Copy|AllocHGlobal|PtrToStructure)|NativeLibrary::)"
        ),
    ),
    ("file system", re.compile(r"System\.IO\.(File|Directory|FileStream)::")),
    (
        "unsafe deserialization",
        re.compile(
            r"BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|"
            r"ObjectStateFormatter"
        ),
    ),
    (
        "environment / host info",
        re.compile(
            r"System\.Environment::(get_MachineName|get_UserName|get_UserDomainName|"
            r"get_OSVersion|GetEnvironmentVariable|SetEnvironmentVariable|GetFolderPath|"
            r"get_CommandLine|GetCommandLineArgs|Exit|FailFast)"
        ),
    ),
)


def _rel(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _method_label(method: MethodInfo) -> str:
    return f"{method.type_name.replace('/', '.')}.{method.name}"


# --------------------------------------------------------------------------
# assemblies.json / container.json
# --------------------------------------------------------------------------


def assemblies_json(
    session: DotnetSession, found: DotnetInput, root: Path
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    loaded = {info.file.path: info for info in session.assemblies}
    for item in found.assemblies:
        info = loaded.get(item.path)
        base: dict[str, Any] = {
            "file": item.entry,
            "source": item.source,
            "framework": item.framework,
            "decompiled": info is not None,
            "skip_reason": item.reason,
            "target_framework_folder": item.tfm,
        }
        if info is None:
            base["name"] = Path(item.entry).stem
            rows.append(base)
            continue
        method_count = sum(
            len(session.types[(info.index, token)].methods) for token in info.types
        )
        base.update(
            {
                "name": info.name,
                "full_name": info.full_name,
                "version": info.version,
                "culture": info.culture or None,
                "public_key_token": info.public_key_token,
                "module": info.module_name,
                "mvid": info.mvid,
                "kind": info.kind,
                "target_framework": info.target_framework,
                "runtime_version": info.pe.runtime_version,
                "machine": info.pe.machine,
                "pe32_plus": info.pe.pe32_plus,
                "cor_flags": info.pe.cor_flag_names,
                "ready_to_run": info.pe.ready_to_run,
                "mixed_mode": info.pe.mixed_mode,
                "strong_name_signed": "StrongNameSigned" in info.pe.cor_flag_names,
                "entry_point": _entry_label(session, info),
                "folder": info.folder,
                "project": f"{info.folder}/{info.name}.csproj" if info.folder else None,
                "type_count": len(info.types),
                "method_count": method_count,
                "user_string_count": len(info.user_strings),
                "assembly_refs": info.assembly_refs,
                "module_refs": info.module_refs,
                "attributes": info.attributes,
                "resources": [
                    {
                        "name": resource.name,
                        "kind": resource.kind,
                        "size": resource.size,
                        "public": resource.public,
                        "path": _rel(resource.path, root),
                    }
                    for resource in info.resources
                ],
                "obfuscation_hints": info.obfuscation_hints,
            }
        )
        rows.append(base)
    return {"count": len(rows), "assemblies": rows}


def _entry_label(session: DotnetSession, info: AssemblyInfo) -> dict[str, Any] | None:
    if info.entry_point is None:
        return None
    method = session.method(info.index, info.entry_point)
    if method is None:
        return {"token": f"0x{info.entry_point:08x}", "name": None, "address": None}
    return {
        "token": f"0x{method.token:08x}",
        "name": method.full_name,
        "address": method.address,
    }


def container_json(
    found: DotnetInput, extracted: dict[str, str | None]
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if found.bundle is not None:
        for entry in found.bundle.entries:
            entries.append(
                {
                    "path": entry.path,
                    "kind": entry.kind,
                    "offset": entry.offset,
                    "size": entry.size,
                    "compressed_size": entry.compressed_size or None,
                    "exported_path": extracted.get(entry.path),
                }
            )
    else:
        for item in found.assemblies:
            entries.append(
                {
                    "path": item.entry,
                    "kind": "assembly",
                    "exported_path": extracted.get(item.entry),
                }
            )
        for native in found.natives:
            entries.append(
                {
                    "path": native.entry,
                    "kind": "native",
                    "exported_path": extracted.get(native.entry),
                }
            )
        for extra in found.extras:
            entries.append(
                {
                    "path": extra.entry,
                    "kind": extra.kind,
                    "exported_path": extracted.get(extra.entry),
                }
            )
    return {
        "kind": found.kind,
        "input": str(found.input),
        "bundle": {
            "version": f"{found.bundle.major}.{found.bundle.minor}",
            "bundle_id": found.bundle.bundle_id,
            "manifest_offset": found.bundle.header_offset,
        }
        if found.bundle is not None
        else None,
        "entries": entries,
    }


# --------------------------------------------------------------------------
# types.json / functions.json / function-index.json
# --------------------------------------------------------------------------


def iter_type_rows(session: DotnetSession, root: Path) -> Iterator[dict[str, Any]]:
    for record in session.types.values():
        assembly = session.assemblies[record.assembly]
        yield {
            "assembly": assembly.name,
            "token": f"0x{record.token:08x}",
            "name": record.full_name.replace("/", "+"),
            "namespace": record.namespace,
            "simple_name": record.name,
            "kind": record.kind,
            "size": None,
            "visibility": record.visibility,
            "flags": record.flags,
            "base_type": record.base_type,
            "interfaces": record.interfaces,
            "generic_parameters": record.generic_params,
            "declaring_type": f"0x{record.declaring_type:08x}"
            if record.declaring_type
            else None,
            "compiler_generated": record.compiler_generated,
            "attributes": record.attributes,
            "cs_file": _rel(record.cs_path, root),
            "il_file": _rel(record.il_path, root),
            "decompile_error": record.error,
            "disassemble_error": record.il_error,
            "members": [
                {
                    "name": item.name,
                    "token": f"0x{item.token:08x}",
                    "type": item.type,
                    "flags": item.flags,
                    "constant": item.constant,
                }
                for item in record.fields
            ],
            "properties": [
                {
                    "name": item.name,
                    "token": f"0x{item.token:08x}",
                    "type": item.type,
                    "getter": f"0x{item.getter:08x}" if item.getter else None,
                    "setter": f"0x{item.setter:08x}" if item.setter else None,
                }
                for item in record.properties
            ],
            "events": [
                {
                    "name": item.name,
                    "token": f"0x{item.token:08x}",
                    "type": item.type,
                }
                for item in record.events
            ],
            "methods": [
                _method_summary(session.methods[method_id])
                for method_id in record.methods
            ],
            "c_decl": None,
        }


def _method_summary(method: MethodInfo) -> dict[str, Any]:
    return {
        "name": method.name,
        "token": f"0x{method.token:08x}",
        "address": method.address,
        "prototype": method.prototype,
        "flags": method.flags,
        "rva": f"0x{method.rva:x}" if method.rva else None,
        "il_size": method.il_size,
        "cs_lines": [method.cs_start, method.cs_end] if method.cs_start else None,
        "il_lines": [method.il_start, method.il_end] if method.il_start else None,
    }


def _source_paths(
    session: DotnetSession, method: MethodInfo, root: Path
) -> tuple[str | None, str | None]:
    record = session.types.get((method.assembly, method.type_token))
    if record is None:
        return None, None
    return _rel(record.cs_path, root), _rel(record.il_path, root)


def is_dead(session: DotnetSession, method: MethodInfo, roots: set[int]) -> bool:
    if method.callers or method.id in roots or method.owner_method is not None:
        return False
    if method.is_virtual or method.is_constructor or method.unmanaged_entry:
        return False
    return method.name not in {".cctor", "Finalize", "Dispose"}


def iter_function_rows(
    session: DotnetSession, root: Path, roots: set[int]
) -> Iterator[dict[str, Any]]:
    by_id = session.methods
    for method in session.methods:
        cs_file, il_file = _source_paths(session, method, root)
        yield {
            "address": method.address,
            "name": method.full_name,
            "c_name": _method_label(method),
            "prototype": method.prototype,
            "size": method.il_size,
            "calltype": "static"
            if method.is_static
            else ("virtual" if method.is_virtual else "instance"),
            "return_type": method.return_type,
            "params": [{"name": name, "type": kind} for name, kind in method.params],
            "locals": [],
            "decl_file": None,
            "decl_dir": None,
            "decl_line": None,
            "nargs": len(method.params),
            "nlocals": None,
            "stackframe": None,
            "callees": [by_id[item].address for item in method.callees],
            "callees_imports": method.external_calls,
            "callee_count": len(method.callees) + len(method.external_calls),
            "callers": [by_id[item].address for item in method.callers],
            "caller_count": len(method.callers),
            "dead_code": is_dead(session, method, roots),
            "source_file": cs_file,
            "source_line_start": method.cs_start,
            "source_line_end": method.cs_end,
            "tree_source_file": None,
            "tree_source_line_start": None,
            "tree_source_line_end": None,
            "asm_file": il_file,
            "asm_line_start": method.il_start,
            "asm_line_end": method.il_end,
            "assembly": method.assembly_name,
            "token": f"0x{method.token:08x}",
            "rva": f"0x{method.rva:x}" if method.rva else None,
            "flags": method.flags,
            "impl_flags": method.impl_flags,
            "attributes": method.attributes,
            "compiler_generated": method.compiler_generated,
            "owner": by_id[method.owner_method].address
            if method.owner_method is not None
            else None,
            "pinvoke": {"module": method.pinvoke_module, "entry": method.pinvoke_entry}
            if method.pinvoke_module
            else None,
            "unmanaged_export": method.unmanaged_entry,
            "string_ref_count": method.string_ref_count,
            "field_refs": method.field_refs,
        }


def iter_function_index_rows(
    session: DotnetSession, root: Path
) -> Iterator[dict[str, Any]]:
    for method in session.methods:
        cs_file, il_file = _source_paths(session, method, root)
        yield {
            "address": method.address,
            "name": method.full_name,
            "c": {
                "path": cs_file,
                "line_start": method.cs_start,
                "line_end": method.cs_end,
            }
            if cs_file and method.cs_start
            else None,
            "asm": {
                "path": il_file,
                "line_start": method.il_start,
                "line_end": method.il_end,
            }
            if il_file and method.il_start
            else None,
            "origin": None,
        }


# --------------------------------------------------------------------------
# strings / imports / exports / sections
# --------------------------------------------------------------------------


def iter_string_rows(session: DotnetSession) -> Iterator[dict[str, Any]]:
    by_id = session.methods
    for info in session.assemblies:
        heap = info.pe.stream("#US")
        base = heap.offset if heap is not None else 0
        for offset, value in info.user_strings:
            xrefs = [
                {
                    "function": by_id[method_id].full_name,
                    "address": by_id[method_id].address,
                    "access": "read",
                }
                for method_id in session.string_xrefs.get((info.index, offset), ())
            ]
            yield {
                "vaddr": f"{info.name}!0x{0x70000000 | offset:08x}",
                "paddr": f"0x{base + offset:x}",
                "size": len(value.encode("utf-16-le")),
                "length": len(value),
                "section": f"{info.name}#US",
                "type": "utf16",
                "value": value,
                "xrefs": xrefs,
            }


def imports_json(session: DotnetSession) -> dict[str, Any]:
    groups: list[dict[str, Any]] = []
    for scope, members in sorted(session.external_refs.items()):
        groups.append(
            {
                "dll": scope,
                "kind": "assembly",
                "functions": [
                    {
                        "name": name,
                        "address": None,
                        "delay": False,
                        "callers": [session.methods[item].address for item in callers],
                    }
                    for name, callers in sorted(members.items())
                ],
            }
        )
    pinvoke: dict[str, list[MethodInfo]] = {}
    for method in session.methods:
        if method.pinvoke_module:
            pinvoke.setdefault(method.pinvoke_module, []).append(method)
    for module, methods in sorted(pinvoke.items()):
        groups.append(
            {
                "dll": module,
                "kind": "pinvoke",
                "functions": [
                    {
                        "name": method.pinvoke_entry or method.name,
                        "address": method.address,
                        "delay": True,
                        "managed": method.full_name,
                        "callers": [
                            session.methods[item].address for item in method.callers
                        ],
                    }
                    for method in methods
                ],
            }
        )
    return {"imports": groups}


def _type_visible(session: DotnetSession, record: TypeInfo) -> bool:
    current: TypeInfo | None = record
    while current is not None:
        if current.visibility not in {
            "Public",
            "NestedPublic",
            "NestedFamily",
            "NestedFamORAssem",
        }:
            return False
        parent = current.declaring_type
        current = session.types.get((current.assembly, parent)) if parent else None
    return True


def export_roots(session: DotnetSession) -> list[tuple[str, MethodInfo]]:
    """(kind, method) for entry points, native exports, and public API."""
    rows: list[tuple[str, MethodInfo]] = []
    for info in session.assemblies:
        if info.entry_point is not None:
            method = session.method(info.index, info.entry_point)
            if method is not None:
                rows.append(("entrypoint", method))
    for method in session.methods:
        if method.unmanaged_entry:
            rows.append(("unmanaged-export", method))
        elif method.type_name == "<Module>" and method.name == ".cctor":
            rows.append(("module-initializer", method))
    for method in session.methods:
        info = session.assemblies[method.assembly]
        if info.entry_point is not None:
            continue  # executables: the entry point is the API
        if "Public" not in method.flags or method.compiler_generated:
            continue
        record = session.types.get((method.assembly, method.type_token))
        if record is not None and _type_visible(session, record):
            rows.append(("public", method))
    return rows


def exports_json(session: DotnetSession) -> dict[str, Any]:
    rows = []
    for ordinal, (kind, method) in enumerate(export_roots(session)):
        rows.append(
            {
                "ordinal": ordinal,
                "name": method.full_name,
                "address": method.address,
                "is_forwarder": False,
                "forwarder_target": method.unmanaged_entry,
                "kind": kind,
                "assembly": method.assembly_name,
            }
        )
    return {"exports": rows}


def sections_json(session: DotnetSession) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for info in session.assemblies:
        for section in info.pe.sections:
            rows.append(
                {
                    "assembly": info.name,
                    "name": section.name,
                    "vaddr": f"0x{info.pe.image_base + section.virtual_address:x}",
                    "paddr": f"0x{section.raw_offset:x}",
                    "size": section.raw_size,
                    "vsize": section.virtual_size,
                    "type": "pe-section",
                    "permissions": section.perms,
                    "rwx": section.perms == "rwx",
                    "entropy": None,
                }
            )
        for stream in info.pe.streams:
            rows.append(
                {
                    "assembly": info.name,
                    "name": stream.name,
                    "vaddr": None,
                    "paddr": f"0x{stream.offset:x}",
                    "size": stream.size,
                    "vsize": stream.size,
                    "type": "metadata-stream",
                    "permissions": "r--",
                    "rwx": False,
                    "entropy": None,
                }
            )
    return {"sections": rows}


# --------------------------------------------------------------------------
# reachable / namespace graph / triage
# --------------------------------------------------------------------------


def reachable_json(session: DotnetSession) -> tuple[dict[str, Any], set[int]]:
    roots = [method.id for _, method in export_roots(session)]
    owned: dict[int, list[int]] = {}
    for method in session.methods:
        if method.owner_method is not None:
            owned.setdefault(method.owner_method, []).append(method.id)
    depths: dict[int, int] = {}
    queue: deque[int] = deque()
    for root in roots:
        if root not in depths:
            depths[root] = 0
            queue.append(root)
    while queue:
        current = queue.popleft()
        depth = depths[current]
        method = session.methods[current]
        for target in [*method.callees, *owned.get(current, ())]:
            if target not in depths:
                depths[target] = depth + 1
                queue.append(target)
    rows = [
        {
            "address": session.methods[item].address,
            "name": session.methods[item].full_name,
            "depth": depth,
        }
        for item, depth in sorted(depths.items(), key=lambda pair: (pair[1], pair[0]))
    ]
    return (
        {
            "reachable": rows,
            "unreachable_count": len(session.methods) - len(depths),
            "seed_count": len(roots),
            "note": "virtual/interface dispatch and reflection are not followed",
        },
        set(roots),
    )


def namespace_graph_json(session: DotnetSession) -> dict[str, Any]:
    def key(method: MethodInfo) -> tuple[str, str]:
        record = session.types.get((method.assembly, method.type_token))
        return method.assembly_name, record.namespace if record else ""

    counts: dict[tuple[str, str], int] = {}
    folders: dict[tuple[str, str], str] = {}
    for record in session.types.values():
        name = (session.assemblies[record.assembly].name, record.namespace)
        counts[name] = counts.get(name, 0) + 1
        if record.cs_path is not None and name not in folders:
            folders[name] = record.cs_path.parent.as_posix()
    calls: dict[tuple[str, str], dict[str, int]] = {}
    external: dict[tuple[str, str], dict[str, int]] = {}
    for method in session.methods:
        source = key(method)
        for callee in method.callees:
            target = key(session.methods[callee])
            if target != source:
                label = f"{target[0]}:{target[1] or '<global>'}"
                bucket = calls.setdefault(source, {})
                bucket[label] = bucket.get(label, 0) + 1
        for call in method.external_calls:
            scope = call[1:].split("]", 1)[0] if call.startswith("[") else "?"
            bucket = external.setdefault(source, {})
            bucket[scope] = bucket.get(scope, 0) + 1
    rows = []
    for name in sorted(counts):
        rows.append(
            {
                "assembly": name[0],
                "namespace": name[1] or "<global>",
                "types": counts[name],
                "folder": folders.get(name),
                "calls_namespaces": [
                    {"namespace": target, "calls": count}
                    for target, count in sorted(
                        calls.get(name, {}).items(), key=lambda pair: -pair[1]
                    )
                ],
                "calls_assemblies": [
                    {"assembly": target, "calls": count}
                    for target, count in sorted(
                        external.get(name, {}).items(), key=lambda pair: -pair[1]
                    )
                ],
            }
        )
    return {"namespaces": rows}


def interesting_strings(
    values: Iterable[tuple[str, str]], *, limit: int = 100
) -> list[dict[str, Any]]:
    buckets: dict[int, list[dict[str, Any]]] = {
        tier: [] for tier, _ in INTERESTING_STRING_TIERS
    }
    seen: set[str] = set()
    for address, value in values:
        if len(value) < 6 or len(value) > 512 or value in seen:
            continue
        for tier, pattern in INTERESTING_STRING_TIERS:
            if pattern.search(value):
                seen.add(value)
                buckets[tier].append({"value": value, "address": address, "tier": tier})
                break
    rows: list[dict[str, Any]] = []
    for tier in sorted(buckets):
        rows.extend(buckets[tier])
    return rows[:limit]


def suspicious_apis(session: DotnetSession) -> list[dict[str, Any]]:
    found: dict[str, dict[str, set[str]]] = {}
    for method in session.methods:
        for name in method.external_calls:
            for label, pattern in SUSPICIOUS_API_PATTERNS:
                if pattern.search(name):
                    found.setdefault(label, {}).setdefault(name, set()).add(
                        method.address
                    )
                    break
    return [
        {
            "category": label,
            "apis": [
                {
                    "name": name,
                    "caller_count": len(callers),
                    "callers": sorted(callers)[:10],
                }
                for name, callers in sorted(apis.items())
            ],
        }
        for label, apis in found.items()
    ]


def triage_json(
    session: DotnetSession,
    found: DotnetInput,
    reachable: dict[str, Any],
    native_libs: list[dict[str, Any]],
) -> dict[str, Any]:
    strings = (
        (f"{info.name}!0x{0x70000000 | offset:08x}", value)
        for info in session.assemblies
        for offset, value in info.user_strings
    )
    pinvoke: dict[str, list[str]] = {}
    for method in session.methods:
        if method.pinvoke_module:
            pinvoke.setdefault(method.pinvoke_module, []).append(
                method.pinvoke_entry or method.name
            )
    main = session.assemblies[0] if session.assemblies else None
    return {
        "binary_type": f"dotnet-{found.kind}",
        "arch": "cil",
        "bits": 64 if main is not None and main.pe.pe32_plus else 32,
        "assemblies": [
            {
                "name": info.name,
                "version": info.version,
                "kind": info.kind,
                "target_framework": info.target_framework,
                "entry_point": _entry_label(session, info),
                "ready_to_run": info.pe.ready_to_run,
                "mixed_mode": info.pe.mixed_mode,
                "strong_name_signed": "StrongNameSigned" in info.pe.cor_flag_names,
                "types": len(info.types),
                "obfuscation_hints": info.obfuscation_hints,
            }
            for info in session.assemblies
        ],
        "skipped_assemblies": [
            {"file": item.entry, "reason": item.reason}
            for item in found.assemblies
            if not item.include
        ][:200],
        "type_count": len(session.types),
        "method_count": len(session.methods),
        "pinvoke": [
            {"module": module, "functions": sorted(set(names))[:50]}
            for module, names in sorted(pinvoke.items())
        ],
        "suspicious_apis": suspicious_apis(session),
        "resources": [
            {"assembly": info.name, "name": resource.name, "size": resource.size}
            for info in session.assemblies
            for resource in info.resources
        ][:100],
        "native_libs": [
            {
                "arch": item["abi"],
                "name": item["name"],
                "status": item["status"],
                "export_dir": item.get("export_dir"),
            }
            for item in native_libs
        ],
        "strings_of_interest": interesting_strings(strings),
        "reachable_count": len(reachable.get("reachable", [])),
        "unreachable_count": reachable.get("unreachable_count", 0),
    }


def resources_json(session: DotnetSession, root: Path) -> dict[str, Any]:
    return {
        "resources": [
            {
                "assembly": info.name,
                "name": resource.name,
                "kind": resource.kind,
                "size": resource.size,
                "public": resource.public,
                "linked_file": resource.file,
                "path": _rel(resource.path, root),
                "entries": resource.entries,
                "error": resource.error,
            }
            for info in session.assemblies
            for resource in info.resources
        ]
    }


# --------------------------------------------------------------------------
# Generated AGENTS.md
# --------------------------------------------------------------------------


def build_dotnet_agents(
    *, title: str, kind: str, assemblies: list[str], native: bool, native_count: int
) -> str:
    shown = ", ".join(f"`{name}`" for name in assemblies[:8])
    if len(assemblies) > 8:
        shown += ", ..."
    lines = [
        "# AGENTS",
        "",
        f"You are working inside a ToCode .NET export of `{title}` ({kind}; assemblies: {shown or 'none'}).",
        "Treat the recovered C#, the IL, the metadata, and the extracted resources as evidence for reverse engineering.",
        "",
        "## Mission",
        "",
        "Reverse the program, answer user questions, or serve as an oracle/helper to the user regarding this recovered source code.",
        "Write a report only when the user asks for one; otherwise keep findings focused on the question or task at hand.",
        "Do not refactor or modify the generated export unless the user explicitly asks for edits.",
        "Use subagents only for narrow evidence-gathering tasks such as strings, entry paths, or one namespace.",
        "",
        "## Files",
        "",
        "- `src/raw/<Assembly>/<Namespace>/.../<Type>.cs`: decompiled C# (ICSharpCode.Decompiler), one file per top-level type with its nested types, folders follow namespaces like a dnSpy/ILSpy project export.",
        "- `src/raw/<Assembly>/<Namespace>/.../<Type>.il`: IL disassembly of the same type with RVA, raw bytecode, and metadata tokens per instruction. Read it when the C# is ambiguous, obfuscated, or failed to decompile.",
        "- `src/raw/<Assembly>/Properties/AssemblyInfo.cs` and `Manifest.il`: assembly/module attributes, references, and the IL manifest; `<Assembly>.csproj`: a project file for the recovered sources.",
        "- `assemblies.json`: every assembly found (version, target framework, entry point, flags, ReadyToRun/mixed-mode, references, resources, obfuscation hints, and why skipped assemblies were not decompiled).",
        "- `types.json`: every type with base type, interfaces, attributes, fields, properties, events, and methods with their C#/IL line ranges.",
        "- `functions.json`: per-method callers/callees, external (framework/library) calls, P/Invoke targets, field references, and C#/IL line ranges. `address` is `<Assembly>!0x<metadata token>`.",
        "- `function-index.json`: exact C# (`c`) and IL (`asm`) file and line range for each method.",
        "- `strings.json`: the user-string heap (`ldstr` literals) with the methods that load each string.",
        "- `imports.json`: members referenced from other assemblies (grouped by assembly) and P/Invoke imports (grouped by native library).",
        "- `exports.json`: entry points, module initializers, `UnmanagedCallersOnly` native exports, and the public API of libraries.",
        "- `reachable.json`: methods reachable from those roots with call depth (virtual dispatch and reflection are not followed).",
        "- `namespace-graph.json`: inter-namespace and inter-assembly call graph.",
        "- `sections.json`: PE sections and metadata streams of every assembly.",
        "- `resources.json` and `data/resources/<Assembly>/`: embedded resources, with `.resources` files decoded to JSON.",
        "- `container.json`: the single-file bundle / NuGet package / assembly layout and where each entry was extracted.",
        "- `triage.json`: first-read summary: assemblies, entry points, P/Invoke, suspicious API families, resources, native libraries, strings of interest, reachability counts.",
    ]
    if native:
        lines.append(
            f"- `native/<arch>/<lib>/`: a complete nested ToCode export for each of the {native_count} native libraries (mixed-mode code, bundled or P/Invoke'd libraries). `native-libs.json` lists their status; `lib/<arch>/` holds the extracted files.",
        )
    else:
        lines.append(
            "- `native/`: not generated (no native code found, or `--no-native`); see `native-libs.json`.",
        )
    lines.extend(
        [
            "- `project.json` and `export-manifest.json`: top-level export paths and artifact inventory.",
            "- `tocode.log`: export history including per-type decompilation and native export status.",
            "- `CLAUDE.md`: Claude entrypoint that references `AGENTS.md`.",
            "",
            "## Working Style",
            "",
            "- Start with `triage.json`, `assemblies.json`, `strings.json`, and `reachable.json`.",
            "- Use `functions.json` and `function-index.json` to open only the method line ranges you need, in C# or IL.",
            "- Compiler-generated types (`<>c`, `<Method>d__N`) are folded back into their owners in the C#; `owner` in `functions.json` links state machines and lambdas to the method that created them.",
            "- Follow P/Invoke methods into `native/` exports when the logic lives in native code.",
            "- Treat obfuscated names as opaque; rely on strings, framework calls, and resources to recover intent.",
            "- Cite file paths, type and method names, metadata tokens, and line numbers for every major claim.",
            "- Be explicit about uncertainty, decompilation failures (`types.json` `decompile_error`), and unresolved references.",
            "",
        ]
    )
    return "\n".join(lines)
