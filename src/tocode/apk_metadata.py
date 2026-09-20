"""JSON metadata documents for APK exports.

The document shapes mirror ``metadata.py`` wherever a native concept has a
Dalvik equivalent (functions, strings, imports, exports, sections, reachable,
triage, project, export-manifest) so agents and tooling that already read
ToCode exports keep working. Android-only facts live in ``manifest.json``,
``classes.json``, ``package-graph.json``, and ``native-libs.json``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Iterator
import xml.etree.ElementTree as ET

from .backends.asc import (
    AscSession,
    ClassRecord,
    MethodRecord,
    StringRecord,
    java_type,
)
from .metadata import _replace_with_retry


ANDROID_NS = "http://schemas.android.com/apk/res/android"
_A = f"{{{ANDROID_NS}}}"

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
DANGEROUS_PERMISSION_HINTS = (
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "CALL_PHONE",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "READ_PHONE_STATE",
    "GET_ACCOUNTS",
    "BLUETOOTH_CONNECT",
    "QUERY_ALL_PACKAGES",
    "RECEIVE_BOOT_COMPLETED",
    "PACKAGE_USAGE_STATS",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
)
# Strings worth reading first, in priority order (URLs/endpoints and secrets
# before generic crypto and platform hints). Each entry is (tier, pattern).
INTERESTING_STRING_TIERS: tuple[tuple[int, re.Pattern[str]], ...] = (
    (
        0,
        re.compile(
            r"(https?://|wss?://|ftp://|content://|\.onion\b|"
            r"BEGIN (RSA|EC|OPENSSH|PGP)? ?PRIVATE KEY|"
            r"\b(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|"
            r"bearer|authorization|passw(or)?d)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        1,
        re.compile(
            r"(/data/(local|data)/|/system/(bin|xbin|app)/|/proc/self|/dev/socket|"
            r"/bin/sh\b|\bsu\b|superuser|magisk|\bxposed|\bfrida|substrate|"
            r"\b(goldfish|ranchu|genymotion|bluestacks|qemu)\b|"
            r"System\.loadLibrary|dlopen|Runtime\.exec|ptrace|"
            r"\b\d{1,3}(\.\d{1,3}){3}(:\d{2,5})?\b)",
            re.IGNORECASE,
        ),
    ),
    (
        2,
        re.compile(
            r"^(javax\.crypto|AES/|RSA/|DES/|DESede/|HmacSHA|PBKDF2|SHA-?256|"
            r"SecretKeySpec|network_security_config|DisabledHostnameVerifier)",
        ),
    ),
)


def write_json_rows(
    path: Path,
    key: str,
    rows: Iterable[dict[str, Any]],
    *,
    header: dict[str, Any] | None = None,
) -> int:
    """Write ``{**header, key: [...rows]}`` without holding the array in memory.

    The big APK documents (one row per method, class, or string) reach hundreds
    of megabytes; ``json.dumps`` on the whole structure would need several
    copies of that at once, so rows are serialized one at a time straight into
    the file and the result is renamed into place like ``write_json``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        handle.write("{\n")
        for name, value in (header or {}).items():
            handle.write(f"  {json.dumps(name)}: {json.dumps(value)},\n")
        handle.write(f"  {json.dumps(key)}: [")
        for row in rows:
            handle.write("\n    " if count == 0 else ",\n    ")
            handle.write(json.dumps(row))
            count += 1
        handle.write("\n  ]\n" if count else "]\n")
        handle.write("}\n")
    try:
        _replace_with_retry(tmp_path, path)
    except OSError:
        tmp_path.unlink(missing_ok=True)
        raise
    return count


@dataclass(slots=True)
class ManifestComponent:
    kind: str
    name: str
    exported: bool | None
    permission: str | None
    intent_filters: list[dict[str, list[str]]]
    attributes: dict[str, str]


@dataclass(slots=True)
class ManifestInfo:
    apk: str
    package: str
    version_code: str | None
    version_name: str | None
    min_sdk: str | None
    target_sdk: str | None
    compile_sdk: str | None
    split: str | None
    permissions: list[str]
    defined_permissions: list[str]
    features: list[dict[str, Any]]
    libraries: list[str]
    application: dict[str, Any]
    components: list[ManifestComponent]
    main_activities: list[str]
    parse_error: str | None = None
    raw_attributes: dict[str, str] = field(default_factory=dict)


def _attr(node: ET.Element, name: str) -> str | None:
    value = node.get(f"{_A}{name}")
    if value is None:
        value = node.get(name)
    return value


def _bool_attr(node: ET.Element, name: str) -> bool | None:
    value = _attr(node, name)
    if value is None:
        return None
    return value.strip().lower() == "true"


def _plain_attrs(node: ET.Element) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in node.attrib.items():
        result[key.replace(_A, "android:")] = value
    return result


def parse_manifest(xml_text: str, *, apk_name: str) -> ManifestInfo:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return ManifestInfo(
            apk=apk_name,
            package="",
            version_code=None,
            version_name=None,
            min_sdk=None,
            target_sdk=None,
            compile_sdk=None,
            split=None,
            permissions=[],
            defined_permissions=[],
            features=[],
            libraries=[],
            application={},
            components=[],
            main_activities=[],
            parse_error=str(exc),
        )
    uses_sdk = root.find("uses-sdk")
    application = root.find("application")
    components: list[ManifestComponent] = []
    main_activities: list[str] = []
    app_attrs: dict[str, Any] = {}
    if application is not None:
        app_attrs = _plain_attrs(application)
        for tag in COMPONENT_TAGS:
            for node in application.iter(tag):
                component = _component(tag, node)
                components.append(component)
                if tag in {"activity", "activity-alias"} and _is_launcher(component):
                    main_activities.append(component.name)
    return ManifestInfo(
        apk=apk_name,
        package=root.get("package", "") or "",
        version_code=_attr(root, "versionCode"),
        version_name=_attr(root, "versionName"),
        min_sdk=_attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None,
        target_sdk=_attr(uses_sdk, "targetSdkVersion")
        if uses_sdk is not None
        else None,
        compile_sdk=_attr(root, "compileSdkVersion"),
        split=root.get("split"),
        permissions=[
            value
            for value in (_attr(node, "name") for node in root.iter("uses-permission"))
            if value
        ]
        + [
            value
            for value in (
                _attr(node, "name") for node in root.iter("uses-permission-sdk-23")
            )
            if value
        ],
        defined_permissions=[
            value
            for value in (_attr(node, "name") for node in root.iter("permission"))
            if value
        ],
        features=[
            {
                "name": _attr(node, "name"),
                "required": _bool_attr(node, "required"),
                "glEsVersion": _attr(node, "glEsVersion"),
            }
            for node in root.iter("uses-feature")
        ],
        libraries=[
            value
            for value in (
                _attr(node, "name")
                for node in list(root.iter("uses-library"))
                + list(root.iter("uses-native-library"))
            )
            if value
        ],
        application=app_attrs,
        components=components,
        main_activities=main_activities,
        raw_attributes={
            key.replace(_A, "android:"): value for key, value in root.attrib.items()
        },
    )


def _component(tag: str, node: ET.Element) -> ManifestComponent:
    filters: list[dict[str, list[str]]] = []
    for item in node.findall("intent-filter"):
        filters.append(
            {
                "actions": [
                    value
                    for value in (
                        _attr(child, "name") for child in item.findall("action")
                    )
                    if value
                ],
                "categories": [
                    value
                    for value in (
                        _attr(child, "name") for child in item.findall("category")
                    )
                    if value
                ],
                "data": [
                    " ".join(
                        f"{key}={value}"
                        for key, value in sorted(_plain_attrs(child).items())
                    )
                    for child in item.findall("data")
                ],
            }
        )
    exported = _bool_attr(node, "exported")
    if exported is None and filters:
        # Pre-API 31 default: components with intent filters are exported.
        exported = True
    name = _attr(node, "name") or ""
    if tag == "activity-alias":
        name = _attr(node, "targetActivity") or name
    return ManifestComponent(
        kind=tag,
        name=name,
        exported=exported,
        permission=_attr(node, "permission"),
        intent_filters=filters,
        attributes=_plain_attrs(node),
    )


def _is_launcher(component: ManifestComponent) -> bool:
    for item in component.intent_filters:
        if "android.intent.action.MAIN" in item["actions"] and (
            "android.intent.category.LAUNCHER" in item["categories"]
            or "android.intent.category.LEANBACK_LAUNCHER" in item["categories"]
        ):
            return True
    return False


def resolve_component_class(package: str, name: str) -> str:
    if not name:
        return name
    if name.startswith("."):
        return f"{package}{name}"
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def class_descriptor(java_name: str) -> str:
    return f"L{java_name.replace('.', '/')};"


def _component_json(package: str, component: ManifestComponent) -> dict[str, Any]:
    resolved = resolve_component_class(package, component.name)
    return {
        "kind": component.kind,
        "name": resolved,
        "descriptor": class_descriptor(resolved) if resolved else None,
        "exported": component.exported,
        "permission": component.permission,
        "intent_filters": component.intent_filters,
        "attributes": component.attributes,
    }


def manifest_json(
    base: ManifestInfo, splits: list[ManifestInfo], *, xml_path: Path
) -> dict[str, Any]:
    package = base.package
    return {
        "package": package,
        "apk": base.apk,
        "manifest_xml": str(xml_path),
        "version_code": base.version_code,
        "version_name": base.version_name,
        "min_sdk": base.min_sdk,
        "target_sdk": base.target_sdk,
        "compile_sdk": base.compile_sdk,
        "attributes": base.raw_attributes,
        "application": base.application,
        "main_activities": [
            resolve_component_class(package, item) for item in base.main_activities
        ],
        "permissions": base.permissions,
        "dangerous_permissions": dangerous_permissions(base.permissions),
        "defined_permissions": base.defined_permissions,
        "uses_features": base.features,
        "uses_libraries": base.libraries,
        "components": [_component_json(package, item) for item in base.components],
        "exported_components": [
            _component_json(package, item) for item in base.components if item.exported
        ],
        "parse_error": base.parse_error,
        "splits": [
            {
                "apk": item.apk,
                "split": item.split,
                "package": item.package,
                "attributes": item.raw_attributes,
                "parse_error": item.parse_error,
            }
            for item in splits
        ],
    }


def dangerous_permissions(permissions: Iterable[str]) -> list[str]:
    return [
        item
        for item in permissions
        if any(item.endswith(hint) for hint in DANGEROUS_PERMISSION_HINTS)
    ]


# --------------------------------------------------------------------------
# Classes / functions
# --------------------------------------------------------------------------


def _relpath(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _method_json(
    method: MethodRecord, session: AscSession, root: Path
) -> dict[str, Any]:
    owner = session.class_by_descriptor(method.class_descriptor)
    return {
        "address": method.address,
        "dex": method.dex,
        "method_index": method.index,
        "name": method.name,
        "class": java_type(method.class_descriptor),
        "descriptor": method.descriptor,
        "prototype": method.prototype,
        "access": method.flag_names,
        "native": method.is_native,
        "abstract": method.is_abstract,
        "static": method.is_static,
        "code_size": method.code_size,
        "registers": method.registers,
        "source_file": _relpath(owner.java_path, root) if owner else None,
        "source_line_start": method.line_start,
        "source_line_end": method.line_end,
    }


def iter_class_rows(session: AscSession, root: Path) -> Iterator[dict[str, Any]]:
    for record in session.classes:
        yield {
            "descriptor": record.descriptor,
            "name": record.java_name,
            "package": record.package,
            "simple_name": record.simple_name,
            "dex": record.dex,
            "class_index": record.index,
            "access": record.flag_names,
            "interface": record.is_interface,
            "superclass": java_type(record.superclass) if record.superclass else None,
            "interfaces": [java_type(item) for item in record.interfaces],
            "source_file": record.source_file,
            "java_file": _relpath(record.java_path, root),
            "line_count": record.line_count,
            "decompile_error": record.error,
            "method_count": len(record.methods),
            "native_method_count": sum(1 for m in record.methods if m.is_native),
            "methods": [
                {
                    "name": item.name,
                    "address": item.address,
                    "prototype": item.prototype,
                    "access": item.flag_names,
                    "native": item.is_native,
                    "code_size": item.code_size,
                    "line_start": item.line_start,
                    "line_end": item.line_end,
                }
                for item in record.methods
            ],
            "fields": [
                {
                    "name": item.name,
                    "type": java_type(item.type),
                    "descriptor": item.type,
                    "access": item.flag_names,
                    "static": item.is_static,
                }
                for item in record.fields
            ],
        }


def iter_function_rows(session: AscSession, root: Path) -> Iterator[dict[str, Any]]:
    by_id = {method.id: method for method in session.methods}
    for method in session.methods:
        owner = session.class_by_descriptor(method.class_descriptor)
        yield {
            "address": method.address,
            "name": method.descriptor,
            "c_name": f"{java_type(method.class_descriptor)}.{method.name}",
            "prototype": method.prototype,
            "size": method.code_size,
            "calltype": "static" if method.is_static else "virtual",
            "return_type": java_type(method.return_type),
            "params": [
                {"name": f"p{index}", "type": java_type(item)}
                for index, item in enumerate(method.params)
            ],
            "locals": [],
            "decl_file": owner.source_file if owner else None,
            "decl_dir": None,
            "decl_line": None,
            "nargs": len(method.params),
            "nlocals": max(0, method.registers - len(method.params)),
            "stackframe": method.registers,
            "callees": [
                by_id[item].address for item in method.callees if item in by_id
            ],
            "callees_imports": method.external_calls,
            "callee_count": len(method.callees) + len(method.external_calls),
            "callers": [
                by_id[item].address for item in method.callers if item in by_id
            ],
            "caller_count": len(method.callers),
            "dead_code": not method.callers
            and not (owner and _is_entry_class(owner))
            and method.name not in {"<init>", "<clinit>"},
            "source_file": _relpath(owner.java_path, root) if owner else None,
            "source_line_start": method.line_start,
            "source_line_end": method.line_end,
            "tree_source_file": None,
            "tree_source_line_start": None,
            "tree_source_line_end": None,
            "asm_file": None,
            "asm_line_start": None,
            "asm_line_end": None,
            "dex": method.dex,
            "class": java_type(method.class_descriptor),
            "access": method.flag_names,
            "native": method.is_native,
            "string_ref_count": method.string_ref_count,
            "field_refs": method.field_refs,
        }


def _is_entry_class(record: ClassRecord) -> bool:
    return record.entry


def iter_function_index_rows(
    session: AscSession, root: Path
) -> Iterator[dict[str, Any]]:
    for method in session.methods:
        owner = session.class_by_descriptor(method.class_descriptor)
        java_file = _relpath(owner.java_path, root) if owner else None
        yield {
            "address": method.address,
            "name": method.descriptor,
            "c": {
                "path": java_file,
                "line_start": method.line_start,
                "line_end": method.line_end,
            }
            if java_file
            else None,
            "asm": None,
            "origin": {"file": owner.source_file, "line": None}
            if owner and owner.source_file
            else None,
        }


# --------------------------------------------------------------------------
# Strings / imports / exports / sections
# --------------------------------------------------------------------------


def iter_string_rows(session: AscSession) -> Iterator[dict[str, Any]]:
    by_id = {method.id: method for method in session.methods}
    for item in session.strings:
        xrefs = [
            {
                "function": by_id[method_id].descriptor,
                "address": by_id[method_id].address,
                "access": "read",
            }
            for method_id in session.string_xrefs.get((item.dex, item.index), ())
            if method_id in by_id
        ]
        yield {
            "vaddr": f"{item.dex}:0x{item.offset:x}",
            "paddr": f"0x{item.offset:x}",
            "size": len(item.value.encode("utf-8", errors="replace")),
            "length": len(item.value),
            "section": item.dex,
            "type": "mutf8",
            "value": item.value,
            "xrefs": xrefs,
        }


def imports_json(session: AscSession) -> dict[str, Any]:
    groups: dict[str, dict[str, dict[str, Any]]] = {}
    for method in session.methods:
        for descriptor in method.external_calls:
            owner = descriptor.split("->", 1)[0]
            package = java_type(owner)
            package = package.rsplit(".", 1)[0] if "." in package else package
            entry = groups.setdefault(package, {}).setdefault(
                descriptor,
                {
                    "name": descriptor,
                    "address": None,
                    "delay": False,
                    "class": java_type(owner),
                    "callers": [],
                },
            )
            if len(entry["callers"]) < 32:
                entry["callers"].append(method.address)
    imports: list[dict[str, Any]] = []
    for package, members in sorted(groups.items()):
        rows: list[dict[str, Any]] = sorted(
            members.values(), key=lambda row: str(row["name"])
        )
        imports.append({"dll": package, "functions": rows})
    return {"imports": imports}


def exports_json(session: AscSession, manifest: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for ordinal, component in enumerate(manifest.get("exported_components", [])):
        record = (
            session.class_by_descriptor(component["descriptor"])
            if component.get("descriptor")
            else None
        )
        rows.append(
            {
                "ordinal": ordinal,
                "name": component["name"],
                "address": record.methods[0].address
                if record and record.methods
                else None,
                "is_forwarder": False,
                "forwarder_target": None,
                "kind": component["kind"],
                "descriptor": component["descriptor"],
                "defined_in_dex": record is not None,
                "intent_filters": component["intent_filters"],
            }
        )
    for method in session.methods:
        if method.is_native:
            rows.append(
                {
                    "ordinal": len(rows),
                    "name": method.descriptor,
                    "address": method.address,
                    "is_forwarder": True,
                    "forwarder_target": jni_symbol(method),
                    "kind": "jni",
                    "descriptor": method.descriptor,
                    "defined_in_dex": True,
                    "intent_filters": [],
                }
            )
    return {"exports": rows}


def jni_symbol(method: MethodRecord) -> str:
    def mangle(text: str) -> str:
        out: list[str] = []
        for ch in text:
            if ch == "_":
                out.append("_1")
            elif ch == ";":
                out.append("_2")
            elif ch == "[":
                out.append("_3")
            elif ch == "/" or ch == ".":
                out.append("_")
            elif ch.isascii() and ch.isalnum():
                out.append(ch)
            else:
                out.append(f"_0{ord(ch):04x}")
        return "".join(out)

    owner = method.class_descriptor[1:-1]
    return f"Java_{mangle(owner)}_{mangle(method.name)}"


@dataclass(slots=True)
class ApkEntry:
    apk: str
    name: str
    size: int
    compressed_size: int
    kind: str
    exported_path: str | None = None


def sections_json(entries: list[ApkEntry]) -> dict[str, Any]:
    rows = []
    for item in entries:
        rows.append(
            {
                "name": item.name,
                "apk": item.apk,
                "vaddr": None,
                "paddr": None,
                "size": item.size,
                "vsize": item.compressed_size,
                "type": item.kind,
                "permissions": "r--",
                "rwx": False,
                "entropy": None,
                "path": item.exported_path,
            }
        )
    return {"sections": rows}


# --------------------------------------------------------------------------
# Reachability / triage / package graph
# --------------------------------------------------------------------------


def entry_methods(session: AscSession, manifest: dict[str, Any]) -> list[MethodRecord]:
    seeds: list[MethodRecord] = []
    seen: set[int] = set()
    descriptors = [
        item["descriptor"]
        for item in manifest.get("components", [])
        if item.get("descriptor")
    ]
    app_name = manifest.get("application", {}).get("android:name")
    if app_name:
        descriptors.insert(
            0, class_descriptor(resolve_component_class(manifest["package"], app_name))
        )
    for descriptor in descriptors:
        record = session.class_by_descriptor(descriptor)
        if record is None:
            continue
        record.entry = True
        for method in record.methods:
            if method.id not in seen:
                seen.add(method.id)
                seeds.append(method)
    return seeds


def reachable_json(session: AscSession, seeds: list[MethodRecord]) -> dict[str, Any]:
    by_id = {method.id: method for method in session.methods}
    depths: dict[int, int] = {}
    queue: deque[int] = deque()
    for seed in seeds:
        if seed.id not in depths:
            depths[seed.id] = 0
            queue.append(seed.id)
    while queue:
        current = queue.popleft()
        depth = depths[current]
        for callee in by_id[current].callees:
            if callee not in depths:
                depths[callee] = depth + 1
                queue.append(callee)
    rows = [
        {
            "address": by_id[item].address,
            "name": by_id[item].descriptor,
            "depth": depth,
        }
        for item, depth in sorted(depths.items(), key=lambda pair: (pair[1], pair[0]))
    ]
    return {
        "reachable": rows,
        "unreachable_count": len(session.methods) - len(depths),
        "seed_count": len(seeds),
    }


def interesting_strings(
    strings: Iterable[StringRecord], *, limit: int = 100
) -> list[dict[str, Any]]:
    buckets: dict[int, list[dict[str, Any]]] = {
        tier: [] for tier, _ in INTERESTING_STRING_TIERS
    }
    seen: set[str] = set()
    for item in strings:
        value = item.value
        if len(value) < 6 or len(value) > 512 or value in seen:
            continue
        if value.startswith(("L", "[")) and value.endswith(";"):
            continue  # type descriptors
        if value.startswith("(") and ")" in value:
            continue  # method prototypes
        if value.startswith("SMAP\n") or value.endswith((".kt", ".java")):
            continue  # Kotlin source maps and source file names
        for tier, pattern in INTERESTING_STRING_TIERS:
            if pattern.search(value):
                seen.add(value)
                buckets[tier].append(
                    {
                        "value": value,
                        "address": f"{item.dex}:0x{item.offset:x}",
                        "tier": tier,
                    }
                )
                break
    rows: list[dict[str, Any]] = []
    for tier in sorted(buckets):
        rows.extend(buckets[tier])
    return rows[:limit]


def triage_json(
    session: AscSession,
    manifest: dict[str, Any],
    reachable: dict[str, Any],
    native_libs: list[dict[str, Any]],
    entries: list[ApkEntry],
) -> dict[str, Any]:
    packages: dict[str, int] = {}
    for record in session.classes:
        packages[record.package] = packages.get(record.package, 0) + 1
    top_packages = sorted(packages.items(), key=lambda pair: (-pair[1], pair[0]))[:25]
    native_methods = [
        {
            "name": method.descriptor,
            "address": method.address,
            "jni_symbol": jni_symbol(method),
        }
        for method in session.methods
        if method.is_native
    ]
    return {
        "binary_type": "apk",
        "arch": "dalvik",
        "bits": 32,
        "package": manifest.get("package"),
        "version_name": manifest.get("version_name"),
        "version_code": manifest.get("version_code"),
        "min_sdk": manifest.get("min_sdk"),
        "target_sdk": manifest.get("target_sdk"),
        "main_activities": manifest.get("main_activities", []),
        "application_class": manifest.get("application", {}).get("android:name"),
        "debuggable": manifest.get("application", {}).get("android:debuggable"),
        "allow_backup": manifest.get("application", {}).get("android:allowBackup"),
        "uses_cleartext_traffic": manifest.get("application", {}).get(
            "android:usesCleartextTraffic"
        ),
        "network_security_config": manifest.get("application", {}).get(
            "android:networkSecurityConfig"
        ),
        "dangerous_permissions": manifest.get("dangerous_permissions", []),
        "permission_count": len(manifest.get("permissions", [])),
        "component_counts": _component_counts(manifest.get("components", [])),
        "exported_components": [
            {"kind": item["kind"], "name": item["name"]}
            for item in manifest.get("exported_components", [])
        ],
        "dex_files": [
            {"name": image.name, "size": image.size, "apk": image.source_apk.name}
            for image in session.images
        ],
        "class_count": len(session.classes),
        "method_count": len(session.methods),
        "string_count": len(session.strings),
        "top_packages": [
            {"package": name or "<default>", "classes": count}
            for name, count in top_packages
        ],
        "native_libs": [
            {
                "abi": item["abi"],
                "name": item["name"],
                "status": item["status"],
                "export_dir": item.get("export_dir"),
            }
            for item in native_libs
        ],
        "native_methods": native_methods,
        "assets": [item.name for item in entries if item.kind == "asset"][:100],
        "strings_of_interest": interesting_strings(session.strings),
        "reachable_count": len(reachable.get("reachable", [])),
        "unreachable_count": reachable.get("unreachable_count", 0),
    }


def _component_counts(components: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in components:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
    return counts


def package_graph_json(session: AscSession) -> dict[str, Any]:
    by_id = {method.id: method for method in session.methods}
    calls: dict[str, dict[str, int]] = {}
    external: dict[str, dict[str, int]] = {}
    class_counts: dict[str, int] = {}
    for record in session.classes:
        class_counts[record.package] = class_counts.get(record.package, 0) + 1
    for method in session.methods:
        source = _package_of(method.class_descriptor)
        for callee in method.callees:
            target = _package_of(by_id[callee].class_descriptor)
            if target != source:
                bucket = calls.setdefault(source, {})
                bucket[target] = bucket.get(target, 0) + 1
        for descriptor in method.external_calls:
            target = _package_of(descriptor.split("->", 1)[0])
            bucket = external.setdefault(source, {})
            bucket[target] = bucket.get(target, 0) + 1
    packages = []
    for name in sorted(class_counts):
        packages.append(
            {
                "package": name or "<default>",
                "folder": f"src/raw/{name.replace('.', '/')}" if name else "src/raw",
                "classes": class_counts[name],
                "calls_packages": [
                    {"package": target or "<default>", "calls": count}
                    for target, count in sorted(
                        calls.get(name, {}).items(), key=lambda pair: -pair[1]
                    )
                ],
                "calls_external": [
                    {"package": target, "calls": count}
                    for target, count in sorted(
                        external.get(name, {}).items(), key=lambda pair: -pair[1]
                    )[:50]
                ],
            }
        )
    return {"packages": packages}


def _package_of(descriptor: str) -> str:
    name = java_type(descriptor)
    return name.rsplit(".", 1)[0] if "." in name else ""


# --------------------------------------------------------------------------
# Generated AGENTS.md
# --------------------------------------------------------------------------


def build_apk_agents(*, package: str, native: bool, native_count: int) -> str:
    lines = [
        "# AGENTS",
        "",
        f"You are working inside a ToCode APK export of `{package}`.",
        "Treat the recovered Java, the manifest, the metadata, and the extracted resources as evidence for reverse engineering.",
        "",
        "## Mission",
        "",
        "Reverse the app, answer user questions, or serve as an oracle/helper to the user regarding this recovered source code.",
        "Write a report only when the user asks for one; otherwise keep findings focused on the question or task at hand.",
        "Do not refactor or modify the generated export unless the user explicitly asks for edits.",
        "Use subagents only for narrow evidence-gathering tasks such as strings, component entry paths, or one package family.",
        "",
        "## Files",
        "",
        "- `src/raw/<package>/<Class>.java`: decompiled Java (ASC + androguard DAD), one file per class, folders follow Java packages. Inner classes are `Outer$Inner.java` next to their outer class.",
        "- `AndroidManifest.xml`: decoded manifest; `manifest.json`: parsed package, versions, SDKs, permissions, components with intent filters and exported state, application attributes, split manifests.",
        "- `classes.json`: every class with superclass, interfaces, access flags, fields, methods (with `address`), source file, and Java file/line ranges.",
        "- `functions.json`: per-method callers/callees, external (framework/library) calls, string/field/type references, prototypes, and source line ranges. `address` is `<dex>:<code offset>`.",
        "- `function-index.json`: exact Java file and line range for each method.",
        "- `strings.json`: DEX string pool with the methods that load each string.",
        "- `imports.json`: methods called but not defined in any DEX (Android framework, JDK, missing libraries), grouped by package.",
        "- `exports.json`: exported manifest components and JNI `native` methods with their expected `Java_...` symbol.",
        "- `reachable.json`: methods reachable from manifest components (Application, activities, services, receivers, providers) with call depth.",
        "- `package-graph.json`: inter-package call graph.",
        "- `sections.json`: every entry of the APK set (dex, native libs, resources, assets) with sizes.",
        "- `triage.json`: first-read summary: package, entry points, dangerous permissions, exported components, native libs and methods, strings of interest, reachability counts.",
        "- `native-libs.json`: every shared object found in the APK set with ABI, hash, and the status of its native decompilation.",
        "- `lib/<abi>/*.so`: extracted native libraries.",
    ]
    if native:
        lines.append(
            f"- `native/<abi>/<lib>/`: a complete nested ToCode export for each of the {native_count} native libraries (own `AGENTS.md`, `src/raw/*.c`, `functions.json`, `exports.json`, ...). Pair `Java_<pkg>_<Class>_<method>` exports there with the `native` methods listed in `exports.json` here.",
        )
    else:
        lines.append(
            "- `native/`: not generated (`--no-native`); native libraries are only extracted under `lib/`.",
        )
    lines.extend(
        [
            "- `data/apk/**`: every non-code APK entry verbatim (assets, res, META-INF, resources.arsc).",
            "- `data/res/**/*.xml`: binary XML resources decoded to text; `data/resources.json`: decoded `resources.arsc` string/resource tables.",
            "- `project.json` and `export-manifest.json`: top-level export paths and artifact inventory.",
            "- `tocode.log`: export history including native library decompilation status.",
            "- `CLAUDE.md`: Claude entrypoint that references `AGENTS.md`.",
            "",
            "## Working Style",
            "",
            "- Start with `triage.json`, `manifest.json`, `strings.json`, and `reachable.json`.",
            "- Use `functions.json` and `function-index.json` to open only the method line ranges you need.",
            "- Follow `native` methods into `native/<abi>/<lib>/` exports when the logic lives in JNI code.",
            "- Treat obfuscated names (`a.b.c`) as opaque; rely on string, field, and framework references to recover intent.",
            "- Cite file paths, class and method names, and line numbers for every major claim.",
            "- Be explicit about uncertainty, decompilation failures (`classes.json` `decompile_error`), and unresolved references.",
            "",
        ]
    )
    return "\n".join(lines)
