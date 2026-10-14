""".NET metadata tables read directly (no dnlib, no runtime).

Produces the binding facts the CLR itself uses: the assembly identity, the
AssemblyRef list, every MemberRef whose declaring type lives in another
assembly (with a canonical signature so it can be matched to the MethodDef it
binds to), the methods that reference each one (from an IL token scan), the
P/Invoke declarations (ImplMap -> ModuleRef), and type forwarders.
"""

from __future__ import annotations

import mmap
import struct
from typing import Any

from ..backends.dotnet_pe import (
    TOK_METHOD,
    PeInfo,
    method_body,
    parse_pe,
    scan_il_tokens,
)
from .model import (
    LIB_ASSEMBLY,
    LIB_PINVOKE,
    ExportSym,
    FileFacts,
    ImportSym,
    LibraryRef,
)

Buffer = bytes | mmap.mmap

# Table ids
MODULE, TYPEREF, TYPEDEF, FIELDPTR, FIELD, METHODPTR, METHODDEF, PARAMPTR, PARAM = (
    range(9)
)
INTERFACEIMPL, MEMBERREF = 0x09, 0x0A
MODULEREF, TYPESPEC, IMPLMAP = 0x1A, 0x1B, 0x1C
ASSEMBLY, ASSEMBLYREF, FILE, EXPORTEDTYPE = 0x20, 0x23, 0x26, 0x27
NESTEDCLASS, GENERICPARAM, METHODSPEC = 0x29, 0x2A, 0x2B
TABLE_COUNT = 0x2D

# Coded index kinds: (tag bits, tables); None = unused tag value.
CODED: dict[str, tuple[int, tuple[int | None, ...]]] = {
    "TypeDefOrRef": (2, (TYPEDEF, TYPEREF, TYPESPEC)),
    "HasConstant": (2, (FIELD, PARAM, 0x17)),
    "HasCustomAttribute": (
        5,
        (
            METHODDEF,
            FIELD,
            TYPEREF,
            TYPEDEF,
            PARAM,
            INTERFACEIMPL,
            MEMBERREF,
            MODULE,
            0x0E,
            0x17,
            0x14,
            0x11,
            MODULEREF,
            TYPESPEC,
            ASSEMBLY,
            ASSEMBLYREF,
            FILE,
            EXPORTEDTYPE,
            0x28,
            GENERICPARAM,
            0x2C,
            METHODSPEC,
        ),
    ),  # fmt: skip
    "HasFieldMarshal": (1, (FIELD, PARAM)),
    "HasDeclSecurity": (2, (TYPEDEF, METHODDEF, ASSEMBLY)),
    "MemberRefParent": (3, (TYPEDEF, TYPEREF, MODULEREF, METHODDEF, TYPESPEC)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (METHODDEF, MEMBERREF)),
    "MemberForwarded": (1, (FIELD, METHODDEF)),
    "Implementation": (2, (FILE, ASSEMBLYREF, EXPORTEDTYPE)),
    "CustomAttributeType": (3, (None, None, METHODDEF, MEMBERREF, None)),
    "ResolutionScope": (2, (MODULE, MODULEREF, ASSEMBLYREF, TYPEREF)),
    "TypeOrMethodDef": (1, (TYPEDEF, METHODDEF)),
}

# Column specs: "2"/"4"/"1" fixed, "S" string, "G" guid, "B" blob,
# "T:<id>" table index, "C:<kind>" coded index.
SCHEMA: dict[int, tuple[str, ...]] = {
    0x00: ("2", "S", "G", "G", "G"),
    0x01: ("C:ResolutionScope", "S", "S"),
    0x02: ("4", "S", "S", "C:TypeDefOrRef", "T:4", "T:6"),
    0x03: ("T:4",),
    0x04: ("2", "S", "B"),
    0x05: ("T:6",),
    0x06: ("4", "2", "2", "S", "B", "T:8"),
    0x07: ("T:8",),
    0x08: ("2", "2", "S"),
    0x09: ("T:2", "C:TypeDefOrRef"),
    0x0A: ("C:MemberRefParent", "S", "B"),
    0x0B: ("1", "1", "C:HasConstant", "B"),
    0x0C: ("C:HasCustomAttribute", "C:CustomAttributeType", "B"),
    0x0D: ("C:HasFieldMarshal", "B"),
    0x0E: ("2", "C:HasDeclSecurity", "B"),
    0x0F: ("2", "4", "T:2"),
    0x10: ("4", "T:4"),
    0x11: ("B",),
    0x12: ("T:2", "T:20"),
    0x13: ("T:20",),
    0x14: ("2", "S", "C:TypeDefOrRef"),
    0x15: ("T:2", "T:23"),
    0x16: ("T:23",),
    0x17: ("2", "S", "B"),
    0x18: ("2", "T:6", "C:HasSemantics"),
    0x19: ("T:2", "C:MethodDefOrRef", "C:MethodDefOrRef"),
    0x1A: ("S",),
    0x1B: ("B",),
    0x1C: ("2", "C:MemberForwarded", "S", "T:26"),
    0x1D: ("4", "T:4"),
    0x1E: ("4", "4"),
    0x1F: ("4",),
    0x20: ("4", "2", "2", "2", "2", "4", "B", "S", "S"),
    0x21: ("4",),
    0x22: ("4", "4", "4"),
    0x23: ("2", "2", "2", "2", "4", "B", "S", "S", "B"),
    0x24: ("4", "T:35"),
    0x25: ("4", "4", "4", "T:35"),
    0x26: ("4", "S", "B"),
    0x27: ("4", "4", "S", "S", "C:Implementation"),
    0x28: ("4", "4", "S", "C:Implementation"),
    0x29: ("T:2", "T:2"),
    0x2A: ("2", "2", "C:TypeOrMethodDef", "S"),
    0x2B: ("C:MethodDefOrRef", "B"),
    0x2C: ("T:42", "C:TypeDefOrRef"),
}

PINVOKE_NO_MANGLE = 0x0001
PINVOKE_CHARSET_MASK = 0x0006
PINVOKE_CHARSET_ANSI = 0x0002
PINVOKE_CHARSET_UNICODE = 0x0004
PINVOKE_CHARSET_AUTO = 0x0006

_PRIMITIVES = {
    0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte", 0x05: "byte",
    0x06: "short", 0x07: "ushort", 0x08: "int", 0x09: "uint", 0x0A: "long",
    0x0B: "ulong", 0x0C: "float", 0x0D: "double", 0x0E: "string",
    0x16: "typedref", 0x18: "nint", 0x19: "nuint", 0x1C: "object",
}  # fmt: skip


class DotnetMetadataError(ValueError):
    pass


class Metadata:
    """Row access to the ``#~``/``#-`` tables of one managed image."""

    def __init__(self, data: Buffer, info: PeInfo) -> None:
        self.data = data
        self.info = info
        tables = info.stream("#~") or info.stream("#-")
        if tables is None:
            raise DotnetMetadataError("no metadata tables stream")
        strings = info.stream("#Strings")
        blobs = info.stream("#Blob")
        self.strings_at = strings.offset if strings else 0
        self.strings_end = strings.offset + strings.size if strings else 0
        self.blobs_at = blobs.offset if blobs else 0
        self.blobs_end = blobs.offset + blobs.size if blobs else 0
        base = tables.offset
        heap_sizes = data[base + 6]
        valid = struct.unpack_from("<Q", data, base + 8)[0]
        cursor = base + 24
        self.rows = [0] * 64
        for table in range(64):
            if valid >> table & 1:
                self.rows[table] = struct.unpack_from("<I", data, cursor)[0]
                cursor += 4
        if heap_sizes & 0x20:
            cursor += 4  # extra data (EnC)
        self.string_size = 4 if heap_sizes & 0x01 else 2
        self.guid_size = 4 if heap_sizes & 0x02 else 2
        self.blob_size = 4 if heap_sizes & 0x04 else 2
        self.layout: dict[int, tuple[int, list[tuple[int, str]]]] = {}
        for table in range(64):
            if not self.rows[table]:
                continue
            spec = SCHEMA.get(table)
            if spec is None:
                raise DotnetMetadataError(f"unsupported metadata table {table:#x}")
            columns: list[tuple[int, str]] = []
            row_size = 0
            for column in spec:
                width = self._width(column)
                columns.append((width, column))
                row_size += width
            self.layout[table] = (cursor, columns)
            cursor += row_size * self.rows[table]
            self.layout[table] = (self.layout[table][0], columns)
        self.row_sizes = {
            table: sum(width for width, _ in columns)
            for table, (_, columns) in self.layout.items()
        }

    def _width(self, column: str) -> int:
        if column in ("1", "2", "4"):
            return int(column)
        if column == "S":
            return self.string_size
        if column == "G":
            return self.guid_size
        if column == "B":
            return self.blob_size
        kind, _, arg = column.partition(":")
        if kind == "T":
            return 2 if self.rows[int(arg)] < 0x10000 else 4
        bits, tables = CODED[arg]
        largest = max(
            (self.rows[item] for item in tables if item is not None), default=0
        )
        return 2 if largest < 1 << (16 - bits) else 4

    def row(self, table: int, rid: int) -> list[int]:
        """Raw column values of row ``rid`` (1-based)."""
        if not 1 <= rid <= self.rows[table]:
            raise DotnetMetadataError(f"row {rid} out of range for table {table:#x}")
        start, columns = self.layout[table]
        cursor = start + (rid - 1) * self.row_sizes[table]
        values: list[int] = []
        for width, _column in columns:
            if width == 1:
                values.append(self.data[cursor])
            elif width == 2:
                values.append(struct.unpack_from("<H", self.data, cursor)[0])
            else:
                values.append(struct.unpack_from("<I", self.data, cursor)[0])
            cursor += width
        return values

    def string(self, index: int) -> str:
        start = self.strings_at + index
        if not index or start >= self.strings_end:
            return ""
        end = self.data.find(b"\0", start, self.strings_end)
        return bytes(self.data[start : end if end >= 0 else self.strings_end]).decode(
            "utf-8", errors="replace"
        )

    def blob(self, index: int) -> bytes:
        start = self.blobs_at + index
        if start >= self.blobs_end:
            return b""
        size, used = _compressed(self.data, start)
        return bytes(self.data[start + used : start + used + size])

    @staticmethod
    def decode(kind: str, value: int) -> tuple[int | None, int]:
        bits, tables = CODED[kind]
        tag = value & ((1 << bits) - 1)
        table = tables[tag] if tag < len(tables) else None
        return table, value >> bits


def _compressed(data: Buffer | bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80 == 0:
        return first, 1
    if first & 0xC0 == 0x80:
        return ((first & 0x3F) << 8) | data[offset + 1], 2
    return (
        ((first & 0x1F) << 24)
        | (data[offset + 1] << 16)
        | (data[offset + 2] << 8)
        | data[offset + 3],
        4,
    )


class _Names:
    """Canonical type names (``Namespace.Outer/Inner``) and signatures."""

    def __init__(self, md: Metadata) -> None:
        self.md = md
        self.enclosing: dict[int, int] = {}
        for rid in range(1, md.rows[NESTEDCLASS] + 1):
            nested, enclosing = md.row(NESTEDCLASS, rid)
            self.enclosing[nested] = enclosing
        self._typedef: dict[int, str] = {}
        self._typeref: dict[int, str] = {}

    def typedef(self, rid: int) -> str:
        cached = self._typedef.get(rid)
        if cached is not None:
            return cached
        row = self.md.row(TYPEDEF, rid)
        name = self.md.string(row[1])
        outer = self.enclosing.get(rid)
        if outer is not None and outer != rid:
            text = f"{self.typedef(outer)}/{name}"
        else:
            namespace = self.md.string(row[2])
            text = f"{namespace}.{name}" if namespace else name
        self._typedef[rid] = text
        return text

    def typeref(self, rid: int, depth: int = 0) -> str:
        cached = self._typeref.get(rid)
        if cached is not None:
            return cached
        scope, name_index, namespace_index = self.md.row(TYPEREF, rid)
        name = self.md.string(name_index)
        table, scope_rid = Metadata.decode("ResolutionScope", scope)
        if table == TYPEREF and scope_rid and depth < 32:
            text = f"{self.typeref(scope_rid, depth + 1)}/{name}"
        else:
            namespace = self.md.string(namespace_index)
            text = f"{namespace}.{name}" if namespace else name
        self._typeref[rid] = text
        return text

    def typeref_assembly(self, rid: int, depth: int = 0) -> int | None:
        """AssemblyRef rid a TypeRef resolves through (None: this module)."""
        scope = self.md.row(TYPEREF, rid)[0]
        table, scope_rid = Metadata.decode("ResolutionScope", scope)
        if table == ASSEMBLYREF:
            return scope_rid
        if table == TYPEREF and scope_rid and depth < 32:
            return self.typeref_assembly(scope_rid, depth + 1)
        return None

    def coded_type(self, value: int, depth: int) -> str:
        table, rid = Metadata.decode("TypeDefOrRef", value)
        if table == TYPEDEF:
            return self.typedef(rid)
        if table == TYPEREF:
            return self.typeref(rid)
        if table == TYPESPEC and depth < 16:
            return self.typespec(rid, depth + 1)
        return "?"

    def typespec(self, rid: int, depth: int = 0) -> str:
        blob = self.md.blob(self.md.row(TYPESPEC, rid)[0])
        text, _ = self.sig_type(blob, 0, depth)
        return text

    def sig_type(self, blob: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
        if depth > 48 or pos >= len(blob):
            return "?", len(blob)
        element = blob[pos]
        pos += 1
        if element in _PRIMITIVES:
            return _PRIMITIVES[element], pos
        if element in (0x11, 0x12):  # VALUETYPE, CLASS
            value, used = _compressed(blob, pos)
            return self.coded_type(value, depth), pos + used
        if element == 0x0F:  # PTR
            inner, pos = self.sig_type(blob, pos, depth + 1)
            return f"{inner}*", pos
        if element == 0x10:  # BYREF
            inner, pos = self.sig_type(blob, pos, depth + 1)
            return f"{inner}&", pos
        if element == 0x1D:  # SZARRAY
            inner, pos = self.sig_type(blob, pos, depth + 1)
            return f"{inner}[]", pos
        if element == 0x14:  # ARRAY
            inner, pos = self.sig_type(blob, pos, depth + 1)
            rank, used = _compressed(blob, pos)
            pos += used
            for _ in range(2):  # sizes, then lower bounds
                count, used = _compressed(blob, pos)
                pos += used
                for _ in range(count):
                    _value, used = _compressed(blob, pos)
                    pos += used
            return f"{inner}[{',' * max(rank - 1, 0)}]", pos
        if element == 0x15:  # GENERICINST
            pos += 1  # CLASS or VALUETYPE
            value, used = _compressed(blob, pos)
            pos += used
            generic = self.coded_type(value, depth)
            count, used = _compressed(blob, pos)
            pos += used
            args = []
            for _ in range(count):
                arg, pos = self.sig_type(blob, pos, depth + 1)
                args.append(arg)
            return f"{generic}<{','.join(args)}>", pos
        if element in (0x13, 0x1E):  # VAR, MVAR
            number, used = _compressed(blob, pos)
            return f"{'!' if element == 0x13 else '!!'}{number}", pos + used
        if element in (0x1F, 0x20):  # CMOD_REQD, CMOD_OPT
            value, used = _compressed(blob, pos)
            modifier = self.coded_type(value, depth)
            inner, pos = self.sig_type(blob, pos + used, depth + 1)
            keyword = "modreq" if element == 0x1F else "modopt"
            return f"{inner} {keyword}({modifier})", pos
        if element == 0x1B:  # FNPTR
            text, pos = self.method_sig(blob, pos, depth + 1)
            return f"method {text}", pos
        if element in (0x41, 0x45):  # SENTINEL, PINNED
            return self.sig_type(blob, pos, depth + 1)
        return "?", len(blob)

    def method_sig(self, blob: bytes, pos: int = 0, depth: int = 0) -> tuple[str, int]:
        if pos >= len(blob):
            return "()", pos
        convention = blob[pos]
        pos += 1
        generic = 0
        if convention & 0x10:
            generic, used = _compressed(blob, pos)
            pos += used
        count, used = _compressed(blob, pos)
        pos += used
        returns, pos = self.sig_type(blob, pos, depth)
        params = []
        for _ in range(min(count, 512)):
            if pos < len(blob) and blob[pos] == 0x41:  # vararg sentinel
                pos += 1
                params.append("...")
            param, pos = self.sig_type(blob, pos, depth)
            params.append(param)
        prefix = "instance " if convention & 0x20 else ""
        arity = f"<{generic}>" if generic else ""
        return f"{prefix}{returns} {arity}({','.join(params)})", pos


def parse_dotnet_links(data: Buffer, path: str = "") -> FileFacts:
    info = parse_pe(data)
    if info is None or not info.is_managed:
        raise DotnetMetadataError("not a managed PE image")
    md = Metadata(data, info)
    names = _Names(md)
    facts = FileFacts(
        path=path,
        format="dotnet",
        # IL (and ReadyToRun, whose machine field is OS-salted) binds by name
        # alone; only C++/CLI images carry real native code for one machine.
        arch=info.machine if info.mixed_mode else "msil",
        bits=64 if info.pe32_plus else 32,
        kind="library" if info.characteristics & 0x2000 else "executable",
        image_base=info.image_base,
    )
    managed: dict[str, Any] = {"forwarders": {}, "mixed_mode": info.mixed_mode}
    if md.rows[ASSEMBLY]:
        row = md.row(ASSEMBLY, 1)
        facts.identity = md.string(row[7])
        managed["version"] = ".".join(str(item) for item in row[1:5])
    if md.rows[MODULE]:
        managed["module"] = md.string(md.row(MODULE, 1)[1])
    # Assembly references, in table order (index = rid - 1).
    for rid in range(1, md.rows[ASSEMBLYREF] + 1):
        row = md.row(ASSEMBLYREF, rid)
        facts.libraries.append(
            LibraryRef(
                md.string(row[6]),
                kind=LIB_ASSEMBLY,
                version=".".join(str(item) for item in row[0:4]),
            )
        )
    # Type forwarders: [TypeForwardedTo] compiles to ExportedType rows whose
    # implementation is an AssemblyRef.
    for rid in range(1, md.rows[EXPORTEDTYPE] + 1):
        _flags, _typedef, name_index, namespace_index, implementation = md.row(
            EXPORTEDTYPE, rid
        )
        table, target = Metadata.decode("Implementation", implementation)
        if table == ASSEMBLYREF and 1 <= target <= len(facts.libraries):
            namespace = md.string(namespace_index)
            name = md.string(name_index)
            full = f"{namespace}.{name}" if namespace else name
            managed["forwarders"][full] = facts.libraries[target - 1].name
    # Methods defined here (binding targets for other assemblies).
    method_owner: dict[int, int] = {}
    typedef_count = md.rows[TYPEDEF]
    method_count = md.rows[METHODDEF]
    for rid in range(1, typedef_count + 1):
        first = md.row(TYPEDEF, rid)[5]
        last = md.row(TYPEDEF, rid + 1)[5] if rid < typedef_count else method_count + 1
        for method in range(first, min(last, method_count + 1)):
            method_owner[method] = rid
    for method, type_rid in sorted(method_owner.items()):
        row = md.row(METHODDEF, method)
        signature, _ = names.method_sig(md.blob(row[4]))
        facts.exports.append(
            ExportSym(
                name=f"{names.typedef(type_rid)}::{md.string(row[3])}",
                kind="method",
                signature=signature,
                token=0x06000000 | method,
            )
        )
    # Member references into other assemblies.
    ref_index: dict[int, int] = {}  # MemberRef rid -> imports index
    for rid in range(1, md.rows[MEMBERREF] + 1):
        parent, name_index, sig_index = md.row(MEMBERREF, rid)
        table, parent_rid = Metadata.decode("MemberRefParent", parent)
        typeref_rid = _owner_typeref(md, table, parent_rid)
        if typeref_rid is None:
            continue
        assembly = names.typeref_assembly(typeref_rid)
        if assembly is None or not 1 <= assembly <= len(facts.libraries):
            continue
        owner = names.typeref(typeref_rid)
        blob = md.blob(sig_index)
        is_field = bool(blob) and blob[0] & 0x0F == 0x06
        if is_field:
            field_type, _ = names.sig_type(blob, 1)
            signature = field_type
        else:
            signature, _ = names.method_sig(blob)
        ref_index[rid] = len(facts.imports)
        facts.imports.append(
            ImportSym(
                name=f"{owner}::{md.string(name_index)}",
                library=assembly - 1,
                kind="data" if is_field else "method",
                owner=owner,
                signature=signature,
                callers=[],
            )
        )
    # P/Invoke declarations.
    module_library: dict[int, int] = {}
    pinvokes: list[tuple[int, int]] = []  # (imports index, method rid)
    for rid in range(1, md.rows[IMPLMAP] + 1):
        flags, forwarded, import_name, module = md.row(IMPLMAP, rid)
        table, method = Metadata.decode("MemberForwarded", forwarded)
        if table != METHODDEF or not 1 <= module <= md.rows[MODULEREF]:
            continue
        if module not in module_library:
            module_library[module] = len(facts.libraries)
            facts.libraries.append(
                LibraryRef(md.string(md.row(MODULEREF, module)[0]), kind=LIB_PINVOKE)
            )
        owner_rid = method_owner.get(method)
        method_name = md.string(md.row(METHODDEF, method)[3])
        owner = (
            f"{names.typedef(owner_rid)}::{method_name}" if owner_rid else method_name
        )
        charset = flags & PINVOKE_CHARSET_MASK
        facts.imports.append(
            ImportSym(
                name=md.string(import_name) or method_name,
                library=module_library[module],
                kind="pinvoke",
                owner=owner,
                signature=_charset_name(flags, charset),
                callers=[0x06000000 | method],
            )
        )
        pinvokes.append((len(facts.imports) - 1, method))
    if ref_index:
        _scan_callers(data, info, md, ref_index, facts)
    managed["entry_point_token"] = info.entry_point_token or None
    facts.managed = managed
    return facts


def _charset_name(flags: int, charset: int) -> str:
    if flags & PINVOKE_NO_MANGLE:
        return "exact"
    return {
        PINVOKE_CHARSET_ANSI: "ansi",
        PINVOKE_CHARSET_UNICODE: "unicode",
        PINVOKE_CHARSET_AUTO: "auto",
    }.get(charset, "ansi")  # CharSet.None behaves as Ansi


def _owner_typeref(md: Metadata, table: int | None, rid: int) -> int | None:
    if table == TYPEREF:
        return rid
    if table == TYPESPEC and rid:
        # Generic instantiation: the generic type definition is a TypeRef.
        blob = md.blob(md.row(TYPESPEC, rid)[0])
        if len(blob) > 2 and blob[0] == 0x15:
            value, _ = _compressed(blob, 2)
            kind, target = Metadata.decode("TypeDefOrRef", value)
            if kind == TYPEREF:
                return target
    return None


def _scan_callers(
    data: Buffer,
    info: PeInfo,
    md: Metadata,
    ref_index: dict[int, int],
    facts: FileFacts,
) -> None:
    """Fill ``callers`` from an IL scan of every method body."""
    method_specs: dict[int, int] = {}
    for rid in range(1, md.rows[METHODSPEC] + 1):
        method, _blob = md.row(METHODSPEC, rid)
        table, target = Metadata.decode("MethodDefOrRef", method)
        if table == MEMBERREF:
            method_specs[rid] = target
    for method in range(1, md.rows[METHODDEF] + 1):
        rva = md.row(METHODDEF, method)[0]
        if not rva:
            continue
        offset = info.rva_to_offset(rva)
        if offset is None:
            continue
        code = method_body(data, offset)
        if not code:
            continue
        token_owner = 0x06000000 | method
        seen: set[int] = set()
        for kind, token in scan_il_tokens(code):
            if kind not in (TOK_METHOD, "field", "token"):
                continue
            table = token >> 24
            rid = token & 0xFFFFFF
            if table == METHODSPEC:
                rid = method_specs.get(rid, 0)
                table = MEMBERREF
            if table != MEMBERREF or rid in seen:
                continue
            index = ref_index.get(rid)
            if index is None:
                continue
            seen.add(rid)
            callers = facts.imports[index].callers
            if callers is not None:
                callers.append(token_owner)
