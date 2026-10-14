"""PE import, delay-import, and export tables (native and managed images)."""

from __future__ import annotations

import mmap
import struct

from ..backends.dotnet_pe import PeInfo, parse_pe
from .model import LIB_DELAY, ExportSym, FileFacts, ImportSym, LibraryRef

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_DEBUG = 6
DIR_DELAY_IMPORT = 13
IMAGE_FILE_DLL = 0x2000
IMAGE_DEBUG_TYPE_CODEVIEW = 2
MAX_IMPORT_DESCRIPTORS = 4096
MAX_THUNKS = 1 << 16
MAX_EXPORTS = 1 << 20

Buffer = bytes | mmap.mmap


class PeError(ValueError):
    pass


def parse_pe_links(data: Buffer, path: str = "") -> FileFacts:
    info = parse_pe(data)
    if info is None:
        raise PeError("not a PE file")
    facts = FileFacts(
        path=path,
        format="pe",
        arch=info.machine,
        bits=64 if info.pe32_plus else 32,
        kind="library" if info.characteristics & IMAGE_FILE_DLL else "executable",
        image_base=info.image_base,
        entry=info.image_base + info.entry_point_rva if info.entry_point_rva else None,
    )
    reader = _Reader(data, info)
    _read_imports(reader, facts)
    _read_delay_imports(reader, facts)
    _read_exports(reader, facts)
    facts.uuid = _codeview_id(reader)
    return facts


class _Reader:
    def __init__(self, data: Buffer, info: PeInfo) -> None:
        self.data = data
        self.info = info
        self.pointer = 8 if info.pe32_plus else 4

    def directory(self, index: int) -> tuple[int, int]:
        dirs = self.info.data_directories
        return dirs[index] if index < len(dirs) else (0, 0)

    def offset(self, rva: int) -> int | None:
        return self.info.rva_to_offset(rva)

    def u32(self, rva: int) -> int:
        offset = self.offset(rva)
        if offset is None:
            raise PeError(f"rva {rva:#x} is not mapped")
        return struct.unpack_from("<I", self.data, offset)[0]

    def unpack(self, fmt: str, rva: int) -> tuple:
        offset = self.offset(rva)
        if offset is None:
            raise PeError(f"rva {rva:#x} is not mapped")
        return struct.unpack_from(fmt, self.data, offset)

    def cstring(self, rva: int, limit: int = 1024) -> str:
        offset = self.offset(rva)
        if offset is None:
            return ""
        end = self.data.find(b"\0", offset, min(len(self.data), offset + limit))
        if end < 0:
            end = min(len(self.data), offset + limit)
        return bytes(self.data[offset:end]).decode("ascii", errors="replace")


def _thunks(
    r: _Reader, lookup_rva: int, slot_rva: int, library: int
) -> list[ImportSym]:
    rows: list[ImportSym] = []
    fmt = "<Q" if r.pointer == 8 else "<I"
    flag = 1 << (r.pointer * 8 - 1)
    for index in range(MAX_THUNKS):
        try:
            value = r.unpack(fmt, lookup_rva + index * r.pointer)[0]
        except (PeError, struct.error):
            break
        if value == 0:
            break
        slot = r.info.image_base + slot_rva + index * r.pointer
        if value & flag:
            ordinal = value & 0xFFFF
            rows.append(
                ImportSym(
                    name=f"#{ordinal}", library=library, ordinal=ordinal, slot=slot
                )
            )
        else:
            name = r.cstring((value & 0x7FFFFFFF) + 2)
            rows.append(ImportSym(name=name, library=library, slot=slot))
    return rows


def _read_imports(r: _Reader, facts: FileFacts) -> None:
    rva, size = r.directory(DIR_IMPORT)
    if not rva or not size:
        return
    for index in range(MAX_IMPORT_DESCRIPTORS):
        try:
            lookup, _stamp, _chain, name_rva, first_thunk = r.unpack(
                "<IIIII", rva + index * 20
            )
        except (PeError, struct.error):
            facts.notes.append("import directory truncated")
            break
        if not (lookup or name_rva or first_thunk):
            break
        dll = r.cstring(name_rva)
        if not dll:
            continue
        library = len(facts.libraries)
        facts.libraries.append(LibraryRef(dll))
        # Without an import lookup table (old binders), the IAT still holds names.
        facts.imports.extend(_thunks(r, lookup or first_thunk, first_thunk, library))


def _read_delay_imports(r: _Reader, facts: FileFacts) -> None:
    rva, size = r.directory(DIR_DELAY_IMPORT)
    if not rva or not size:
        return
    for index in range(MAX_IMPORT_DESCRIPTORS):
        try:
            attrs, name_rva, _hmod, iat, int_rva, _bound, _unload, _stamp = r.unpack(
                "<IIIIIIII", rva + index * 32
            )
        except (PeError, struct.error):
            facts.notes.append("delay-import directory truncated")
            break
        if not (name_rva or iat or int_rva):
            break
        if not attrs & 1:
            # Visual C++ 6 format: the fields are VAs, not RVAs.
            base = r.info.image_base & 0xFFFFFFFF
            name_rva, iat, int_rva = (
                (value - base) & 0xFFFFFFFF if value else 0
                for value in (name_rva, iat, int_rva)
            )
        dll = r.cstring(name_rva)
        if not dll:
            continue
        library = len(facts.libraries)
        facts.libraries.append(LibraryRef(dll, kind=LIB_DELAY))
        facts.imports.extend(_thunks(r, int_rva or iat, iat, library))


def _read_exports(r: _Reader, facts: FileFacts) -> None:
    rva, size = r.directory(DIR_EXPORT)
    if not rva or not size:
        return
    try:
        (_chars, _stamp, _major, _minor, name_rva, base, function_count, name_count,
         functions_rva, names_rva, ordinals_rva) = r.unpack("<IIHHIIIIIII", rva)  # fmt: skip
    except (PeError, struct.error):
        facts.notes.append("export directory unreadable")
        return
    facts.identity = r.cstring(name_rva) or None
    function_count = min(function_count, MAX_EXPORTS)
    name_count = min(name_count, MAX_EXPORTS)
    names: dict[int, list[str]] = {}
    for index in range(name_count):
        try:
            name_ptr = r.u32(names_rva + index * 4)
            ordinal_index = r.unpack("<H", ordinals_rva + index * 2)[0]
        except (PeError, struct.error):
            break
        names.setdefault(ordinal_index, []).append(r.cstring(name_ptr))
    for index in range(function_count):
        try:
            target = r.u32(functions_rva + index * 4)
        except (PeError, struct.error):
            break
        if target == 0:
            continue
        ordinal = base + index
        forwarder = None
        address: int | None = r.info.image_base + target
        if rva <= target < rva + size:
            forwarder = r.cstring(target)
            address = None
        for name in names.get(index) or [f"#{ordinal}"]:
            facts.exports.append(
                ExportSym(
                    name=name,
                    address=address,
                    ordinal=ordinal,
                    forwarder=forwarder,
                    kind="function"
                    if address is not None and _is_code(r, target)
                    else None,
                )
            )


def _is_code(r: _Reader, rva: int) -> bool:
    for section in r.info.sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            return "x" in section.perms
    return False


def _codeview_id(r: _Reader) -> str | None:
    rva, size = r.directory(DIR_DEBUG)
    if not rva or not size:
        return None
    for index in range(min(size // 28, 32)):
        try:
            entry = r.unpack("<IIHHIIII", rva + index * 28)
        except (PeError, struct.error):
            return None
        kind, data_size, _addr, pointer = entry[4], entry[5], entry[6], entry[7]
        if kind != IMAGE_DEBUG_TYPE_CODEVIEW or data_size < 24:
            continue
        if bytes(r.data[pointer : pointer + 4]) != b"RSDS":
            continue
        guid = bytes(r.data[pointer + 4 : pointer + 20])
        age = struct.unpack_from("<I", r.data, pointer + 20)[0]
        return f"{guid.hex()}{age:x}"
    return None
