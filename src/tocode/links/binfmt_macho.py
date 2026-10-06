"""Mach-O linking facts: load commands, two-level imports, the export trie.

Imports come from whichever table dyld itself reads: chained fixups
(``LC_DYLD_CHAINED_FIXUPS``), the bind opcode streams of
``LC_DYLD_INFO(_ONLY)``, or, for old/simple images, the undefined ``nlist``
symbols. Each import keeps its two-level library ordinal, so the library it
binds to is a fact recorded by the static linker, not a guess.
"""

from __future__ import annotations

from dataclasses import dataclass
import mmap
import struct
import zlib

from .model import (
    LIB_LAZY,
    LIB_NEEDED,
    LIB_REEXPORT,
    LIB_UPWARD,
    LIB_WEAK,
    SPECIAL_FLAT,
    SPECIAL_MAIN,
    SPECIAL_SELF,
    SPECIAL_WEAK,
    ExportSym,
    FileFacts,
    ImportSym,
    LibraryRef,
)
from .sniff import FAT_MAGIC, FAT_MAGIC_64, KNOWN_CPU_TYPES, MAX_FAT_ARCHS

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8
MH_DYLINKER = 0x7
MH_DSYM = 0xA
MH_TWOLEVEL = 0x80
LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x20
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD
DYLIB_COMMANDS = {
    LC_LOAD_DYLIB: LIB_NEEDED,
    LC_LOAD_WEAK_DYLIB: LIB_WEAK,
    LC_REEXPORT_DYLIB: LIB_REEXPORT,
    LC_LAZY_LOAD_DYLIB: LIB_LAZY,
    LC_LOAD_UPWARD_DYLIB: LIB_UPWARD,
}
FILE_KINDS = {
    MH_EXECUTE: "executable",
    MH_DYLIB: "library",
    MH_BUNDLE: "bundle",
    MH_DYLINKER: "library",
    MH_DSYM: "debug",
    0x1: "object",
}
EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03
EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01
EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x04
EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10
BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1
N_STAB = 0xE0
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x0
N_SECT = 0xE
N_WEAK_REF = 0x40
MAX_TRIE_NODES = 4_000_000
MAX_SYMBOLS = 4_000_000

Buffer = bytes | mmap.mmap


class MachoError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FatSlice:
    arch: str
    cputype: int
    cpusubtype: int
    offset: int
    size: int


def cpu_name(cputype: int, cpusubtype: int = 0) -> str:
    name = KNOWN_CPU_TYPES.get(cputype, f"cpu-{cputype:#x}")
    if name == "arm64" and cpusubtype & 0xFF == 2:
        return "arm64e"
    return name


def fat_slices(data: Buffer) -> list[FatSlice]:
    magic, count = struct.unpack_from(">II", data, 0)
    if magic not in (FAT_MAGIC, FAT_MAGIC_64) or not 0 < count <= MAX_FAT_ARCHS:
        raise MachoError("not a fat Mach-O file")
    slices: list[FatSlice] = []
    for index in range(count):
        if magic == FAT_MAGIC_64:
            cputype, subtype, offset, size, _align, _res = struct.unpack_from(
                ">iiQQII", data, 8 + index * 32
            )
        else:
            cputype, subtype, offset, size, _align = struct.unpack_from(
                ">iiIII", data, 8 + index * 20
            )
        cputype &= 0xFFFFFFFF
        if offset + size > len(data):
            raise MachoError("fat slice extends past the end of the file")
        slices.append(
            FatSlice(cpu_name(cputype, subtype), cputype, subtype, offset, size)
        )
    return slices


def _uleb(data: Buffer, offset: int, end: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < end:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
        shift += 7
        if shift > 63:
            raise MachoError("ULEB128 too long")
    raise MachoError("truncated ULEB128")


def _sleb(data: Buffer, offset: int, end: int) -> tuple[int, int]:
    result = 0
    shift = 0
    byte = 0x80
    while offset < end and byte & 0x80:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
    if byte & 0x80:
        raise MachoError("truncated SLEB128")
    if byte & 0x40:
        result -= 1 << shift
    return result, offset


def _cstring(data: Buffer, offset: int, end: int) -> tuple[str, int]:
    stop = data.find(b"\0", offset, end)
    if stop < 0:
        raise MachoError("unterminated string")
    return bytes(data[offset:stop]).decode("utf-8", errors="replace"), stop + 1


def _special(ordinal: int) -> str | None:
    return {0: SPECIAL_SELF, -1: SPECIAL_MAIN, -2: SPECIAL_FLAT, -3: SPECIAL_WEAK}.get(
        ordinal
    )


def parse_macho(
    data: Buffer, path: str = "", *, base: int = 0, size: int | None = None
) -> FileFacts:
    """Parse one thin Mach-O image starting at ``base`` (a fat slice offset)."""
    end_of_image = base + size if size is not None else len(data)
    magic = struct.unpack_from("<I", data, base)[0]
    if magic == MH_MAGIC_64:
        is64 = True
        header_size = 32
    elif magic == MH_MAGIC:
        is64 = False
        header_size = 28
    else:
        raise MachoError("not a little-endian Mach-O image")
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
        "<iiIIII", data, base + 4
    )
    facts = FileFacts(
        path=path,
        format="macho",
        arch=cpu_name(cputype & 0xFFFFFFFF, cpusubtype),
        bits=64 if is64 else 32,
        kind=FILE_KINDS.get(filetype, "other"),
        flat_namespace=not flags & MH_TWOLEVEL,
        slice_offset=base,
        slice_size=size,
    )
    segments: list[
        tuple[str, int, int, int, int]
    ] = []  # name, vmaddr, vmsize, fileoff, filesize
    dyld_info: tuple[int, ...] | None = None
    chained: tuple[int, int] | None = None
    exports_trie: tuple[int, int] | None = None
    symtab: tuple[int, int, int, int] | None = None
    entry_offset: int | None = None
    cursor = base + header_size
    limit = min(cursor + sizeofcmds, end_of_image)
    for _ in range(min(ncmds, 65535)):
        if cursor + 8 > limit:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > limit:
            facts.notes.append(f"bad load command size at {cursor - base:#x}")
            break
        if cmd in DYLIB_COMMANDS or cmd == LC_ID_DYLIB:
            name_offset, _stamp, current, compat = struct.unpack_from(
                "<IIII", data, cursor + 8
            )
            name, _ = _cstring(data, cursor + name_offset, cursor + cmdsize)
            if cmd == LC_ID_DYLIB:
                facts.identity = name
            else:
                facts.libraries.append(
                    LibraryRef(
                        name, kind=DYLIB_COMMANDS[cmd], version=_version(current)
                    )
                )
        elif cmd == LC_RPATH:
            name_offset = struct.unpack_from("<I", data, cursor + 8)[0]
            facts.rpaths.append(
                _cstring(data, cursor + name_offset, cursor + cmdsize)[0]
            )
        elif cmd == LC_SEGMENT_64:
            name = bytes(data[cursor + 8 : cursor + 24]).split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", data, cursor + 24
            )
            segments.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == LC_SEGMENT:
            name = bytes(data[cursor + 8 : cursor + 24]).split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<IIII", data, cursor + 24
            )
            segments.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            dyld_info = struct.unpack_from("<10I", data, cursor + 8)
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            chained = struct.unpack_from("<II", data, cursor + 8)
        elif cmd == LC_DYLD_EXPORTS_TRIE:
            exports_trie = struct.unpack_from("<II", data, cursor + 8)
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack_from("<IIII", data, cursor + 8)
        elif cmd == LC_UUID:
            facts.uuid = bytes(data[cursor + 8 : cursor + 24]).hex()
        elif cmd == LC_MAIN:
            entry_offset = struct.unpack_from("<Q", data, cursor + 8)[0]
        cursor += cmdsize
    text = next((item for item in segments if item[0] == "__TEXT"), None)
    facts.image_base = text[1] if text else 0
    if entry_offset is not None:
        facts.entry = facts.image_base + entry_offset
    image = _Image(data, base, end_of_image, facts, segments, is64)
    try:
        if chained is not None:
            image.chained_imports(*chained)
        elif dyld_info is not None:
            image.bind_opcodes(dyld_info)
        if exports_trie is not None:
            image.export_trie(*exports_trie)
        elif dyld_info is not None and dyld_info[9]:
            image.export_trie(dyld_info[8], dyld_info[9])
        if symtab is not None:
            image.nlist(
                *symtab,
                imports=not facts.imports and chained is None and dyld_info is None,
                exports=not facts.exports,
            )
    except (MachoError, struct.error, IndexError, zlib.error) as exc:
        facts.notes.append(f"incomplete link tables: {exc}")
    return facts


def _version(packed: int) -> str:
    return f"{packed >> 16}.{(packed >> 8) & 0xFF}.{packed & 0xFF}"


class _Image:
    def __init__(self, data, base, end, facts, segments, is64) -> None:
        self.data = data
        self.base = base
        self.end = end
        self.facts = facts
        self.segments = segments
        self.pointer = 8 if is64 else 4
        self._bound_names: set[str] = set()

    def _span(self, offset: int, size: int) -> tuple[int, int]:
        start = self.base + offset
        stop = start + size
        if offset < 0 or stop > self.end:
            raise MachoError("link-edit data outside the image")
        return start, stop

    def _library(self, ordinal: int) -> tuple[int | None, str | None]:
        special = _special(ordinal) if ordinal <= 0 else None
        if special is not None:
            return None, special
        if self.facts.flat_namespace:
            return None, SPECIAL_FLAT
        index = ordinal - 1
        if 0 <= index < len(self.facts.libraries):
            return index, None
        return None, None

    # -- chained fixups ---------------------------------------------------
    def chained_imports(self, offset: int, size: int) -> None:
        start, stop = self._span(offset, size)
        (_version, _starts, imports_offset, symbols_offset, count, imports_format,
         symbols_format) = struct.unpack_from("<7I", self.data, start)  # fmt: skip
        symbols_start = start + symbols_offset
        if symbols_format == 1:
            pool: Buffer = zlib.decompress(bytes(self.data[symbols_start:stop]))
            pool_base, pool_end = 0, len(pool)
        else:
            pool, pool_base, pool_end = self.data, symbols_start, stop
        cursor = start + imports_offset
        seen: set[tuple[str, int | None, str | None]] = set()
        entry_size = {1: 4, 2: 8, 3: 16}.get(imports_format)
        if entry_size is None:
            raise MachoError(f"unknown chained imports format {imports_format}")
        for _ in range(min(count, MAX_SYMBOLS)):
            if imports_format == 3:
                raw = struct.unpack_from("<Q", self.data, cursor)[0]
                lib = raw & 0xFFFF
                weak = bool(raw >> 16 & 1)
                name_offset = raw >> 32
                ordinal = lib - 0x10000 if lib > 0xFFF0 else lib
            else:
                raw = struct.unpack_from("<I", self.data, cursor)[0]
                lib = raw & 0xFF
                weak = bool(raw >> 8 & 1)
                name_offset = raw >> 9
                ordinal = lib - 0x100 if lib > 0xF0 else lib
            cursor += entry_size
            name, _ = _cstring(pool, pool_base + name_offset, pool_end)
            library, special = self._library(ordinal)
            # The same symbol appears once per distinct addend; one fact is enough.
            key = (name, library, special)
            if key in seen:
                continue
            seen.add(key)
            self.facts.imports.append(
                ImportSym(name=name, library=library, special=special, weak=weak)
            )

    # -- bind opcodes -----------------------------------------------------
    def bind_opcodes(self, info: tuple[int, ...]) -> None:
        seen: set[tuple[str, int | None, str | None]] = set()
        (_rebase_off, _rebase_size, bind_off, bind_size, weak_off, weak_size,
         lazy_off, lazy_size, _export_off, _export_size) = info  # fmt: skip
        for offset, size, stream in (
            (bind_off, bind_size, "bind"),
            (lazy_off, lazy_size, "lazy"),
            (weak_off, weak_size, "weak"),
        ):
            if offset and size:
                self._run_bind(offset, size, stream, seen)

    def _run_bind(self, offset: int, size: int, stream: str, seen: set) -> None:
        cursor, stop = self._span(offset, size)
        bound_names = self._bound_names
        data = self.data
        ordinal = 0
        name = ""
        flags = 0
        segment = 0
        seg_offset = 0
        pointer = self.pointer

        def record() -> None:
            if not name:
                return
            special: str | None
            library: int | None
            if stream == "weak":
                # 0x8 marks this image's own strong definition, not an import;
                # a symbol the two-level binds already cover keeps that library.
                if flags & 0x8 or name in bound_names:
                    return
                library, special = None, SPECIAL_WEAK
            else:
                library, special = self._library(ordinal)
            slot = None
            if segment < len(self.segments):
                slot = self.segments[segment][1] + seg_offset
            key = (name, library, special)
            if key in seen:
                return
            seen.add(key)
            bound_names.add(name)
            self.facts.imports.append(
                ImportSym(
                    name=name,
                    library=library,
                    special=special,
                    weak=bool(flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT),
                    slot=slot,
                )
            )

        while cursor < stop:
            byte = data[cursor]
            cursor += 1
            opcode = byte & 0xF0
            imm = byte & 0x0F
            if opcode == 0x00:  # DONE (separates lazy entries)
                if stream != "lazy":
                    break
            elif opcode == 0x10:
                ordinal = imm
            elif opcode == 0x20:
                ordinal, cursor = _uleb(data, cursor, stop)
            elif opcode == 0x30:
                ordinal = 0 if imm == 0 else (imm | 0xF0) - 0x100
            elif opcode == 0x40:
                flags = imm
                name, cursor = _cstring(data, cursor, stop)
            elif opcode == 0x50:
                pass  # type
            elif opcode == 0x60:
                _addend, cursor = _sleb(data, cursor, stop)
            elif opcode == 0x70:
                segment = imm
                seg_offset, cursor = _uleb(data, cursor, stop)
            elif opcode == 0x80:
                delta, cursor = _uleb(data, cursor, stop)
                seg_offset += delta
            elif opcode == 0x90:
                record()
                seg_offset += pointer
            elif opcode == 0xA0:
                record()
                delta, cursor = _uleb(data, cursor, stop)
                seg_offset += delta + pointer
            elif opcode == 0xB0:
                record()
                seg_offset += imm * pointer + pointer
            elif opcode == 0xC0:
                count, cursor = _uleb(data, cursor, stop)
                skip, cursor = _uleb(data, cursor, stop)
                record()
                seg_offset += count * (skip + pointer)
            elif opcode == 0xD0:  # THREADED
                if imm == 0:
                    _size, cursor = _uleb(data, cursor, stop)
            else:
                raise MachoError(f"unknown bind opcode {byte:#x}")

    # -- exports ----------------------------------------------------------
    def export_trie(self, offset: int, size: int) -> None:
        if not size:
            return
        start, stop = self._span(offset, size)
        data = self.data
        image_base = self.facts.image_base
        stack: list[tuple[int, str]] = [(start, "")]
        visited: set[int] = set()
        while stack:
            node, prefix = stack.pop()
            if node in visited or not start <= node < stop:
                continue
            visited.add(node)
            if len(visited) > MAX_TRIE_NODES:
                raise MachoError("export trie too large")
            terminal, cursor = _uleb(data, node, stop)
            children_at = cursor + terminal
            if terminal:
                flags, cursor = _uleb(data, cursor, stop)
                kind_bits = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
                weak = bool(flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION)
                if flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                    ordinal, cursor = _uleb(data, cursor, stop)
                    imported, cursor = _cstring(data, cursor, stop)
                    index = ordinal - 1
                    self.facts.exports.append(
                        ExportSym(
                            name=prefix,
                            reexport_library=index
                            if 0 <= index < len(self.facts.libraries)
                            else None,
                            reexport_name=imported or prefix,
                            weak=weak,
                        )
                    )
                else:
                    address, cursor = _uleb(data, cursor, stop)
                    kind = "function"
                    if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                        _resolver, cursor = _uleb(data, cursor, stop)
                        kind = "resolver"
                    if kind_bits == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
                        kind = "tls"
                    elif kind_bits == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
                        kind = "absolute"
                    self.facts.exports.append(
                        ExportSym(
                            name=prefix,
                            address=address
                            if kind_bits == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
                            else image_base + address,
                            weak=weak,
                            kind=None if kind == "function" else kind,
                        )
                    )
            if children_at >= stop:
                continue
            count = data[children_at]
            cursor = children_at + 1
            for _ in range(count):
                edge, cursor = _cstring(data, cursor, stop)
                child, cursor = _uleb(data, cursor, stop)
                stack.append((start + child, prefix + edge))

    def nlist(
        self,
        symoff: int,
        nsyms: int,
        stroff: int,
        strsize: int,
        *,
        imports: bool,
        exports: bool,
    ) -> None:
        if not (imports or exports) or not nsyms:
            return
        entsize = 16 if self.pointer == 8 else 12
        sym_start, _ = self._span(symoff, min(nsyms, MAX_SYMBOLS) * entsize)
        str_start, str_stop = self._span(stroff, strsize)
        fmt = "<IBBHQ" if self.pointer == 8 else "<IBBHI"
        for index in range(min(nsyms, MAX_SYMBOLS)):
            strx, n_type, _sect, desc, value = struct.unpack_from(
                fmt, self.data, sym_start + index * entsize
            )
            if n_type & N_STAB or not n_type & N_EXT or not strx:
                continue
            name, _ = _cstring(self.data, str_start + strx, str_stop)
            kind = n_type & N_TYPE
            if kind == N_UNDF and imports and value == 0:
                raw = desc >> 8 & 0xFF
                ordinal = {0xFE: -2, 0xFF: -1}.get(raw, raw)
                library, special = self._library(ordinal)
                self.facts.imports.append(
                    ImportSym(
                        name=name,
                        library=library,
                        special=special,
                        weak=bool(desc & N_WEAK_REF),
                    )
                )
            elif kind == N_SECT and exports:
                self.facts.exports.append(ExportSym(name=name, address=value))


def parse_macho_file(
    data: Buffer, path: str = "", *, arch: str | None = None
) -> list[FileFacts]:
    """Every image in a thin or fat file (only ``arch`` when given)."""
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        result = []
        for item in fat_slices(data):
            if arch is not None and item.arch != arch:
                continue
            result.append(parse_macho(data, path, base=item.offset, size=item.size))
        return result
    return [parse_macho(data, path)]
