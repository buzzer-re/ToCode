"""Synthetic ELF, PE, Mach-O, and .NET images for the folder link tests.

Each builder writes only the structures the link parsers read, with the same
layout a linker produces, so the tests run without any toolchain.
"""

from __future__ import annotations

from pathlib import Path
import struct

from tocode.links.binfmt_dotnet import SCHEMA

# --------------------------------------------------------------------------
# ELF (64-bit little-endian, one PT_LOAD at vaddr 0 mapping the whole file)
# --------------------------------------------------------------------------

EM_AARCH64 = 0xB7
EM_X86_64 = 0x3E


def elf(
    *,
    soname: str | None = None,
    needed: list[str] = (),  # type: ignore[assignment]
    rpath: str | None = None,
    runpath: str | None = None,
    exports: list[tuple[str, int, str | None]] = (),  # type: ignore[assignment]
    imports: list[tuple[str, str | None, str | None]] = (),  # type: ignore[assignment]
    executable: bool = False,
    machine: int = EM_AARCH64,
) -> bytes:
    """``exports``: (name, address, version); ``imports``: (name, version, file)."""
    strtab = bytearray(b"\0")

    def string(value: str) -> int:
        offset = len(strtab)
        strtab.extend(value.encode() + b"\0")
        return offset

    # Version indexes: 2.. for definitions, then requirements.
    def_versions = sorted({version for _n, _a, version in exports if version})
    need_versions: dict[str, list[str]] = {}
    for _name, version, file in imports:
        if version and file:
            need_versions.setdefault(file, [])
            if version not in need_versions[file]:
                need_versions[file].append(version)
    index_of: dict[tuple[str | None, str], int] = {}
    next_index = 2
    for version in def_versions:
        index_of[(None, version)] = next_index
        next_index += 1
    for file, versions in need_versions.items():
        for version in versions:
            index_of[(file, version)] = next_index
            next_index += 1

    symbols = [(0, 0, 0, 0, 0)]  # name, info, shndx, value, versym
    for name, address, version in exports:
        symbols.append(
            (
                string(name),
                0x12,
                1,
                address,
                index_of.get((None, version), 1) if version else 1,
            )
        )
    for name, version, file in imports:
        symbols.append(
            (
                string(name),
                0x12,
                0,
                0,
                index_of[(file, version)] if version and file else 1,
            )
        )
    needed_offsets = [string(item) for item in needed]
    soname_offset = string(soname) if soname else None
    rpath_offset = string(rpath) if rpath else None
    runpath_offset = string(runpath) if runpath else None
    verdef = bytearray()
    for position, version in enumerate(def_versions):
        version_name = string(version)
        last = position == len(def_versions) - 1
        verdef += struct.pack(
            "<HHHHIII", 1, 0, index_of[(None, version)], 1, 0, 20, 0 if last else 28
        )
        verdef += struct.pack("<II", version_name, 0)
    verneed = bytearray()
    files = list(need_versions)
    for position, file in enumerate(files):
        versions = need_versions[file]
        last = position == len(files) - 1
        size = 16 + 16 * len(versions)
        verneed += struct.pack(
            "<HHIII", 1, len(versions), string(file), 16, 0 if last else size
        )
        for number, version in enumerate(versions):
            final = number == len(versions) - 1
            verneed += struct.pack(
                "<IHHII",
                0,
                0,
                index_of[(file, version)],
                string(version),
                0 if final else 16,
            )

    base = 0x200
    layout: dict[str, int] = {}
    blob = bytearray()

    def place(key: str, data: bytes, align: int = 8) -> None:
        while (base + len(blob)) % align:
            blob.append(0)
        layout[key] = base + len(blob)
        blob.extend(data)

    dynsym = b"".join(
        struct.pack("<IBBHQQ", name, info, 0, shndx, value, 0)
        for name, info, shndx, value, _v in symbols
    )
    place("dynsym", dynsym)
    place("versym", b"".join(struct.pack("<H", item[4]) for item in symbols), 2)
    place(
        "hash", struct.pack("<II", 1, len(symbols)) + b"\0" * (4 + 4 * len(symbols)), 4
    )
    if verdef:
        place("verdef", bytes(verdef), 4)
    if verneed:
        place("verneed", bytes(verneed), 4)
    place("dynstr", bytes(strtab), 1)
    tags: list[tuple[int, int]] = [(1, offset) for offset in needed_offsets]
    if soname_offset is not None:
        tags.append((14, soname_offset))
    if rpath_offset is not None:
        tags.append((15, rpath_offset))
    if runpath_offset is not None:
        tags.append((29, runpath_offset))
    tags += [
        (4, layout["hash"]),
        (5, layout["dynstr"]),
        (6, layout["dynsym"]),
        (10, len(strtab)),
        (11, 24),
        (0x6FFFFFF0, layout["versym"]),
    ]
    if verdef:
        tags += [(0x6FFFFFFC, layout["verdef"]), (0x6FFFFFFD, len(def_versions))]
    if verneed:
        tags += [(0x6FFFFFFE, layout["verneed"]), (0x6FFFFFFF, len(files))]
    if executable:
        tags.append((0x6FFFFFFB, 0x08000000))  # DF_1_PIE
    tags.append((0, 0))
    place("dynamic", b"".join(struct.pack("<qQ", tag, value) for tag, value in tags))
    total = base + len(blob)
    header = bytearray(64)
    header[0:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH", header, 16, 3, machine, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0
    )
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    dyn_size = len(tags) * 16
    phdrs += struct.pack(
        "<IIQQQQQQ",
        2,
        6,
        layout["dynamic"],
        layout["dynamic"],
        0,
        dyn_size,
        dyn_size,
        8,
    )
    image = bytearray(header + phdrs)
    image += b"\0" * (base - len(image))
    image += blob
    return bytes(image)


# --------------------------------------------------------------------------
# PE32+ / PE32
# --------------------------------------------------------------------------


class _Rdata:
    def __init__(self, rva: int) -> None:
        self.rva = rva
        self.data = bytearray()

    def add(self, payload: bytes, align: int = 4) -> int:
        while len(self.data) % align:
            self.data.append(0)
        offset = self.rva + len(self.data)
        self.data.extend(payload)
        return offset

    def reserve(self, size: int, align: int = 8) -> int:
        return self.add(b"\0" * size, align)

    def put(self, rva: int, payload: bytes) -> None:
        start = rva - self.rva
        self.data[start : start + len(payload)] = payload


def pe(
    *,
    name: str | None = None,
    exports: list[tuple[str | None, int, int | str]] = (),  # type: ignore[assignment]
    imports: dict[str, list[str | int]] | None = None,
    delay: dict[str, list[str]] | None = None,
    dll: bool = True,
    machine: int = 0x8664,
    image_base: int = 0x180000000,
) -> bytes:
    """``exports``: (name or None for NONAME, ordinal, text rva or "DLL.Forwarder")."""
    plus = machine in (0x8664, 0xAA64)
    pointer = 8 if plus else 4
    rdata = _Rdata(0x2000)
    directories: dict[int, tuple[int, int]] = {}

    def thunk_tables(names: list[str | int]) -> tuple[int, int]:
        entries = []
        for item in names:
            if isinstance(item, int):
                entries.append((1 << (pointer * 8 - 1)) | item)
            else:
                entries.append(
                    rdata.add(struct.pack("<H", 0) + item.encode() + b"\0", 2)
                )
        fmt = "<Q" if plus else "<I"
        body = b"".join(struct.pack(fmt, value) for value in entries) + struct.pack(
            fmt, 0
        )
        return rdata.add(body, 8), rdata.add(body, 8)

    if imports:
        built = []
        for dll_name, names in imports.items():
            lookup, iat = thunk_tables(names)
            built.append((lookup, rdata.add(dll_name.encode() + b"\0", 1), iat))
        table = rdata.add(
            b"".join(
                struct.pack("<IIIII", lookup, 0, 0, name_rva, iat)
                for lookup, name_rva, iat in built
            )
            + b"\0" * 20
        )
        directories[1] = (table, 20 * (len(built) + 1))
    if delay:
        built = []
        for dll_name, delayed in delay.items():
            lookup, iat = thunk_tables(list(delayed))
            built.append((rdata.add(dll_name.encode() + b"\0", 1), iat, lookup))
        table = rdata.add(
            b"".join(
                struct.pack("<8I", 1, name_rva, 0, iat, lookup, 0, 0, 0)
                for name_rva, iat, lookup in built
            )
            + b"\0" * 32
        )
        directories[13] = (table, 32 * (len(built) + 1))
    if exports:
        ordinals = [ordinal for _n, ordinal, _t in exports]
        base = min(ordinals)
        count = max(ordinals) - base + 1
        directory = rdata.reserve(40)
        functions = rdata.reserve(4 * count, 4)
        named = sorted(
            (item for item in exports if item[0]), key=lambda item: item[0] or ""
        )
        names_rva = rdata.reserve(4 * len(named), 4)
        ordinals_rva = rdata.reserve(2 * len(named), 2)
        start = directory
        for export_name, ordinal, target in exports:
            if isinstance(target, str):
                value = rdata.add(target.encode() + b"\0", 1)
            else:
                value = target
            rdata.put(functions + 4 * (ordinal - base), struct.pack("<I", value))
        for index, (export_name, ordinal, _t) in enumerate(named):
            rdata.put(
                names_rva + 4 * index,
                struct.pack("<I", rdata.add((export_name or "").encode() + b"\0", 1)),
            )
            rdata.put(ordinals_rva + 2 * index, struct.pack("<H", ordinal - base))
        name_rva = rdata.add((name or "lib.dll").encode() + b"\0", 1)
        rdata.put(
            directory,
            struct.pack(
                "<IIHHIIIIIII",
                0,
                0,
                0,
                0,
                name_rva,
                base,
                count,
                len(named),
                functions,
                names_rva,
                ordinals_rva,
            ),
        )
        # Forwarder strings must sit inside the export directory range.
        directories[0] = (start, rdata.rva + len(rdata.data) - start)
    rdata_size = (len(rdata.data) + 0x1FF) & ~0x1FF or 0x200
    image = bytearray(0x400 + 0x200 + rdata_size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if plus else 224
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x84,
        machine,
        2,
        0,
        0,
        0,
        optional_size,
        0x2022 if dll else 0x0022,
    )
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B if plus else 0x10B)
    struct.pack_into("<I", image, optional + 16, 0x1000)  # entry point
    if plus:
        struct.pack_into("<Q", image, optional + 24, image_base)
        dirs = optional + 112
        struct.pack_into("<I", image, optional + 108, 16)
    else:
        struct.pack_into("<I", image, optional + 28, image_base & 0xFFFFFFFF)
        dirs = optional + 96
        struct.pack_into("<I", image, optional + 92, 16)
    struct.pack_into("<I", image, optional + 60, 0x400)  # SizeOfHeaders
    for index, (rva, size) in directories.items():
        struct.pack_into("<II", image, dirs + index * 8, rva, size)
    sections = optional + optional_size
    image[sections : sections + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, sections + 8, 0x1000, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", image, sections + 36, 0x60000020)
    image[sections + 40 : sections + 48] = b".rdata\0\0"
    struct.pack_into(
        "<IIII", image, sections + 48, rdata_size, 0x2000, rdata_size, 0x600
    )
    struct.pack_into("<I", image, sections + 76, 0x40000040)
    image[0x600 : 0x600 + len(rdata.data)] = rdata.data
    return bytes(image)


# --------------------------------------------------------------------------
# Mach-O (64-bit arm64)
# --------------------------------------------------------------------------

CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_RPATH = 0x8000001C


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def export_trie(entries: list[tuple[str, int] | tuple[str, int, str]]) -> bytes:
    """Root node with one edge per symbol. (name, address) or (name, ordinal, imported) for re-exports."""
    terminals = []
    for entry in entries:
        if len(entry) == 3:
            name, ordinal, imported = entry  # type: ignore[misc]
            info = _uleb(0x08) + _uleb(ordinal) + imported.encode() + b"\0"
        else:
            name, address = entry  # type: ignore[misc]
            info = _uleb(0) + _uleb(address)
        terminals.append((name, _uleb(len(info)) + info + b"\0"))
    # Fixed point: child offsets depend on the root size.
    root_size = 0
    for _ in range(4):
        offsets = []
        cursor = root_size
        for _name, node in terminals:
            offsets.append(cursor)
            cursor += len(node)
        root = bytearray(b"\0" + bytes([len(terminals)]))
        for (name, _node), offset in zip(terminals, offsets):
            root += name.encode() + b"\0" + _uleb(offset)
        if len(root) == root_size:
            break
        root_size = len(root)
    return bytes(root) + b"".join(node for _name, node in terminals)


def macho(
    *,
    filetype: str = "dylib",
    install_name: str | None = None,
    libraries: list[tuple[str, int]] = (),  # type: ignore[assignment]
    rpaths: list[str] = (),  # type: ignore[assignment]
    imports: list[tuple[str, int]] = (),  # type: ignore[assignment]
    exports: list[tuple[str, int] | tuple[str, int, str]] = (),  # type: ignore[assignment]
    imports_format: int = 1,
    bind_opcodes: bool = False,
    cputype: int = CPU_ARM64,
) -> bytes:
    """``libraries``: (path, load command); ``imports``: (symbol, ordinal) with
    ordinal 1-based or special (0 self, -1 main, -2 flat, -3 weak)."""
    text_vmaddr = 0x100000000 if filetype == "executable" else 0
    commands: list[bytes] = []

    def dylib_command(cmd: int, path: str) -> bytes:
        name = path.encode() + b"\0"
        size = (24 + len(name) + 7) & ~7
        return struct.pack("<IIIIII", cmd, size, 24, 2, 0x10000, 0x10000) + name.ljust(
            size - 24, b"\0"
        )

    if install_name:
        commands.append(dylib_command(LC_ID_DYLIB, install_name))
    for path, cmd in libraries:
        commands.append(dylib_command(cmd, path))
    for path in rpaths:
        name = path.encode() + b"\0"
        size = (12 + len(name) + 7) & ~7
        commands.append(
            struct.pack("<III", LC_RPATH, size, 12) + name.ljust(size - 12, b"\0")
        )
    linkedit = bytearray(8)  # offset 0 means "absent" in dyld_info
    trie = export_trie(list(exports)) if exports else b""
    if bind_opcodes:
        stream = bytearray()
        for offset, (symbol, ordinal) in enumerate(imports):
            if ordinal <= 0:
                stream.append(0x30 | (ordinal & 0x0F))
            elif ordinal < 16:
                stream.append(0x10 | ordinal)
            else:
                stream.append(0x20)
                stream += _uleb(ordinal)
            stream.append(0x40)
            stream += symbol.encode() + b"\0"
            stream.append(0x71)  # segment 1 (__DATA), offset
            stream += _uleb(offset * 8)
            stream.append(0x90)
        stream.append(0x00)
        bind_off = len(linkedit)
        linkedit += stream
        export_off = len(linkedit)
        linkedit += trie
        info_fields = [0, 0, bind_off, len(stream), 0, 0, 0, 0, export_off, len(trie)]
    else:
        names = bytearray(b"\0")
        rows = bytearray()
        for symbol, ordinal in imports:
            offset = len(names)
            names += symbol.encode() + b"\0"
            if imports_format == 3:
                lib = ordinal & 0xFFFF
                rows += struct.pack("<QQ", lib | (offset << 32), 0)
            else:
                lib = ordinal & 0xFF
                raw = lib | (offset << 9)
                rows += struct.pack("<I", raw) + (
                    struct.pack("<i", 0) if imports_format == 2 else b""
                )
        header_size = 28
        chained = struct.pack(
            "<7I",
            0,
            header_size,
            header_size + 4,
            header_size + 4 + len(rows),
            len(imports),
            imports_format,
            0,
        )
        chained += struct.pack("<I", 0) + bytes(rows) + bytes(names)
        chained_off = len(linkedit)
        linkedit += chained
        trie_off = len(linkedit)
        linkedit += trie
    while len(linkedit) % 8:
        linkedit.append(0)
    # Segments: __TEXT (headers), __DATA, __LINKEDIT
    ncmds_extra = 3 + 1
    sizeof_fixed = 72 * 3 + (48 if bind_opcodes else 16 * 2)
    sizeofcmds = sum(len(item) for item in commands) + sizeof_fixed
    header_total = 32 + sizeofcmds
    text_size = (header_total + 0xFFF) & ~0xFFF
    data_off = text_size
    linkedit_off = data_off + 0x1000
    segments = [
        ("__TEXT", text_vmaddr, text_size, 0, text_size),
        ("__DATA", text_vmaddr + text_size, 0x1000, data_off, 0x1000),
        (
            "__LINKEDIT",
            text_vmaddr + text_size + 0x1000,
            len(linkedit),
            linkedit_off,
            len(linkedit),
        ),
    ]
    seg_cmds = [
        struct.pack(
            "<II16sQQQQiiII",
            0x19,
            72,
            name.encode(),
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            7,
            5,
            0,
            0,
        )
        for name, vmaddr, vmsize, fileoff, filesize in segments
    ]
    if bind_opcodes:
        link_cmds = [
            struct.pack(
                "<II10I",
                0x80000022,
                48,
                *[
                    value + linkedit_off
                    if index in (2, 8) and info_fields[index + 1]
                    else value
                    for index, value in enumerate(info_fields)
                ],
            )
        ]
    else:
        link_cmds = [
            struct.pack(
                "<IIII", 0x80000034, 16, linkedit_off + chained_off, len(chained)
            ),
            struct.pack("<IIII", 0x80000033, 16, linkedit_off + trie_off, len(trie)),
        ]
    all_cmds = seg_cmds + commands + link_cmds
    del ncmds_extra
    filetype_value = {"executable": 2, "dylib": 6, "bundle": 8}[filetype]
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        cputype,
        0,
        filetype_value,
        len(all_cmds),
        sum(len(item) for item in all_cmds),
        0x85,
        0,
    )
    image = bytearray(header + b"".join(all_cmds))
    image += b"\0" * (linkedit_off - len(image))
    image += linkedit
    return bytes(image)


def fat(slices: list[tuple[int, bytes]]) -> bytes:
    align = 0x4000
    header = bytearray(struct.pack(">II", 0xCAFEBABE, len(slices)))
    offset = align
    body = bytearray()
    for cputype, data in slices:
        header += struct.pack(">iiIII", cputype, 0, offset, len(data), 14)
        body += data + b"\0" * ((-len(data)) % align)
        offset += len(data) + ((-len(data)) % align)
    return bytes(header + b"\0" * (align - len(header)) + body)


# --------------------------------------------------------------------------
# .NET metadata
# --------------------------------------------------------------------------


class Metadata:
    """Rows for a #~ stream with small (2-byte) heap and table indexes."""

    def __init__(self) -> None:
        self.strings = bytearray(b"\0")
        self.blobs = bytearray(b"\0")
        self.tables: dict[int, list[tuple[int, ...]]] = {}

    def string(self, value: str) -> int:
        offset = len(self.strings)
        self.strings += value.encode() + b"\0"
        return offset

    def blob(self, value: bytes) -> int:
        offset = len(self.blobs)
        self.blobs += bytes([len(value)]) + value
        return offset

    def add(self, table: int, *values: int) -> int:
        self.tables.setdefault(table, []).append(values)
        return len(self.tables[table])

    def stream(self) -> bytes:
        valid = 0
        for table in self.tables:
            valid |= 1 << table
        out = bytearray(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0))
        for table in sorted(self.tables):
            out += struct.pack("<I", len(self.tables[table]))
        for table in sorted(self.tables):
            spec = SCHEMA[table]
            for row in self.tables[table]:
                for column, value in zip(spec, row):
                    width = int(column) if column in ("1", "2", "4") else 2
                    out += value.to_bytes(width, "little")
        while len(out) % 4:
            out.append(0)
        return bytes(out)


def managed(
    md: Metadata, *, bodies: dict[int, bytes] | None = None, dll: bool = True
) -> bytes:
    """A PE32+ with ``md`` as its metadata. ``bodies``: MethodDef rid -> IL;
    each MethodDef's RVA column is patched to point at its body."""
    body_rva = 0x3000
    code = bytearray()
    for rid, il in sorted((bodies or {}).items()):
        rva = body_rva + len(code)
        row = list(md.tables[6][rid - 1])
        row[0] = rva
        md.tables[6][rid - 1] = tuple(row)
        code += bytes([(len(il) << 2) | 0x2]) + il
        while len(code) % 4:
            code.append(0)
    strings = bytes(md.strings) + b"\0" * ((-len(md.strings)) % 4)
    blobs = bytes(md.blobs) + b"\0" * ((-len(md.blobs)) % 4)
    streams = [
        ("#~", md.stream()),
        ("#Strings", strings),
        ("#Blob", blobs),
        ("#GUID", b"\0" * 16),
    ]
    version = b"v4.0.30319\0\0"
    root = bytearray(
        b"BSJB"
        + struct.pack("<HHII", 1, 1, 0, len(version))
        + version
        + struct.pack("<HH", 0, len(streams))
    )
    header_size = len(root) + sum(8 + ((len(name) + 4) & ~3) for name, _ in streams)
    offset = (header_size + 3) & ~3
    data = bytearray()
    for name, payload in streams:
        encoded = name.encode() + b"\0"
        encoded += b"\0" * ((-len(encoded)) % 4)
        root += struct.pack("<II", offset + len(data), len(payload)) + encoded
        data += payload
    root += b"\0" * (offset - len(root))
    metadata = bytes(root + data)
    image = bytearray(0x200 + 0x3000)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", image, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x2022 if dll else 0x22
    )
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<Q", image, optional + 24, 0x180000000)
    struct.pack_into("<I", image, optional + 60, 0x200)
    struct.pack_into("<I", image, optional + 108, 16)
    struct.pack_into("<II", image, optional + 112 + 14 * 8, 0x2008, 72)
    section = optional + 240
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x3000, 0x2000, 0x3000, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor20 = 0x200 + 0x8
    struct.pack_into(
        "<IHHIIII",
        image,
        cor20,
        72,
        2,
        5,
        0x2100,
        len(metadata),
        1,
        0 if dll else 0x06000001,
    )
    image[0x300 : 0x300 + len(metadata)] = metadata
    image[0x1200 : 0x1200 + len(code)] = code
    return bytes(image)


def write(path: Path, data: bytes, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path
