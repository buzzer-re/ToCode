"""Pure-Python readers for .NET containers: PE/CLR headers, single-file bundles.

Nothing here loads the .NET runtime, so input routing (``is_dotnet_input``)
stays cheap for every binary ToCode is pointed at, and the readers are
testable without a .NET install.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import mmap
from pathlib import Path
import struct
import zlib

# IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
_CLR_DIRECTORY = 14
COMIMAGE_FLAGS_ILONLY = 0x1
COMIMAGE_FLAGS_32BITREQUIRED = 0x2
COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x8
COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x10
COMIMAGE_FLAGS_32BITPREFERRED = 0x20000

PE_MACHINES = {
    0x14C: "x86",
    0x8664: "x86_64",
    0x1C0: "arm",
    0x1C4: "arm",
    0xAA64: "arm64",
    0x200: "ia64",
}
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Marker the .NET host (apphost / singlefilehost) uses to find the bundle
# manifest; the 8 bytes before it hold the manifest offset (0 = not a bundle).
BUNDLE_SIGNATURE = bytes(
    [
        0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38,
        0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
        0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18,
        0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE,
    ]
)  # fmt: skip
BUNDLE_ENTRY_KINDS = {
    0: "unknown",
    1: "assembly",
    2: "native",
    3: "deps-json",
    4: "runtime-config",
    5: "symbols",
}
_EXECUTABLE_MAGICS = (
    b"MZ",
    b"\x7fELF",
    b"\xcf\xfa\xed\xfe",  # Mach-O 64
    b"\xce\xfa\xed\xfe",  # Mach-O 32
    b"\xca\xfe\xba\xbe",  # Mach-O fat
)


@dataclass(slots=True)
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def perms(self) -> str:
        flags = self.characteristics
        return (
            ("r" if flags & IMAGE_SCN_MEM_READ else "-")
            + ("w" if flags & IMAGE_SCN_MEM_WRITE else "-")
            + ("x" if flags & IMAGE_SCN_MEM_EXECUTE else "-")
        )


@dataclass(slots=True)
class MetadataStream:
    name: str
    offset: int  # file offset
    size: int


@dataclass(slots=True)
class PeInfo:
    machine: str
    pe32_plus: bool
    image_base: int
    sections: list[PeSection]
    clr_rva: int = 0
    clr_size: int = 0
    runtime_version: str | None = None
    cor_flags: int = 0
    entry_point_token: int = 0
    metadata_rva: int = 0
    metadata_size: int = 0
    resources_rva: int = 0
    resources_size: int = 0
    strong_name_rva: int = 0
    managed_native_header_rva: int = 0
    streams: list[MetadataStream] = field(default_factory=list)

    @property
    def is_managed(self) -> bool:
        return self.clr_rva != 0 and self.clr_size != 0

    @property
    def il_only(self) -> bool:
        return bool(self.cor_flags & COMIMAGE_FLAGS_ILONLY)

    @property
    def mixed_mode(self) -> bool:
        # C++/CLI images clear ILONLY because they carry native code. So do
        # ReadyToRun images, but their native code is precompiled IL that the
        # IL decompiler already covers, so they are not "mixed" for our purpose.
        return self.is_managed and not self.il_only and not self.ready_to_run

    @property
    def ready_to_run(self) -> bool:
        return self.managed_native_header_rva != 0

    @property
    def cor_flag_names(self) -> list[str]:
        names = []
        for bit, name in (
            (COMIMAGE_FLAGS_ILONLY, "ILOnly"),
            (COMIMAGE_FLAGS_32BITREQUIRED, "32BitRequired"),
            (COMIMAGE_FLAGS_STRONGNAMESIGNED, "StrongNameSigned"),
            (COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, "NativeEntryPoint"),
            (COMIMAGE_FLAGS_32BITPREFERRED, "32BitPreferred"),
        ):
            if self.cor_flags & bit:
                names.append(name)
        return names

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    return None
                return section.raw_offset + delta
        return None

    def stream(self, name: str) -> MetadataStream | None:
        return next((item for item in self.streams if item.name == name), None)


def parse_pe(data: bytes | mmap.mmap) -> PeInfo | None:
    """Parse the PE headers we need; ``None`` for anything that is not a PE."""
    try:
        if data[:2] != b"MZ":
            return None
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return None
        machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
        optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        optional = pe_offset + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic == 0x20B:
            pe32_plus = True
            image_base = struct.unpack_from("<Q", data, optional + 24)[0]
            dirs_count = struct.unpack_from("<I", data, optional + 108)[0]
            dirs = optional + 112
        elif magic == 0x10B:
            pe32_plus = False
            image_base = struct.unpack_from("<I", data, optional + 28)[0]
            dirs_count = struct.unpack_from("<I", data, optional + 92)[0]
            dirs = optional + 96
        else:
            return None
        sections: list[PeSection] = []
        table = optional + optional_size
        for index in range(section_count):
            base = table + index * 40
            raw_name = bytes(data[base : base + 8]).split(b"\0", 1)[0]
            vsize, vaddr, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, base + 8
            )
            characteristics = struct.unpack_from("<I", data, base + 36)[0]
            sections.append(
                PeSection(
                    raw_name.decode("ascii", errors="replace"),
                    vaddr,
                    vsize,
                    raw_offset,
                    raw_size,
                    characteristics,
                )
            )
        info = PeInfo(
            machine=PE_MACHINES.get(machine, f"0x{machine:x}"),
            pe32_plus=pe32_plus,
            image_base=image_base,
            sections=sections,
        )
        if dirs_count > _CLR_DIRECTORY:
            clr_rva, clr_size = struct.unpack_from(
                "<II", data, dirs + _CLR_DIRECTORY * 8
            )
            info.clr_rva = clr_rva
            info.clr_size = clr_size
        if info.is_managed:
            _parse_cor20(data, info)
        return info
    except (struct.error, IndexError, ValueError):
        return None


def _parse_cor20(data: bytes | mmap.mmap, info: PeInfo) -> None:
    offset = info.rva_to_offset(info.clr_rva)
    if offset is None:
        info.clr_rva = info.clr_size = 0
        return
    (
        _cb,
        _major,
        _minor,
        info.metadata_rva,
        info.metadata_size,
        info.cor_flags,
        info.entry_point_token,
        info.resources_rva,
        info.resources_size,
        info.strong_name_rva,
    ) = struct.unpack_from("<IHHIIIIIII", data, offset)
    # ManagedNativeHeader (ReadyToRun) is the last directory of the header.
    info.managed_native_header_rva = struct.unpack_from("<I", data, offset + 64)[0]
    root = info.rva_to_offset(info.metadata_rva)
    if root is None or data[root : root + 4] != b"BSJB":
        return
    version_length = struct.unpack_from("<I", data, root + 12)[0]
    info.runtime_version = (
        bytes(data[root + 16 : root + 16 + version_length])
        .split(b"\0", 1)[0]
        .decode("ascii", errors="replace")
    )
    cursor = root + 16 + version_length + 2  # flags
    stream_count = struct.unpack_from("<H", data, cursor)[0]
    cursor += 2
    for _ in range(stream_count):
        stream_offset, stream_size = struct.unpack_from("<II", data, cursor)
        cursor += 8
        end = bytes(data[cursor : cursor + 32]).index(b"\0")
        name = bytes(data[cursor : cursor + end]).decode("ascii", errors="replace")
        cursor += (end + 4) & ~3
        info.streams.append(MetadataStream(name, root + stream_offset, stream_size))


def read_pe_info(path: Path) -> PeInfo | None:
    try:
        with path.open("rb") as handle:
            head = handle.read(2)
            if head != b"MZ":
                return None
            handle.seek(0)
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
                return parse_pe(view)
    except (OSError, ValueError):
        return None


def is_managed_pe(path: Path) -> bool:
    info = read_pe_info(path)
    return info is not None and info.is_managed


# --------------------------------------------------------------------------
# User string heap (#US)
# --------------------------------------------------------------------------


def _compressed_uint(data: bytes, offset: int) -> tuple[int, int]:
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


def iter_user_strings(heap: bytes) -> list[tuple[int, str]]:
    """``(heap offset, value)`` for every string in a #US heap."""
    result: list[tuple[int, str]] = []
    offset = 1  # offset 0 is the empty blob
    length = len(heap)
    while offset < length:
        try:
            size, used = _compressed_uint(heap, offset)
        except IndexError:
            break
        start = offset + used
        if size == 0:
            offset = start
            continue
        chars = (size - 1) & ~1  # drop the trailing flag byte
        if start + chars > length:
            break
        value = heap[start : start + chars].decode("utf-16-le", errors="replace")
        result.append((offset, value))
        offset = start + size
    return result


# --------------------------------------------------------------------------
# Method bodies and IL token scan
# --------------------------------------------------------------------------

# Operand kinds; the scan only needs sizes plus the token-bearing kinds.
_N, _B1, _B2, _B4, _B8 = "none", "i1", "i2", "i4", "i8"
TOK_METHOD, TOK_FIELD, TOK_TYPE, TOK_STRING, TOK_SIG, TOK_TOKEN = (
    "method",
    "field",
    "type",
    "string",
    "sig",
    "token",
)
_SWITCH = "switch"


def _one_byte_table() -> dict[int, str]:
    table: dict[int, str] = {}
    for code in range(0x00, 0x0E):  # nop .. stloc.3
        table[code] = _N
    for code in range(0x0E, 0x14):  # ldarg.s .. stloc.s
        table[code] = _B1
    for code in range(0x14, 0x1F):  # ldnull, ldc.i4.m1 .. ldc.i4.8
        table[code] = _N
    table[0x1F] = _B1  # ldc.i4.s
    table[0x20] = _B4  # ldc.i4
    table[0x21] = _B8  # ldc.i8
    table[0x22] = _B4  # ldc.r4
    table[0x23] = _B8  # ldc.r8
    table[0x25] = _N  # dup
    table[0x26] = _N  # pop
    table[0x27] = TOK_METHOD  # jmp
    table[0x28] = TOK_METHOD  # call
    table[0x29] = TOK_SIG  # calli
    table[0x2A] = _N  # ret
    for code in range(0x2B, 0x38):  # short branches
        table[code] = _B1
    for code in range(0x38, 0x45):  # long branches
        table[code] = _B4
    table[0x45] = _SWITCH
    for code in range(0x46, 0x6F):  # ldind/stind/arith/conv
        table[code] = _N
    table[0x6F] = TOK_METHOD  # callvirt
    table[0x70] = TOK_TYPE  # cpobj
    table[0x71] = TOK_TYPE  # ldobj
    table[0x72] = TOK_STRING  # ldstr
    table[0x73] = TOK_METHOD  # newobj
    table[0x74] = TOK_TYPE  # castclass
    table[0x75] = TOK_TYPE  # isinst
    table[0x76] = _N  # conv.r.un
    table[0x79] = TOK_TYPE  # unbox
    table[0x7A] = _N  # throw
    for code in range(0x7B, 0x81):  # ldfld .. stsfld
        table[code] = TOK_FIELD
    table[0x81] = TOK_TYPE  # stobj
    for code in range(0x82, 0x8C):  # conv.ovf.*.un
        table[code] = _N
    table[0x8C] = TOK_TYPE  # box
    table[0x8D] = TOK_TYPE  # newarr
    table[0x8E] = _N  # ldlen
    table[0x8F] = TOK_TYPE  # ldelema
    for code in range(0x90, 0xA3):  # ldelem.* / stelem.*
        table[code] = _N
    table[0xA3] = TOK_TYPE  # ldelem
    table[0xA4] = TOK_TYPE  # stelem
    table[0xA5] = TOK_TYPE  # unbox.any
    for code in range(0xB3, 0xBB):  # conv.ovf.*
        table[code] = _N
    table[0xC2] = TOK_TYPE  # refanyval
    table[0xC3] = _N  # ckfinite
    table[0xC6] = TOK_TYPE  # mkrefany
    table[0xD0] = TOK_TOKEN  # ldtoken
    for code in range(0xD1, 0xDD):  # conv.u2 .. endfinally
        table[code] = _N
    table[0xDD] = _B4  # leave
    table[0xDE] = _B1  # leave.s
    table[0xDF] = _N  # stind.i
    table[0xE0] = _N  # conv.u
    return table


def _two_byte_table() -> dict[int, str]:
    table: dict[int, str] = {code: _N for code in range(0x00, 0x06)}
    table[0x06] = TOK_METHOD  # ldftn
    table[0x07] = TOK_METHOD  # ldvirtftn
    for code in range(0x09, 0x0F):  # ldarg .. stloc
        table[code] = _B2
    table[0x0F] = _N  # localloc
    table[0x11] = _N  # endfilter
    table[0x12] = _B1  # unaligned.
    table[0x13] = _N  # volatile.
    table[0x14] = _N  # tail.
    table[0x15] = TOK_TYPE  # initobj
    table[0x16] = TOK_TYPE  # constrained.
    table[0x17] = _N  # cpblk
    table[0x18] = _N  # initblk
    table[0x19] = _B1  # no.
    table[0x1A] = _N  # rethrow
    table[0x1C] = TOK_TYPE  # sizeof
    table[0x1D] = _N  # refanytype
    table[0x1E] = _N  # readonly.
    return table


ONE_BYTE_OPCODES = _one_byte_table()
TWO_BYTE_OPCODES = _two_byte_table()
_OPERAND_SIZES = {_N: 0, _B1: 1, _B2: 2, _B4: 4, _B8: 8}
_TOKEN_KINDS = {TOK_METHOD, TOK_FIELD, TOK_TYPE, TOK_STRING, TOK_SIG, TOK_TOKEN}


def method_body(data: bytes | mmap.mmap, offset: int) -> bytes | None:
    """IL code bytes of the method body at ``offset`` (tiny or fat header)."""
    try:
        first = data[offset]
    except IndexError:
        return None
    if first & 0x3 == 0x2:  # tiny
        size = first >> 2
        return bytes(data[offset + 1 : offset + 1 + size])
    if first & 0x3 == 0x3:  # fat
        flags_size = struct.unpack_from("<H", data, offset)[0]
        header_size = (flags_size >> 12) * 4
        code_size = struct.unpack_from("<I", data, offset + 4)[0]
        start = offset + header_size
        return bytes(data[start : start + code_size])
    return None


def scan_il_tokens(code: bytes) -> list[tuple[str, int]]:
    """Every ``(kind, metadata token)`` an IL stream references, in order."""
    refs: list[tuple[str, int]] = []
    pc = 0
    length = len(code)
    while pc < length:
        opcode = code[pc]
        pc += 1
        if opcode == 0xFE:
            if pc >= length:
                break
            kind = TWO_BYTE_OPCODES.get(code[pc])
            pc += 1
        else:
            kind = ONE_BYTE_OPCODES.get(opcode)
        if kind is None:
            break  # invalid/encrypted body: stop rather than misread
        if kind == _SWITCH:
            if pc + 4 > length:
                break
            count = struct.unpack_from("<I", code, pc)[0]
            pc += 4 + 4 * count
            continue
        if kind in _TOKEN_KINDS:
            if pc + 4 > length:
                break
            refs.append((kind, struct.unpack_from("<I", code, pc)[0]))
            pc += 4
            continue
        pc += _OPERAND_SIZES[kind]
    return refs


# --------------------------------------------------------------------------
# Single-file bundles
# --------------------------------------------------------------------------


@dataclass(slots=True)
class BundleEntry:
    offset: int
    size: int
    compressed_size: int
    kind: str
    path: str


@dataclass(slots=True)
class BundleManifest:
    major: int
    minor: int
    bundle_id: str
    header_offset: int
    entries: list[BundleEntry]


def _read_dotnet_string(data: bytes | mmap.mmap, offset: int) -> tuple[str, int]:
    length = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        length |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            break
    raw = bytes(data[offset : offset + length])
    return raw.decode("utf-8", errors="replace"), offset + length


def find_bundle_header(data: bytes | mmap.mmap) -> tuple[int, int] | None:
    """``(signature offset, manifest offset)``; manifest 0 = plain apphost."""
    position = data.find(BUNDLE_SIGNATURE)
    if position < 8:
        return None
    header = struct.unpack_from("<q", data, position - 8)[0]
    return position, header


def parse_bundle(data: bytes | mmap.mmap) -> BundleManifest | None:
    found = find_bundle_header(data)
    if found is None:
        return None
    _signature, header = found
    if header <= 0 or header >= len(data):
        return None
    try:
        major, minor, count = struct.unpack_from("<IIi", data, header)
        cursor = header + 12
        bundle_id, cursor = _read_dotnet_string(data, cursor)
        if major >= 2:
            cursor += 40  # deps.json / runtimeconfig.json locations + flags
        entries: list[BundleEntry] = []
        for _ in range(max(0, count)):
            offset, size = struct.unpack_from("<qq", data, cursor)
            cursor += 16
            compressed = 0
            if major >= 6:
                compressed = struct.unpack_from("<q", data, cursor)[0]
                cursor += 8
            kind = BUNDLE_ENTRY_KINDS.get(data[cursor], "unknown")
            cursor += 1
            path, cursor = _read_dotnet_string(data, cursor)
            entries.append(BundleEntry(offset, size, compressed, kind, path))
    except (struct.error, IndexError):
        return None
    return BundleManifest(major, minor, bundle_id, header, entries)


def read_bundle(path: Path) -> BundleManifest | None:
    try:
        with path.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
                if not bytes(view[:4]).startswith(_EXECUTABLE_MAGICS):
                    return None
                return parse_bundle(view)
    except (OSError, ValueError):
        return None


def is_apphost_launcher(path: Path) -> bool:
    """A non-bundled .NET apphost: the real code is ``<name>.dll`` beside it."""
    try:
        with path.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
                if not bytes(view[:4]).startswith(_EXECUTABLE_MAGICS):
                    return False
                found = find_bundle_header(view)
                return found is not None and found[1] == 0
    except (OSError, ValueError):
        return False


def extract_bundle_entry(source: Path, entry: BundleEntry, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as handle:
        handle.seek(entry.offset)
        if entry.compressed_size:
            payload = handle.read(entry.compressed_size)
            data = zlib.decompress(payload, -15)
        else:
            data = handle.read(entry.size)
    target.write_bytes(data)
