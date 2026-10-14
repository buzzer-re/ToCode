"""ELF dynamic linking facts: DT_NEEDED, SONAME, RPATH/RUNPATH, dynamic symbols.

Driven by the program headers (PT_DYNAMIC and PT_LOAD), the same view the
runtime loader has, so it works on stripped files without section headers.
"""

from __future__ import annotations

import mmap
import struct

from .model import ExportSym, FileFacts, ImportSym, LibraryRef

PT_LOAD = 1
PT_DYNAMIC = 2
ET_EXEC = 2
ET_DYN = 3
DT_NULL = 0
DT_NEEDED = 1
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
DT_FLAGS_1 = 0x6FFFFFFB
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
DF_1_PIE = 0x08000000
SHT_DYNSYM = 11
SHN_UNDEF = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_GNU_UNIQUE = 10
STT_OBJECT = 1
STT_FUNC = 2
STT_TLS = 6
STT_GNU_IFUNC = 10
STV_HIDDEN = 2
STV_INTERNAL = 1
VER_FLG_BASE = 1
VER_FLG_WEAK = 2
EM_ARM = 40
MAX_SYMBOLS = 2_000_000

ELF_MACHINES = {
    0x03: "x86",
    0x08: "mips",
    0x14: "ppc",
    0x15: "ppc64",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
    0xF3: "riscv",
    0x102: "loongarch",
}

Buffer = bytes | mmap.mmap


class ElfError(ValueError):
    pass


class _Reader:
    def __init__(self, data: Buffer) -> None:
        self.data = data
        if bytes(data[:4]) != b"\x7fELF":
            raise ElfError("not an ELF file")
        self.is64 = data[4] == 2
        self.endian = "<" if data[5] == 1 else ">"
        if data[4] not in (1, 2) or data[5] not in (1, 2):
            raise ElfError("bad ELF class or data encoding")
        self.word = "Q" if self.is64 else "I"
        self.loads: list[tuple[int, int, int, int]] = []  # vaddr, memsz, offset, filesz

    def unpack(self, fmt: str, offset: int) -> tuple:
        if offset < 0:
            raise ElfError("negative offset")
        return struct.unpack_from(self.endian + fmt, self.data, offset)

    def va_to_offset(self, va: int) -> int | None:
        for vaddr, _memsz, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        return None

    def cstring(self, offset: int, limit: int = 4096) -> str:
        if offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\0", offset, min(len(self.data), offset + limit))
        if end < 0:
            end = min(len(self.data), offset + limit)
        return bytes(self.data[offset:end]).decode("utf-8", errors="replace")


def parse_elf(data: Buffer, path: str = "") -> FileFacts:
    r = _Reader(data)
    if r.is64:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = r.unpack(
            "HHIQQQIHHHHHH", 16
        )  # fmt: skip
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = r.unpack(
            "HHIIIIIHHHHHH", 16
        )  # fmt: skip
    facts = FileFacts(
        path=path,
        format="elf",
        arch=ELF_MACHINES.get(e_machine, f"elf-{e_machine:#x}"),
        bits=64 if r.is64 else 32,
        kind="other",
        entry=e_entry or None,
    )
    dynamic: tuple[int, int] | None = None
    for index in range(min(e_phnum, 4096)):
        base = e_phoff + index * e_phentsize
        if r.is64:
            p_type, _pf, p_offset, p_vaddr, _pa, p_filesz, p_memsz, _al = r.unpack(
                "IIQQQQQQ", base
            )
        else:
            p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, _pf, _al = r.unpack(
                "IIIIIIII", base
            )
        if p_type == PT_LOAD:
            r.loads.append((p_vaddr, p_memsz, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)
    if r.loads:
        facts.image_base = min(item[0] for item in r.loads) & ~0xFFF
    tags = _dynamic_tags(r, dynamic) if dynamic else []
    flags_1 = next((value for tag, value in tags if tag == DT_FLAGS_1), 0)
    has_soname = any(tag == DT_SONAME for tag, _value in tags)
    if e_type == ET_EXEC or (e_type == ET_DYN and flags_1 & DF_1_PIE):
        facts.kind = "executable"
    elif e_type == ET_DYN:
        # Older toolchains do not set DF_1_PIE: a PIE has an interpreter and no
        # SONAME. libc.so.6 has both (it is runnable) and is a library.
        interp = _has_interp(r, e_phoff, e_phnum, e_phentsize)
        facts.kind = "executable" if interp and not has_soname else "library"
    if not tags:
        return facts
    strtab_va = _tag(tags, DT_STRTAB)
    strtab = r.va_to_offset(strtab_va) if strtab_va is not None else None
    if strtab is None:
        facts.notes.append("no dynamic string table")
        return facts

    def dynstr(offset: int) -> str:
        return r.cstring(strtab + offset)

    for tag, value in tags:
        if tag == DT_NEEDED:
            facts.libraries.append(LibraryRef(dynstr(value)))
        elif tag == DT_SONAME:
            facts.identity = dynstr(value)
        elif tag == DT_RPATH:
            facts.rpaths.extend(_split_paths(dynstr(value)))
        elif tag == DT_RUNPATH:
            facts.runpaths.extend(_split_paths(dynstr(value)))
    needed_index = {lib.name: index for index, lib in enumerate(facts.libraries)}
    # Version tables: index -> (name, file or None, weak)
    versions: dict[int, tuple[str, str | None, bool]] = {}
    verneed_va = _tag(tags, DT_VERNEED)
    if verneed_va is not None:
        _read_verneed(r, verneed_va, _tag(tags, DT_VERNEEDNUM) or 0, dynstr, versions)
    verdef_va = _tag(tags, DT_VERDEF)
    if verdef_va is not None:
        _read_verdef(r, verdef_va, _tag(tags, DT_VERDEFNUM) or 0, dynstr, versions)

    symtab_va = _tag(tags, DT_SYMTAB)
    symtab = r.va_to_offset(symtab_va) if symtab_va is not None else None
    if symtab is None:
        return facts
    count = _symbol_count(r, tags, e_shoff, e_shnum, e_shentsize, symtab)
    versym_va = _tag(tags, DT_VERSYM)
    versym = r.va_to_offset(versym_va) if versym_va is not None else None
    entsize = 24 if r.is64 else 16
    thumb = e_machine == EM_ARM
    for index in range(1, count):
        base = symtab + index * entsize
        if base + entsize > len(data):
            break
        if r.is64:
            st_name, st_info, st_other, st_shndx, st_value, _size = r.unpack(
                "IBBHQQ", base
            )
        else:
            st_name, st_value, _size, st_info, st_other, st_shndx = r.unpack(
                "IIIBBH", base
            )
        bind = st_info >> 4
        if bind not in (STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE) or not st_name:
            continue
        name = dynstr(st_name)
        if not name:
            continue
        sym_type = st_info & 0xF
        kind = _symbol_kind(sym_type)
        version: str | None = None
        version_file: str | None = None
        hidden = False
        if versym is not None:
            raw = r.unpack("H", versym + index * 2)[0]
            hidden = bool(raw & 0x8000)
            entry = versions.get(raw & 0x7FFF)
            if entry is not None:
                version, version_file, _weak = entry
        if st_shndx == SHN_UNDEF:
            library = needed_index.get(version_file) if version_file else None
            facts.imports.append(
                ImportSym(
                    name=name,
                    library=library,
                    version=version,
                    weak=bind == STB_WEAK,
                    kind=kind,
                )
            )
            continue
        visibility = st_other & 3
        if visibility in (STV_HIDDEN, STV_INTERNAL):
            continue
        address = st_value
        if thumb and sym_type == STT_FUNC:
            address &= ~1
        facts.exports.append(
            ExportSym(
                name=name,
                address=address,
                version=version,
                default_version=not hidden,
                weak=bind == STB_WEAK,
                kind=kind,
            )
        )
    return facts


def _symbol_kind(sym_type: int) -> str | None:
    if sym_type in (STT_FUNC, STT_GNU_IFUNC):
        return "function"
    if sym_type == STT_OBJECT:
        return "data"
    if sym_type == STT_TLS:
        return "tls"
    return None


def _has_interp(r: _Reader, phoff: int, phnum: int, phentsize: int) -> bool:
    for index in range(min(phnum, 4096)):
        if r.unpack("I", phoff + index * phentsize)[0] == 3:  # PT_INTERP
            return True
    return False


def _tag(tags: list[tuple[int, int]], wanted: int) -> int | None:
    return next((value for tag, value in tags if tag == wanted), None)


def _split_paths(value: str) -> list[str]:
    return [item for item in value.split(":") if item]


def _dynamic_tags(r: _Reader, dynamic: tuple[int, int]) -> list[tuple[int, int]]:
    offset, size = dynamic
    entsize = 16 if r.is64 else 8
    fmt = "qQ" if r.is64 else "iI"
    tags: list[tuple[int, int]] = []
    for index in range(size // entsize):
        tag, value = r.unpack(fmt, offset + index * entsize)
        if tag == DT_NULL:
            break
        tags.append((tag & 0xFFFFFFFF if tag < 0 else tag, value))
    return tags


def _read_verneed(r, va, count, dynstr, versions) -> None:
    offset = r.va_to_offset(va)
    seen = 0
    while offset is not None and seen < max(count, 1) and seen < 4096:
        _vn_version, vn_cnt, vn_file, vn_aux, vn_next = r.unpack("HHIII", offset)
        file_name = dynstr(vn_file)
        aux = offset + vn_aux
        for _ in range(min(vn_cnt, 4096)):
            _hash, flags, other, name, next_aux = r.unpack("IHHII", aux)
            versions[other] = (dynstr(name), file_name, bool(flags & VER_FLG_WEAK))
            if not next_aux:
                break
            aux += next_aux
        seen += 1
        if not vn_next:
            break
        offset += vn_next


def _read_verdef(r, va, count, dynstr, versions) -> None:
    offset = r.va_to_offset(va)
    seen = 0
    while offset is not None and seen < max(count, 1) and seen < 4096:
        _version, flags, ndx, _cnt, _hash, aux, next_def = r.unpack("HHHHIII", offset)
        if not flags & VER_FLG_BASE:
            name_offset = r.unpack("I", offset + aux)[0]
            versions[ndx] = (dynstr(name_offset), None, False)
        seen += 1
        if not next_def:
            break
        offset += next_def


def _symbol_count(r: _Reader, tags, shoff, shnum, shentsize, symtab) -> int:
    # Section headers, when present, give the exact size of .dynsym.
    if shoff and shnum and shentsize:
        for index in range(min(shnum, 65535)):
            base = shoff + index * shentsize
            try:
                if r.is64:
                    (
                        _name,
                        sh_type,
                        _f,
                        _a,
                        sh_offset,
                        sh_size,
                        _l,
                        _i,
                        _al,
                        sh_entsize,
                    ) = r.unpack("IIQQQQIIQQ", base)
                else:
                    (
                        _name,
                        sh_type,
                        _f,
                        _a,
                        sh_offset,
                        sh_size,
                        _l,
                        _i,
                        _al,
                        sh_entsize,
                    ) = r.unpack("IIIIIIIIII", base)
            except struct.error:
                break
            if sh_type == SHT_DYNSYM and sh_entsize:
                return min(sh_size // sh_entsize, MAX_SYMBOLS)
    hash_va = _tag(tags, DT_HASH)
    if hash_va is not None:
        offset = r.va_to_offset(hash_va)
        if offset is not None:
            return min(r.unpack("II", offset)[1], MAX_SYMBOLS)
    gnu_va = _tag(tags, DT_GNU_HASH)
    if gnu_va is not None:
        offset = r.va_to_offset(gnu_va)
        if offset is not None:
            return min(_gnu_hash_count(r, offset), MAX_SYMBOLS)
    # Last resort: the string table usually follows the symbol table.
    strtab = r.va_to_offset(_tag(tags, DT_STRTAB) or 0)
    entsize = 24 if r.is64 else 16
    if strtab is not None and strtab > symtab:
        return min((strtab - symtab) // entsize, MAX_SYMBOLS)
    return 0


def _gnu_hash_count(r: _Reader, offset: int) -> int:
    nbuckets, symoffset, bloom_size, _shift = r.unpack("IIII", offset)
    word = 8 if r.is64 else 4
    buckets = offset + 16 + bloom_size * word
    chains = buckets + nbuckets * 4
    highest = 0
    for index in range(min(nbuckets, 1 << 24)):
        highest = max(highest, r.unpack("I", buckets + index * 4)[0])
    if highest < symoffset:
        return symoffset
    index = highest
    while index - symoffset < MAX_SYMBOLS:
        value = r.unpack("I", chains + (index - symoffset) * 4)[0]
        if value & 1:
            break
        index += 1
    return index + 1
