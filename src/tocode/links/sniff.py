"""Classify a file from its first bytes without parsing it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
import zipfile

ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe": 64,  # MH_MAGIC_64, little-endian
    b"\xce\xfa\xed\xfe": 32,  # MH_MAGIC
}
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
# A Java .class starts with the same 0xCAFEBABE; its next 4 bytes are
# (minor, major) with major >= 45, while a fat header has a small arch count.
MAX_FAT_ARCHS = 30
KNOWN_CPU_TYPES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
    18: "ppc",
    0x01000012: "ppc64",
}
HEAD_SIZE = 4096

# Kinds
ELF = "elf"
PE = "pe"
MACHO = "macho"
MACHO_FAT = "macho_fat"
JAVA_CLASS = "java_class"
ZIP = "zip"
DATA = "data"
CODE_KINDS = frozenset({ELF, PE, MACHO, MACHO_FAT})


@dataclass(frozen=True, slots=True)
class Sniff:
    kind: str
    detail: str = ""


def classify_bytes(head: bytes) -> Sniff:
    if head[:4] == ELF_MAGIC:
        return Sniff(ELF)
    if head[:4] in MACHO_MAGICS:
        return Sniff(MACHO)
    if len(head) >= 8:
        magic, count = struct.unpack_from(">II", head, 0)
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            if 0 < count <= MAX_FAT_ARCHS and _fat_cpu_known(head, magic, count):
                return Sniff(MACHO_FAT, f"{count} slices")
            if magic == FAT_MAGIC:
                return Sniff(JAVA_CLASS)
    if head[:2] == b"MZ" and len(head) >= 0x40:
        pe_offset = struct.unpack_from("<I", head, 0x3C)[0]
        if pe_offset + 4 <= len(head) and head[pe_offset : pe_offset + 4] == b"PE\0\0":
            return Sniff(PE)
        if pe_offset + 4 > len(head):
            return Sniff(PE, "header beyond sniff window")
        return Sniff(DATA, "DOS stub only")
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return Sniff(ZIP)
    return Sniff(DATA)


def _fat_cpu_known(head: bytes, magic: int, count: int) -> bool:
    size = 32 if magic == FAT_MAGIC_64 else 20
    first = 8
    if len(head) < first + size:
        return False
    cpu = struct.unpack_from(">I", head, first)[0]
    return cpu in KNOWN_CPU_TYPES


def read_head(path: Path, size: int = HEAD_SIZE) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def classify(path: Path) -> Sniff:
    head = read_head(path)
    sniff = classify_bytes(head)
    if sniff.kind == PE and sniff.detail:
        # The PE header sits past the first 4 KiB (rare: large DOS stubs).
        from ..backends.dotnet_pe import read_pe_info

        return Sniff(PE) if read_pe_info(path) is not None else Sniff(DATA)
    if sniff.kind == ZIP:
        return Sniff(ZIP, _zip_flavour(path))
    return sniff


def _zip_flavour(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".apk", ".nupkg", ".snupkg", ".jar", ".aar"}:
        return suffix.lstrip(".")
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist()[:2000])
    except (OSError, zipfile.BadZipFile, ValueError):
        return "zip"
    if "AndroidManifest.xml" in names:
        return "apk"
    return "zip"
