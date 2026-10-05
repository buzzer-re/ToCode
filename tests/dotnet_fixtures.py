"""Synthetic .NET containers for tests (no .NET SDK or runtime needed)."""

from __future__ import annotations

from pathlib import Path
import struct
import zlib

from tocode.backends.dotnet_pe import BUNDLE_SIGNATURE

TEXT_RVA = 0x2000
TEXT_OFFSET = 0x200
COR20_RVA = TEXT_RVA + 0x8
METADATA_RVA = TEXT_RVA + 0x100


def _compressed(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return struct.pack(">H", value | 0x8000)
    return struct.pack(">I", value | 0xC0000000)


def user_string_heap(values: list[str]) -> bytes:
    heap = bytearray(b"\x00")
    for value in values:
        encoded = value.encode("utf-16-le")
        heap += _compressed(len(encoded) + 1) + encoded + b"\x00"
    while len(heap) % 4:
        heap += b"\x00"
    return bytes(heap)


def managed_pe(
    *,
    strings: list[str] | None = None,
    cor_flags: int = 0x1,
    ready_to_run: bool = False,
    machine: int = 0x8664,
) -> bytes:
    """A minimal PE32+ image with a CLR header, metadata root, and #US heap."""
    heap = user_string_heap(strings or ["hello", "https://example.invalid/api"])
    table_stream = b"\x00" * 8
    version = b"v4.0.30319\x00\x00"
    streams = [("#~", table_stream), ("#US", heap)]
    header = bytearray(b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version)
    header += struct.pack("<HH", 0, len(streams))
    header_size = len(header) + sum(8 + ((len(name) + 4) & ~3) for name, _ in streams)
    offset = (header_size + 3) & ~3
    blobs = bytearray()
    for name, data in streams:
        encoded = name.encode() + b"\x00"
        encoded += b"\x00" * ((-len(encoded)) % 4)
        header += struct.pack("<II", offset + len(blobs), len(data)) + encoded
        blobs += data
    header += b"\x00" * (offset - len(header))
    metadata = bytes(header + blobs)

    image = bytearray(TEXT_OFFSET + 0x1000)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x84, machine, 1, 0, 0, 0, 240, 0x2022)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<Q", image, optional + 24, 0x180000000)
    struct.pack_into("<I", image, optional + 108, 16)
    struct.pack_into("<II", image, optional + 112 + 14 * 8, COR20_RVA, 72)
    section = optional + 240
    image[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", image, section + 8, 0x1000, TEXT_RVA, 0x1000, TEXT_OFFSET)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor20 = TEXT_OFFSET + (COR20_RVA - TEXT_RVA)
    struct.pack_into(
        "<IHHIIII",
        image,
        cor20,
        72,
        2,
        5,
        METADATA_RVA,
        len(metadata),
        cor_flags,
        0x06000001,
    )
    if ready_to_run:
        struct.pack_into("<II", image, cor20 + 64, TEXT_RVA + 0x800, 0x40)
    meta_offset = TEXT_OFFSET + (METADATA_RVA - TEXT_RVA)
    image[meta_offset : meta_offset + len(metadata)] = metadata
    return bytes(image)


def native_elf(machine: int = 0xB7) -> bytes:
    data = bytearray(b"\x7fELF\x02\x01\x01" + b"\x00" * 57)
    struct.pack_into("<HH", data, 16, 3, machine)
    return bytes(data)


def _dotnet_string(value: str) -> bytes:
    raw = value.encode()
    length = len(raw)
    prefix = bytearray()
    while True:
        byte = length & 0x7F
        length >>= 7
        prefix.append(byte | (0x80 if length else 0))
        if not length:
            break
    return bytes(prefix) + raw


def single_file_bundle(
    entries: list[tuple[str, int, bytes, bool]], *, launcher: bool = False
) -> bytes:
    """An ELF "apphost" with a v6 bundle manifest.

    ``entries`` are ``(path, kind, data, compress)``; ``launcher=True`` writes
    a plain apphost (signature with a zero manifest offset).
    """
    host = bytearray(native_elf())
    host += b"\x00" * 64
    marker_at = len(host)
    host += b"\x00" * 8 + BUNDLE_SIGNATURE + b"\x00" * 32
    if launcher:
        return bytes(host)
    payload = bytearray(host)
    records: list[tuple[int, int, int, int, str]] = []
    for path, kind, data, compress in entries:
        stored = data
        compressed = 0
        if compress:
            deflater = zlib.compressobj(9, zlib.DEFLATED, -15)
            stored = deflater.compress(data) + deflater.flush()
            compressed = len(stored)
        records.append((len(payload), len(data), compressed, kind, path))
        payload += stored
    manifest_at = len(payload)
    manifest = bytearray(struct.pack("<IIi", 6, 0, len(records)))
    manifest += _dotnet_string("testbundle01")
    manifest += struct.pack("<qqqqQ", 0, 0, 0, 0, 0)
    for offset, size, compressed, kind, path in records:
        manifest += struct.pack("<qqqB", offset, size, compressed, kind)
        manifest += _dotnet_string(path)
    payload += manifest
    struct.pack_into("<q", payload, marker_at, manifest_at)
    return bytes(payload)


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path
