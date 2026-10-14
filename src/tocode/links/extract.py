"""Read link facts from a file on disk, whatever its format."""

from __future__ import annotations

import mmap
from pathlib import Path

from .binfmt_dotnet import DotnetMetadataError, parse_dotnet_links
from .binfmt_elf import ElfError, parse_elf
from .binfmt_macho import MachoError, fat_slices, parse_macho
from .binfmt_pe import PeError, parse_pe_links
from .model import FileFacts
from .sniff import ELF, MACHO, MACHO_FAT, PE

PARSE_ERRORS = (
    ElfError,
    PeError,
    MachoError,
    DotnetMetadataError,
    ValueError,
    IndexError,
    OSError,
)


def read_facts(path: Path, relpath: str, kind: str) -> list[FileFacts]:
    """Facts for every image in ``path`` (one per fat slice).

    ``kind`` is the sniffed kind. Parse problems are reported as a single
    ``FileFacts`` with notes, so one bad file never stops a folder scan.
    """
    try:
        with path.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
                return _read(view, relpath, kind)
    except PARSE_ERRORS as exc:
        broken = FileFacts(
            path=relpath, format=kind, arch="unknown", bits=0, kind="other"
        )
        broken.notes.append(f"unparsed: {type(exc).__name__}: {exc}")
        return [broken]


def _read(view: mmap.mmap, relpath: str, kind: str) -> list[FileFacts]:
    if kind == ELF:
        return [parse_elf(view, relpath)]
    if kind == MACHO:
        return [parse_macho(view, relpath)]
    if kind == MACHO_FAT:
        result = []
        for item in fat_slices(view):
            try:
                result.append(
                    parse_macho(view, relpath, base=item.offset, size=item.size)
                )
            except PARSE_ERRORS as exc:
                broken = FileFacts(
                    path=relpath, format="macho", arch=item.arch, bits=0, kind="other"
                )
                broken.notes.append(f"unparsed slice: {exc}")
                result.append(broken)
        return result
    if kind == PE:
        facts = parse_pe_links(view, relpath)
        from ..backends.dotnet_pe import parse_pe

        info = parse_pe(view)
        if info is not None and info.is_managed:
            try:
                managed = parse_dotnet_links(view, relpath)
            except PARSE_ERRORS as exc:
                facts.notes.append(f"managed metadata unreadable: {exc}")
                return [facts]
            if info.mixed_mode:
                # C++/CLI: keep the native import table next to the managed refs.
                offset = len(managed.libraries)
                managed.libraries.extend(facts.libraries)
                for symbol in facts.imports:
                    if symbol.library is not None:
                        symbol.library += offset
                managed.imports.extend(facts.imports)
                managed.exports.extend(facts.exports)
            return [managed]
        return [facts]
    raise ValueError(f"no link parser for {kind}")
