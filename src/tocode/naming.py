from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .schema import Cluster, ProgramAnalysis


_IDENT_BAD = re.compile(r"[^0-9A-Za-z_]")
_ANSI = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def clean_path_component(value: str) -> str:
    parts: list[str] = []
    just_inserted_sep = False
    for ch in value:
        if ch.isascii() and (ch.isalnum() or ch == "_"):
            parts.append(ch)
            just_inserted_sep = False
        elif not just_inserted_sep:
            parts.append("_")
            just_inserted_sep = True
    return "".join(parts).strip("_") or "unnamed"


def clean_c_identifier(value: str) -> str:
    text = _IDENT_BAD.sub("_", value)
    if not re.search(r"[0-9A-Za-z_]", text):
        return "unnamed"
    return f"fn_{text}" if text[0].isdigit() else text


def default_output_name(binary: Path) -> str:
    return f"{clean_path_component(binary.stem or 'binary')}_decompiler"


def c_file_name(cluster: Cluster) -> str:
    if cluster.root == SHARED_CLUSTER_ID:
        return "utils.c"
    return f"cluster_{cluster.root:016x}.c"


def asm_file_name(cluster: Cluster) -> str:
    return c_file_name(cluster).removesuffix(".c") + ".asm"


def summary_file_name(cluster: Cluster) -> str:
    return c_file_name(cluster).removesuffix(".c") + ".summary"


SHARED_CLUSTER_ID = 0xFFFFFFFFFFFFFFFF


class _Allocator:
    def __init__(self) -> None:
        self.used: set[str] = set()

    def claim(self, raw: str | None, fallback: str) -> str:
        base = clean_c_identifier(raw or "")
        if base == "unnamed":
            base = clean_c_identifier(fallback)
        name = base
        if name not in self.used:
            self.used.add(name)
            return name
        suffix = clean_c_identifier(fallback)
        name = f"{base}_{suffix}" if suffix != base else f"{base}_dup"
        while name in self.used:
            name = f"{name}_dup"
        self.used.add(name)
        return name


@dataclass(slots=True)
class NameBook:
    functions: dict[int, str]
    imports: dict[int, str]
    aliases: dict[str, str]
    _pattern: re.Pattern[str] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        keys = sorted(
            (k for k, v in self.aliases.items() if k and k != v), key=len, reverse=True
        )
        if keys:
            joined = "|".join(re.escape(key) for key in keys)
            self._pattern = re.compile(
                rf"(?<![0-9A-Za-z_])(?:{joined})(?![0-9A-Za-z_])"
            )

    def function_name(self, address: int, fallback: str) -> str:
        return self.functions.get(address, clean_c_identifier(fallback))

    def import_name(self, address: int, fallback: str) -> str:
        return self.imports.get(address, clean_c_identifier(fallback))

    def rewrite(self, text: str) -> str:
        stripped = _ANSI.sub("", text)
        if self._pattern is None:
            return stripped
        return self._pattern.sub(lambda match: self.aliases[match.group(0)], stripped)


def build_name_book(analysis: ProgramAnalysis) -> NameBook:
    allocator = _Allocator()
    function_names: dict[int, str] = {}
    import_names: dict[int, str] = {}
    aliases: dict[str, str] = {}

    for address, routine in sorted(analysis.routines.items()):
        if routine.imported:
            continue
        c_name = allocator.claim(routine.name, f"sub_{address:x}")
        function_names[address] = c_name
        _alias(aliases, c_name, routine.name)

    for address, item in sorted(analysis.imports.items()):
        c_name = allocator.claim(item.name, f"imp_{address:x}")
        import_names[address] = c_name
        _alias(
            aliases, c_name, item.name, f"sym.imp.{item.name}", f"loc.imp.{item.name}"
        )

    for item in sorted(analysis.symbols, key=lambda s: (s.vaddr, s.name, s.flag_name)):
        c_name = function_names.get(item.vaddr) or import_names.get(item.vaddr)
        if c_name is None:
            c_name = allocator.claim(
                item.flag_name or item.real_name or item.name, f"sym_{item.vaddr:x}"
            )
        _alias(aliases, c_name, item.name, item.flag_name, item.real_name)

    for item in sorted(analysis.relocations, key=lambda r: (r.vaddr, r.name)):
        raw = item.name or f"reloc_{item.vaddr:x}"
        c_name = allocator.claim(f"reloc_{raw}", f"reloc_{item.vaddr:x}")
        _alias(aliases, c_name, raw, f"reloc.{raw}")

    for item in sorted(analysis.flags, key=lambda f: (f.offset, f.name)):
        c_name = function_names.get(item.offset) or import_names.get(item.offset)
        if c_name is None:
            c_name = allocator.claim(
                item.name or item.real_name, f"flag_{item.offset:x}"
            )
        _alias(aliases, c_name, item.name, item.real_name)

    return NameBook(function_names, import_names, aliases)


def normalize_source(text: str, names: NameBook) -> str:
    lines = names.rewrite(text).splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and _warning(lines[0]):
        lines.pop(0)
        while lines and not lines[0].strip():
            lines.pop(0)
    return "\n".join(lines).rstrip()


def _alias(target: dict[str, str], canonical: str, *raw_names: str | None) -> None:
    for raw in raw_names:
        if raw:
            target.setdefault(raw, canonical)


def _warning(line: str) -> bool:
    value = line.strip()
    return value.startswith("//WARNING:") or value.startswith("WARNING:")
