"""DWARF debug-info extraction shared by backends.

This reads source-file/line information and recovered type definitions straight
from a binary's DWARF data using pyelftools. It is import-guarded: when
pyelftools is unavailable or the binary carries no DWARF, ``load_dwarf`` returns
``None`` and callers fall back to whatever the decompiler recovered on its own.

The output is intentionally backend-agnostic: plain dicts/dataclasses matching
the shapes the analysis pipeline already consumes (see ``DecompilerSession`` in
``base.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any

try:  # pyelftools ships with the angr extra (via cle); optional otherwise.
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
except Exception:  # noqa: BLE001  # pragma: no cover - optional dependency
    ELFFile = None  # type: ignore[assignment,misc]


@dataclass(slots=True)
class SourceLoc:
    """Where a function was declared, as recorded in DWARF."""

    file: str  # path relative to comp_dir, e.g. "net/socket.c"
    directory: str  # relative directory, e.g. "net" ("" for the root)
    line: int | None
    comp_dir: str | None


@dataclass(slots=True)
class FuncTypes:
    """Recovered prototype pieces for one function."""

    return_type: str | None = None
    params: list[tuple[str, str]] = field(default_factory=list)
    locals: list[tuple[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class DwarfData:
    sources: dict[int, SourceLoc]  # low_pc -> location
    func_types: dict[int, FuncTypes]  # low_pc -> prototype pieces
    types: list[dict[str, Any]]  # catalog rows (name/kind/size/c_decl/members)


def load_dwarf(path: str | Path) -> DwarfData | None:
    """Parse DWARF from ``path``; return ``None`` when unavailable."""

    if ELFFile is None:
        return None
    try:
        with open(path, "rb") as handle:
            elf = ELFFile(handle)
            if not elf.has_dwarf_info():
                return None
            return _Extractor(elf.get_dwarf_info()).run()
    except Exception:  # noqa: BLE001 - never let debug info break analysis
        return None


_AGGREGATE_TAGS = {
    "DW_TAG_structure_type",
    "DW_TAG_union_type",
    "DW_TAG_enumeration_type",
    "DW_TAG_typedef",
}


class _Extractor:
    def __init__(self, dwarf: Any) -> None:
        self._dwarf = dwarf
        self.sources: dict[int, SourceLoc] = {}
        self.func_types: dict[int, FuncTypes] = {}
        self.types: list[dict[str, Any]] = []
        self._seen_types: set[str] = set()
        # Per-CU caches (file/dir table and comp_dir) keyed by CU offset, since a
        # function's decl_file may resolve through a DIE in a different CU.
        self._file_tables: dict[int, list[tuple[str, str]]] = {}
        self._comp_dirs: dict[int, str | None] = {}

    def run(self) -> DwarfData:
        for cu in self._dwarf.iter_CUs():
            try:
                self._handle_cu(cu)
            except Exception:  # noqa: BLE001 - skip malformed CUs, keep the rest
                pass
            finally:
                _release_cu(cu)
        return DwarfData(self.sources, self.func_types, self.types)

    def _handle_cu(self, cu: Any) -> None:
        for die in cu.iter_DIEs():
            tag = die.tag
            if tag == "DW_TAG_subprogram" and "DW_AT_low_pc" in die.attributes:
                self._handle_subprogram(die)
            elif tag in _AGGREGATE_TAGS and "DW_AT_name" in die.attributes:
                self._handle_type(die)

    def _file_table(self, cu: Any) -> list[tuple[str, str]]:
        """Return [(directory, filename)] indexed the DWARF-version way."""

        key = cu.cu_offset
        cached = self._file_tables.get(key)
        if cached is not None:
            return cached
        line_program = self._dwarf.line_program_for_CU(cu)
        files: list[tuple[str, str]] = []
        if line_program is not None:
            version = line_program.header["version"]
            dirs = [_decode(entry) for entry in line_program["include_directory"]]
            for entry in line_program["file_entry"]:
                name = _decode(entry.name)
                index = entry.dir_index
                directory = dirs[index] if 0 <= index < len(dirs) else ""
                files.append((directory, name))
            # DWARF < 5 indexes file_entry from 1; pad so direct indexing works.
            if version < 5:
                files.insert(0, ("", ""))
        self._file_tables[key] = files
        return files

    def _comp_dir(self, cu: Any) -> str | None:
        key = cu.cu_offset
        if key not in self._comp_dirs:
            self._comp_dirs[key] = _attr_str(cu.get_top_DIE(), "DW_AT_comp_dir")
        return self._comp_dirs[key]

    def _resolved_attr(self, die: Any, attr: str, depth: int = 0) -> tuple[Any, Any]:
        """Find ``attr``, following DW_AT_specification / DW_AT_abstract_origin.

        C++ and optimized code routinely leave the concrete function DIE without
        decl_file/decl_line/type, pointing instead at a specification or
        abstract-origin DIE that carries them. Returns ``(holder_die, value)``.
        """
        value = die.attributes.get(attr)
        if value is not None:
            return die, value
        if depth > 8:
            return None, None
        for ref in ("DW_AT_specification", "DW_AT_abstract_origin"):
            if ref not in die.attributes:
                continue
            try:
                target = die.get_DIE_from_attribute(ref)
            except Exception:  # noqa: BLE001
                target = None
            if target is not None:
                holder, found = self._resolved_attr(target, attr, depth + 1)
                if found is not None:
                    return holder, found
        return None, None

    def _handle_subprogram(self, die: Any) -> None:
        low_pc = die.attributes["DW_AT_low_pc"].value
        file_holder, file_attr = self._resolved_attr(die, "DW_AT_decl_file")
        _, line_attr = self._resolved_attr(die, "DW_AT_decl_line")
        if file_attr is not None and file_holder is not None:
            # decl_file indexes the file table of the CU that *holds* it.
            cu = file_holder.cu
            files = self._file_table(cu)
            if 0 <= file_attr.value < len(files):
                directory, filename = files[file_attr.value]
                comp_dir = self._comp_dir(cu)
                rel = _relative_source(directory, filename, comp_dir)
                self.sources[low_pc] = SourceLoc(
                    file=rel,
                    directory=os.path.dirname(rel),
                    line=line_attr.value if line_attr is not None else None,
                    comp_dir=comp_dir,
                )
        self.func_types[low_pc] = self._subprogram_types(die)

    def _subprogram_types(self, die: Any) -> FuncTypes:
        result = FuncTypes(return_type=self._type_of(die) or "void")
        for child in die.iter_children():
            if child.tag == "DW_TAG_formal_parameter":
                name = _attr_str(child, "DW_AT_name") or ""
                result.params.append((name, self._type_of(child) or "int"))
            elif child.tag == "DW_TAG_variable" and "DW_AT_name" in child.attributes:
                name = _attr_str(child, "DW_AT_name") or ""
                result.locals.append((name, self._type_of(child) or "int"))
        return result

    def _handle_type(self, die: Any) -> None:
        name = _attr_str(die, "DW_AT_name")
        if not name:
            return
        kind = {
            "DW_TAG_structure_type": "struct",
            "DW_TAG_union_type": "union",
            "DW_TAG_enumeration_type": "enum",
            "DW_TAG_typedef": "typedef",
        }[die.tag]
        key = f"{kind} {name}"
        if key in self._seen_types:
            return
        self._seen_types.add(key)
        size = die.attributes.get("DW_AT_byte_size")
        c_decl, members = self._render_aggregate(die, kind, name)
        self.types.append(
            {
                "name": name,
                "kind": kind,
                "size": size.value if size is not None else None,
                "c_decl": c_decl,
                "members": members,
                "ordinal": None,
            }
        )

    def _render_aggregate(
        self, die: Any, kind: str, name: str
    ) -> tuple[str, list[dict[str, Any]]]:
        members: list[dict[str, Any]] = []
        if kind == "typedef":
            underlying = _ref(die)
            return f"typedef {self._declarator(underlying, name)};", members
        if kind == "enum":
            return self._render_enum(die, name=name, members=members) + ";", members
        body = self._render_record(die, kind, members=members)
        return f"{kind} {name} {body};", members

    def _render_enum(
        self, die: Any, *, name: str | None, members: list[dict[str, Any]]
    ) -> str:
        header = f"enum {name} " if name else "enum "
        lines = [header + "{"]
        for child in die.iter_children():
            if child.tag != "DW_TAG_enumerator":
                continue
            ename = _attr_str(child, "DW_AT_name") or ""
            value = child.attributes.get("DW_AT_const_value")
            val = value.value if value is not None else None
            members.append({"name": ename, "value": val})
            lines.append(
                f"    {ename} = {val}," if val is not None else f"    {ename},"
            )
        lines.append("}")
        return "\n".join(lines)

    def _render_record(
        self, die: Any, kind: str, *, members: list[dict[str, Any]], depth: int = 0
    ) -> str:
        lines = ["{"]
        for child in die.iter_children():
            if child.tag != "DW_TAG_member":
                continue
            mname = _attr_str(child, "DW_AT_name") or ""
            member_die = _ref(child)
            lines.append("    " + self._declarator(member_die, mname, depth + 1) + ";")
            offset = child.attributes.get("DW_AT_data_member_location")
            members.append(
                {
                    "name": mname,
                    "type": self._type_str(member_die),
                    "offset": offset.value if offset is not None else None,
                }
            )
        lines.append("}")
        return "\n".join(lines)

    def _declarator(self, type_die: Any, name: str, depth: int = 0) -> str:
        """Render a full C declarator, handling pointers, arrays and anon types."""

        if type_die is not None and type_die.tag == "DW_TAG_array_type" and depth < 12:
            element, dims = self._array_info(type_die)
            suffix = "".join(f"[{d}]" if d is not None else "[]" for d in dims) or "[]"
            return _declare(self._type_str(element, depth + 1), name) + suffix
        return _declare(self._type_str(type_die, depth), name)

    def _array_info(self, die: Any) -> tuple[Any, list[int | None]]:
        dims: list[int | None] = []
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            upper = child.attributes.get("DW_AT_upper_bound")
            count = child.attributes.get("DW_AT_count")
            if count is not None:
                dims.append(int(count.value))
            elif upper is not None and isinstance(upper.value, int):
                dims.append(int(upper.value) + 1)
            else:
                dims.append(None)
        return _ref(die), dims or [None]

    def _type_of(self, die: Any) -> str | None:
        holder, _ = self._resolved_attr(die, "DW_AT_type")
        if holder is None:
            return None
        return self._type_str(_ref(holder))

    def _type_str(self, die: Any, depth: int = 0) -> str:
        if die is None or depth > 12:
            return "void"
        tag = die.tag
        name = _attr_str(die, "DW_AT_name")
        if tag == "DW_TAG_base_type":
            return name or "int"
        if tag == "DW_TAG_typedef":
            return name or "void"
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            kind = "struct" if tag == "DW_TAG_structure_type" else "union"
            if name:
                return f"{kind} {name}"
            return f"{kind} " + self._render_record(die, kind, members=[], depth=depth)
        if tag == "DW_TAG_enumeration_type":
            if name:
                return f"enum {name}"
            return self._render_enum(die, name=None, members=[])
        if tag == "DW_TAG_pointer_type":
            return _ptr(self._type_str(_ref(die), depth + 1))
        if tag == "DW_TAG_const_type":
            return "const " + self._type_str(_ref(die), depth + 1)
        if tag == "DW_TAG_volatile_type":
            return "volatile " + self._type_str(_ref(die), depth + 1)
        if tag == "DW_TAG_array_type":
            return self._type_str(_ref(die), depth + 1) + " *"
        if tag == "DW_TAG_subroutine_type":
            return "void *"  # function pointer; keep it simple
        return name or "void"


def _release_cu(cu: Any) -> None:
    """Drop pyelftools' per-CU DIE cache so memory does not grow per unit.

    pyelftools caches every DIE it parses on the CompileUnit; without this,
    walking all units of a large .debug_info accumulates the whole tree in RAM
    (gigabytes), which can OOM the process. We are done with the CU here.
    """
    try:
        cu._dielist = []
        cu._diemap = {}
    except Exception:  # noqa: BLE001
        pass


def _ref(die: Any) -> Any:
    if die is None or "DW_AT_type" not in die.attributes:
        return None
    try:
        return die.get_DIE_from_attribute("DW_AT_type")
    except Exception:  # noqa: BLE001
        return None


def _ptr(inner: str) -> str:
    return inner + ("*" if inner.endswith("*") else " *")


def _declare(type_str: str, name: str) -> str:
    """Render a C declaration, placing the name correctly for pointers."""

    if not name:
        return type_str
    if type_str.endswith("*"):
        return f"{type_str}{name}"
    return f"{type_str} {name}"


def _attr_str(die: Any, attr: str) -> str | None:
    value = die.attributes.get(attr)
    if value is None:
        return None
    return _decode(value.value)


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _relative_source(directory: str, filename: str, comp_dir: str | None) -> str:
    """Build a clean source path relative to the compilation directory."""

    if os.path.isabs(directory):
        absolute = os.path.join(directory, filename)
        if comp_dir:
            rel = os.path.relpath(absolute, comp_dir)
            if not rel.startswith(".."):
                return rel
        return absolute.lstrip("/")
    joined = os.path.join(directory, filename) if directory else filename
    return joined
