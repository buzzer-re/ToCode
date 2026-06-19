"""Tests for DWARF source/type extraction.

These compile a tiny debug binary with the system C compiler and require
pyelftools (shipped with the angr extra), so they skip when either is missing.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

pytest.importorskip("elftools")

from tocode.backends.dwarf import load_dwarf  # noqa: E402

_SOURCE = """
#include <stdint.h>
struct point { int x; int y; char tag[8]; };
enum color { RED, GREEN = 5, BLUE };
int dist2(struct point *p) { return p->x * p->x + p->y * p->y; }
enum color pick(int n) { return n > 0 ? GREEN : RED; }
int main(void) { struct point p = {1, 2, "o"}; return dist2(&p); }
"""


@pytest.fixture(scope="module")
def debug_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler available")
    work = tmp_path_factory.mktemp("dwarf")
    src = work / "prog.c"
    src.write_text(_SOURCE, encoding="utf-8")
    out = work / "prog"
    result = subprocess.run(
        [compiler, "-g", "-O0", "-o", str(out), str(src)],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip(f"compiler failed: {result.stderr.decode(errors='replace')}")
    return out


def test_load_dwarf_recovers_sources_and_types(debug_binary: Path) -> None:
    data = load_dwarf(debug_binary)
    assert data is not None

    # Every recovered function should map to prog.c with a positive line.
    files = {loc.file for loc in data.sources.values()}
    assert any(f.endswith("prog.c") for f in files)
    assert all(loc.line and loc.line > 0 for loc in data.sources.values())

    # Function prototypes carry recovered return/param types.
    protos = {ft.return_type for ft in data.func_types.values()}
    assert "int" in protos
    pointer_params = [
        t for ft in data.func_types.values() for _, t in ft.params if "*" in t
    ]
    assert any("struct point" in t for t in pointer_params)

    # The struct and enum show up in the type catalog with real C declarations.
    by_name = {t["name"]: t for t in data.types}
    assert "point" in by_name and by_name["point"]["kind"] == "struct"
    assert "char tag[8]" in by_name["point"]["c_decl"]  # array, not pointer
    assert "color" in by_name and by_name["color"]["kind"] == "enum"
    assert "GREEN = 5" in by_name["color"]["c_decl"]


def test_load_dwarf_returns_none_without_debug_info(tmp_path: Path) -> None:
    not_elf = tmp_path / "data.bin"
    not_elf.write_bytes(b"not an elf file")
    assert load_dwarf(not_elf) is None
