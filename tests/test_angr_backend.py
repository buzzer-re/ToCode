"""Smoke tests for the angr backend.

These require a real angr install and a small ELF to analyze, so they skip when
either is unavailable. They assert structural parity (dict shapes / tuple types),
not decompilation quality.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("angr")

from tocode.backends.angr import AngrSession  # noqa: E402


def _sample_binary() -> Path:
    for candidate in ("/bin/true", "/usr/bin/true", "/bin/ls"):
        path = Path(candidate)
        if path.is_file():
            return path
    pytest.skip("no sample ELF binary available")


@pytest.fixture(scope="module")
def session() -> Iterator[AngrSession]:
    sess = AngrSession(_sample_binary())
    sess.analyze()
    yield sess
    sess.close()


def test_backend_identity() -> None:
    assert AngrSession.backend_name == "angr"
    assert AngrSession.parallel_safe is False


def test_info_shape(session: AngrSession) -> None:
    info = session.info()
    binary = info["bin"]
    assert isinstance(binary["arch"], str)
    assert isinstance(binary["bits"], int)
    assert isinstance(binary["baddr"], int)
    assert info["tocode"]["input_path"]


def test_collections_are_lists_of_dicts(session: AngrSession) -> None:
    for rows in (
        session.entries(),
        session.sections(),
        session.imports(),
        session.exports(),
        session.symbols(),
        session.relocations(),
        session.strings(),
        session.flags(),
        session.functions(),
    ):
        assert isinstance(rows, list)
        assert all(isinstance(row, dict) for row in rows)


def test_sections_have_required_keys(session: AngrSession) -> None:
    required = {"name", "size", "vsize", "type", "perm", "paddr", "vaddr"}
    for row in session.sections():
        assert required <= row.keys()
        assert len(row["perm"]) == 3


def test_functions_have_required_keys(session: AngrSession) -> None:
    funcs = session.functions()
    if not funcs:
        pytest.skip("angr recovered no functions for this binary")
    required = {
        "addr",
        "name",
        "size",
        "noreturn",
        "is_library",
        "is_thunk",
        "source_kind",
    }
    for row in funcs:
        assert required <= row.keys()
        assert isinstance(row["addr"], int)


def test_render_and_callgraph_on_first_function(session: AngrSession) -> None:
    funcs = session.functions()
    if not funcs:
        pytest.skip("angr recovered no functions for this binary")
    addr = funcs[0]["addr"]

    assert isinstance(session.disasm(addr), str)
    decompiled = session.decompile(addr)
    assert decompiled and "{" in decompiled  # exporter parses prototype before '{'
    assert "args:" in session.function_summary(addr)

    targets, imported = session.calls_from(addr, {}, {})
    assert isinstance(targets, list)
    assert all(isinstance(t, int) for t in targets)
    assert isinstance(imported, list)
    assert all(isinstance(n, str) for n in imported)


def test_angr_uses_dwarf_for_source_and_types(tmp_path: Path) -> None:
    import shutil
    import subprocess

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler available")
    src = tmp_path / "prog.c"
    src.write_text(
        "struct box { int w; int h; };\n"
        "int area(struct box *b) { return b->w * b->h; }\n"
        "int main(void) { struct box b = {3, 4}; return area(&b); }\n",
        encoding="utf-8",
    )
    out = tmp_path / "prog"
    result = subprocess.run(
        [compiler, "-g", "-O0", "-o", str(out), str(src)], capture_output=True
    )
    if result.returncode != 0:
        pytest.skip("compiler failed")

    sess = AngrSession(out)
    sess.analyze()
    try:
        rows = {r["name"]: r for r in sess.functions()}
        assert "area" in rows
        assert rows["area"].get("source_file", "").endswith("prog.c")
        assert rows["area"].get("source_line")
        assert rows["area"].get("return_type") == "int"
        type_names = {t["name"] for t in sess.types()}
        assert "box" in type_names
    finally:
        sess.close()


def test_data_xrefs_returns_mapping(session: AngrSession) -> None:
    strings = session.strings()
    addresses = {row["vaddr"] for row in strings[:5]} or {session.project.entry}
    xrefs = session.data_xrefs(addresses)
    assert isinstance(xrefs, dict)
    for refs in xrefs.values():
        assert all(isinstance(item, tuple) and len(item) == 2 for item in refs)
