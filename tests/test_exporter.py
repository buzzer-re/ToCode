from __future__ import annotations

import json
from pathlib import Path

from tocode.exporter import export_binary, tree_safe_function
from tocode.progress import Progress
from tocode.schema import (
    BinaryFacts,
    ProgramAnalysis,
    Routine,
    Segment,
    StringEntry,
)


class FakeAnalyzer:
    backend_name = "fake"
    backend_label = "Fake Backend"
    decompiler_label = "Fake Decompiler"
    supports_parallel = False
    analysis_seconds = 0.01

    def __init__(self, analysis: ProgramAnalysis) -> None:
        self.analysis = analysis
        self.binary = analysis.binary.path
        self.progress = Progress(enabled=False)

    def collect(self) -> ProgramAnalysis:
        return self.analysis

    def disasm(self, address: int) -> str:
        return f"push rbp\nmov rbp, rsp\n; addr {address:x}"

    def decompile(self, address: int) -> str:
        if address == 0x1000:
            return "int main(void)\n{\n    helper();\n    return 0;\n}"
        return "int helper(void)\n{\n    return 7;\n}"

    def function_summary(self, address: int) -> str:
        return f"address: 0x{address:x}\ncallees: 0"

    def cluster_description_from_imports(self, _members: list[int]) -> str:
        return "General functions"

    def prepare_parallel_workers(self) -> None:
        return


def test_export_binary_writes_source_tree_and_metadata(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 256 + b"hello\x00")
    analysis = ProgramAnalysis(
        binary=BinaryFacts(
            path=binary,
            arch="x86",
            bits=64,
            image_base=0x1000,
            os_name="linux",
            format_name="elf",
            file_type="EXEC",
            entrypoints=[0x1000],
        ),
        segments=[
            Segment(".text", 128, 128, "PROGBITS", "r-x", 0, 0x1000),
            Segment(".rodata", 32, 32, "PROGBITS", "r--", 256, 0x2000),
        ],
        routines={
            0x1000: Routine(0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 1, 0),
            0x1050: Routine(0x1050, "helper", 32, "int helper(void)", None, False, 0, 0, 0, 0, 1),
        },
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[StringEntry(0x2000, 256, 6, 5, ".rodata", "ascii", "hello")],
        flags=[],
        callees={0x1000: [0x1050], 0x1050: []},
        callers={0x1000: [], 0x1050: [0x1000]},
        import_calls={0x1000: [], 0x1050: []},
        roots=[0x1000],
        thunks=set(),
    )

    summary = export_binary(
        FakeAnalyzer(analysis),  # type: ignore[arg-type]
        out_dir=tmp_path / "export",
        progress=Progress(enabled=False),
        jobs=None,
    )

    assert summary.function_count == 2
    assert summary.cluster_count == 1
    assert (summary.root_dir / "AGENTS.md").is_file()
    assert (summary.root_dir / "project.json").is_file()
    assert (summary.root_dir / "export-manifest.json").is_file()
    assert (summary.root_dir / "src" / "raw" / "app" / "cluster_0000000000001000.c").is_file()
    assert (summary.root_dir / "src" / "tree" / "app" / "cluster_0000000000001000.c").is_file()
    assert (summary.root_dir / "function-index-tree.json").is_file()
    assert (summary.root_dir / "include" / "tocode_tree.h").is_file()
    assert not (summary.root_dir / "src" / ("ll" + "m")).exists()
    assert (summary.root_dir / "data" / "rodata.bin").is_file()

    manifest = json.loads((summary.root_dir / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["function_count"] == 2
    assert len(manifest["tree_source_files"]) == 1
    assert manifest["tree_function_index"].endswith("function-index-tree.json")
    assert ("ll" + "m_available") not in manifest

    functions = json.loads((summary.root_dir / "functions.json").read_text(encoding="utf-8"))
    first_function = functions["functions"][0]
    assert first_function["tree_source_file"]
    assert first_function["tree_source_line_start"]

    agents = (summary.root_dir / "AGENTS.md").read_text(encoding="utf-8")
    assert "ToCode binary export" in agents


def test_export_binary_can_skip_tree_source(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 256)
    analysis = ProgramAnalysis(
        binary=BinaryFacts(
            path=binary,
            arch="x86",
            bits=64,
            image_base=0x1000,
            os_name="linux",
            format_name="elf",
            file_type="EXEC",
            entrypoints=[0x1000],
        ),
        segments=[Segment(".text", 128, 128, "PROGBITS", "r-x", 0, 0x1000)],
        routines={
            0x1000: Routine(0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 0, 0),
        },
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={0x1000: []},
        callers={0x1000: []},
        import_calls={0x1000: []},
        roots=[0x1000],
        thunks=set(),
    )
    export_root = tmp_path / "export"
    (export_root / "include").mkdir(parents=True)
    (export_root / "include" / "tocode_tree.h").write_text("stale", encoding="utf-8")
    (export_root / "src" / "tree").mkdir(parents=True)
    (export_root / "src" / "tree" / "stale.c").write_text("stale", encoding="utf-8")
    (export_root / "function-index-tree.json").write_text("{}", encoding="utf-8")

    summary = export_binary(
        FakeAnalyzer(analysis),  # type: ignore[arg-type]
        out_dir=export_root,
        progress=Progress(enabled=False),
        jobs=None,
        tree=False,
    )

    assert summary.tree_src_dir is None
    assert summary.tree_source_files == []
    assert summary.tree_function_index_path is None
    assert not (summary.root_dir / "src" / "tree").exists()
    assert not (summary.root_dir / "include" / "tocode_tree.h").exists()
    assert not (summary.root_dir / "function-index-tree.json").exists()


def test_tree_safe_function_preserves_scanner_calls() -> None:
    source = (
        "__int64 __fastcall sub_1000@<x0>(char *a1)\n"
        "{\n"
        "  if ( a1 > 1 )\n"
        "    strcpy__GLIBC_2_17(dest, a1);\n"
        "  return 0i64;\n"
        "}"
    )

    tree_source = tree_safe_function(source, fallback_name="sub_1000")

    assert "__fastcall" not in tree_source
    assert "__int64" not in tree_source
    assert "long long sub_1000_x0" in tree_source
    assert "if ( a1 > 1 )" in tree_source
    assert "strcpy(dest, a1);" in tree_source
    assert "strcpy__GLIBC_2_17" not in tree_source
    assert "return 0LL;" in tree_source
