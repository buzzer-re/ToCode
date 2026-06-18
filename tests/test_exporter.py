from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from tocode.exporter import (
    CheckpointStore,
    _counts_from_summary,
    _render_missing_with_timeout,
    _uses_timeout_worker,
    _worker_spec,
    export_binary,
    fallback_prototype,
    render_and_write_source_tree,
    render_one,
    tree_safe_function,
)
from tocode.metadata import functions_json
from tocode.naming import NameBook
from tocode.progress import Progress
from tocode.schema import (
    BinaryFacts,
    Cluster,
    FunctionRange,
    ProgramAnalysis,
    RenderedFunction,
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

    def __init__(
        self,
        analysis: ProgramAnalysis,
        database_path: Path | None = None,
        binary_path: Path | None = None,
    ) -> None:
        self.analysis = analysis
        self.binary = binary_path or analysis.binary.path
        self.progress = Progress(enabled=False)
        self.session = FakeSession(database_path)

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


class CountingAnalyzer(FakeAnalyzer):
    def __init__(
        self,
        analysis: ProgramAnalysis,
        *,
        interrupt_after: int | None = None,
    ) -> None:
        super().__init__(analysis)
        self.decompile_calls = 0
        self.interrupt_after = interrupt_after

    def decompile(self, address: int) -> str:
        self.decompile_calls += 1
        if (
            self.interrupt_after is not None
            and self.decompile_calls > self.interrupt_after
        ):
            raise KeyboardInterrupt
        return super().decompile(address)


class FakeSession:
    def __init__(self, database_path: Path | None) -> None:
        self._database_path = database_path

    def database_path(self) -> Path | None:
        return self._database_path


class TrackingSession:
    backend_name = "ida"
    backend_label = "IDA Domain"
    decompiler_label = "Hex-Rays"
    parallel_safe = False
    analysis_command = None

    def __init__(self) -> None:
        self.decompile_calls = 0

    def disasm(self, _address: int) -> str:
        return "xor eax, eax\nretn"

    def function_summary(self, _address: int) -> str:
        return "signature: _BOOL8()\ncallees: 0"

    def decompile(self, _address: int) -> str:
        self.decompile_calls += 1
        return (
            "_BOOL8 __scrt_is_ucrt_dll_in_use()\n{\n  return dword_140005070 != 0;\n}"
        )


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
            0x1000: Routine(
                0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 1, 0
            ),
            0x1050: Routine(
                0x1050, "helper", 32, "int helper(void)", None, False, 0, 0, 0, 0, 1
            ),
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
        tree=True,
    )

    assert summary.function_count == 2
    assert summary.cluster_count == 1
    assert (summary.root_dir / "AGENTS.md").is_file()
    assert (summary.root_dir / "CLAUDE.md").read_text(
        encoding="utf-8"
    ) == "@./AGENTS.md\n"
    assert (summary.root_dir / "project.json").is_file()
    assert (summary.root_dir / "export-manifest.json").is_file()
    assert (
        summary.root_dir / "src" / "raw" / "app" / "cluster_0000000000001000.c"
    ).is_file()
    assert (
        summary.root_dir / "src" / "tree" / "app" / "cluster_0000000000001000.c"
    ).is_file()
    assert (summary.root_dir / "function-index-tree.json").is_file()
    assert (summary.root_dir / "include" / "tocode_tree.h").is_file()
    assert not (summary.root_dir / "src" / ("ll" + "m")).exists()
    assert (summary.root_dir / "data" / "rodata.bin").is_file()

    manifest = json.loads(
        (summary.root_dir / "export-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["function_count"] == 2
    assert manifest["claude"].endswith("CLAUDE.md")
    assert len(manifest["tree_source_files"]) == 1
    assert manifest["tree_function_index"].endswith("function-index-tree.json")
    assert ("ll" + "m_available") not in manifest

    functions = json.loads(
        (summary.root_dir / "functions.json").read_text(encoding="utf-8")
    )
    first_function = functions["functions"][0]
    assert first_function["tree_source_file"]
    assert first_function["tree_source_line_start"]

    project = json.loads(
        (summary.root_dir / "project.json").read_text(encoding="utf-8")
    )
    assert project["claude"].endswith("CLAUDE.md")

    agents = (summary.root_dir / "AGENTS.md").read_text(encoding="utf-8")
    assert "ToCode binary export" in agents
    assert "oracle/helper" in agents

    triage = json.loads((summary.root_dir / "triage.json").read_text(encoding="utf-8"))
    assert "dynamic_api_resolution" not in triage
    assert "has_debug_strings" not in triage
    assert "embedded_pe" not in triage
    assert "embedded_shellcode_hint" not in triage
    assert "evasion" not in triage
    assert (summary.root_dir / "tocode.log").is_file()
    assert "Export run started" in (summary.root_dir / "tocode.log").read_text(
        encoding="utf-8"
    )
    assert not (summary.root_dir / ".tocode").exists()


def test_export_binary_resumes_from_checkpoint_after_interrupt(tmp_path: Path) -> None:
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
            0x1000: Routine(
                0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 1, 0
            ),
            0x1050: Routine(
                0x1050, "helper", 32, "int helper(void)", None, False, 0, 0, 0, 0, 1
            ),
        },
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={0x1000: [0x1050], 0x1050: []},
        callers={0x1000: [], 0x1050: [0x1000]},
        import_calls={0x1000: [], 0x1050: []},
        roots=[0x1000],
        thunks=set(),
    )
    export_root = tmp_path / "export"

    with pytest.raises(KeyboardInterrupt):
        export_binary(
            CountingAnalyzer(analysis, interrupt_after=1),  # type: ignore[arg-type]
            out_dir=export_root,
            progress=Progress(enabled=False),
        )

    assert (export_root / ".tocode" / "checkpoint.json").is_file()
    log_text = (export_root / "tocode.log").read_text(encoding="utf-8")
    assert "Export interrupted" in log_text
    assert "export main 0x1000 - 48 bytes done" in log_text

    resumed = CountingAnalyzer(analysis)
    summary = export_binary(
        resumed,  # type: ignore[arg-type]
        out_dir=export_root,
        progress=Progress(enabled=False),
    )

    assert resumed.decompile_calls == 1
    assert summary.function_count == 2
    assert not (export_root / ".tocode").exists()
    resumed_log = (export_root / "tocode.log").read_text(encoding="utf-8")
    assert "Checkpoint: resuming at 1/2 with 1 cached functions" in resumed_log
    assert "export main 0x1000 - 48 bytes cached" not in resumed_log
    assert "export helper 0x1050 - 32 bytes done" in resumed_log


def test_export_binary_restart_ignores_checkpoint(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 256)
    routine = Routine(0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 0, 0)
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
        routines={routine.address: routine},
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={routine.address: []},
        callers={routine.address: []},
        import_calls={routine.address: []},
        roots=[routine.address],
        thunks=set(),
    )
    export_root = tmp_path / "export"

    with pytest.raises(KeyboardInterrupt):
        export_binary(
            CountingAnalyzer(analysis, interrupt_after=0),  # type: ignore[arg-type]
            out_dir=export_root,
            progress=Progress(enabled=False),
        )

    restarted = CountingAnalyzer(analysis)
    export_binary(
        restarted,  # type: ignore[arg-type]
        out_dir=export_root,
        progress=Progress(enabled=False),
        restart=True,
    )

    assert restarted.decompile_calls == 1
    log_text = (export_root / "tocode.log").read_text(encoding="utf-8")
    assert "Checkpoint: discarded previous state (--restart)" in log_text


def test_checkpoint_store_tracks_compact_resume_cursor(tmp_path: Path) -> None:
    checkpoint = CheckpointStore(
        root=tmp_path / "export",
        cache_id="cache",
        progress=Progress(enabled=False),
    )
    addresses = [0x1000, 0x1050, 0x1100]
    checkpoint.start(
        binary=tmp_path / "sample.bin", backend="fake", addresses=addresses
    )

    assert checkpoint.first_pending_index() == 0
    checkpoint.save(
        RenderedFunction(
            address=0x1050,
            c_name="helper",
            prototype="int helper(void)",
            c_text="int helper(void) { return 0; }",
            asm_text="",
            summary_text="",
        )
    )
    assert checkpoint.first_pending_index() == 0
    assert checkpoint.completed_count == 1

    checkpoint.save(
        RenderedFunction(
            address=0x1000,
            c_name="main",
            prototype="int main(void)",
            c_text="int main(void) { return 0; }",
            asm_text="",
            summary_text="",
        )
    )
    assert checkpoint.first_pending_index() == 2
    assert checkpoint.completed_count == 2

    state = json.loads(
        (tmp_path / "export" / ".tocode" / "checkpoint.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["schema_version"] == 2
    assert state["next_index"] == 2
    assert state["completed_ranges"] == [[0, 1]]


def test_checkpoint_store_migrates_legacy_rendered_files(tmp_path: Path) -> None:
    root = tmp_path / "export"
    rendered_dir = root / ".tocode" / "rendered"
    rendered_dir.mkdir(parents=True)
    (root / ".tocode" / "checkpoint.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "interrupted",
                "cache_id": "cache",
                "completed": ["0x1000"],
            }
        ),
        encoding="utf-8",
    )
    (rendered_dir / "0000000000001000.json").write_text("{}", encoding="utf-8")

    checkpoint = CheckpointStore(
        root=root, cache_id="cache", progress=Progress(enabled=False)
    )
    checkpoint.start(
        binary=tmp_path / "sample.bin",
        backend="fake",
        addresses=[0x1000, 0x1050],
    )

    state = json.loads((root / ".tocode" / "checkpoint.json").read_text("utf-8"))
    assert state["schema_version"] == 2
    assert state["next_index"] == 1
    assert state["completed_ranges"] == [[0, 0]]


def test_stream_resume_reuses_completed_cluster_record(
    tmp_path: Path, monkeypatch
) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 256)
    routines = {
        0x1000: Routine(
            0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 0, 0
        ),
        0x1050: Routine(
            0x1050, "helper", 32, "int helper(void)", None, False, 0, 0, 0, 0, 0
        ),
        0x2000: Routine(
            0x2000, "later", 24, "int later(void)", None, False, 0, 0, 0, 0, 0
        ),
    }
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
        segments=[Segment(".text", 256, 256, "PROGBITS", "r-x", 0, 0x1000)],
        routines=routines,
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={address: [] for address in routines},
        callers={address: [] for address in routines},
        import_calls={address: [] for address in routines},
        roots=list(routines),
        thunks=set(),
    )
    clusters = [
        Cluster(0x1000, "cluster_0x1000", "", [0x1000, 0x1050]),
        Cluster(0x2000, "cluster_0x2000", "", [0x2000]),
    ]
    root = tmp_path / "export"
    checkpoint = CheckpointStore(
        root=root, cache_id="cache", progress=Progress(enabled=False)
    )
    checkpoint.start(binary=binary, backend="fake", addresses=[0x1000, 0x1050, 0x2000])
    names = NameBook(functions={}, imports={}, aliases={})

    first = CountingAnalyzer(analysis)
    render_and_write_source_tree(
        analyzer=first,  # type: ignore[arg-type]
        analysis=analysis,
        clusters=clusters[:1],
        src_dir=root / "src" / "raw",
        asm_dir=root / "src" / "raw",
        summary_dir=root / "src" / "raw",
        include_dir=root / "include",
        header_name="sample.h",
        names=names,
        prototypes={},
        progress=Progress(enabled=False),
        checkpoint=checkpoint,
    )
    assert first.decompile_calls == 2

    original_load = CheckpointStore.load

    def fail_on_completed_cluster(self: CheckpointStore, address: int):
        if address in {0x1000, 0x1050}:
            raise AssertionError("completed cluster should use the cluster record")
        return original_load(self, address)

    monkeypatch.setattr(CheckpointStore, "load", fail_on_completed_cluster)
    resumed = CountingAnalyzer(analysis)
    summary = render_and_write_source_tree(
        analyzer=resumed,  # type: ignore[arg-type]
        analysis=analysis,
        clusters=clusters,
        src_dir=root / "src" / "raw",
        asm_dir=root / "src" / "raw",
        summary_dir=root / "src" / "raw",
        include_dir=root / "include",
        header_name="sample.h",
        names=names,
        prototypes={},
        progress=Progress(enabled=False),
        checkpoint=checkpoint,
    )

    assert resumed.decompile_calls == 1
    assert len(summary["sources"]) == 2
    assert len(summary["ranges"]) == 3


def test_export_binary_skips_oversized_function(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TOCODE_MAX_FUNCTION_BYTES", "16")
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 256)
    routine = Routine(0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 0, 0)
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
        routines={routine.address: routine},
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={routine.address: []},
        callers={routine.address: []},
        import_calls={routine.address: []},
        roots=[routine.address],
        thunks=set(),
    )
    analyzer = CountingAnalyzer(analysis)

    summary = export_binary(
        analyzer,  # type: ignore[arg-type]
        out_dir=tmp_path / "export",
        progress=Progress(enabled=False),
    )

    assert analyzer.decompile_calls == 0
    assert len(summary.failed_functions) == 1
    source = next(summary.raw_src_dir.rglob("*.c")).read_text(encoding="utf-8")
    assert "// too big to export:" in source
    log_text = (summary.root_dir / "tocode.log").read_text(encoding="utf-8")
    assert "export main 0x1000 - 48 bytes failed" in log_text


def test_timeout_scheduler_requeues_other_inflight_functions(monkeypatch) -> None:
    monkeypatch.setenv("TOCODE_FUNCTION_TIMEOUT_SECONDS", "1")
    binary = Path("/bin/sample")
    routines = {
        0x1000: Routine(
            0x1000, "slow", 48, "int slow(void)", None, False, 0, 0, 0, 0, 0
        ),
        0x1050: Routine(
            0x1050, "first", 32, "int first(void)", None, False, 0, 0, 0, 0, 0
        ),
        0x1100: Routine(
            0x1100, "second", 24, "int second(void)", None, False, 0, 0, 0, 0, 0
        ),
    }
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
        segments=[],
        routines=routines,
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={address: [] for address in routines},
        callers={address: [] for address in routines},
        import_calls={address: [] for address in routines},
        roots=list(routines),
        thunks=set(),
    )
    names = NameBook(
        functions={address: routine.name for address, routine in routines.items()},
        imports={},
        aliases={},
    )
    wait_calls = 0
    terminated: list[object] = []

    class FakeFuture:
        def __init__(self, address: int) -> None:
            self.address = address

        def result(self) -> tuple[int, RenderedFunction]:
            routine = routines[self.address]
            return (
                self.address,
                RenderedFunction(
                    address=self.address,
                    c_name=routine.name,
                    prototype=routine.signature or f"int {routine.name}(void)",
                    c_text=f"int {routine.name}(void) {{ return 0; }}",
                    asm_text="",
                    summary_text="",
                ),
            )

    class FakeExecutor:
        def __init__(self) -> None:
            self.submitted: list[int] = []

        def submit(self, _fn: object, address: int) -> FakeFuture:
            self.submitted.append(address)
            return FakeFuture(address)

    first_executor = FakeExecutor()
    second_executor = FakeExecutor()

    def fake_wait(futures, timeout=None, return_when=None):  # noqa: ANN001, ANN202
        nonlocal wait_calls
        wait_calls += 1
        future_set = set(futures)
        if wait_calls == 1:
            return set(), future_set
        return future_set, set()

    def fake_monotonic() -> float:
        return 2.0 if wait_calls else 0.0

    def fake_terminate(executor: object) -> None:
        terminated.append(executor)

    def fake_start_render_executor(**_kwargs) -> FakeExecutor:  # noqa: ANN003
        return second_executor

    monkeypatch.setattr("tocode.exporter.wait", fake_wait)
    monkeypatch.setattr("tocode.exporter.time.monotonic", fake_monotonic)
    monkeypatch.setattr("tocode.exporter._terminate_executor", fake_terminate)
    monkeypatch.setattr(
        "tocode.exporter._start_render_executor", fake_start_render_executor
    )

    rendered: dict[int, RenderedFunction] = {}
    returned_executor = _render_missing_with_timeout(
        executor=first_executor,  # type: ignore[arg-type]
        worker_count=2,
        spec=object(),  # type: ignore[arg-type]
        analysis=analysis,
        names=names,
        addresses=[0x1000, 0x1050, 0x1100],
        rendered=rendered,
        checkpoint=None,
        progress=None,
        bar=None,
    )

    assert returned_executor is second_executor
    assert first_executor.submitted == [0x1000, 0x1050]
    assert second_executor.submitted == [0x1050, 0x1100]
    assert terminated == [first_executor]
    assert rendered[0x1000].failure is not None
    assert rendered[0x1000].failure.message == "decompiler timed out after 1s"
    assert rendered[0x1050].failure is None
    assert rendered[0x1100].failure is None


def test_timeout_worker_covers_angr_without_parallel(monkeypatch) -> None:
    monkeypatch.setenv("TOCODE_FUNCTION_TIMEOUT_SECONDS", "300")

    class AngrLikeAnalyzer:
        backend_name = "angr"
        supports_parallel = False

    assert _uses_timeout_worker(cast(Any, AngrLikeAnalyzer()))


def test_export_binary_publishes_ida_database(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 256)
    database = tmp_path / "cache.i64"
    database.write_bytes(b"IDA database")
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
            0x1000: Routine(
                0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 0, 0
            ),
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

    summary = export_binary(
        FakeAnalyzer(analysis, database_path=database),  # type: ignore[arg-type]
        out_dir=tmp_path / "export",
        progress=Progress(enabled=False),
        jobs=None,
    )

    exported_database = summary.root_dir / "sample.i64"
    assert exported_database.read_bytes() == b"IDA database"

    manifest = json.loads(
        (summary.root_dir / "export-manifest.json").read_text(encoding="utf-8")
    )
    project = json.loads(
        (summary.root_dir / "project.json").read_text(encoding="utf-8")
    )
    assert manifest["ida_database"] == str(exported_database.resolve())
    assert project["ida_database"] == str(exported_database.resolve())


def test_bool_return_signature_uses_routine_name() -> None:
    routine = Routine(
        0x140001FDC,
        "__scrt_is_ucrt_dll_in_use",
        12,
        "_BOOL8()",
        None,
        False,
        0,
        0,
        0,
        0,
        3,
    )
    names = NameBook(
        functions={routine.address: "__scrt_is_ucrt_dll_in_use"},
        imports={},
        aliases={},
    )

    assert fallback_prototype(routine, 8, names) == "_BOOL8 __scrt_is_ucrt_dll_in_use()"


def test_short_non_thunk_routine_is_decompiled() -> None:
    routine = Routine(
        0x140001FDC,
        "__scrt_is_ucrt_dll_in_use",
        12,
        "_BOOL8()",
        None,
        False,
        0,
        0,
        0,
        0,
        3,
        thunk=False,
    )
    analysis = ProgramAnalysis(
        binary=BinaryFacts(
            path=Path("sample.exe"),
            arch="x86",
            bits=64,
            image_base=0x140000000,
            os_name="windows",
            format_name="pe",
            file_type="EXEC",
            entrypoints=[routine.address],
        ),
        segments=[],
        routines={routine.address: routine},
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={routine.address: []},
        callers={routine.address: []},
        import_calls={routine.address: []},
        roots=[routine.address],
        thunks=set(),
    )
    names = NameBook(
        functions={routine.address: "__scrt_is_ucrt_dll_in_use"},
        imports={},
        aliases={},
    )
    session = TrackingSession()

    rendered = render_one(session, analysis, routine, names)

    assert session.decompile_calls == 1
    assert "short routine" not in rendered.c_text
    assert "dword_140005070 != 0" in rendered.c_text


def test_worker_spec_uses_ida_database_input_for_worker_copies(tmp_path: Path) -> None:
    database = tmp_path / "sample.i64"
    database.write_bytes(b"IDA database")
    analysis = ProgramAnalysis(
        binary=BinaryFacts(
            path=database,
            arch="x86",
            bits=64,
            image_base=0x1000,
            os_name="windows",
            format_name="pe",
            file_type="EXEC",
            entrypoints=[0x1000],
        ),
        segments=[],
        routines={},
        imports={},
        exports=[],
        symbols=[],
        relocations=[],
        strings=[],
        flags=[],
        callees={},
        callers={},
        import_calls={},
        roots=[],
        thunks=set(),
    )
    analyzer = FakeAnalyzer(analysis, database_path=database)
    analyzer.backend_name = "ida"

    spec = _worker_spec(analyzer)  # type: ignore[arg-type]

    assert spec.db_path == database


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
            0x1000: Routine(
                0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 0, 0
            ),
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
    )

    assert summary.tree_src_dir is None
    assert summary.tree_source_files == []
    assert summary.tree_function_index_path is None
    assert not (summary.root_dir / "src" / "tree").exists()
    assert not (summary.root_dir / "include" / "tocode_tree.h").exists()
    assert not (summary.root_dir / "function-index-tree.json").exists()


def test_default_output_uses_invoked_binary_path(tmp_path: Path) -> None:
    invoked_root = tmp_path / "tmp_view"
    ida_root = tmp_path / "ida_view"
    invoked_root.mkdir()
    ida_root.mkdir()
    invoked_binary = invoked_root / "sample.bin"
    ida_binary = ida_root / "sample.bin"
    invoked_binary.write_bytes(b"\x7fELF" + b"\x00" * 256)
    ida_binary.write_bytes(invoked_binary.read_bytes())
    analysis = ProgramAnalysis(
        binary=BinaryFacts(
            path=ida_binary,
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
            0x1000: Routine(
                0x1000, "main", 48, "int main(void)", None, False, 0, 0, 0, 0, 0
            ),
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

    summary = export_binary(
        FakeAnalyzer(analysis, binary_path=invoked_binary),  # type: ignore[arg-type]
        progress=Progress(enabled=False),
        jobs=None,
    )

    assert summary.root_dir == (invoked_root / "sample_decompiler").resolve()


def test_counts_from_summary_reads_args_and_locals() -> None:
    summary = (
        "signature: int f(int a, int b)\n"
        "address: 0x1000\n"
        "size: 32 bytes\n"
        "args: 2\n"
        "locals: 5\n"
    )
    assert _counts_from_summary(summary) == (2, 5)


def test_counts_from_summary_missing_fields_returns_none() -> None:
    assert _counts_from_summary("radare-style summary with no counts") == (None, None)


def _single_routine_analysis() -> ProgramAnalysis:
    binary = BinaryFacts(
        path=Path("/bin/sample"),
        arch="x86",
        bits=64,
        image_base=0,
        os_name="linux",
        format_name="elf",
        file_type="elf",
        entrypoints=[],
    )
    routine = Routine(
        address=0x1000,
        name="sub_1000",
        size=32,
        signature=None,
        calltype=None,
        noreturn=False,
        stack_size=0,
        locals_count=0,
        args_count=0,
        outdegree=0,
        indegree=0,
    )
    return ProgramAnalysis(
        binary=binary,
        segments=[],
        routines={0x1000: routine},
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


def test_strings_json_xrefs_come_from_backend_data() -> None:
    from tocode.metadata import strings_json

    analysis = _single_routine_analysis()  # routine 0x1000 covers 0x1000..0x1020
    analysis.strings.append(
        StringEntry(0x4000, 0x4000, 5, 5, ".rodata", "ascii", "hello")
    )
    analysis.data_xrefs[0x4000] = [(0x1008, False), (0x1010, True)]

    rows = cast(list[dict[str, Any]], strings_json(analysis)["strings"])

    assert rows[0]["xrefs"] == [
        {"function": "sub_1000", "address": "0x1000", "access": "read"},
        {"function": "sub_1000", "address": "0x1000", "access": "write"},
    ]


def test_add_variable_xrefs_uses_backend_data() -> None:
    from tocode.metadata import add_variable_xrefs

    analysis = _single_routine_analysis()
    analysis.data_xrefs[0x4000] = [(0x1004, False)]
    variables: dict[str, dict[str, object]] = {"obj_4000": {"va": "0x4000"}}

    add_variable_xrefs(variables, analysis)

    assert variables["obj_4000"]["xrefs"] == [
        {"function": "sub_1000", "address": "0x1000", "access": "read"}
    ]


def test_data_xref_to_address_outside_any_function_is_dropped() -> None:
    from tocode.metadata import add_variable_xrefs

    analysis = _single_routine_analysis()
    analysis.data_xrefs[0x4000] = [(0x9999, False)]  # not inside any routine
    variables: dict[str, dict[str, object]] = {"obj_4000": {"va": "0x4000"}}

    add_variable_xrefs(variables, analysis)

    assert variables["obj_4000"]["xrefs"] == []


def test_sections_json_omits_entropy_unless_enabled() -> None:
    from tocode.metadata import sections_json

    analysis = _single_routine_analysis()
    analysis.segments.append(
        Segment(".text", 16, 16, "PROGBITS", "r-x", 0, 0x1000, entropy=5.0)
    )

    off = cast(list[dict[str, Any]], sections_json(analysis, entropy=False)["sections"])
    on = cast(list[dict[str, Any]], sections_json(analysis, entropy=True)["sections"])

    assert off[0]["entropy"] is None
    assert on[0]["entropy"] == 5.0


def test_functions_json_prefers_render_time_counts() -> None:
    analysis = _single_routine_analysis()
    ranges = [
        FunctionRange(
            address=0x1000,
            name="sub_1000",
            c_file=Path("a.c"),
            c_line_start=1,
            c_line_end=2,
            asm_file=Path("a.asm"),
            asm_line_start=1,
            asm_line_end=2,
            arg_count=3,
            local_count=7,
        )
    ]
    rows = cast(
        list[dict[str, Any]], functions_json(analysis, ranges, {}, {})["functions"]
    )
    assert rows[0]["nargs"] == 3
    assert rows[0]["nlocals"] == 7


def test_functions_json_falls_back_to_inventory_counts() -> None:
    analysis = _single_routine_analysis()
    analysis.routines[0x1000].args_count = 4
    analysis.routines[0x1000].locals_count = 1
    # Range without recovered counts (e.g. radare2 backend summary).
    ranges = [
        FunctionRange(
            address=0x1000,
            name="sub_1000",
            c_file=Path("a.c"),
            c_line_start=1,
            c_line_end=2,
            asm_file=Path("a.asm"),
            asm_line_start=1,
            asm_line_end=2,
        )
    ]
    rows = cast(
        list[dict[str, Any]], functions_json(analysis, ranges, {}, {})["functions"]
    )
    assert rows[0]["nargs"] == 4
    assert rows[0]["nlocals"] == 1


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
