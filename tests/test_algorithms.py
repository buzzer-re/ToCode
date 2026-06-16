from pathlib import Path

import pytest

from tocode.backends.base import choose_backend, discover_idadir
from tocode.backends.r2 import R2Session
from tocode.cluster import cluster_routines
from tocode.errors import BackendError, ToCodeError
from tocode.naming import SHARED_CLUSTER_ID, clean_c_identifier, clean_path_component
from tocode.parallel import choose_jobs


def test_cluster_routines_groups_shared_callees() -> None:
    clusters = cluster_routines(
        addresses=[0x1000, 0x1100, 0x2000],
        roots=[0x1000, 0x2000],
        callees={0x1000: [0x1100], 0x2000: [0x1100], 0x1100: []},
        callers={0x1000: [], 0x2000: [], 0x1100: [0x1000, 0x2000]},
        thunks=set(),
    )

    shared = [cluster for cluster in clusters if cluster.root == SHARED_CLUSTER_ID]

    assert shared
    assert shared[0].members == [0x1100]
    assert {cluster.root for cluster in clusters} >= {0x1000, 0x2000}


def test_choose_jobs_caps_auto_ida_parallelism() -> None:
    assert (
        choose_jobs(
            function_count=300,
            analysis_seconds=0.2,
            requested=None,
            backend="ida",
            cpu_count=32,
            job_limit=64,
        )
        == 2
    )


def test_choose_jobs_limits_auto_ida_parallelism_by_available_memory() -> None:
    assert (
        choose_jobs(
            function_count=300,
            analysis_seconds=0.2,
            requested=None,
            backend="ida",
            cpu_count=32,
            job_limit=64,
            available_memory_mb=3500,
            ida_worker_memory_mb=4096,
        )
        == 1
    )


def test_choose_jobs_auto_ida_budget_scales_with_database_size() -> None:
    # A large database (e.g. a kernel `.i64`) inflates the per-worker memory
    # estimate so the auto budget falls back to a single worker even when the
    # default flat estimate would have allowed more.
    assert (
        choose_jobs(
            function_count=18000,
            analysis_seconds=30.0,
            requested=None,
            backend="ida",
            cpu_count=32,
            job_limit=64,
            available_memory_mb=6800,
            ida_worker_memory_mb=3072,
            database_size_mb=4000,
        )
        == 1
    )


def test_choose_jobs_auto_ida_budget_allows_parallel_for_small_database() -> None:
    assert (
        choose_jobs(
            function_count=18000,
            analysis_seconds=30.0,
            requested=None,
            backend="ida",
            cpu_count=32,
            job_limit=64,
            available_memory_mb=64000,
            ida_worker_memory_mb=3072,
            database_size_mb=200,
        )
        == 2
    )


def test_requested_ida_jobs_are_capped_by_available_memory() -> None:
    # Each IDA worker loads the whole database; 3 requested workers cannot fit in
    # ~3.5 GB at 4 GB/worker, so the count is capped to avoid OOM-killed workers.
    assert (
        choose_jobs(
            function_count=300,
            analysis_seconds=0.2,
            requested=3,
            backend="ida",
            cpu_count=32,
            job_limit=64,
            available_memory_mb=3500,
            ida_worker_memory_mb=4096,
        )
        == 1
    )


def test_ida_memory_model_is_env_tunable(monkeypatch) -> None:
    def select() -> int:
        return choose_jobs(
            function_count=18000,
            analysis_seconds=20.0,
            requested=8,
            backend="ida",
            cpu_count=8,
            job_limit=16,
            available_memory_mb=6800,
            database_size_mb=1900,
        )

    for name in (
        "TOCODE_IDA_DB_RESIDENT_FACTOR",
        "TOCODE_IDA_WORKER_BASE_MEMORY_MB",
        "TOCODE_IDA_WORKER_MEMORY_MB",
    ):
        monkeypatch.delenv(name, raising=False)
    # Default model caps a 1.9 GB database on ~6.8 GB to a single worker.
    assert select() == 1
    # Operators can relax the model without code changes.
    monkeypatch.setenv("TOCODE_IDA_DB_RESIDENT_FACTOR", "0")
    monkeypatch.setenv("TOCODE_IDA_WORKER_BASE_MEMORY_MB", "0")
    monkeypatch.setenv("TOCODE_IDA_WORKER_MEMORY_MB", "1024")
    assert select() == 6  # 6800 // 1024


def test_requested_jobs_ignore_memory_for_non_ida_backends() -> None:
    assert (
        choose_jobs(
            function_count=300,
            analysis_seconds=0.2,
            requested=3,
            backend="r2",
            cpu_count=32,
            job_limit=64,
            available_memory_mb=3500,
            ida_worker_memory_mb=4096,
        )
        == 3
    )


def test_requested_jobs_are_limited_by_function_count() -> None:
    assert (
        choose_jobs(
            function_count=3,
            analysis_seconds=0.1,
            requested=8,
            backend="ida",
            cpu_count=16,
            job_limit=16,
        )
        == 3
    )


def test_name_sanitizers_are_c_and_path_safe() -> None:
    assert clean_c_identifier("123 bad-name") == "fn_123_bad_name"
    assert clean_path_component("../bad name!") == "bad_name"


def test_discover_idadir_checks_windows_program_files(tmp_path, monkeypatch) -> None:
    install = tmp_path / "IDA Professional 9.2"
    (install / "idalib").mkdir(parents=True)

    monkeypatch.delenv("IDADIR", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)

    assert discover_idadir() == install.resolve()


def test_ida_database_input_rejects_r2_backend(tmp_path) -> None:
    db_path = tmp_path / "sample.idb"
    db_path.write_bytes(b"IDA")

    with pytest.raises(ToCodeError):
        choose_backend("r2", input_path=db_path)


def test_ida_database_input_rejects_angr_backend(tmp_path) -> None:
    db_path = tmp_path / "sample.i64"
    db_path.write_bytes(b"IDA")

    with pytest.raises(ToCodeError):
        choose_backend("angr", input_path=db_path)


def _force_backend_probes(monkeypatch, *, ida: bool, r2: bool, angr: bool) -> None:
    from tocode.backends import base

    monkeypatch.setattr(
        base,
        "probe_ida",
        lambda **_: base.IdaProbe(ida, "forced" if ida else "unavailable"),
    )
    monkeypatch.setattr(base, "probe_r2", lambda: r2)
    monkeypatch.setattr(base, "probe_angr", lambda: angr)


def test_auto_falls_back_to_angr_when_ida_and_r2_missing(monkeypatch) -> None:
    _force_backend_probes(monkeypatch, ida=False, r2=False, angr=True)

    choice = choose_backend("auto")

    assert choice.selected == "angr"


def test_auto_prefers_r2_over_angr(monkeypatch) -> None:
    _force_backend_probes(monkeypatch, ida=False, r2=True, angr=True)

    choice = choose_backend("auto")

    assert choice.selected == "r2"


def test_explicit_angr_requires_angr_installed(monkeypatch) -> None:
    _force_backend_probes(monkeypatch, ida=False, r2=False, angr=False)

    with pytest.raises(ToCodeError):
        choose_backend("angr")


def test_auto_with_no_backend_available_raises(monkeypatch) -> None:
    _force_backend_probes(monkeypatch, ida=False, r2=False, angr=False)

    with pytest.raises(ToCodeError):
        choose_backend("auto")


def test_r2_decompiler_probe_reports_missing_sleigh() -> None:
    class MissingSleighSession(R2Session):
        def __init__(self) -> None:
            pass

        def cmd(self, command: str) -> str:
            return {
                "pdg?": "Usage: pdg",
                "pdgL": "",
            }[command]

    session = MissingSleighSession()

    with pytest.raises(BackendError, match="r2ghidra SLEIGH languages"):
        session.ensure_decompiler()
