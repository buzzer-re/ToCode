import pytest

from tocode.backends.base import choose_backend, discover_idadir
from tocode.cluster import cluster_routines
from tocode.errors import ToCodeError
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
        == 4
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
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)

    assert discover_idadir() == install.resolve()


def test_ida_database_input_rejects_r2_backend(tmp_path) -> None:
    db_path = tmp_path / "sample.idb"
    db_path.write_bytes(b"IDA")

    with pytest.raises(ToCodeError):
        choose_backend("r2", input_path=db_path)
