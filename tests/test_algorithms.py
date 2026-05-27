from tocode.cluster import cluster_routines
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
    assert choose_jobs(
        function_count=300,
        analysis_seconds=0.2,
        requested=None,
        backend="ida",
        cpu_count=32,
        job_limit=64,
    ) == 4


def test_requested_jobs_are_limited_by_function_count() -> None:
    assert choose_jobs(
        function_count=3,
        analysis_seconds=0.1,
        requested=8,
        backend="ida",
        cpu_count=16,
        job_limit=16,
    ) == 3


def test_name_sanitizers_are_c_and_path_safe() -> None:
    assert clean_c_identifier("123 bad-name") == "fn_123_bad_name"
    assert clean_path_component("../bad name!") == "bad_name"
