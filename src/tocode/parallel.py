from __future__ import annotations

import math
import os


FAST_ANALYSIS_SECONDS = 5.0
MIN_FUNCTIONS_FOR_AUTO = 32
MAX_AUTO_JOBS = 8
MAX_AUTO_IDA_JOBS = 2
FUNCTIONS_PER_WORKER = 32
DEFAULT_JOB_LIMIT = 16
DEFAULT_IDA_WORKER_MEMORY_MB = 3072
# A worker loads the whole IDA database into memory. Estimate its resident cost
# from the database size so that huge databases (kernels) do not over-subscribe
# RAM. Base covers IDA runtime + Hex-Rays; the factor covers the loaded database.
# Both are tunable defaults, not hardware-specific values: the resulting ceiling
# is computed from the host's real available memory and the real database size.
DEFAULT_IDA_WORKER_BASE_MEMORY_MB = 768
DEFAULT_IDA_DB_RESIDENT_FACTOR = 1.5
# A headless Binary Ninja worker loads the core, its plugins, and the .bndb
# (about 650 MB for a tiny binary on Binary Ninja 6).
DEFAULT_BINJA_WORKER_MEMORY_MB = 1024
DEFAULT_BINJA_WORKER_BASE_MEMORY_MB = 768
DEFAULT_BINJA_DB_RESIDENT_FACTOR = 2.0
MAX_AUTO_BINJA_JOBS = 4


def choose_jobs(
    *,
    function_count: int,
    analysis_seconds: float | None,
    requested: int | None,
    backend: str,
    cpu_count: int | None = None,
    job_limit: int | None = None,
    available_memory_mb: int | None = None,
    ida_worker_memory_mb: int | None = None,
    database_size_mb: int | None = None,
    measured_worker_memory_mb: int | None = None,
) -> int:
    limit = job_limit if job_limit is not None else configured_job_limit()
    is_ida = backend.lower() == "ida"
    is_binja = backend.lower() == "binja-headless"
    memory_ceiling = (
        _ida_memory_ceiling(available_memory_mb, ida_worker_memory_mb, database_size_mb)
        if is_ida
        else _binja_memory_ceiling(
            available_memory_mb, database_size_mb, measured_worker_memory_mb
        )
        if is_binja
        else None
    )

    # An explicit `--jobs N` is honored, but still capped by the memory budget for
    # IDA: each worker loads the whole database, so N workers that cannot fit in
    # RAM get OOM-killed mid-export, which is strictly worse than running fewer.
    if requested is not None:
        chosen = max(1, min(requested, function_count or 1, limit))
        if memory_ceiling is not None:
            chosen = min(chosen, memory_ceiling)
        return max(1, chosen)

    if function_count < MIN_FUNCTIONS_FOR_AUTO or analysis_seconds is None:
        return 1
    if not (is_ida or is_binja) and analysis_seconds > FAST_ANALYSIS_SECONDS:
        return 1

    cpus = cpu_count if cpu_count is not None else (os.cpu_count() or 1)
    backend_limit = (
        MAX_AUTO_IDA_JOBS
        if is_ida
        else MAX_AUTO_BINJA_JOBS
        if is_binja
        else MAX_AUTO_JOBS
    )
    ceiling = min(cpus, backend_limit, limit, function_count)
    if memory_ceiling is not None:
        ceiling = min(ceiling, memory_ceiling)
    target = math.ceil(function_count / FUNCTIONS_PER_WORKER)
    return max(1, min(ceiling, target))


def _ida_memory_ceiling(
    available_memory_mb: int | None,
    ida_worker_memory_mb: int | None,
    database_size_mb: int | None,
) -> int | None:
    if available_memory_mb is None:
        return None
    worker_memory_mb = (
        ida_worker_memory_mb
        if ida_worker_memory_mb is not None
        else configured_ida_worker_memory_mb()
    )
    if database_size_mb is not None and database_size_mb > 0:
        estimated = configured_ida_worker_base_mb() + int(
            database_size_mb * configured_ida_db_resident_factor()
        )
        worker_memory_mb = max(worker_memory_mb, estimated)
    return max(1, available_memory_mb // worker_memory_mb)


def _binja_memory_ceiling(
    available_memory_mb: int | None,
    database_size_mb: int | None,
    measured_worker_memory_mb: int | None = None,
) -> int | None:
    if available_memory_mb is None:
        return None
    worker_memory_mb = _env_int(
        "TOCODE_BINJA_WORKER_MEMORY_MB", DEFAULT_BINJA_WORKER_MEMORY_MB, 256
    )
    if database_size_mb is not None and database_size_mb > 0:
        estimated = DEFAULT_BINJA_WORKER_BASE_MEMORY_MB + int(
            database_size_mb * DEFAULT_BINJA_DB_RESIDENT_FACTOR
        )
        worker_memory_mb = max(worker_memory_mb, estimated)
    # A worker reopening the database holds about what the analyzing process
    # peaked at (a 38k-function binary: ~1.8 GB, far above the size estimate).
    if measured_worker_memory_mb is not None and measured_worker_memory_mb > 0:
        worker_memory_mb = max(worker_memory_mb, measured_worker_memory_mb)
    return max(1, available_memory_mb // worker_memory_mb)


def _env_int(name: str, default: int, minimum: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return max(minimum, int(raw)) if raw else default
    except ValueError:
        return default


def describe_jobs(
    *,
    function_count: int,
    analysis_seconds: float | None,
    requested: int | None,
    selected: int,
    backend: str,
) -> str:
    if requested is not None:
        if selected < requested:
            return f"Workers: {selected} (requested {requested}, capped for memory)"
        return f"Workers: {selected} requested"
    if function_count < MIN_FUNCTIONS_FOR_AUTO:
        return f"Workers: 1 for {function_count} functions"
    if analysis_seconds is None:
        return "Workers: 1, no analysis timing"
    if selected == 1:
        return f"Workers: 1 after {analysis_seconds:.2f}s analysis"
    if backend.lower() == "ida":
        return f"Workers: {selected}, IDA cache ready"
    if backend.lower() == "binja-headless":
        return f"Workers: {selected}, Binary Ninja database ready"
    return f"Workers: {selected} after {analysis_seconds:.2f}s analysis"


# Folder exports: binaries exported at once when --parallel-files is auto.
MAX_AUTO_PARALLEL_FILES = 16
# With -j auto, each of the parallel files may use at least this many workers.
# Small binaries (most of a folder) render with one worker anyway; a big one
# gets a second instead of rendering alone on one CPU at the end.
MIN_AUTO_WORKERS_PER_FILE = 2


def choose_parallel_files(
    *,
    pending: int,
    requested_files: int | None,
    requested_jobs: int | None,
    cpu_count: int | None = None,
    available_memory_mb: int | None = None,
    file_memory_mb: int = 0,
) -> tuple[int, int | None]:
    """How many binaries a folder export runs at once, and the worker cap per file.

    Explicit values are honored (only capped by the number of pending files).
    Auto runs one file per CPU (one per ``-j`` workers' worth of CPUs when
    ``-j`` is given), at most ``MAX_AUTO_PARALLEL_FILES``, and no more than
    free memory holds at ``file_memory_mb`` each. With ``-j`` auto, each file's
    workers are capped at its share of the CPUs (at least
    ``MIN_AUTO_WORKERS_PER_FILE``); the cap is None when one file runs at a
    time, which keeps the export's own choice.
    """
    if pending <= 0:
        return 1, None
    cpus = cpu_count if cpu_count is not None else (os.cpu_count() or 1)
    if requested_files is not None:
        files = requested_files
    else:
        files = max(1, cpus // (requested_jobs or 1))
        files = min(files, MAX_AUTO_PARALLEL_FILES)
        if available_memory_mb is not None and file_memory_mb > 0:
            files = min(files, max(1, available_memory_mb // file_memory_mb))
    files = max(1, min(files, pending))
    if files == 1 or requested_jobs is not None:
        return files, None
    return files, max(MIN_AUTO_WORKERS_PER_FILE, cpus // files)


def configured_job_limit() -> int:
    raw = os.environ.get("TOCODE_MAX_DECOMPILE_WORKERS", str(DEFAULT_JOB_LIMIT)).strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_JOB_LIMIT
    return max(1, value)


def configured_ida_worker_memory_mb() -> int:
    raw = os.environ.get(
        "TOCODE_IDA_WORKER_MEMORY_MB", str(DEFAULT_IDA_WORKER_MEMORY_MB)
    ).strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_IDA_WORKER_MEMORY_MB
    return max(512, value)


def configured_ida_worker_base_mb() -> int:
    raw = os.environ.get(
        "TOCODE_IDA_WORKER_BASE_MEMORY_MB", str(DEFAULT_IDA_WORKER_BASE_MEMORY_MB)
    ).strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_IDA_WORKER_BASE_MEMORY_MB
    return max(0, value)


def configured_ida_db_resident_factor() -> float:
    raw = os.environ.get(
        "TOCODE_IDA_DB_RESIDENT_FACTOR", str(DEFAULT_IDA_DB_RESIDENT_FACTOR)
    ).strip()
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_IDA_DB_RESIDENT_FACTOR
    return max(0.0, value)


def available_memory_mb() -> int | None:
    meminfo = _linux_mem_available_mb()
    if meminfo is not None:
        return meminfo
    # os.sysconf is POSIX-only (absent on Windows); fetch it dynamically so the
    # attribute access does not fail static analysis on Windows.
    sysconf = getattr(os, "sysconf", None)
    if sysconf is None:
        return None
    try:
        pages = sysconf("SC_AVPHYS_PAGES")
        page_size = sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        return None
    if not isinstance(pages, int) or not isinstance(page_size, int):
        return None
    if pages <= 0 or page_size <= 0:
        return None
    return pages * page_size // (1024 * 1024)


def _linux_mem_available_mb() -> int | None:
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) // 1024
    except (OSError, ValueError):
        return None
    return None
