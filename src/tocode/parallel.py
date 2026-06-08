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
) -> int:
    limit = job_limit if job_limit is not None else configured_job_limit()
    if requested is not None:
        return max(1, min(requested, function_count or 1, limit))

    if function_count < MIN_FUNCTIONS_FOR_AUTO or analysis_seconds is None:
        return 1
    if backend.lower() != "ida" and analysis_seconds > FAST_ANALYSIS_SECONDS:
        return 1

    cpus = cpu_count if cpu_count is not None else (os.cpu_count() or 1)
    backend_limit = MAX_AUTO_IDA_JOBS if backend.lower() == "ida" else MAX_AUTO_JOBS
    ceiling = min(cpus, backend_limit, limit, function_count)
    if backend.lower() == "ida" and available_memory_mb is not None:
        worker_memory_mb = (
            ida_worker_memory_mb
            if ida_worker_memory_mb is not None
            else configured_ida_worker_memory_mb()
        )
        memory_ceiling = available_memory_mb // worker_memory_mb
        ceiling = min(ceiling, max(1, memory_ceiling))
    target = math.ceil(function_count / FUNCTIONS_PER_WORKER)
    return max(1, min(ceiling, target))


def describe_jobs(
    *,
    function_count: int,
    analysis_seconds: float | None,
    requested: int | None,
    selected: int,
    backend: str,
) -> str:
    if requested is not None:
        return f"Workers: {selected} requested"
    if function_count < MIN_FUNCTIONS_FOR_AUTO:
        return f"Workers: 1 for {function_count} functions"
    if analysis_seconds is None:
        return "Workers: 1, no analysis timing"
    if selected == 1:
        return f"Workers: 1 after {analysis_seconds:.2f}s analysis"
    if backend.lower() == "ida":
        return f"Workers: {selected}, IDA cache ready"
    return f"Workers: {selected} after {analysis_seconds:.2f}s analysis"


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


def available_memory_mb() -> int | None:
    meminfo = _linux_mem_available_mb()
    if meminfo is not None:
        return meminfo
    try:
        pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
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
