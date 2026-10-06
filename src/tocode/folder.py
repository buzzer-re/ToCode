"""Folder exports: every binary of an application folder, plus the links between them.

``tocode <folder>`` scans the folder, reads the import/export and load
tables of every binary (``tocode.links``), schedules one export per binary in
dependency order (executables, then what they load), runs each in an isolated
process, and finally joins the link facts to the exported functions
(``folder_links``): ``mappings.json`` at the top, and per-file enrichment and
source comments inside each export.

Re-running the same command skips every binary whose export is complete and
unchanged, resumes an interrupted one from its checkpoint, and recomputes the
links.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import posixpath
import re
import shutil
import sys
import time
from typing import Any, Callable

from .apk_native import (
    NativeExporter,
    NativeLib,
    NativeOptions,
    NativeRunner,
    _active_children,
    _active_lock,
    _redirect_output,
    collect_child_result,
    native_min_free_mb,
    run_native_export,
    watch_parent,
)
from .errors import ToCodeError
from .links.analyze import FolderLinks, link_folder
from .links.inventory import JOB_APK, JOB_DOTNET, JOB_NATIVE, Entry, Inventory, scan
from .metadata import write_json
from .naming import clean_path_component
from .parallel import available_memory_mb
from .progress import Progress

STATE_DIR = ".tocode-folder"
STATE_SCHEMA = 1
MASTER_SUFFIX = "_decompiled"

# Job statuses
DONE = "done"
PENDING = "pending"
FILTERED = "filtered"
RUNTIME = "skipped: runtime library (use --include-framework)"
NO_NATIVE = "skipped: --no-native"
NO_MANAGED = "skipped: --no-managed"
NO_DOTNET_LIBS = "skipped: .NET libraries not installed (run tocode --setup-dotnet)"


@dataclass(slots=True)
class FolderOptions:
    out_dir: Path | None = None
    only: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    include_framework: bool = False
    native: bool = True
    managed: bool = True
    dotnet_available: bool = True
    # Called once when managed binaries are scheduled: makes the .NET libraries
    # available (asking the user once), returns False when they are not.
    ensure_dotnet: Callable[[], bool] | None = None
    arch: str | None = None
    plan: bool = False
    links_only: bool = False
    restart: bool = False
    jobs: int | None = None
    native_options: NativeOptions = field(default_factory=NativeOptions)


@dataclass(slots=True)
class FolderJob:
    relpath: str
    job: str
    path: Path  # file the backend opens (a thin slice for fat Mach-O)
    export_dir: Path
    key: str
    status: str = PENDING
    backend: str | None = None
    decompiler: str | None = None
    function_count: int | None = None
    failure_count: int | None = None
    seconds: float | None = None
    reused: bool = False  # complete from an earlier run

    def to_json(self, root: Path) -> dict[str, Any]:
        return {
            "path": self.relpath,
            "job": self.job,
            "export_dir": _rel(self.export_dir, root),
            "status": self.status,
            "backend": self.backend,
            "decompiler": self.decompiler,
            "function_count": self.function_count,
            "failure_count": self.failure_count,
            "seconds": round(self.seconds, 1) if self.seconds is not None else None,
            "key": self.key,
        }


@dataclass
class FolderSummary:
    root_dir: Path
    input_dir: Path
    binaries: int
    jobs: list[FolderJob]
    edges: int
    links: int
    bound: int
    mapped: int
    plan_only: bool = False
    interrupted: bool = False
    errors: list[str] = field(default_factory=list)
    seconds: float = 0.0
    inventory: Inventory | None = None
    facts: FolderLinks | None = None

    @property
    def done(self) -> int:
        return sum(1 for job in self.jobs if job.status == DONE)

    @property
    def failed(self) -> int:
        return sum(1 for job in self.jobs if job.status.startswith("failed"))


def default_master_dir(input_dir: Path) -> Path:
    name = f"{clean_path_component(input_dir.name or 'folder')}{MASTER_SUFFIX}"
    default_root = os.environ.get("TOCODE_DEFAULT_OUT_ROOT", "").strip()
    if default_root:
        return Path(default_root).expanduser().resolve() / name
    return input_dir.parent / name


# --------------------------------------------------------------------------
# Globs
# --------------------------------------------------------------------------


def glob_regex(pattern: str) -> re.Pattern[str]:
    """``**``-aware glob over POSIX relative paths."""
    text = pattern.strip().lstrip("./") if pattern.startswith("./") else pattern.strip()
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if text.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif text.startswith("**", index):
            out.append(".*")
            index += 2
        elif char == "*":
            out.append("[^/]*")
            index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        elif char == "[":
            end = text.find("]", index + 1)
            if end < 0:
                out.append(re.escape(char))
                index += 1
            else:
                out.append(text[index : end + 1])
                index = end + 1
        else:
            out.append(re.escape(char))
            index += 1
    return re.compile("^" + "".join(out) + "$")


def path_matches(relpath: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        target = relpath if "/" in pattern.strip("/") else posixpath.basename(relpath)
        if glob_regex(
            pattern.strip("/") if "/" in pattern.strip("/") else pattern
        ).match(target):
            return True
    return False


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def export_dir_for(master: Path, relpath: str) -> Path:
    """One export per binary, mirroring the input layout, named after the file."""
    return master.joinpath(*relpath.split("/"))


def job_key(entry: Entry, options: FolderOptions) -> str:
    native = options.native_options
    payload = {
        "schema": STATE_SCHEMA,
        "sha256": entry.sha256 or f"size:{entry.size}",
        "arch": entry.arch,
        "job": entry.job,
        "backend": native.backend if entry.job == JOB_NATIVE else None,
        "analysis": native.analysis_command if entry.job == JOB_NATIVE else None,
        "tree": native.tree,
        "entropy": native.entropy,
        "include_framework": options.include_framework
        if entry.job == JOB_DOTNET
        else None,
        "native_in_apk": options.native if entry.job == JOB_APK else None,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:24]


def schedule(inventory: Inventory, links: FolderLinks) -> list[str]:
    """Binaries in export order: each chain in load order, then the rest."""
    order: list[str] = []
    seen: set[str] = set()
    for root in inventory.roots:
        for relpath in links.resolution.chains.get(root, [root]):
            if relpath not in seen:
                seen.add(relpath)
                order.append(relpath)
    for root, chain in links.resolution.chains.items():
        for relpath in chain:
            if relpath not in seen:
                seen.add(relpath)
                order.append(relpath)
    for entry in inventory.entries:
        if entry.job is not None and entry.relpath not in seen:
            seen.add(entry.relpath)
            order.append(entry.relpath)
    return order


def plan_jobs(
    inventory: Inventory,
    links: FolderLinks,
    master: Path,
    options: FolderOptions,
) -> list[FolderJob]:
    jobs: list[FolderJob] = []
    for relpath in schedule(inventory, links):
        entry = inventory.entry(relpath)
        if entry is None or entry.job is None:
            continue
        source = inventory.root.joinpath(*relpath.split("/"))
        job = FolderJob(
            relpath=relpath,
            job=entry.job,
            path=source,
            export_dir=export_dir_for(master, relpath),
            key=job_key(entry, options),
        )
        if entry.duplicate_of is not None:
            job.status = f"duplicate of {entry.duplicate_of}"
            job.export_dir = export_dir_for(master, entry.duplicate_of)
        elif (options.only and not path_matches(relpath, options.only)) or (
            options.exclude and path_matches(relpath, options.exclude)
        ):
            job.status = FILTERED
        elif entry.runtime and not options.include_framework:
            job.status = RUNTIME
        elif entry.job == JOB_NATIVE and not options.native:
            job.status = NO_NATIVE
        elif entry.job == JOB_DOTNET and not options.managed:
            job.status = NO_MANAGED
        elif entry.job == JOB_DOTNET and not options.dotnet_available:
            job.status = NO_DOTNET_LIBS
        jobs.append(job)
    return jobs


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


def state_path(master: Path) -> Path:
    return master / STATE_DIR / "state.json"


def load_state(master: Path) -> dict[str, Any]:
    try:
        payload = json.loads(state_path(master).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"schema": STATE_SCHEMA, "jobs": {}}
    if not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA:
        return {"schema": STATE_SCHEMA, "jobs": {}}
    payload.setdefault("jobs", {})
    return payload


def save_state(master: Path, jobs: list[FolderJob], state: dict[str, Any]) -> None:
    recorded = state.setdefault("jobs", {})
    for job in jobs:
        if job.status == DONE or job.status.startswith("failed"):
            recorded[job.relpath] = {
                "key": job.key,
                "status": job.status,
                "backend": job.backend,
                "decompiler": job.decompiler,
                "function_count": job.function_count,
                "failure_count": job.failure_count,
                "seconds": round(job.seconds, 1) if job.seconds is not None else None,
            }
    write_json(state_path(master), state)


def apply_state(jobs: list[FolderJob], state: dict[str, Any]) -> None:
    """Mark jobs whose export is complete and still matches as done."""
    recorded = state.get("jobs", {})
    for job in jobs:
        if job.status != PENDING:
            continue
        previous = recorded.get(job.relpath)
        if not isinstance(previous, dict) or previous.get("key") != job.key:
            continue
        if previous.get("status") != DONE:
            continue
        if not (job.export_dir / "export-manifest.json").is_file():
            continue
        job.status = DONE
        job.reused = True
        job.backend = previous.get("backend")
        job.decompiler = previous.get("decompiler")
        job.function_count = previous.get("function_count")
        job.failure_count = previous.get("failure_count")
        job.seconds = previous.get("seconds")


# --------------------------------------------------------------------------
# Running one binary
# --------------------------------------------------------------------------


@dataclass(slots=True)
class JobSettings:
    """What a spawned export process needs (picklable)."""

    job: str
    native_options: NativeOptions
    jobs: int | None
    include_framework: bool
    native: bool
    origin: str
    restart: bool


def run_folder_job(
    lib: NativeLib, out_dir: Path, settings: JobSettings, progress: Progress
) -> tuple[str, str, int, int]:
    if settings.job == JOB_NATIVE:
        return run_native_export(lib, out_dir, settings.native_options, progress)
    if settings.job == JOB_DOTNET:
        from .dotnet import DotnetExportOptions, export_dotnet

        summary = export_dotnet(
            lib.path,
            options=DotnetExportOptions(
                out_dir=out_dir,
                jobs=settings.jobs,
                native=False,
                include_framework=settings.include_framework,
                native_options=settings.native_options,
                pinvoke_neighbours=False,
                origin=settings.origin,
            ),
            progress=progress,
        )
        return (
            "dotnet",
            "ICSharpCode.Decompiler",
            summary.method_count,
            len(summary.failed_types),
        )
    if settings.job == JOB_APK:
        from .apk import ApkExportOptions, export_apk

        apk = export_apk(
            lib.path,
            options=ApkExportOptions(
                out_dir=out_dir,
                jobs=settings.jobs,
                native=settings.native,
                splits=False,
                native_options=settings.native_options,
            ),
            progress=progress,
        )
        return ("asc", "droidasc", apk.method_count, len(apk.failed_classes))
    raise ToCodeError(f"unknown job type {settings.job}")


def _folder_job_child(
    lib: NativeLib,
    out_dir: Path,
    settings: JobSettings,
    log_path: Path,
    result_queue: Any,
) -> None:
    """Entry point of the isolated per-binary export process."""
    if hasattr(os, "setsid"):
        try:
            os.setsid()
        except OSError:  # pragma: no cover - already a session leader
            pass
    watch_parent()
    progress = Progress(enabled=False)
    progress.set_log_path(log_path)
    _redirect_output(log_path)
    try:
        result = run_folder_job(lib, out_dir, settings, progress)
    except ToCodeError as exc:
        result_queue.put(("error", str(exc)))
    except BaseException as exc:  # pragma: no cover - backend crash isolation
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))
    else:
        result_queue.put(("ok", result))


def isolated_exporter(
    settings_for: Callable[[NativeLib], JobSettings],
) -> NativeExporter:
    """Each binary in its own process: a crash or OOM fails only that binary."""

    def run(
        lib: NativeLib, out_dir: Path, progress: Progress
    ) -> tuple[str, str, int, int]:
        context = multiprocessing.get_context("spawn")
        result_queue: Any = context.Queue()
        log_path = progress.log_path or out_dir / "tocode.log"
        process = context.Process(
            target=_folder_job_child,
            args=(lib, out_dir, settings_for(lib), log_path, result_queue),
            name=f"tocode-folder-{lib.stem}",
        )
        process.start()
        if process.pid is not None:
            with _active_lock:
                _active_children.add(process.pid)
        return collect_child_result(process, result_queue)

    return run


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------


def origin_text(input_dir: Path, relpath: str, entry: Entry | None) -> str:
    up = "/".join([".."] * len(relpath.split("/")))
    arch = (
        f", {entry.arch} slice of a universal binary"
        if entry and len(entry.archs) > 1
        else ""
    )
    return (
        f"This is the decompiled `{relpath}` from the folder `{input_dir.name}`{arch}, "
        "exported as part of a ToCode folder export. The folder's master metadata is "
        f"`{up}`: its `AGENTS.md` explains the layout, `dependency-graph.json` lists the "
        "files this one loads and is loaded by (with the loader rule behind each link), "
        "and `mappings.json` maps every imported symbol to the file and line range of its "
        "definition in the other exports. In this export, `imports.json` (`libraries`, "
        "per-import `link`) and `functions.json` (`import_links`, `imported_by`) carry the "
        "same links, and calls into other files of the folder are annotated in the "
        "decompiled source with `tocode-link:` comments."
    )


def export_folder(
    input_dir: Path,
    *,
    options: FolderOptions | None = None,
    progress: Progress | None = None,
    exporter: NativeExporter | None = None,
) -> FolderSummary:
    from . import folder_docs, folder_links

    options = options or FolderOptions()
    progress = progress or Progress()
    started = time.monotonic()
    input_dir = input_dir.resolve()
    master = (options.out_dir or default_master_dir(input_dir)).resolve()
    if master == input_dir or input_dir in master.parents:
        # Inside the input, the scan skips it by name (*_decompiled); refuse
        # anything else rather than export our own output on the next run.
        if master == input_dir or not master.name.endswith(MASTER_SUFFIX):
            raise ToCodeError(
                f"output directory {master} is inside the input folder; "
                f"pick a different -o or name it *{MASTER_SUFFIX}"
            )
    if not options.plan:
        progress.set_log_path(master / "tocode.log")
        progress.file_log(f"Command: {' '.join(sys.argv)}")
    progress.log(f"Scanning {input_dir}")
    inventory = scan(input_dir, arch=options.arch, log=progress.file_log)
    links = link_folder(inventory)
    jobs = plan_jobs(inventory, links, master, options)
    code = [entry for entry in inventory.entries if entry.job is not None]
    progress.log(
        f"Found {len(code)} binaries ({_kind_counts(code)}) in {len(inventory.entries)} files; "
        f"{len(links.resolution.edges)} library references, {len(links.links)} imported symbols"
    )
    summary = FolderSummary(
        root_dir=master,
        input_dir=input_dir,
        binaries=len(code),
        jobs=jobs,
        edges=len(links.resolution.edges),
        links=len(links.links),
        bound=sum(1 for link in links.links if link.status == "bound"),
        mapped=0,
        plan_only=options.plan,
        inventory=inventory,
        facts=links,
    )
    if options.plan:
        summary.seconds = time.monotonic() - started
        return summary

    state = (
        {"schema": STATE_SCHEMA, "jobs": {}} if options.restart else load_state(master)
    )
    if options.restart:
        shutil.rmtree(master / STATE_DIR / "index", ignore_errors=True)
    apply_state(jobs, state)
    managed_pending = [
        job for job in jobs if job.job == JOB_DOTNET and job.status == PENDING
    ]
    if managed_pending and not options.links_only and options.ensure_dotnet is not None:
        if not options.ensure_dotnet():
            for job in managed_pending:
                job.status = NO_DOTNET_LIBS
    _prepare_slices(master, inventory, jobs)
    folder_docs.write_master_documents(
        master, inventory, links, jobs, options, progress=None
    )

    try:
        if not options.links_only:
            _run_jobs(master, inventory, jobs, options, state, progress, exporter)
    except KeyboardInterrupt:
        summary.interrupted = True
        progress.log("tocode: interrupted; finished exports are kept, rerun to resume")
    finally:
        save_state(master, jobs, state)
    try:
        progress.log("Linking exports (mappings.json, per-file links, source comments)")
        result = folder_links.link_exports(
            master, inventory, links, jobs, progress=progress
        )
        summary.mapped = result.mapped
        folder_docs.write_master_documents(
            master,
            inventory,
            links,
            jobs,
            options,
            progress=progress,
            link_result=result,
        )
    except KeyboardInterrupt:
        summary.interrupted = True
    summary.errors = [
        f"{job.relpath}: {job.status}"
        for job in jobs
        if job.status.startswith("failed")
    ]
    summary.seconds = time.monotonic() - started
    return summary


def _kind_counts(entries: list[Entry]) -> str:
    counts: dict[str, int] = {}
    for entry in entries:
        label = entry.format or entry.detail or entry.kind
        counts[label] = counts.get(label, 0) + 1
    return ", ".join(f"{count} {label}" for label, count in sorted(counts.items()))


def _prepare_slices(master: Path, inventory: Inventory, jobs: list[FolderJob]) -> None:
    """Thin the chosen slice out of universal binaries (backends want one arch)."""
    for job in jobs:
        entry = inventory.entry(job.relpath)
        if entry is None or entry.kind != "macho_fat" or entry.arch is None:
            continue
        facts = inventory.folder.facts(job.relpath, entry.arch)
        if facts is None or facts.slice_size is None:
            continue
        target = (
            master
            / STATE_DIR
            / "slices"
            / f"{(entry.sha256 or 'x')[:16]}-{entry.arch}"
            / posixpath.basename(job.relpath)
        )
        if not target.is_file() or target.stat().st_size != facts.slice_size:
            target.parent.mkdir(parents=True, exist_ok=True)
            with job.path.open("rb") as source, target.open("wb") as sink:
                source.seek(facts.slice_offset)
                remaining = facts.slice_size
                while remaining > 0:
                    chunk = source.read(min(remaining, 1 << 20))
                    if not chunk:
                        break
                    sink.write(chunk)
                    remaining -= len(chunk)
            # A stable mtime keeps backend caches keyed on it valid across runs.
            stat = job.path.stat()
            os.utime(target, (stat.st_atime, stat.st_mtime))
        job.path = target


def _run_jobs(
    master: Path,
    inventory: Inventory,
    jobs: list[FolderJob],
    options: FolderOptions,
    state: dict[str, Any],
    progress: Progress,
    exporter: NativeExporter | None,
) -> None:
    pending = [job for job in jobs if job.status == PENDING]
    reused = sum(1 for job in jobs if job.reused)
    if reused:
        progress.log(f"{reused} binaries already exported and unchanged; skipping them")
    if not pending:
        return
    progress.log(
        f"Exporting {len(pending)} binaries one at a time, in load order "
        f"(backend: {options.native_options.backend}; per-binary logs in tocode.log)"
    )
    by_entry: dict[str, FolderJob] = {}
    libs: list[NativeLib] = []
    for job in pending:
        entry = inventory.entry(job.relpath)
        lib = NativeLib(
            abi=(entry.arch if entry and entry.arch else job.job),
            name=job.relpath,
            entry=job.relpath,
            source_apk=inventory.root.name,
            size=job.path.stat().st_size,
            sha256=(entry.sha256 if entry else "") or "",
            path=job.path,
            export_dir=job.export_dir,
            origin=origin_text(inventory.root, job.relpath, entry),
        )
        by_entry[job.relpath] = job
        libs.append(lib)
    native = options.native_options
    native_options = NativeOptions(
        backend=native.backend,
        analysis_command=native.analysis_command,
        idadir=native.idadir,
        ida_domain_path=native.ida_domain_path,
        purge_cache=native.purge_cache,
        jobs=options.jobs,
        tree=native.tree,
        entropy=native.entropy,
        restart=options.restart,
    )

    def settings_for(lib: NativeLib) -> JobSettings:
        return JobSettings(
            job=by_entry[lib.entry].job,
            native_options=native_options,
            jobs=options.jobs,
            include_framework=options.include_framework,
            native=options.native,
            origin=lib.origin or "",
            restart=options.restart,
        )

    run_one = exporter or isolated_exporter(settings_for)
    holder: list[NativeRunner] = []

    def tracked(
        lib: NativeLib, out_dir: Path, child: Progress
    ) -> tuple[str, str, int, int]:
        job = by_entry[lib.entry]
        started = time.monotonic()
        try:
            result = run_one(lib, out_dir, child)
        except BaseException as exc:
            # Killed by Ctrl-C: stays pending and resumes from its checkpoint.
            if not (holder and holder[0].stop_event.is_set()):
                job.status = f"failed: {exc}"
            job.seconds = time.monotonic() - started
            save_state(master, jobs, state)
            raise
        job.status = DONE
        job.backend, job.decompiler, job.function_count, job.failure_count = result
        job.seconds = time.monotonic() - started
        save_state(master, jobs, state)
        return result

    runner = NativeRunner(
        libs=libs,
        root=master,
        progress=progress,
        exporter=tracked,
        min_free_mb=native_min_free_mb(),
        available_memory=available_memory_mb,
        quiet=True,
    )
    holder.append(runner)
    display = FolderDisplay(progress, pending)
    runner.start()
    thread = runner.thread
    try:
        while thread is not None and thread.is_alive():
            thread.join(timeout=DISPLAY_REFRESH_SECONDS)
            display.refresh(runner)
    except KeyboardInterrupt:
        display.close()
        runner.stop()
        runner.join()
        raise
    runner.join()
    display.refresh(runner)
    display.close()
    for lib in libs:
        job = by_entry[lib.entry]
        if (
            job.status == PENDING
            and lib.status.startswith("failed")
            and not runner.stop_event.is_set()
        ):
            job.status = lib.status
    done = sum(1 for job in pending if job.status == DONE)
    failed = sum(1 for job in pending if job.status.startswith("failed"))
    progress.log(
        f"Exported {done}/{len(pending)} binaries"
        + (
            f", {failed} failed (details in tocode.log and project.json)"
            if failed
            else ""
        )
    )


DISPLAY_REFRESH_SECONDS = 0.5
TEXT_HEARTBEAT_SECONDS = 60.0
NAME_WIDTH = 36
LABEL_WIDTH = NAME_WIDTH + 4
# Same columns for every bar: label, bar, count, extra, time.
BAR_FORMAT = (
    "{desc} {bar:24} {n_fmt}/{total_fmt} {unit_label}{postfix} [{elapsed}<{remaining}]"
)


def _short(text: str, width: int = NAME_WIDTH) -> str:
    return text if len(text) <= width else "…" + text[-(width - 1) :]


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


class FolderDisplay:
    """Progress for many binaries without flooding the terminal.

    On a terminal: one bar for the folder (binaries done, failures, ETA) and
    one for the binary being exported (its phase, then functions rendered).
    Nested export logs only go to ``tocode.log``; failures are printed above
    the bars. When stderr is not a terminal: one line per finished binary and
    a status line every minute.
    """

    def __init__(self, progress: Progress, jobs: list[FolderJob]) -> None:
        self.progress = progress
        self.jobs = jobs
        self.total = len(jobs)
        self.started = time.monotonic()
        self.reported: set[str] = set()
        self.overall = progress.new_bar(
            total=self.total,
            desc=f"{'binaries':<{LABEL_WIDTH}}",
            unit="bin",
            position=0,
            disable=None,  # bars only on a terminal
            bar_format=BAR_FORMAT.replace("{unit_label}", "binaries"),
        )
        self.tty = self.overall is not None and not getattr(
            self.overall, "disable", True
        )
        if self.overall is not None and not self.tty:
            self.overall.close()
            self.overall = None
        self.current: Any = None
        self.current_name: str | None = None
        self.current_total: int | None = None
        self.last_text = self.started

    def _finished(self) -> list[FolderJob]:
        return [job for job in self.jobs if job.status != PENDING]

    def refresh(self, runner: NativeRunner) -> None:
        finished = self._finished()
        for job in finished:
            if job.relpath in self.reported:
                continue
            self.reported.add(job.relpath)
            self._report(job, len(self.reported))
        if self.tty and self.overall is not None:
            failed = sum(1 for job in finished if job.status.startswith("failed"))
            self.overall.n = len(finished)
            self.overall.set_postfix_str(
                f"{failed} failed" if failed else "", refresh=False
            )
            self.overall.refresh()
            self._refresh_current(runner)
        elif time.monotonic() - self.last_text >= TEXT_HEARTBEAT_SECONDS:
            self.last_text = time.monotonic()
            status = runner.describe_current()
            if status:
                self.progress.log(
                    f"[{len(finished)}/{self.total}] "
                    + status.replace("native: ", "", 1).replace("libraries", "binaries")
                )

    def _report(self, job: FolderJob, number: int) -> None:
        took = _duration(job.seconds or 0)
        if job.status.startswith("failed"):
            reason = job.status.removeprefix("failed: ").splitlines()[0][:160]
            self.progress.log(f"✗ {job.relpath}: {reason}")
        elif not self.tty:
            self.progress.log(
                f"[{number}/{self.total}] ✓ {job.relpath}: {job.function_count} functions in {took}"
            )

    def _refresh_current(self, runner: NativeRunner) -> None:
        lib = runner.current
        waiting = runner.waiting
        name = lib.name if lib is not None else (waiting[0].name if waiting else None)
        if name != self.current_name:
            self._close_current()
            self.current_name = name
            if name is None:
                return
            self._open_current(None)
        tail = runner.current_tail
        if self.current is None:
            return
        if tail is not None and tail.total and self.current_total is None:
            self._close_current()
            self._open_current(tail.total)
        if self.current_total is not None and tail is not None:
            self.current.n = min(tail.rendered, self.current_total)
            self.current.refresh()
            return
        if waiting is not None:
            phase = f"waiting for memory ({waiting[1]} MB free, need {runner.min_free_mb} MB)"
        elif tail is not None:
            phase = tail.last_line
        else:
            phase = "starting"
        self.current.set_postfix_str(_short(phase, 60), refresh=False)
        self.current.refresh()

    def _open_current(self, total: int | None) -> None:
        label = "  ↳ " + _short(self.current_name or "", NAME_WIDTH)
        self.current_total = total
        if total is None:
            fmt = "{desc}{postfix} [{elapsed}]"  # "  ↳ name, <phase> [time]"
        else:
            label = f"{label:<{LABEL_WIDTH}}"
            fmt = BAR_FORMAT.replace("{unit_label}", "functions")
        self.current = self.progress.new_bar(
            total=total, desc=label, position=1, disable=None, bar_format=fmt
        )

    def _close_current(self) -> None:
        if self.current is not None:
            self.current.close()
        self.current = None
        self.current_total = None

    def close(self) -> None:
        self._close_current()
        if self.overall is not None:
            self.overall.close()
            self.overall = None


def _rel(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def format_plan(summary: FolderSummary) -> str:
    """Human-readable ``--plan`` output."""
    inventory = summary.inventory
    facts = summary.facts
    lines = [f"Folder: {summary.input_dir}", f"Output: {summary.root_dir}"]
    if inventory is not None:
        lines.append(
            f"Files: {len(inventory.entries)}, binaries: {summary.binaries}, "
            f"architecture: {inventory.arch or 'n/a'}"
        )
    lines.extend(["", "Export order (status):"])
    for number, job in enumerate(summary.jobs, 1):
        entry = inventory.entry(job.relpath) if inventory else None
        detail = ""
        if entry is not None:
            role = entry.role or entry.kind
            detail = f" [{entry.format or entry.kind} {role}{', ' + entry.arch if entry.arch else ''}]"
        lines.append(f"  {number:3}. {job.relpath}{detail} - {job.status}")
    if facts is not None:
        edges = facts.resolution.edges
        statuses = Counter(edge.status for edge in edges)
        lines.extend(["", f"Library references: {len(edges)} ({_counts(statuses)})"])
        for edge in edges:
            if edge.status in ("missing", "arch_mismatch", "name_match_unreachable"):
                lines.append(
                    f"  {edge.source} -> {edge.name}: {edge.status} ({'; '.join(edge.via[-2:])})"
                )
        if facts.resolution.cycles:
            lines.append(f"Cycles: {len(facts.resolution.cycles)}")
            for cycle in facts.resolution.cycles[:10]:
                lines.append("  " + " <-> ".join(cycle))
        link_status = Counter(link.status for link in facts.links)
        lines.append(f"Imported symbols: {len(facts.links)} ({_counts(link_status)})")
        bound = Counter(
            (link.importer, link.target)
            for link in facts.links
            if link.status == "bound" and link.target != link.importer
        )
        if bound:
            lines.append("Symbols bound between files of the folder (top 20):")
            for (importer, target), count in bound.most_common(20):
                lines.append(f"  {importer} -> {target}: {count}")
    lines.append(
        f"\nPlanned in {summary.seconds:.1f}s; nothing was decompiled (--plan)."
    )
    return "\n".join(lines)


def _counts(counter: Counter[str]) -> str:
    return ", ".join(f"{key} {value}" for key, value in sorted(counter.items()))
