""".NET export pipeline (dnlib + ICSharpCode.Decompiler backend).

Writes one project tree for a managed assembly, an apphost launcher, a
single-file bundle, or a NuGet package: C# and IL per top-level type under
``src/raw/<Assembly>/<Namespace>/``, assembly attributes, a project file,
resources, JSON metadata, and (unless disabled) a nested native ToCode export
for every native library found (mixed-mode code, bundled libraries, and
P/Invoke targets shipped next to the input).
"""

from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any, Callable

from . import __version__
from . import dotnet_metadata as meta
from .apk_metadata import write_json_rows
from .apk_native import (
    NATIVE_HEARTBEAT_SECONDS,
    NativeExporter,
    NativeLib,
    NativeOptions,
    NativeRunner,
    default_native_exporter,
    native_libs_json,
    native_min_free_mb,
)
from .backends.asc import sha256_file
from .backends.dotnet import (
    AssemblyInfo,
    DecompiledType,
    DotnetInput,
    DotnetSession,
    NativeFile,
    TypeInfo,
    WorkItem,
    decompile_batch_in_worker,
    discover_dotnet_input,
    init_dotnet_worker,
    is_framework_native,
    native_arch,
    pinvoke_neighbours,
)
from .errors import ToCodeError
from .exporter import _terminate_executor
from .metadata import write_json, write_text_atomic
from .naming import clean_path_component
from .parallel import available_memory_mb, choose_jobs
from .progress import Progress
from .schema import DotnetExportSummary

DECOMPILE_BATCH_SIZE = 16
# A worker holds the CLR, the decompiler's type system for the assemblies it
# touches, and the current syntax tree; large assemblies reach ~600 MB.
DOTNET_WORKER_MEMORY_MB = 1024
DOTNET_BATCHES_PER_ROUND = 64
DEFAULT_TYPE_TIMEOUT_SECONDS = 300
_INVALID_FILE_CHARS = re.compile(r"[^0-9A-Za-z_.\-$@+]")
_TFM_ATTRIBUTE_RX = re.compile(
    r"^\.(NETCoreApp|NETStandard|NETFramework),Version=v(\d+)\.(\d+)(?:\.(\d+))?"
)


@dataclass(slots=True)
class DotnetExportOptions:
    out_dir: Path | None = None
    jobs: int | None = None
    native: bool = True
    include_framework: bool = False
    native_options: NativeOptions = field(default_factory=NativeOptions)


@dataclass
class DotnetContext:
    input_path: Path
    options: DotnetExportOptions
    progress: Progress
    found: DotnetInput | None = None
    session: DotnetSession | None = None
    root: Path | None = None
    raw_dir: Path | None = None
    data_dir: Path | None = None
    workdir: Path | None = None
    title: str = ""
    libs: list[NativeLib] = field(default_factory=list)
    native_runner: NativeRunner | None = None
    source_files: list[Path] = field(default_factory=list)
    il_files: list[Path] = field(default_factory=list)
    project_files: list[Path] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)
    extracted: dict[str, str | None] = field(default_factory=dict)
    reachable: dict[str, Any] = field(default_factory=dict)
    roots: set[int] = field(default_factory=set)
    worker_count: int = 1
    render_mode: str = "single"
    started: float = 0.0


def export_dotnet(
    input_path: Path,
    *,
    options: DotnetExportOptions | None = None,
    progress: Progress | None = None,
    native_exporter: NativeExporter | None = None,
    decompiler_factory: Callable[[DotnetSession], Any] | None = None,
    session_factory: Callable[[DotnetInput], DotnetSession] | None = None,
) -> DotnetExportSummary:
    options = options or DotnetExportOptions()
    progress = progress or Progress()
    context = DotnetContext(
        input_path=Path(input_path).resolve(),
        options=options,
        progress=progress,
        started=time.monotonic(),
    )
    try:
        _discover(context)
        _prepare_root(context)
        _inventory(context, session_factory)
        _collect_natives(context)
        _start_native(context, native_exporter)
        _assign_paths(context)
        _decompile(context, decompiler_factory)
        _write_projects(context)
        _write_resources(context)
        _write_metadata(context)
        _join_native(context)
        _write_final_documents(context)
    except BaseException:
        if context.native_runner is not None:
            context.native_runner.stop()
        raise
    finally:
        if context.session is not None:
            context.session.close()
        if context.workdir is not None:
            shutil.rmtree(context.workdir, ignore_errors=True)
    return _summary(context)


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------


def _work_root() -> str | None:
    explicit = os.environ.get("TOCODE_WORKER_TMP_DIR", "").strip()
    if not explicit:
        return None
    candidate = Path(explicit).expanduser()
    try:
        candidate.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return str(candidate)


def _discover(context: DotnetContext) -> None:
    path = context.input_path
    if not path.is_file():
        raise ToCodeError(f".NET input not found: {path}")
    context.workdir = Path(tempfile.mkdtemp(prefix="tocode-dotnet-", dir=_work_root()))
    context.found = discover_dotnet_input(
        path,
        workdir=context.workdir,
        include_framework=context.options.include_framework,
    )
    if not context.found.included:
        raise ToCodeError(
            f"no assemblies to decompile in {path.name} (all are framework "
            "assemblies; pass --include-framework)"
        )
    stem = path.name
    for suffix in (".dll", ".exe", ".nupkg", ".snupkg", ".winmd"):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
    context.title = stem or path.stem


def _root_dir(context: DotnetContext) -> Path:
    out_dir = context.options.out_dir
    source = context.input_path
    if out_dir is not None:
        out = Path(out_dir).expanduser()
        return out.resolve() if out.is_absolute() else (source.parent / out).resolve()
    name = f"{clean_path_component(context.title)}_decompiler"
    default_root = os.environ.get("TOCODE_DEFAULT_OUT_ROOT", "").strip()
    if default_root:
        return (Path(default_root).expanduser().resolve() / name).resolve()
    return (source.parent / name).resolve()


def _prepare_root(context: DotnetContext) -> None:
    found = _need(context.found)
    root = _root_dir(context)
    context.root = root
    context.raw_dir = root / "src" / "raw"
    context.data_dir = root / "data"
    if context.progress.log_path is None:
        context.progress.set_log_path(root / "tocode.log")
    context.raw_dir.mkdir(parents=True, exist_ok=True)
    context.data_dir.mkdir(parents=True, exist_ok=True)
    included = found.included
    skipped = len(found.assemblies) - len(included)
    context.progress.log("Export run started")
    context.progress.log(
        f"Using .NET (dnlib + ICSharpCode.Decompiler) as backend for {context.title} "
        f"({found.kind})"
    )
    context.progress.log(
        f"Assemblies: {len(included)} to decompile"
        + (f", {skipped} skipped (framework/duplicates)" if skipped else "")
        + (f", {len(found.natives)} native libraries" if found.natives else "")
    )
    for item in found.assemblies:
        if not item.include:
            context.progress.file_log(f"skip {item.entry}: {item.reason}")


def _inventory(
    context: DotnetContext,
    session_factory: Callable[[DotnetInput], DotnetSession] | None,
) -> None:
    found = _need(context.found)
    session = session_factory(found) if session_factory else DotnetSession(found)
    with context.progress.bar(total=1, desc="inventory", unit="step") as bar:
        session.load()
        bar.update(1)
    context.session = session
    context.progress.log(
        f"Inventory: {len(session.assemblies)} assemblies, {len(session.types)} types, "
        f"{len(session.methods)} methods, "
        f"{sum(len(item.user_strings) for item in session.assemblies)} strings"
    )
    for info in session.assemblies:
        for hint in info.obfuscation_hints:
            context.progress.log(f"warning: {info.name}: possible obfuscation ({hint})")


def _native_origin(context: DotnetContext, native: NativeFile) -> str:
    found = _need(context.found)
    container = {
        "bundle": "single-file bundle",
        "nupkg": "NuGet package",
        "apphost": "app",
        "assembly": "assembly",
    }.get(found.kind, found.kind)
    if native.path == found.input or native.entry.startswith("(native code"):
        how = "the native (C++/CLI) half of the mixed-mode assembly"
    elif native.source.startswith("beside "):
        how = f"a native library next to the input that P/Invoke declarations name (`{native.entry}`)"
    else:
        how = f"`{native.entry}` inside `{native.source}`"
    return (
        f"This is a decompiled native library from the `{context.title}` .NET "
        f"{container}: `{native.name}` ({native.arch}), {how}. "
        "The .NET export that owns it is three directories up (`../../..`): its "
        "`imports.json` lists the P/Invoke declarations (module and entry point) "
        "that call into native code, `functions.json` marks those managed methods "
        "with `pinvoke`, `native-libs.json` lists the other native libraries, and "
        "`src/raw/<Assembly>/` holds the decompiled C# that uses them."
    )


def _collect_natives(context: DotnetContext) -> None:
    found = _need(context.found)
    session = _need(context.session)
    root = _need(context.root)
    natives = list(found.natives)
    if found.kind in {"assembly", "apphost"}:
        known = {native.path.resolve() for native in natives}
        for module, path in pinvoke_neighbours(
            found.input.parent, session.pinvoke_modules
        ):
            if path.resolve() in known:
                continue
            known.add(path.resolve())
            natives.append(
                NativeFile(
                    name=path.name,
                    path=path,
                    entry=module,
                    source=f"beside {found.input.name}",
                    arch=native_arch(path),
                    framework=is_framework_native(path.name),
                )
            )
    libs: list[NativeLib] = []
    for native in natives:
        arch = clean_path_component(native.arch or "unknown")
        target = root / "lib" / arch / native.name
        if native.path != found.input:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(native.path, target)
            path = target
        else:
            path = native.path  # mixed-mode: decompile the assembly file itself
        lib = NativeLib(
            abi=native.arch or "unknown",
            name=native.name,
            entry=native.entry,
            source_apk=native.source,
            size=path.stat().st_size,
            sha256=sha256_file(path),
            path=path,
            package=context.title,
            origin=_native_origin(context, native),
        )
        if native.framework and not context.options.include_framework:
            lib.status = "skipped: .NET runtime library (use --include-framework)"
        libs.append(lib)
        context.extracted[native.entry] = (
            target.relative_to(root).as_posix() if native.path != found.input else None
        )
    context.libs = libs
    if libs:
        context.progress.log(
            f"Native libraries: {len(libs)} found, "
            f"{sum(1 for lib in libs if lib.status == 'pending')} to decompile"
        )
    _write_native_libs(context)


def _start_native(context: DotnetContext, exporter: NativeExporter | None) -> None:
    pending = [lib for lib in context.libs if lib.status == "pending"]
    if not pending:
        return
    if not context.options.native:
        for lib in pending:
            lib.status = "skipped: --no-native"
        context.progress.log(
            f"Native decompilation skipped (--no-native) for {len(pending)} libraries"
        )
        _write_native_libs(context)
        return
    runner = NativeRunner(
        libs=pending,
        root=_need(context.root),
        progress=context.progress,
        exporter=exporter or default_native_exporter(context.options.native_options),
        min_free_mb=native_min_free_mb(),
        available_memory=available_memory_mb,
    )
    context.progress.log(
        f"Native decompilation started in background for {len(pending)} libraries "
        f"(backend: {context.options.native_options.backend})"
    )
    runner.start()
    context.native_runner = runner


def _join_native(context: DotnetContext) -> None:
    runner = context.native_runner
    if runner is None:
        return
    thread = runner.thread
    if thread is not None and thread.is_alive():
        context.progress.log(
            "Managed export done; waiting for native library export(s) "
            "(progress below is mirrored from native/<arch>/<lib>/tocode.log)"
        )
        while thread.is_alive():
            thread.join(timeout=NATIVE_HEARTBEAT_SECONDS)
            if thread.is_alive():
                status = runner.describe_current()
                if status:
                    context.progress.log(status)
    runner.join()
    done = sum(1 for lib in context.libs if lib.status == "done")
    context.progress.log(
        f"Native decompilation finished: {done}/{len(context.libs)} libraries exported"
    )
    _write_native_libs(context)


def _write_native_libs(context: DotnetContext) -> None:
    root = _need(context.root)
    write_json(root / "native-libs.json", native_libs_json(context.libs, root))


# -- paths ---------------------------------------------------------------------


def safe_file_name(name: str) -> str:
    cleaned = _INVALID_FILE_CHARS.sub("_", name).strip(".")
    return cleaned[:120] or "_"


def type_file_stem(record: TypeInfo) -> str:
    """``List`1`` -> ``List-1``; compiler/obfuscator names made filesystem-safe."""
    name = record.name
    if "`" in name:
        base, _, arity = name.partition("`")
        name = f"{base}-{arity}" if arity.isdigit() else name.replace("`", "-")
    return safe_file_name(name)


def namespace_parts(namespace: str) -> list[str]:
    return [safe_file_name(part) for part in namespace.split(".") if part]


def _assembly_folders(session: DotnetSession) -> None:
    used: dict[str, int] = {}
    for info in session.assemblies:
        base = safe_file_name(info.name)
        count = used.get(base.lower(), 0)
        used[base.lower()] = count + 1
        info.folder = base if count == 0 else f"{base}~{count}"


def _assign_paths(context: DotnetContext) -> None:
    session = _need(context.session)
    raw_dir = _need(context.raw_dir)
    _assembly_folders(session)
    seen: dict[str, int] = {}
    for info in session.assemblies:
        base = raw_dir / info.folder
        for record in session.top_level_types(info.index):
            folder = base.joinpath(*namespace_parts(record.namespace))
            stem = type_file_stem(record)
            key = (folder / stem).as_posix().lower()
            count = seen.get(key, 0)
            seen[key] = count + 1
            if count:
                stem = f"{stem}~{count}"
            record.cs_path = folder / f"{stem}.cs"
            record.il_path = folder / f"{stem}.il"
            for nested in session.nested_types(info.index, record.token):
                nested.cs_path = record.cs_path
                nested.il_path = record.il_path


# -- decompilation ---------------------------------------------------------------


class _PoolBroken(RuntimeError):
    pass


def _work_items(context: DotnetContext) -> list[WorkItem]:
    session = _need(context.session)
    items: list[WorkItem] = []
    for info in session.assemblies:
        items.append(WorkItem(info.index, str(info.file.path), 0))
        for record in session.top_level_types(info.index):
            if record.name == "<Module>" and not record.methods and not record.fields:
                continue
            items.append(WorkItem(info.index, str(info.file.path), record.token))
    return items


def _select_workers(context: DotnetContext, count: int) -> int:
    chosen = choose_jobs(
        function_count=count,
        analysis_seconds=0.0,
        requested=context.options.jobs,
        backend="dotnet",
    )
    memory = available_memory_mb()
    if memory is not None and chosen > 1:
        ceiling = max(1, memory // DOTNET_WORKER_MEMORY_MB)
        if ceiling < chosen:
            context.progress.log(
                f"Limiting decompile workers to {ceiling} ({memory} MB available, "
                f"{DOTNET_WORKER_MEMORY_MB} MB per worker)"
            )
            chosen = ceiling
    context.worker_count = max(1, chosen)
    context.render_mode = "process" if context.worker_count > 1 else "single"
    return context.worker_count


def _type_timeout() -> int:
    raw = os.environ.get("TOCODE_DOTNET_TYPE_TIMEOUT_SECONDS", "").strip()
    try:
        return max(10, int(raw)) if raw else DEFAULT_TYPE_TIMEOUT_SECONDS
    except ValueError:
        return DEFAULT_TYPE_TIMEOUT_SECONDS


def _decompile(
    context: DotnetContext, decompiler_factory: Callable[[DotnetSession], Any] | None
) -> None:
    session = _need(context.session)
    items = _work_items(context)
    type_items = sum(1 for item in items if item.token)
    _remove_stale_sources(context)
    if decompiler_factory is not None:
        context.progress.log(f"Decompiling {type_items} types in-process")
        decompiler = decompiler_factory(session)
        with context.progress.bar(
            total=len(items), desc="decompile", unit="type"
        ) as bar:
            for item in items:
                _store_result(context, decompiler.decompile(item))
                bar.update(1)
    else:
        workers = _select_workers(context, type_items)
        context.progress.log(
            f"Decompiling {type_items} types to C# and IL with {workers} worker(s)"
        )
        with context.progress.bar(
            total=len(items), desc="decompile", unit="type"
        ) as bar:
            _decompile_pool(context, items, workers, bar)
    _inherit_owner_ranges(session)
    context.progress.log(
        f"Decompiled {type_items - len(context.failures)} types, "
        f"{len(context.failures)} failed"
    )


def _decompile_pool(
    context: DotnetContext, items: list[WorkItem], workers: int, bar: Any
) -> None:
    found = _need(context.found)
    search_dirs = [str(path) for path in found.search_dirs]
    queue: deque[tuple[list[WorkItem], bool]] = deque(
        (items[start : start + DECOMPILE_BATCH_SIZE], False)
        for start in range(0, len(items), DECOMPILE_BATCH_SIZE)
    )
    timeout = _type_timeout()
    while queue:
        # A fresh pool per round recycles worker memory (cached type systems).
        round_batches = [
            queue.popleft()
            for _ in range(min(len(queue), workers * DOTNET_BATCHES_PER_ROUND))
        ]
        failed = _run_round(context, round_batches, workers, search_dirs, timeout, bar)
        for batch, isolated, reason in failed:
            if len(batch) > 1:
                # Re-run each type alone to find the one that crashed or hung.
                context.progress.file_log(
                    f"decompile: batch of {len(batch)} failed ({reason}); isolating"
                )
                queue.extendleft((([item], True) for item in reversed(batch)))
                continue
            item = batch[0]
            if not isolated:
                queue.appendleft(([item], True))
                continue
            _store_result(
                context,
                DecompiledType(
                    item.assembly, item.token, None, reason, None, reason, {}, {}
                ),
            )
            bar.update(1)


def _run_round(
    context: DotnetContext,
    batches: list[tuple[list[WorkItem], bool]],
    workers: int,
    search_dirs: list[str],
    timeout: int,
    bar: Any,
) -> list[tuple[list[WorkItem], bool, str]]:
    executor = ProcessPoolExecutor(
        max_workers=max(1, min(workers, len(batches))),
        mp_context=multiprocessing.get_context("spawn"),
        initializer=init_dotnet_worker,
        initargs=(search_dirs,),
    )
    futures: dict[Future[list[DecompiledType]], tuple[list[WorkItem], bool, float]] = {}
    failed: list[tuple[list[WorkItem], bool, str]] = []
    pending = deque(batches)
    broken = False

    def submit() -> None:
        while pending and len(futures) < max(1, workers) * 2:
            batch, isolated = pending.popleft()
            futures[executor.submit(decompile_batch_in_worker, batch)] = (
                batch,
                isolated,
                time.monotonic(),
            )

    try:
        submit()
        while futures:
            done, _ = wait(list(futures), timeout=5, return_when=FIRST_COMPLETED)
            for future in done:
                batch, isolated, _started = futures.pop(future)
                try:
                    results = future.result()
                except BrokenProcessPool:
                    failed.append((batch, isolated, "decompiler process crashed"))
                    broken = True
                    continue
                except Exception as exc:
                    failed.append((batch, isolated, f"{type(exc).__name__}: {exc}"))
                    continue
                for result in results:
                    _store_result(context, result)
                    bar.update(1)
            now = time.monotonic()
            overdue = [
                future
                for future, (batch, _isolated, started) in futures.items()
                if future.running() and now - started > timeout + 30 * len(batch)
            ]
            if overdue or broken:
                for future in list(futures):
                    batch, isolated, _started = futures.pop(future)
                    reason = (
                        f"decompilation timed out after {timeout}s"
                        if future in overdue
                        else "decompiler process crashed"
                    )
                    if future not in overdue and not broken:
                        reason = "worker pool restarted"
                    failed.append((batch, isolated, reason))
                failed.extend(
                    (batch, isolated, "worker pool restarted")
                    for batch, isolated in pending
                )
                pending.clear()
                break
            submit()
    finally:
        if broken or failed:
            _terminate_executor(executor)
        else:
            executor.shutdown(wait=True, cancel_futures=True)
    return failed


def _store_result(context: DotnetContext, result: DecompiledType) -> None:
    session = _need(context.session)
    info = session.assemblies[result.assembly]
    if result.token == 0:
        _store_assembly_attributes(context, info, result)
        return
    record = session.types.get((result.assembly, result.token))
    if record is None or record.cs_path is None or record.il_path is None:
        return
    header = f"// ToCode: {record.full_name.replace('/', '+')} (0x{record.token:08x}) from {info.name} {info.version}\n"
    if result.cs is not None:
        cs_text = header + result.cs.rstrip("\n") + "\n"
        cs_offset = 1
    else:
        record.error = result.cs_error or "unknown decompilation error"
        context.failures.append((record.full_name, record.error))
        cs_text = header + _failure_stub(session, record)
        cs_offset = 0
        context.progress.file_log(
            f"export {info.name}!{record.full_name} failed: {record.error}"
        )
    if result.il is not None:
        il_text = header + result.il.rstrip("\n") + "\n"
    else:
        record.il_error = result.il_error or "unknown disassembly error"
        il_text = header + f"// IL disassembly failed: {record.il_error}\n"
    write_text_atomic(record.cs_path, cs_text)
    write_text_atomic(record.il_path, il_text)
    record.cs_lines = cs_text.count("\n")
    record.il_lines = il_text.count("\n")
    context.source_files.append(record.cs_path)
    context.il_files.append(record.il_path)
    for nested in session.nested_types(record.assembly, record.token):
        nested.error = record.error
        nested.il_error = record.il_error
        nested.cs_lines = record.cs_lines
        nested.il_lines = record.il_lines
        for method_id in nested.methods:
            method = session.methods[method_id]
            span = result.cs_ranges.get(method.token)
            if span is not None and result.cs is not None:
                method.cs_start, method.cs_end = (
                    span[0] + cs_offset,
                    span[1] + cs_offset,
                )
            elif result.cs is None:
                method.cs_start, method.cs_end = 1, record.cs_lines
            il_span = result.il_ranges.get(method.token)
            if il_span is not None:
                method.il_start, method.il_end = il_span[0] + 1, il_span[1] + 1
    if record.error is None:
        context.progress.file_log(
            f"export {info.name}!{record.full_name} - {record.cs_lines} C# / "
            f"{record.il_lines} IL lines done"
        )


def _store_assembly_attributes(
    context: DotnetContext, info: AssemblyInfo, result: DecompiledType
) -> None:
    folder = _need(context.raw_dir) / info.folder / "Properties"
    header = f"// ToCode: assembly and module attributes of {info.full_name}\n"
    cs = header + (result.cs or f"// decompilation failed: {result.cs_error}\n")
    il = header + (result.il or f"// IL manifest failed: {result.il_error}\n")
    write_text_atomic(
        folder / "AssemblyInfo.cs", cs if cs.endswith("\n") else cs + "\n"
    )
    write_text_atomic(folder / "Manifest.il", il if il.endswith("\n") else il + "\n")
    context.source_files.append(folder / "AssemblyInfo.cs")
    context.il_files.append(folder / "Manifest.il")


def _failure_stub(session: DotnetSession, record: TypeInfo) -> str:
    lines = [
        f"// decompilation failed: {record.error}",
        "// The IL next to this file (.il) is complete; read it instead.",
    ]
    if record.namespace:
        lines.append(f"namespace {record.namespace};")
    lines.append(f"// {record.visibility} {record.kind} {record.name}")
    for member in session.nested_types(record.assembly, record.token):
        for method_id in member.methods:
            method = session.methods[method_id]
            lines.append(f"//   {member.name}::{method.prototype}")
    return "\n".join(lines) + "\n"


def _inherit_owner_ranges(session: DotnetSession) -> None:
    """State machine / closure methods without their own C# span point at the
    method that the decompiler folded them into."""
    for method in session.methods:
        if method.cs_start is not None or method.owner_method is None:
            continue
        owner = session.methods[method.owner_method]
        if owner.cs_start is not None:
            method.cs_start, method.cs_end = owner.cs_start, owner.cs_end


def _remove_stale_sources(context: DotnetContext) -> None:
    raw_dir = _need(context.raw_dir)
    session = _need(context.session)
    expected = {
        path
        for record in session.types.values()
        for path in (record.cs_path, record.il_path)
        if path is not None
    }
    for info in session.assemblies:
        expected.add(raw_dir / info.folder / "Properties" / "AssemblyInfo.cs")
        expected.add(raw_dir / info.folder / "Properties" / "Manifest.il")
        expected.add(raw_dir / info.folder / f"{info.name}.csproj")
    removed = 0
    for pattern in ("*.cs", "*.il", "*.csproj"):
        for path in raw_dir.rglob(pattern):
            if path not in expected:
                path.unlink(missing_ok=True)
                removed += 1
    if removed:
        context.progress.file_log(f"removed {removed} stale source files")


# -- project files / resources -----------------------------------------------------


def target_framework_moniker(attribute: str | None) -> str | None:
    if not attribute:
        return None
    match = _TFM_ATTRIBUTE_RX.match(attribute)
    if not match:
        return None
    family, major, minor = match.group(1), int(match.group(2)), int(match.group(3))
    patch = match.group(4)
    if family == "NETCoreApp":
        return f"net{major}.{minor}" if major >= 5 else f"netcoreapp{major}.{minor}"
    if family == "NETStandard":
        return f"netstandard{major}.{minor}"
    return f"net{major}{minor}{patch or ''}"


def build_csproj(info: AssemblyInfo, *, internal_refs: set[str]) -> str:
    framework = target_framework_moniker(info.target_framework) or "net10.0"
    output = "Exe" if info.entry_point is not None else "Library"
    if output == "Exe" and "Windows" in info.kind:
        output = "WinExe"
    references = [
        ref["name"]
        for ref in info.assembly_refs
        if ref["name"] in internal_refs
        or not re.match(
            r"^(System|Microsoft|mscorlib|netstandard|WindowsBase)\b", ref["name"]
        )
    ]
    lines = [
        "<!-- ToCode: recovered project for the decompiled sources; references are",
        "     best-effort (package versions are unknown), so restore may need edits. -->",
        '<Project Sdk="Microsoft.NET.Sdk">',
        "  <PropertyGroup>",
        f"    <AssemblyName>{info.name}</AssemblyName>",
        f"    <OutputType>{output}</OutputType>",
        f"    <TargetFramework>{framework}</TargetFramework>",
        "    <LangVersion>latest</LangVersion>",
        "    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>",
        "    <Nullable>annotations</Nullable>",
        "    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>",
        "    <EnableDefaultCompileItems>true</EnableDefaultCompileItems>",
        "  </PropertyGroup>",
    ]
    if references:
        lines.append("  <ItemGroup>")
        for name in sorted(set(references)):
            if name in internal_refs:
                lines.append(
                    f'    <ProjectReference Include="../{safe_file_name(name)}/{name}.csproj" />'
                )
            else:
                lines.append(f'    <Reference Include="{name}" />')
        lines.append("  </ItemGroup>")
    lines.append("</Project>")
    return "\n".join(lines) + "\n"


def _write_projects(context: DotnetContext) -> None:
    session = _need(context.session)
    raw_dir = _need(context.raw_dir)
    internal = {info.name for info in session.assemblies}
    for info in session.assemblies:
        path = raw_dir / info.folder / f"{info.name}.csproj"
        write_text_atomic(
            path, build_csproj(info, internal_refs=internal - {info.name})
        )
        context.project_files.append(path)


def _write_resources(context: DotnetContext) -> None:
    session = _need(context.session)
    found = _need(context.found)
    root = _need(context.root)
    data_dir = _need(context.data_dir)
    count = 0
    for info in session.assemblies:
        folder = data_dir / "resources" / info.folder
        for resource in info.resources:
            if resource.kind != "embedded":
                continue
            target = folder / safe_file_name(resource.name)
            try:
                size = session.save_resource(info, resource.name, target)
            except Exception as exc:  # pragma: no cover - backend specific
                resource.error = f"{type(exc).__name__}: {exc}"
                continue
            if size is None:
                resource.error = "cannot read resource data"
                continue
            resource.path = target
            resource.size = size
            count += 1
            if resource.name.endswith(".resources"):
                try:
                    resource.entries = session.decode_resources_file(
                        info, resource.name
                    )
                    write_json(
                        target.with_name(target.name + ".json"),
                        {"resource": resource.name, "entries": resource.entries},
                    )
                except Exception as exc:
                    resource.error = f"cannot decode .resources: {exc}"
    for extra in found.extras:
        target = data_dir / found.kind / safe_file_name(extra.entry.replace("/", "__"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(extra.path, target)
        context.extracted[extra.entry] = target.relative_to(root).as_posix()
    for item in found.assemblies:
        if item.path.is_relative_to(context.workdir or Path("/nonexistent")):
            target = (
                data_dir / "assemblies" / safe_file_name(item.entry.replace("/", "__"))
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item.path, target)
            context.extracted[item.entry] = target.relative_to(root).as_posix()
        else:
            context.extracted.setdefault(item.entry, None)
    if count:
        context.progress.log(f"Extracted {count} embedded resources")


# -- metadata ---------------------------------------------------------------------


def _write_metadata(context: DotnetContext) -> None:
    root = _need(context.root)
    session = _need(context.session)
    found = _need(context.found)
    with context.progress.bar(total=11, desc="metadata", unit="doc") as bar:
        context.reachable, context.roots = meta.reachable_json(session)
        write_json(root / "reachable.json", context.reachable)
        bar.update(1)
        write_json(root / "assemblies.json", meta.assemblies_json(session, found, root))
        bar.update(1)
        write_json_rows(
            root / "types.json",
            "types",
            meta.iter_type_rows(session, root),
            header={"count": len(session.types)},
        )
        bar.update(1)
        write_json_rows(
            root / "functions.json",
            "functions",
            meta.iter_function_rows(session, root, context.roots),
        )
        bar.update(1)
        write_json_rows(
            root / "function-index.json",
            "functions",
            meta.iter_function_index_rows(session, root),
            header={"schema_version": 2, "language": "csharp", "asm_language": "il"},
        )
        bar.update(1)
        write_json_rows(
            root / "strings.json", "strings", meta.iter_string_rows(session)
        )
        bar.update(1)
        write_json(root / "imports.json", meta.imports_json(session))
        bar.update(1)
        write_json(root / "exports.json", meta.exports_json(session))
        bar.update(1)
        write_json(root / "sections.json", meta.sections_json(session))
        bar.update(1)
        write_json(root / "namespace-graph.json", meta.namespace_graph_json(session))
        bar.update(1)
        write_json(root / "resources.json", meta.resources_json(session, root))
        bar.update(1)


def _write_final_documents(context: DotnetContext) -> None:
    root = _need(context.root)
    session = _need(context.session)
    found = _need(context.found)
    libs_doc = native_libs_json(context.libs, root)
    write_json(root / "container.json", meta.container_json(found, context.extracted))
    write_json(
        root / "triage.json",
        meta.triage_json(session, found, context.reachable, libs_doc["libs"]),
    )
    native_exports = [
        {
            "abi": lib.abi,
            "name": lib.name,
            "export_dir": str(lib.export_dir) if lib.export_dir else None,
            "status": lib.status,
            "backend": lib.backend,
        }
        for lib in context.libs
    ]
    common: dict[str, Any] = {
        "binary": str(context.input_path),
        "kind": found.kind,
        "assemblies": [info.name for info in session.assemblies],
        "backend": "dotnet",
        "decompiler": DotnetSession.decompiler_label,
        "root_dir": str(root),
        "src_dir": str(_need(context.raw_dir)),
        "raw_src_dir": str(_need(context.raw_dir)),
        "tree_src_dir": None,
        "include_dir": None,
        "data_dir": str(_need(context.data_dir)),
        "header": None,
        "agents": str(root / "AGENTS.md"),
        "claude": str(root / "CLAUDE.md"),
        "log": str(root / "tocode.log"),
        "ida_database": None,
        "source_files": [str(item) for item in context.source_files],
        "il_files": [str(item) for item in context.il_files],
        "project_files": [str(item) for item in context.project_files],
        "tree_source_files": [],
        "summary_files": [],
        "asm_files": [str(item) for item in context.il_files],
        "function_index": str(root / "function-index.json"),
        "tree_function_index": None,
        "function_count": len(session.methods),
        "type_count": len(session.types),
        "cluster_count": 0,
        "failure_count": len(context.failures),
        "requested_worker_count": context.options.jobs
        if context.options.jobs is not None
        else "auto",
        "worker_count": context.worker_count,
        "parallel_mode": context.render_mode,
        "native_enabled": context.options.native,
        "include_framework": context.options.include_framework,
        "native_exports": native_exports,
    }
    write_json(root / "project.json", common)
    manifest: dict[str, Any] = dict(common)
    manifest.update(
        {
            "schema_version": 2,
            "tocode_version": __version__,
            "format": f"dotnet-{found.kind}",
            "arch": "cil",
            "bits": 64,
            "entrypoints": [
                method.address
                for kind, method in meta.export_roots(session)
                if kind == "entrypoint"
            ],
            "raw_source_files": [str(item) for item in context.source_files],
            "data_variable_count": 0,
            "triage": str(root / "triage.json"),
            "imports": str(root / "imports.json"),
            "exports": str(root / "exports.json"),
            "reachable": str(root / "reachable.json"),
            "cluster_graph": None,
            "namespace_graph": str(root / "namespace-graph.json"),
            "assemblies_index": str(root / "assemblies.json"),
            "types": str(root / "types.json"),
            "type_count": len(session.types),
            "strings": str(root / "strings.json"),
            "sections": str(root / "sections.json"),
            "resources": str(root / "resources.json"),
            "container": str(root / "container.json"),
            "native_libs": str(root / "native-libs.json"),
            "variables_interesting": None,
            "failures": [
                {"address": None, "name": name, "error": error}
                for name, error in context.failures
            ],
            "native_errors": context.native_runner.errors
            if context.native_runner
            else [],
        }
    )
    write_json(root / "export-manifest.json", manifest)
    write_text_atomic(
        root / "AGENTS.md",
        meta.build_dotnet_agents(
            title=context.title,
            kind=found.kind,
            assemblies=[info.name for info in session.assemblies],
            native=context.options.native
            and any(
                lib.status not in {"pending"} and not lib.status.startswith("skipped")
                for lib in context.libs
            ),
            native_count=sum(
                1 for lib in context.libs if not lib.status.startswith("skipped")
            ),
        )
        + "\n",
    )
    write_text_atomic(root / "CLAUDE.md", "@./AGENTS.md\n")
    context.progress.log("Wrote project.json, export-manifest.json, AGENTS.md")


def _summary(context: DotnetContext) -> DotnetExportSummary:
    session = context.session
    found = _need(context.found)
    return DotnetExportSummary(
        root_dir=_need(context.root),
        kind=found.kind,
        assemblies=[info.name for info in session.assemblies] if session else [],
        type_count=len(session.types) if session else 0,
        method_count=len(session.methods) if session else 0,
        source_files=list(context.source_files),
        failed_types=list(context.failures),
        native_total=len(context.libs),
        native_done=sum(1 for lib in context.libs if lib.status == "done"),
        native_errors=list(context.native_runner.errors)
        if context.native_runner
        else [],
        seconds=time.monotonic() - context.started,
    )


def _need(value: Any) -> Any:
    if value is None:
        raise RuntimeError("export context not initialized")
    return value
