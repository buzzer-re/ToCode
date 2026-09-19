"""APK export pipeline (ASC backend).

Writes one project tree for an APK, split-APK set, or ``.apks``/``.xapk``
bundle: decompiled Java per class under ``src/raw/<package>/``, the decoded
manifest, Android metadata documents, extracted resources, and (unless
disabled) a nested native ToCode export for every shared object found.
"""

from __future__ import annotations

from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time
from typing import Any, Callable, Iterable
import zipfile

from . import __version__
from . import apk_metadata as meta
from .apk_native import (
    DEFAULT_NATIVE_MIN_FREE_MB,
    NATIVE_HEARTBEAT_SECONDS,
    NativeExporter,
    NativeLib,
    NativeOptions,
    NativeRunner,
    classify_native_entry,
    default_native_exporter,
    extract_native_libs,
    native_libs_json,
)
from .backends.asc import (
    ApkSet,
    AscSession,
    ClassRecord,
    DecompiledClass,
    MethodRecord,
    InlineDecompiler,
    class_java_relpath,
    decompile_batch_in_worker,
    discover_apk_set,
    init_decompile_worker,
    manifest_xml,
    sha256_file,
)
from .errors import ToCodeError
from .metadata import write_json, write_text_atomic
from .naming import clean_path_component
from .parallel import available_memory_mb, choose_jobs
from .progress import Progress
from .schema import ApkExportSummary


DECOMPILE_BATCH_SIZE = 24
# A decompile worker holds the parsed DEX tables plus androguard's per-class
# state; budget this much RAM per worker and recycle workers periodically so
# their resident size stays bounded on long runs.
ASC_WORKER_MEMORY_MB = 768
ASC_WORKER_BATCHES_PER_CHILD = 48
DEX_ENTRY_RX = re.compile(r"^classes\d*\.dex$")
# A DAD member declaration at class-body indent: modifiers, return type, name,
# parameter list, optional throws, and a ``;`` only for bodiless methods.
METHOD_DECL_RX = re.compile(
    r"^    (?!\{|\}|@)(?P<decl>[^;{]*?(?<![\w$])(?P<name>[\w$<>\-]+)\((?P<params>.*)\))"
    r"\s*(throws [^;{]*)?(?P<end>;?)\s*$"
)


@dataclass(slots=True)
class ApkExportOptions:
    out_dir: Path | None = None
    jobs: int | None = None
    native: bool = True
    splits: bool = True
    native_options: NativeOptions = field(default_factory=NativeOptions)
    decode_resources: bool = True


@dataclass
class ApkContext:
    input_path: Path
    options: ApkExportOptions
    progress: Progress
    apk_set: ApkSet | None = None
    session: AscSession | None = None
    root: Path | None = None
    raw_dir: Path | None = None
    data_dir: Path | None = None
    package: str = ""
    manifest_infos: list[meta.ManifestInfo] = field(default_factory=list)
    manifest_doc: dict[str, Any] = field(default_factory=dict)
    manifest_xml_path: Path | None = None
    entries: list[meta.ApkEntry] = field(default_factory=list)
    libs: list[NativeLib] = field(default_factory=list)
    native_runner: NativeRunner | None = None
    resource_thread: threading.Thread | None = None
    resource_errors: list[str] = field(default_factory=list)
    resource_files: list[Path] = field(default_factory=list)
    source_files: list[Path] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)
    reachable: dict[str, Any] = field(default_factory=dict)
    worker_count: int = 1
    render_mode: str = "single"
    started: float = 0.0
    bundle_dir: Path | None = None


def export_apk(
    input_path: Path,
    *,
    options: ApkExportOptions | None = None,
    progress: Progress | None = None,
    native_exporter: NativeExporter | None = None,
    decompiler_factory: Callable[[AscSession], Any] | None = None,
) -> ApkExportSummary:
    options = options or ApkExportOptions()
    progress = progress or Progress()
    context = ApkContext(
        input_path=Path(input_path).resolve(),
        options=options,
        progress=progress,
        started=time.monotonic(),
    )
    try:
        _discover(context)
        _prepare_root(context)
        _extract_entries(context)
        _start_native(context, native_exporter)
        _start_resources(context)
        _inventory(context)
        _decompile(context, decompiler_factory)
        _join_resources(context)
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
        if context.bundle_dir is not None:
            shutil.rmtree(context.bundle_dir, ignore_errors=True)
    return _summary(context)


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------


def _discover(context: ApkContext) -> None:
    path = context.input_path
    if not path.is_file():
        raise ToCodeError(f"APK not found: {path}")
    workdir = Path(tempfile.mkdtemp(prefix="tocode-apks-", dir=_bundle_tmp_root()))
    apk_set = discover_apk_set(path, splits=context.options.splits, workdir=workdir)
    if apk_set.workdir is not None:
        context.bundle_dir = workdir
    else:
        shutil.rmtree(workdir, ignore_errors=True)
    context.apk_set = apk_set
    infos: list[meta.ManifestInfo] = []
    for apk in apk_set.apks:
        try:
            xml_text = manifest_xml(apk)
        except ToCodeError as exc:
            if apk == apk_set.primary:
                raise
            context.progress.log(f"warning: {exc}")
            infos.append(meta.parse_manifest("", apk_name=apk.name))
            continue
        info = meta.parse_manifest(xml_text, apk_name=apk.name)
        infos.append(info)
        if apk == apk_set.primary:
            context.manifest_doc["_xml"] = xml_text
    context.manifest_infos = infos
    primary = infos[0]
    if primary.parse_error:
        raise ToCodeError(
            f"cannot parse AndroidManifest.xml of {apk_set.primary.name}: "
            f"{primary.parse_error}"
        )
    context.package = primary.package or clean_path_component(path.stem)


def _bundle_tmp_root() -> str | None:
    # Bundles are unpacked here before the package name (and so the export root)
    # is known. Honour the same override as the worker database copies so the
    # unpacked APKs can be kept off a RAM-backed /tmp.
    explicit = os.environ.get("TOCODE_WORKER_TMP_DIR", "").strip()
    if not explicit:
        return None
    candidate = Path(explicit).expanduser()
    try:
        candidate.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return str(candidate)


def _root_dir(context: ApkContext) -> Path:
    out_dir = context.options.out_dir
    source = context.input_path
    if out_dir is not None:
        out = Path(out_dir).expanduser()
        return out.resolve() if out.is_absolute() else (source.parent / out).resolve()
    name = f"{clean_path_component(context.package)}_decompiler"
    default_root = os.environ.get("TOCODE_DEFAULT_OUT_ROOT", "").strip()
    if default_root:
        return (Path(default_root).expanduser().resolve() / name).resolve()
    return (source.parent / name).resolve()


def _prepare_root(context: ApkContext) -> None:
    root = _root_dir(context)
    context.root = root
    context.raw_dir = root / "src" / "raw"
    context.data_dir = root / "data"
    if context.progress.log_path is None:
        context.progress.set_log_path(root / "tocode.log")
    for path in (context.raw_dir, context.data_dir, root / "lib"):
        path.mkdir(parents=True, exist_ok=True)
    apk_set = _need(context.apk_set)
    context.progress.log("Export run started")
    context.progress.log(f"Using ASC as backend for {context.package}")
    context.progress.log("APK set: " + ", ".join(item.name for item in apk_set.apks))
    xml_text = context.manifest_doc.pop("_xml", "")
    manifest_path = root / "AndroidManifest.xml"
    write_text_atomic(
        manifest_path, xml_text if xml_text.endswith("\n") else xml_text + "\n"
    )
    context.manifest_xml_path = manifest_path
    context.manifest_doc = meta.manifest_json(
        context.manifest_infos[0], context.manifest_infos[1:], xml_path=manifest_path
    )
    write_json(root / "manifest.json", context.manifest_doc)


def _extract_entries(context: ApkContext) -> None:
    root = _need(context.root)
    apk_set = _need(context.apk_set)
    data_root = _need(context.data_dir) / "apk"
    entries: list[meta.ApkEntry] = []
    total = 0
    for apk in apk_set.apks:
        with zipfile.ZipFile(apk) as archive:
            total += len(archive.infolist())
    with context.progress.bar(total=total, desc="extract", unit="entry") as bar:
        for apk in apk_set.apks:
            target_root = data_root / clean_path_component(apk.stem)
            with zipfile.ZipFile(apk) as archive:
                for info in archive.infolist():
                    bar.update(1)
                    if info.is_dir():
                        continue
                    name = info.filename
                    with archive.open(info) as handle:
                        head = handle.read(4)
                    kind = _entry_kind(name, head)
                    exported: str | None = None
                    if kind not in {"dex", "native"}:
                        target = _safe_join(target_root, name)
                        if target is not None:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with (
                                archive.open(info) as source,
                                target.open("wb") as sink,
                            ):
                                shutil.copyfileobj(source, sink, 1 << 20)
                            exported = target.relative_to(root).as_posix()
                    entries.append(
                        meta.ApkEntry(
                            apk=apk.name,
                            name=name,
                            size=info.file_size,
                            compressed_size=info.compress_size,
                            kind=kind,
                            exported_path=exported,
                        )
                    )
    context.entries = entries
    context.libs = extract_native_libs(apk_set.apks, root, sha256=sha256_file)
    for lib in context.libs:
        lib.package = context.package
        for entry in entries:
            if entry.name == lib.entry and entry.apk == lib.source_apk:
                entry.exported_path = lib.path.relative_to(root).as_posix()
    context.progress.log(
        f"Extracted {len(entries)} entries, {len(context.libs)} native libraries"
    )
    _write_native_libs(context)


def _entry_kind(name: str, head: bytes) -> str:
    leaf = name.rsplit("/", 1)[-1]
    if "/" not in name and DEX_ENTRY_RX.match(leaf):
        return "dex"
    if classify_native_entry(name, head) is not None:
        return "native"
    if name == "AndroidManifest.xml":
        return "manifest"
    if name == "resources.arsc":
        return "arsc"
    if name.startswith("res/"):
        return "resource"
    if name.startswith("assets/"):
        return "asset"
    if name.startswith("META-INF/"):
        return "meta"
    if name.startswith("kotlin/"):
        return "kotlin"
    return "other"


def _safe_join(root: Path, name: str) -> Path | None:
    parts = [part for part in name.split("/") if part not in {"", ".", ".."}]
    if not parts:
        return None
    return root.joinpath(*parts)


def _start_native(context: ApkContext, exporter: NativeExporter | None) -> None:
    root = _need(context.root)
    if not context.libs:
        return
    if not context.options.native:
        for lib in context.libs:
            lib.status = "skipped: --no-native"
        context.progress.log(
            f"Native decompilation skipped (--no-native) for {len(context.libs)} libraries"
        )
        _write_native_libs(context)
        return
    runner = NativeRunner(
        libs=context.libs,
        root=root,
        progress=context.progress,
        exporter=exporter or default_native_exporter(context.options.native_options),
        min_free_mb=_native_min_free_mb(),
        available_memory=available_memory_mb,
    )
    context.progress.log(
        f"Native decompilation started in background for {len(context.libs)} "
        f"libraries (backend: {context.options.native_options.backend})"
    )
    runner.start()
    context.native_runner = runner


def _native_min_free_mb() -> int:
    raw = os.environ.get("TOCODE_APK_NATIVE_MIN_FREE_MB", "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return DEFAULT_NATIVE_MIN_FREE_MB


def _join_native(context: ApkContext) -> None:
    runner = context.native_runner
    if runner is None:
        return
    thread = runner.thread
    if thread is not None and thread.is_alive():
        pending = sum(1 for lib in context.libs if lib.status == "pending")
        context.progress.log(
            f"DEX export done; waiting for {pending} native library export(s) "
            "(progress below is mirrored from native/<abi>/<lib>/tocode.log)"
        )
        # Heartbeat while the native side is in a silent phase (loading or
        # auto-analysis produce no log lines for a while).
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


def _write_native_libs(context: ApkContext) -> None:
    root = _need(context.root)
    write_json(root / "native-libs.json", native_libs_json(context.libs, root))


def _start_resources(context: ApkContext) -> None:
    if not context.options.decode_resources:
        return
    thread = threading.Thread(
        target=_decode_resources, args=(context,), name="tocode-resources", daemon=True
    )
    thread.start()
    context.resource_thread = thread


def _join_resources(context: ApkContext) -> None:
    thread = context.resource_thread
    if thread is None:
        return
    thread.join()
    context.progress.log(
        f"Decoded {len(context.resource_files)} resource files"
        + (
            f" ({len(context.resource_errors)} failed)"
            if context.resource_errors
            else ""
        )
    )
    for line in context.resource_errors[:20]:
        context.progress.file_log(f"resource decode failed: {line}")


def _decode_resources(context: ApkContext) -> None:
    root = _need(context.root)
    data_dir = _need(context.data_dir)
    try:
        from androguard.core import axml as androguard_axml
    except Exception as exc:  # pragma: no cover - androguard ships with droidasc
        context.resource_errors.append(f"androguard unavailable: {exc}")
        return
    resources: dict[str, Any] = {"packages": []}
    for entry in context.entries:
        if entry.exported_path is None:
            continue
        source = root / entry.exported_path
        if entry.kind == "resource" and entry.name.endswith(".xml"):
            target = data_dir / "res" / clean_path_component(Path(entry.apk).stem)
            target = target.joinpath(*entry.name.split("/")[1:])
            try:
                data = source.read_bytes()
                if not data.startswith(b"\x03\x00\x08\x00"):
                    continue  # already plain text
                printer = androguard_axml.AXMLPrinter(data)
                if not printer.is_valid():
                    raise ValueError("invalid binary XML")
                text = printer.get_xml(pretty=True).decode("utf-8", errors="replace")
                write_text_atomic(target, text)
                context.resource_files.append(target)
            except Exception as exc:
                context.resource_errors.append(f"{entry.apk}:{entry.name}: {exc}")
        elif entry.kind == "arsc":
            try:
                resources["packages"].extend(
                    _decode_arsc(androguard_axml, source.read_bytes(), entry.apk)
                )
            except Exception as exc:
                context.resource_errors.append(f"{entry.apk}:{entry.name}: {exc}")
    write_json(data_dir / "resources.json", resources)


def _decode_arsc(axml_module: Any, data: bytes, apk_name: str) -> list[dict[str, Any]]:
    parser = axml_module.ARSCParser(data)
    packages: list[dict[str, Any]] = []
    resolved = parser.get_resolved_strings()
    for package in parser.get_packages_names():
        strings: dict[str, dict[str, str]] = {}
        for locale, table in (resolved.get(package) or {}).items():
            strings[str(locale) or "default"] = {
                f"0x{res_id:08x}" if isinstance(res_id, int) else str(res_id): value
                for res_id, value in table.items()
            }
        public: list[dict[str, Any]] = []
        try:
            public_xml = parser.get_public_resources(package).decode(
                "utf-8", errors="replace"
            )
            for match in re.finditer(
                r'<public\s+type="([^"]+)"\s+name="([^"]+)"\s+id="([^"]+)"',
                public_xml,
            ):
                public.append(
                    {
                        "type": match.group(1),
                        "name": match.group(2),
                        "id": match.group(3),
                    }
                )
        except Exception:
            public = []
        packages.append(
            {
                "apk": apk_name,
                "name": package,
                "public": public,
                "strings": strings,
            }
        )
    return packages


def _inventory(context: ApkContext) -> None:
    apk_set = _need(context.apk_set)
    session = AscSession(apk_set)
    with context.progress.bar(total=1, desc="inventory", unit="step") as bar:
        session.load()
        bar.update(1)
    context.session = session
    context.progress.log(
        f"Inventory: {len(session.images)} dex, {len(session.classes)} classes, "
        f"{len(session.methods)} methods, {len(session.strings)} strings"
    )
    _assign_java_paths(context)
    meta.entry_methods(session, context.manifest_doc)


def _assign_java_paths(context: ApkContext) -> None:
    raw_dir = _need(context.raw_dir)
    session = _need(context.session)
    seen: dict[str, int] = {}
    for record in session.classes:
        rel = class_java_relpath(record.descriptor)
        key = rel.as_posix().lower()
        count = seen.get(key, 0)
        seen[key] = count + 1
        if count:
            rel = rel.with_name(f"{rel.stem}~{count}{rel.suffix}")
        record.java_path = raw_dir / rel


def _select_workers(context: ApkContext) -> int:
    session = _need(context.session)
    chosen = choose_jobs(
        function_count=len(session.classes),
        analysis_seconds=0.0,
        requested=context.options.jobs,
        backend="asc",
    )
    memory = available_memory_mb()
    if memory is not None and chosen > 1:
        ceiling = max(1, memory // ASC_WORKER_MEMORY_MB)
        if ceiling < chosen:
            context.progress.log(
                f"Limiting decompile workers to {ceiling} "
                f"({memory} MB available, {ASC_WORKER_MEMORY_MB} MB per worker)"
            )
            chosen = ceiling
    context.worker_count = max(1, chosen)
    context.render_mode = "process" if context.worker_count > 1 else "single"
    return context.worker_count


def _decompile(
    context: ApkContext, decompiler_factory: Callable[[AscSession], Any] | None
) -> None:
    session = _need(context.session)
    classes = session.classes
    if not classes:
        context.progress.log("No DEX classes to decompile")
        _remove_stale_sources(context, set())
        return
    workers = _select_workers(context)
    expected = {record.java_path for record in classes if record.java_path}
    _remove_stale_sources(context, {path for path in expected if path})
    context.progress.log(f"Decompiling {len(classes)} classes with {workers} worker(s)")
    with context.progress.bar(
        total=len(classes), desc="decompile", unit="class"
    ) as bar:
        if decompiler_factory is not None or workers <= 1:
            _decompile_serial(context, decompiler_factory, bar)
        else:
            try:
                _decompile_parallel(context, workers, bar)
            except _PoolFailure as exc:
                context.progress.log(
                    f"Worker pool failed ({exc}); finishing remaining classes in-process"
                )
                context.render_mode = "single-fallback"
                _decompile_serial(context, None, bar)
    context.progress.log(
        f"Decompiled {len(classes) - len(context.failures)} classes, "
        f"{len(context.failures)} failed"
    )


class _PoolFailure(RuntimeError):
    pass


def _pending_classes(context: ApkContext) -> list[ClassRecord]:
    session = _need(context.session)
    return [
        record
        for record in session.classes
        if record.line_count == 0 and record.error is None
    ]


def _decompile_serial(
    context: ApkContext, factory: Callable[[AscSession], Any] | None, bar: Any
) -> None:
    session = _need(context.session)
    decompiler = factory(session) if factory is not None else InlineDecompiler(session)
    for record in _pending_classes(context):
        result = decompiler.decompile(record)
        _store_result(context, record, result)
        bar.update(1)


def _decompile_parallel(context: ApkContext, workers: int, bar: Any) -> None:
    pending = _pending_classes(context)
    by_descriptor = {record.descriptor: record for record in pending}
    # Group by dex so each worker keeps its DexManager hot for long stretches.
    ordered = sorted(pending, key=lambda record: (record.dex, record.index))
    batches: list[list[tuple[str, str, int]]] = []
    for start in range(0, len(ordered), DECOMPILE_BATCH_SIZE):
        chunk = ordered[start : start + DECOMPILE_BATCH_SIZE]
        batches.append([(item.dex, item.descriptor, item.index) for item in chunk])
    context.progress.file_log(
        f"decompile: {len(batches)} batches of up to {DECOMPILE_BATCH_SIZE} classes"
    )
    # Workers are recycled between rounds to keep their resident size bounded.
    # (``max_tasks_per_child`` is not used: it deadlocks spawn pools on some
    # CPython builds, e.g. 3.14.4, after the first recycle.)
    round_size = workers * ASC_WORKER_BATCHES_PER_CHILD
    for start in range(0, len(batches), round_size):
        _run_decompile_round(
            context, workers, batches[start : start + round_size], by_descriptor, bar
        )


def _run_decompile_round(
    context: ApkContext,
    workers: int,
    batches: list[list[tuple[str, str, int]]],
    by_descriptor: dict[str, ClassRecord],
    bar: Any,
) -> None:
    apk_set = _need(context.apk_set)
    executor = ProcessPoolExecutor(
        max_workers=min(workers, len(batches)),
        mp_context=multiprocessing.get_context("spawn"),
        initializer=init_decompile_worker,
        initargs=(apk_set,),
    )
    try:
        futures: dict[Future[list[DecompiledClass]], list[tuple[str, str, int]]] = {}
        for batch in batches:
            futures[executor.submit(decompile_batch_in_worker, batch)] = batch
        for future in as_completed(futures):
            batch = futures[future]
            try:
                results = future.result()
            except Exception as exc:
                raise _PoolFailure(f"{type(exc).__name__}: {exc}") from exc
            for result in results:
                record = by_descriptor.get(result.descriptor)
                if record is not None:
                    _store_result(context, record, result)
            bar.update(len(batch))
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def _store_result(
    context: ApkContext, record: ClassRecord, result: DecompiledClass
) -> None:
    session = _need(context.session)
    root = _need(context.root)
    session.apply_refs(record, result.refs)
    path = _need(record.java_path)
    if result.source is None:
        record.error = result.error or "unknown decompilation error"
        context.failures.append((record.descriptor, record.error))
        text = _failure_stub(record)
        context.progress.file_log(f"export {record.descriptor} failed: {record.error}")
    else:
        text = result.source if result.source.endswith("\n") else result.source + "\n"
        text = _annotate_source(record, text)
    write_text_atomic(path, text)
    record.line_count = text.count("\n")
    assign_method_lines(record, text)
    context.source_files.append(path)
    if record.error is None:
        context.progress.file_log(
            f"export {record.descriptor} - {record.line_count} lines done "
            f"({path.relative_to(root).as_posix()})"
        )


def _annotate_source(record: ClassRecord, text: str) -> str:
    header = (
        f"// ToCode: {record.descriptor} from {record.dex}"
        + (f" (source: {record.source_file})" if record.source_file else "")
        + "\n"
    )
    return header + text


def _failure_stub(record: ClassRecord) -> str:
    lines = [
        f"// ToCode: {record.descriptor} from {record.dex}",
        f"// decompilation failed: {record.error}",
        f"package {record.package};" if record.package else "",
        f"{' '.join(record.flag_names)} class {record.simple_name} {{",
    ]
    for method in record.methods:
        lines.append(
            f"    {' '.join(method.flag_names)} {method.prototype};".replace("  ", " ")
        )
    lines.append("}")
    return "\n".join(line for line in lines if line is not None) + "\n"


def assign_method_lines(record: ClassRecord, text: str) -> None:
    """Best-effort mapping of each method to its line range in the Java text.

    DAD prints constructors and the static initializer under the class's
    simple name (``Outer$Inner(...)`` / ``static Outer$Inner()``), so those are
    keyed by that name and told apart by the ``static`` modifier.
    """
    lines = text.splitlines()
    simple = record.simple_name
    by_name: dict[str, list[MethodRecord]] = {}
    for method in record.methods:
        method.line_start = None
        method.line_end = None
        name = simple if method.name in {"<init>", "<clinit>"} else method.name
        by_name.setdefault(name, []).append(method)
    starts: list[tuple[int, str, int, bool, bool]] = []
    for number, line in enumerate(lines, start=1):
        match = METHOD_DECL_RX.match(line)
        if not match:
            continue
        name = match.group("name")
        if name not in by_name:
            continue
        count = _param_count(match.group("params").strip())
        has_body = match.group("end") != ";"
        is_static = " static " in f" {match.group('decl')[: match.start('name') - 4]} "
        starts.append((number, name, count, has_body, is_static))
    total = len(lines)
    for position, (start, name, count, has_body, is_static) in enumerate(starts):
        candidates = [m for m in by_name.get(name, []) if m.line_start is None]
        if name == simple:
            wanted = "<clinit>" if is_static else "<init>"
            special = [m for m in candidates if m.name == wanted]
            candidates = special or [
                m for m in candidates if m.name not in {"<init>", "<clinit>"}
            ]
        if not candidates:
            continue
        chosen = next((m for m in candidates if len(m.params) == count), candidates[0])
        # Annotations directly above the declaration belong to the method.
        first = start
        while first > 1 and lines[first - 2].startswith("    @"):
            first -= 1
        if not has_body:
            end = start
        else:
            closing = _closing_brace(lines, start)
            if closing is None:
                closing = (
                    starts[position + 1][0] - 1 if position + 1 < len(starts) else total
                )
            end = closing
        chosen.line_start = first
        chosen.line_end = end
    if record.error is not None:
        for method in record.methods:
            if method.line_start is None:
                method.line_start = 1
                method.line_end = max(total, 1)


def _param_count(params: str) -> int:
    if not params:
        return 0
    depth = 0
    count = 1
    for ch in params:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


def _closing_brace(lines: list[str], start: int) -> int | None:
    for number in range(start, len(lines) + 1):
        if lines[number - 1] == "    }":
            return number
    return None


def _remove_stale_sources(context: ApkContext, expected: set[Path]) -> None:
    raw_dir = _need(context.raw_dir)
    if not raw_dir.exists():
        return
    removed = 0
    for path in raw_dir.rglob("*.java"):
        if path not in expected:
            path.unlink(missing_ok=True)
            removed += 1
    if removed:
        context.progress.file_log(f"removed {removed} stale source files")


def _write_metadata(context: ApkContext) -> None:
    root = _need(context.root)
    session = _need(context.session)
    with context.progress.bar(total=9, desc="metadata", unit="doc") as bar:
        # The class/method/string documents are written row by row: on a large
        # APK they reach hundreds of megabytes, which cannot be built as one
        # Python structure plus its serialized copy in memory.
        meta.write_json_rows(
            root / "classes.json",
            "classes",
            meta.iter_class_rows(session, root),
            header={"count": len(session.classes)},
        )
        bar.update(1)
        meta.write_json_rows(
            root / "functions.json",
            "functions",
            meta.iter_function_rows(session, root),
        )
        bar.update(1)
        meta.write_json_rows(
            root / "function-index.json",
            "functions",
            meta.iter_function_index_rows(session, root),
            header={"schema_version": 2, "language": "java"},
        )
        bar.update(1)
        meta.write_json_rows(
            root / "strings.json", "strings", meta.iter_string_rows(session)
        )
        bar.update(1)
        write_json(root / "imports.json", meta.imports_json(session))
        bar.update(1)
        write_json(
            root / "exports.json", meta.exports_json(session, context.manifest_doc)
        )
        bar.update(1)
        write_json(root / "sections.json", meta.sections_json(context.entries))
        bar.update(1)
        write_json(root / "package-graph.json", meta.package_graph_json(session))
        bar.update(1)
        seeds = meta.entry_methods(session, context.manifest_doc)
        context.reachable = meta.reachable_json(session, seeds)
        write_json(root / "reachable.json", context.reachable)
        bar.update(1)


def _write_final_documents(context: ApkContext) -> None:
    root = _need(context.root)
    session = _need(context.session)
    reachable = context.reachable
    libs_doc = native_libs_json(context.libs, root)
    write_json(
        root / "triage.json",
        meta.triage_json(
            session, context.manifest_doc, reachable, libs_doc["libs"], context.entries
        ),
    )
    apk_set = _need(context.apk_set)
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
        "apks": [str(item) for item in apk_set.apks],
        "package": context.package,
        "backend": "asc",
        "decompiler": AscSession.decompiler_label,
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
        "manifest_xml": str(context.manifest_xml_path)
        if context.manifest_xml_path
        else None,
        "manifest": str(root / "manifest.json"),
        "ida_database": None,
        "source_files": [str(item) for item in context.source_files],
        "tree_source_files": [],
        "summary_files": [],
        "asm_files": [],
        "function_index": str(root / "function-index.json"),
        "tree_function_index": None,
        "function_count": len(session.methods),
        "class_count": len(session.classes),
        "cluster_count": 0,
        "failure_count": len(context.failures),
        "requested_worker_count": context.options.jobs
        if context.options.jobs is not None
        else "auto",
        "worker_count": context.worker_count,
        "parallel_mode": context.render_mode,
        "native_enabled": context.options.native,
        "native_exports": native_exports,
    }
    write_json(root / "project.json", common)
    manifest: dict[str, Any] = dict(common)
    manifest.update(
        {
            "schema_version": 2,
            "tocode_version": __version__,
            "format": "apk",
            "arch": "dalvik",
            "bits": 32,
            "entrypoints": context.manifest_doc.get("main_activities", []),
            "raw_source_files": [str(item) for item in context.source_files],
            "data_variable_count": 0,
            "triage": str(root / "triage.json"),
            "imports": str(root / "imports.json"),
            "exports": str(root / "exports.json"),
            "reachable": str(root / "reachable.json"),
            "cluster_graph": None,
            "package_graph": str(root / "package-graph.json"),
            "classes": str(root / "classes.json"),
            "strings": str(root / "strings.json"),
            "sections": str(root / "sections.json"),
            "native_libs": str(root / "native-libs.json"),
            "resources": str(_need(context.data_dir) / "resources.json"),
            "resource_files": len(context.resource_files),
            "types": None,
            "type_count": 0,
            "variables_interesting": None,
            "dex_files": [image.name for image in session.images],
            "failures": [
                {"address": None, "name": descriptor, "error": error}
                for descriptor, error in context.failures
            ],
            "native_errors": context.native_runner.errors
            if context.native_runner
            else [],
        }
    )
    write_json(root / "export-manifest.json", manifest)
    write_text_atomic(
        root / "AGENTS.md",
        meta.build_apk_agents(
            package=context.package,
            native=context.options.native and bool(context.libs),
            native_count=len(context.libs),
        )
        + "\n",
    )
    write_text_atomic(root / "CLAUDE.md", "@./AGENTS.md\n")
    context.progress.log("Wrote project.json, export-manifest.json, AGENTS.md")


def _summary(context: ApkContext) -> ApkExportSummary:
    session = context.session
    apk_set = _need(context.apk_set)
    return ApkExportSummary(
        root_dir=_need(context.root),
        package=context.package,
        apks=list(apk_set.apks),
        class_count=len(session.classes) if session else 0,
        method_count=len(session.methods) if session else 0,
        source_files=list(context.source_files),
        failed_classes=list(context.failures),
        native_total=len(context.libs),
        native_done=sum(1 for lib in context.libs if lib.status == "done"),
        native_errors=list(context.native_runner.errors)
        if context.native_runner
        else [],
        manifest_path=context.manifest_xml_path,
        seconds=time.monotonic() - context.started,
    )


def _need(value: Any) -> Any:
    if value is None:
        raise RuntimeError("export context not initialized")
    return value


def iter_source_files(root: Path) -> Iterable[Path]:
    yield from sorted((root / "src" / "raw").rglob("*.java"))
