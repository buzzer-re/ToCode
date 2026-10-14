from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from .analysis import create_analyzer
from .apk import ApkExportOptions, export_apk
from .apk_native import NativeOptions
from .backends.asc import is_apk_input
from .backends.base import is_binja_database, probe_binja_headless
from .backends.dotnet import is_dotnet_input
from .errors import ToCodeError
from .exporter import export_binary
from .naming import default_output_name
from .progress import Progress


def parse_jobs(value: str) -> int | None:
    text = value.strip().lower()
    if text == "auto":
        return None
    try:
        jobs = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "jobs must be a positive integer or 'auto'"
        ) from exc
    if jobs < 1:
        raise argparse.ArgumentTypeError("jobs must be at least 1")
    return jobs


def _env_port(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def build_parser() -> argparse.ArgumentParser:
    default_backend = os.environ.get("TOCODE_BACKEND", "auto").strip().lower()
    if default_backend not in {"auto", "ida", "r2", "angr", "binja"}:
        default_backend = "auto"
    default_binja_host = (
        os.environ.get("TOCODE_BINJA_HOST", "127.0.0.1").strip() or "127.0.0.1"
    )
    default_binja_port = _env_port("TOCODE_BINJA_PORT", 18812)
    default_binja_transport = (
        os.environ.get("TOCODE_BINJA_TRANSPORT", "auto").strip().lower() or "auto"
    )
    if default_binja_transport not in {"auto", "headless", "mcp", "rpyc"}:
        default_binja_transport = "auto"
    parser = argparse.ArgumentParser(
        prog="tocode",
        description="Export a compiled binary into a source-like reverse-engineering project.",
    )
    parser.add_argument(
        "binary",
        type=Path,
        nargs="?",
        default=None,
        help="Input binary or folder to export. Optional for --backend binja, which exports an open Binary Ninja view (a path given there is opened in Binary Ninja, or matched to an open file).",
    )
    parser.add_argument(
        "-o",
        "--out-dir",
        type=Path,
        default=None,
        help="Output project directory.",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "ida", "r2", "angr", "binja"),
        default=default_backend,
        help="Decompiler backend: auto prefers IDA, then Binary Ninja's Python API (headless), then r2, then angr as a last-resort fallback; binja always uses Binary Ninja, also through a running Binary Ninja (see --binja-transport) (default: TOCODE_BACKEND or auto). For APK input this selects the backend for the native .so libraries (binja needs the headless API there).",
    )
    parser.add_argument(
        "--no-native",
        action="store_true",
        help="APK and .NET input: only export the DEX/managed side; native libraries are extracted and listed but not decompiled.",
    )
    parser.add_argument(
        "--as-native",
        action="store_true",
        help=".NET input: skip the .NET backend and export the file with the native backend (IDA/r2/angr) like any PE/ELF.",
    )
    parser.add_argument(
        "--setup-dotnet",
        action="store_true",
        help="Download and verify the .NET decompiler libraries (dnlib, ICSharpCode.Decompiler) from nuget.org without prompting, or re-verify an existing install, then exit. .NET exports otherwise ask once on first use.",
    )
    parser.add_argument(
        "--include-framework",
        action="store_true",
        help=".NET input: also decompile .NET framework/runtime assemblies and native runtime libraries found in bundles and packages.",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="GLOB",
        help="Folder input: export only binaries whose path (relative to the folder) matches; '**' crosses directories and a pattern without '/' matches the file name. Repeatable. Other binaries are still scanned and linked.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Folder input: do not export binaries matching this glob (same syntax as --only). Repeatable.",
    )
    parser.add_argument(
        "--no-managed",
        action="store_true",
        help="Folder input: do not export .NET assemblies (they are still scanned and linked).",
    )
    parser.add_argument(
        "--arch",
        default=None,
        help="Folder input: slice to use from universal (fat) Mach-O files, e.g. arm64 or x86_64 (default: the main executable's).",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Folder input: scan, resolve links, print what would be exported in which order, and exit without decompiling.",
    )
    parser.add_argument(
        "--links-only",
        action="store_true",
        help="Folder input: skip decompilation and only recompute mappings.json, per-file links, and source comments over the existing exports.",
    )
    parser.add_argument(
        "--no-splits",
        action="store_true",
        help="APK input: export base.apk alone instead of merging sibling split_*.apk files.",
    )
    parser.add_argument(
        "--binja-transport",
        choices=("auto", "headless", "mcp", "rpyc"),
        default=default_binja_transport,
        help="How the binja backend reaches Binary Ninja: headless loads the input file with the Binary Ninja Python API in this process (needs a license that allows headless use), mcp uses Binary Ninja 6's built-in MCP server, rpyc uses binja-headless. auto uses headless when an input file is given and the API is installed, then MCP, then RPyc (default: TOCODE_BINJA_TRANSPORT or auto).",
    )
    parser.add_argument(
        "--binja-dir",
        type=Path,
        default=None,
        help="Binary Ninja install folder (or its python/ folder) for the headless API (default: TOCODE_BINJA_DIR, BN_INSTALL_DIR, the binaryninja.pth written by Binary Ninja's install_api.py, or common install paths).",
    )
    parser.add_argument(
        "--binja-license",
        type=Path,
        default=None,
        metavar="PATH",
        help="Binary Ninja license file for the headless API, handed to the core instead of the license.dat in Binary Ninja's user folder; its contents are never logged (default: TOCODE_BINJA_LICENSE).",
    )
    parser.add_argument(
        "--binja-mcp-url",
        default=None,
        metavar="URL",
        help="URL of Binary Ninja's MCP server (default: TOCODE_BINJA_MCP_URL or http://127.0.0.1:24642/mcp).",
    )
    parser.add_argument(
        "--binja-host",
        default=default_binja_host,
        help="Host of the binja-headless RPyc service for the binja backend (default: TOCODE_BINJA_HOST or 127.0.0.1).",
    )
    parser.add_argument(
        "--binja-port",
        type=int,
        default=default_binja_port,
        help="Port of the binja-headless RPyc service for the binja backend (default: TOCODE_BINJA_PORT or 18812).",
    )
    parser.add_argument(
        "--list-binja",
        action="store_true",
        help="List the binary views open in Binary Ninja with their index, then exit (binja backend).",
    )
    parser.add_argument(
        "--binja-view",
        type=int,
        default=None,
        metavar="N",
        help="Export the open Binary Ninja view with this index (from --list-binja). Default: the active view (MCP) or the focused view (RPyc).",
    )
    parser.add_argument(
        "--all-views",
        action="store_true",
        help="Export every open Binary Ninja view, each into its own folder under the output directory (binja backend).",
    )
    parser.add_argument(
        "--idadir",
        type=Path,
        default=None,
        help="Path to the local IDA installation.",
    )
    parser.add_argument(
        "--ida-domain-path",
        type=Path,
        default=None,
        help="Path to a local ida-domain checkout.",
    )
    parser.add_argument(
        "--purge-cache",
        action="store_true",
        help=(
            "Discard and rebuild a cached IDA database that cannot be opened "
            "because it is unpacked (open in another IDA session or left by an "
            "interrupted run). Destroys that database, so close IDA first."
        ),
    )
    parser.add_argument(
        "--analysis",
        default="aaa",
        help="radare2 analysis command (default: aaa; r2 backend only).",
    )

    parser.add_argument(
        "-j",
        "--jobs",
        type=parse_jobs,
        default=None,
        help="Worker sessions for decompilation: positive integer or 'auto' (default: auto). In a folder export, the workers of each binary.",
    )
    parser.add_argument(
        "-pf",
        "--parallel-files",
        type=parse_jobs,
        default=None,
        metavar="N",
        help="Folder input: binaries exported at once, each in its own process with -j workers: positive integer or 'auto' (default: auto, from the CPU count and free memory).",
    )
    parser.add_argument(
        "--tree",
        action="store_true",
        help="Also write tree-sitter/Semgrep friendly source under src/tree.",
    )
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Compute per-section Shannon entropy (off by default; slow on large binaries).",
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Ignore any saved checkpoint for this output directory and start over.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Disable status logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    progress = Progress(enabled=not args.quiet)
    if args.setup_dotnet:
        return _setup_dotnet()

    binja_only = args.list_binja or args.all_views or args.binja_view is not None
    if args.backend != "binja" and binja_only:
        parser.error(
            "--list-binja, --binja-view, and --all-views require --backend binja"
        )
    if args.binja_view is not None and args.all_views:
        parser.error("--binja-view and --all-views cannot be combined")
    if args.binja_license is not None:
        license_file = args.binja_license.expanduser().resolve()
        if not license_file.is_file():
            parser.error(f"--binja-license: {license_file} is not a file")
        # Through the environment so render workers and the per-binary
        # processes of folder and APK exports pick it up too.
        os.environ["TOCODE_BINJA_LICENSE"] = str(license_file)
    if (
        args.backend == "auto"
        and args.binary is not None
        and is_binja_database(args.binary)
    ):
        # Only Binary Ninja reads a .bndb: headless when the API is installed,
        # otherwise through a running Binary Ninja.
        args.backend = "binja"
    if args.backend == "binja":
        headless = (
            args.binja_transport in ("auto", "headless")
            and not binja_only
            and args.binary is not None
            and probe_binja_headless(args.binja_dir)
        )
        if args.binja_transport == "headless" and not headless:
            parser.error(
                "--binja-transport headless needs the Binary Ninja Python API and an "
                "input file; pass --binja-dir (or set TOCODE_BINJA_DIR) to the "
                "Binary Ninja install"
            )
        if headless:
            from .backends.binja_headless import headless_problem

            # A personal license ships the API but refuses headless use; auto
            # then exports through a running Binary Ninja instead.
            problem = headless_problem(args.binja_dir)
            if problem is not None:
                if args.binja_transport == "headless":
                    print(f"tocode: {problem}", file=sys.stderr)
                    return 1
                progress.log(
                    f"Binary Ninja headless unavailable ({problem}); "
                    "using a running Binary Ninja"
                )
                headless = False
        if not headless:
            # A live Binary Ninja view (MCP or RPyc) exports one binary at a time.
            if args.binary is not None and args.binary.is_dir():
                parser.error(
                    "--backend binja needs the Binary Ninja Python API (headless) "
                    "for folder input; use ida, r2, or angr otherwise"
                )
            if args.binary is not None and is_apk_input(args.binary):
                parser.error(
                    "--backend binja needs the Binary Ninja Python API (headless) "
                    "for APK input; native libraries use ida, r2, or angr otherwise"
                )
            if (
                args.binary is not None
                and not args.as_native
                and args.binary.is_file()
                and is_dotnet_input(args.binary)
            ):
                parser.error(
                    "--backend binja needs the Binary Ninja Python API (headless) "
                    "for .NET input; native code uses ida, r2, or angr (or pass "
                    "--as-native)"
                )
            return _run_binja(args, progress, parser, argv)
        # Headless: the regular file pipeline below, with Binary Ninja in-process.

    if args.binary is None:
        parser.error("the following arguments are required: binary")
    binary = args.binary.expanduser().resolve()
    if not binary.exists():
        parser.error(f"binary not found: {binary}")
    args.out_dir = (
        args.out_dir.expanduser().resolve() if args.out_dir is not None else None
    )
    if binary.is_dir():
        return _run_folder(binary, args=args, progress=progress)
    if args.parallel_files is not None:
        parser.error("--parallel-files applies to folder input")
    if is_apk_input(binary):
        return _run_apk(binary, args=args, progress=progress, parser=parser)
    if not args.as_native and binary.is_file() and is_dotnet_input(binary):
        return _run_dotnet(binary, args=args, progress=progress)
    log_root = (
        args.out_dir
        if args.out_dir is not None
        else binary.parent / default_output_name(binary)
    )
    progress.set_log_path(log_root / "tocode.log")
    started = time.monotonic()
    try:
        if not binary.is_file():
            parser.error(f"input must be a regular file: {binary}")
        summary = _run_one(binary, args=args, progress=progress, out_dir=args.out_dir)
    except KeyboardInterrupt:
        progress.log("tocode: interrupted; progress saved if checkpointing had started")
        print("tocode: interrupted; rerun the same command to resume", file=sys.stderr)
        return 130
    except ToCodeError as exc:
        progress.log(f"tocode: {exc}")
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"Project: {summary.root_dir}")
        print(
            f"Summary: functions={summary.function_count} "
            f"clusters={summary.cluster_count} failures={len(summary.failed_functions)}"
        )
        print(f"Exported in {_format_duration(time.monotonic() - started)}")
    return 0


def _run_apk(
    binary: Path,
    *,
    args: argparse.Namespace,
    progress: Progress,
    parser: argparse.ArgumentParser,
) -> int:
    if not binary.is_file():
        parser.error(f"input must be a regular file: {binary}")
    options = ApkExportOptions(
        out_dir=args.out_dir,
        jobs=args.jobs,
        native=not args.no_native,
        splits=not args.no_splits,
        native_options=_native_options(args),
    )
    started = time.monotonic()
    try:
        summary = export_apk(binary, options=options, progress=progress)
    except KeyboardInterrupt:
        progress.log("tocode: interrupted")
        print("tocode: interrupted", file=sys.stderr)
        return 130
    except ToCodeError as exc:
        progress.log(f"tocode: {exc}")
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"Project: {summary.root_dir}")
        print(
            f"Summary: package={summary.package} classes={summary.class_count} "
            f"methods={summary.method_count} failures={len(summary.failed_classes)} "
            f"natives={summary.native_done}/{summary.native_total}"
        )
        for line in summary.native_errors:
            print(f"native: {line}", file=sys.stderr)
        print(f"Exported in {_format_duration(time.monotonic() - started)}")
    return 0


def _native_options(args: argparse.Namespace) -> NativeOptions:
    return NativeOptions(
        backend=args.backend,
        analysis_command=args.analysis,
        idadir=args.idadir,
        ida_domain_path=args.ida_domain_path,
        purge_cache=args.purge_cache,
        jobs=args.jobs,
        tree=args.tree,
        entropy=args.entropy,
        binja_dir=args.binja_dir,
    )


def _setup_dotnet() -> int:
    from .backends import dotnet_libs

    try:
        dotnet_libs.setup(log=lambda message: print(message, file=sys.stderr))
    except ToCodeError as exc:
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    return 0


def _run_dotnet(binary: Path, *, args: argparse.Namespace, progress: Progress) -> int:
    from .backends import dotnet_libs
    from .dotnet import DotnetExportOptions, export_dotnet

    try:
        dotnet_libs.ensure_libraries(
            interactive=sys.stdin.isatty() and sys.stderr.isatty(),
            ask=_ask_on_stderr,
            log=progress.log,
        )
    except ToCodeError as exc:
        print(f"tocode: {exc}", file=sys.stderr)
        return 1

    options = DotnetExportOptions(
        out_dir=args.out_dir,
        jobs=args.jobs,
        native=not args.no_native,
        include_framework=args.include_framework,
        native_options=_native_options(args),
    )
    started = time.monotonic()
    try:
        summary = export_dotnet(binary, options=options, progress=progress)
    except KeyboardInterrupt:
        progress.log("tocode: interrupted")
        print("tocode: interrupted", file=sys.stderr)
        return 130
    except ToCodeError as exc:
        progress.log(f"tocode: {exc}")
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"Project: {summary.root_dir}")
        print(
            f"Summary: kind={summary.kind} assemblies={len(summary.assemblies)} "
            f"types={summary.type_count} methods={summary.method_count} "
            f"failures={len(summary.failed_types)} "
            f"natives={summary.native_done}/{summary.native_total}"
        )
        for line in summary.native_errors:
            print(f"native: {line}", file=sys.stderr)
        print(f"Exported in {_format_duration(time.monotonic() - started)}")
    return 0


def _run_folder(folder: Path, *, args: argparse.Namespace, progress: Progress) -> int:
    from .folder import FolderOptions, export_folder, format_plan

    def ensure_dotnet() -> bool:
        from .backends import dotnet_libs

        try:
            dotnet_libs.ensure_libraries(
                interactive=sys.stdin.isatty() and sys.stderr.isatty(),
                ask=_ask_on_stderr,
                log=progress.log,
            )
        except ToCodeError as exc:
            progress.log(f"tocode: .NET assemblies will not be decompiled: {exc}")
            return False
        return True

    options = FolderOptions(
        out_dir=args.out_dir,
        only=list(args.only),
        exclude=list(args.exclude),
        include_framework=args.include_framework,
        native=not args.no_native,
        managed=not args.no_managed,
        ensure_dotnet=ensure_dotnet,
        arch=args.arch,
        plan=args.plan,
        links_only=args.links_only,
        restart=args.restart,
        jobs=args.jobs,
        parallel_files=args.parallel_files,
        native_options=_native_options(args),
    )
    try:
        summary = export_folder(folder, options=options, progress=progress)
    except KeyboardInterrupt:
        print("tocode: interrupted; rerun the same command to resume", file=sys.stderr)
        return 130
    except ToCodeError as exc:
        progress.log(f"tocode: {exc}")
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    if summary.plan_only:
        print(format_plan(summary))
        return 0
    if not args.quiet:
        print(f"Project: {summary.root_dir}")
        print(
            f"Summary: binaries={summary.binaries} exported={summary.done} "
            f"failed={summary.failed} library_refs={summary.edges} "
            f"imports={summary.links} bound_in_folder={summary.bound} "
            f"mapped_to_functions={summary.mapped}"
        )
        for line in summary.errors:
            print(f"failed: {line}", file=sys.stderr)
        print(f"Exported in {_format_duration(summary.seconds)}")
    return 130 if summary.interrupted else 0


def _ask_on_stderr(prompt: str) -> str:
    print(prompt, end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if not line:  # end of input is a "no", never an implicit yes
        raise EOFError
    return line


def _format_duration(seconds: float) -> str:
    if seconds >= 60:
        minutes, secs = divmod(int(round(seconds)), 60)
        return f"{minutes}m {secs}s"
    return f"{seconds:.1f}s"


def _run_one(
    binary: Path, *, args: argparse.Namespace, progress: Progress, out_dir: Path | None
):
    with create_analyzer(
        binary,
        backend=args.backend,
        analysis_command=args.analysis,
        progress=progress,
        idadir=args.idadir,
        ida_domain_path=args.ida_domain_path,
        purge_cache=args.purge_cache,
        binja_host=args.binja_host,
        binja_port=args.binja_port,
        binja_dir=args.binja_dir,
    ) as analyzer:
        return export_binary(
            analyzer,
            out_dir=out_dir,
            progress=progress,
            jobs=args.jobs,
            tree=args.tree,
            entropy=args.entropy,
            restart=args.restart,
        )


def _run_binja(
    args: argparse.Namespace,
    progress: Progress,
    parser: argparse.ArgumentParser,
    argv: list[str] | None,
) -> int:
    if args.binja_transport in ("auto", "mcp"):
        from .backends import binja_mcp

        url = args.binja_mcp_url or binja_mcp.mcp_url()
        try:
            client = binja_mcp.connect(url)
        except ToCodeError as exc:
            if args.binja_transport == "mcp":
                print(f"tocode: {exc}", file=sys.stderr)
                return 1
            progress.log(
                f"Binary Ninja MCP not reachable at {url} ({exc}); "
                f"trying binja-headless at {args.binja_host}:{args.binja_port}"
            )
        else:
            return _run_binja_mcp(client, args, progress, argv)
    # Drive a running Binary Ninja over binja-headless. One connection is shared
    # across every exported view; injected views never own it (their session
    # close() leaves it alone), so the CLI closes it once at the end.
    from .backends import binja as binja_backend

    out_dir = args.out_dir.expanduser().resolve() if args.out_dir is not None else None
    started = time.monotonic()
    try:
        conn = binja_backend.connect_rpyc(args.binja_host, args.binja_port)
    except ToCodeError as exc:
        print(f"tocode: {exc}", file=sys.stderr)
        return 1

    try:
        if args.list_binja:
            _print_binja_views(binja_backend.open_views(conn), binja_backend)
            return 0

        bn = binja_backend.binaryninja_module(conn)
        try:
            targets = _select_binja_views(args, conn, binja_backend, bn)
        except ToCodeError as exc:
            print(f"tocode: {exc}", file=sys.stderr)
            return 1
        if not targets:
            print("tocode: no Binary Ninja views to export", file=sys.stderr)
            return 1

        multi = args.all_views or len(targets) > 1
        for view in targets:
            summary = _export_binja_view(
                view,
                bn,
                args=args,
                progress=progress,
                out_dir=out_dir,
                multi=multi,
                argv=argv,
            )
            if not args.quiet:
                print(f"Project: {summary.root_dir}")
                print(
                    f"Summary: functions={summary.function_count} "
                    f"clusters={summary.cluster_count} "
                    f"failures={len(summary.failed_functions)}"
                )
    except KeyboardInterrupt:
        progress.log("tocode: interrupted; progress saved if checkpointing had started")
        print("tocode: interrupted; rerun the same command to resume", file=sys.stderr)
        return 130
    except ToCodeError as exc:
        progress.log(f"tocode: {exc}")
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    if not args.quiet:
        print(
            f"Exported {len(targets)} view(s) in "
            f"{_format_duration(time.monotonic() - started)}"
        )
    return 0


def _run_binja_mcp(
    client, args: argparse.Namespace, progress: Progress, argv: list[str] | None
) -> int:
    """Export through Binary Ninja's built-in MCP server (Binary Ninja 6+)."""
    from .backends import binja_mcp

    out_dir = args.out_dir.expanduser().resolve() if args.out_dir is not None else None
    started = time.monotonic()
    try:
        views = binja_mcp.list_views(client)
        if args.list_binja:
            if not views:
                print("No binary views are open in Binary Ninja.")
            else:
                print(f"Open binary views ({len(views)}, via MCP at {client.url}):")
                for index, view in enumerate(views):
                    print(f"  [{index}] {view.describe()}")
            return 0
        targets: list = []
        if args.all_views:
            targets = list(views)
        elif args.binja_view is not None:
            if not 0 <= args.binja_view < len(views):
                upper = len(views) - 1
                raise ToCodeError(
                    f"--binja-view {args.binja_view} is out of range (open views: "
                    f"0..{upper if upper >= 0 else 'none'}); run --list-binja"
                )
            targets = [views[args.binja_view]]
        elif args.binary is not None:
            path = args.binary.expanduser().resolve()
            found = binja_mcp.find_view_for_path(views, path)
            if found is None:
                progress.log(f"Opening {path} in Binary Ninja (it stays open there)")
                found = binja_mcp.open_path(client, path)
            targets = [found]
        else:
            active = next((view for view in views if view.active), None)
            if active is None:
                raise ToCodeError(
                    "Binary Ninja has no active binary view for MCP; run --list-binja "
                    "and pass --binja-view N, --all-views, or a binary path"
                )
            targets = [active]
        if not targets:
            print("tocode: no Binary Ninja views to export", file=sys.stderr)
            return 1
        multi = args.all_views or len(targets) > 1
        for view in targets:
            source = Path(view.path or "binaryview")
            if multi:
                parent = out_dir if out_dir is not None else Path.cwd()
                view_out: Path | None = parent / default_output_name(source)
            else:
                view_out = out_dir
            log_root = (
                view_out
                if view_out is not None
                else source.parent / default_output_name(source)
            )
            progress.set_log_path(log_root / "tocode.log")
            progress.log(
                f"Command: {' '.join(sys.argv if argv is None else ['tocode', *argv])}"
            )
            progress.log(f"Exporting Binary Ninja view {view.describe()} over MCP")
            session = binja_mcp.BinjaMcpSession(client, view)
            with create_analyzer(
                source, backend="binja", progress=progress, session=session
            ) as analyzer:
                summary = export_binary(
                    analyzer,
                    out_dir=view_out,
                    progress=progress,
                    jobs=args.jobs,
                    tree=args.tree,
                    entropy=args.entropy,
                    restart=args.restart,
                )
            if not args.quiet:
                print(f"Project: {summary.root_dir}")
                print(
                    f"Summary: functions={summary.function_count} "
                    f"clusters={summary.cluster_count} failures={len(summary.failed_functions)}"
                )
    except KeyboardInterrupt:
        progress.log("tocode: interrupted; progress saved if checkpointing had started")
        print("tocode: interrupted; rerun the same command to resume", file=sys.stderr)
        return 130
    except ToCodeError as exc:
        progress.log(f"tocode: {exc}")
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(
            f"Exported {len(targets)} view(s) in {_format_duration(time.monotonic() - started)}"
        )
    return 0


def _select_binja_views(args: argparse.Namespace, conn, binja_backend, bn) -> list:
    if args.all_views:
        return binja_backend.open_views(conn)
    if args.binja_view is not None:
        views = binja_backend.open_views(conn)
        if args.binja_view < 0 or args.binja_view >= len(views):
            upper = len(views) - 1
            raise ToCodeError(
                f"--binja-view {args.binja_view} is out of range "
                f"(open views: 0..{upper if upper >= 0 else 'none'}); run --list-binja"
            )
        return [views[args.binja_view]]
    view = binja_backend.focused_view(conn)
    if view is None and args.binary is not None:
        view = bn.load(str(args.binary.expanduser().resolve()))
    if view is None:
        raise ToCodeError(
            "no focused BinaryView in Binary Ninja; open one, pass a binary path "
            "to load, or use --list-binja / --all-views"
        )
    return [view]


def _export_binja_view(
    view,
    bn,
    *,
    args: argparse.Namespace,
    progress: Progress,
    out_dir: Path | None,
    multi: bool,
    argv: list[str] | None,
):
    from .backends import binja as binja_backend

    source = Path(binja_backend.view_source_path(view) or "binaryview")
    if multi:
        parent = out_dir if out_dir is not None else Path.cwd()
        view_out: Path | None = parent / default_output_name(source)
    else:
        view_out = out_dir
    log_root = (
        view_out
        if view_out is not None
        else source.parent / default_output_name(source)
    )
    progress.set_log_path(log_root / "tocode.log")
    progress.log(
        f"Command: {' '.join(sys.argv if argv is None else ['tocode', *argv])}"
    )
    progress.log(f"Exporting Binary Ninja view {binja_backend.describe_view(view)}")
    with create_analyzer(
        source,
        backend="binja",
        progress=progress,
        binja_bv=view,
        binja_bn=bn,
    ) as analyzer:
        return export_binary(
            analyzer,
            out_dir=view_out,
            progress=progress,
            jobs=args.jobs,
            tree=args.tree,
            entropy=args.entropy,
            restart=args.restart,
        )


def _print_binja_views(views: list, binja_backend) -> None:
    if not views:
        print("No BinaryViews are open in Binary Ninja.")
        return
    print(f"Open BinaryViews ({len(views)}):")
    for index, view in enumerate(views):
        print(f"  [{index}] {binja_backend.describe_view(view)}")
