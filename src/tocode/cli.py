from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from .analysis import create_analyzer
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
    parser = argparse.ArgumentParser(
        prog="tocode",
        description="Export a compiled binary into a source-like reverse-engineering project.",
    )
    parser.add_argument(
        "binary",
        type=Path,
        nargs="?",
        default=None,
        help="Input binary to export. Optional for --backend binja, which exports an open Binary Ninja view.",
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
        help="Decompiler backend: auto prefers IDA, then r2, then angr as a last-resort fallback; binja drives Binary Ninja and is opt-in (default: TOCODE_BACKEND or auto).",
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
        help="List the BinaryViews open in Binary Ninja with their index, then exit (binja backend).",
    )
    parser.add_argument(
        "--binja-view",
        type=int,
        default=None,
        metavar="N",
        help="Export the open Binary Ninja view with this index (from --list-binja). Default: the focused view.",
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
        help="Worker sessions for decompilation: positive integer or 'auto' (default: auto).",
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

    binja_only = args.list_binja or args.all_views or args.binja_view is not None
    if args.backend != "binja" and binja_only:
        parser.error(
            "--list-binja, --binja-view, and --all-views require --backend binja"
        )
    if args.binja_view is not None and args.all_views:
        parser.error("--binja-view and --all-views cannot be combined")
    if args.backend == "binja":
        return _run_binja(args, progress, parser, argv)

    if args.binary is None:
        parser.error("the following arguments are required: binary")
    binary = args.binary.expanduser().resolve()
    if not binary.exists():
        parser.error(f"binary not found: {binary}")
    args.out_dir = (
        args.out_dir.expanduser().resolve() if args.out_dir is not None else None
    )
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
