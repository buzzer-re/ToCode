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


def build_parser() -> argparse.ArgumentParser:
    default_backend = os.environ.get("TOCODE_BACKEND", "auto").strip().lower()
    if default_backend not in {"auto", "ida", "r2", "angr"}:
        default_backend = "auto"
    parser = argparse.ArgumentParser(
        prog="tocode",
        description="Export a compiled binary into a source-like reverse-engineering project.",
    )
    parser.add_argument("binary", type=Path, help="Input binary to export")
    parser.add_argument(
        "-o",
        "--out-dir",
        type=Path,
        default=None,
        help="Output project directory.",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "ida", "r2", "angr"),
        default=default_backend,
        help="Decompiler backend: auto prefers IDA, then r2, then angr as a last-resort fallback (default: TOCODE_BACKEND or auto).",
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
    progress.log(
        f"Command: {' '.join(sys.argv if argv is None else ['tocode', *argv])}"
    )
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
