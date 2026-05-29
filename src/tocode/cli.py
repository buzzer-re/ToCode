from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .analysis import create_analyzer
from .errors import ToCodeError
from .exporter import export_binary
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
    if default_backend not in {"auto", "ida", "r2"}:
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
        choices=("auto", "ida", "r2"),
        default=default_backend,
        help="Decompiler backend: prefer IDA when available, otherwise use r2 (default: TOCODE_BACKEND or auto).",
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
        "--no-tree",
        action="store_true",
        help="Skip Semgrep/tree-sitter friendly source under src/tree.",
    )
    parser.add_argument(
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
    try:
        if not binary.is_file():
            parser.error(f"input must be a regular file: {binary}")
        summary = _run_one(binary, args=args, progress=progress, out_dir=args.out_dir)
    except ToCodeError as exc:
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    print(f"project: {summary.root_dir}")
    print(
        f"summary: functions={summary.function_count} "
        f"clusters={summary.cluster_count} failures={len(summary.failed_functions)}"
    )
    return 0


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
    ) as analyzer:
        return export_binary(
            analyzer,
            out_dir=out_dir,
            progress=progress,
            jobs=args.jobs,
            tree=not args.no_tree,
        )
