"""``tocode mcp``: the stdio MCP server entry point."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any, BinaryIO

from .. import __version__
from ..errors import ToCodeError
from .jsonrpc import McpApp, StdioServer
from .sessions import (
    DEFAULT_CALL_TIMEOUT,
    DEFAULT_IDLE_SECONDS,
    DEFAULT_MAX_SESSIONS,
    SessionManager,
)
from .tools import ToolTable

INSTRUCTIONS = """\
ToCode keeps decompiler sessions (IDA, Binary Ninja, radare2, angr) open and \
syncs them with a ToCode export: a source-like project on disk (src/raw/**/*.c, \
functions.json, types.json, ...).

Start with `open` on an export folder (or a folder export, a binary, a database) \
and pass the returned `session` to the other tools. Read the export's files for \
the big picture; use `decompile`, `function`, `xrefs`, `strings`, `types` for live \
answers. Improve the database with `rename`, `set_type`, `declare_types`, \
`set_comment`, `rename_local`, `set_local_type` (or `eval` for anything else), \
then call `sync` so the export on disk shows the new names and types; `save` \
writes the database. Addresses are hex strings like 0x401000; names work too."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tocode mcp",
        description="Serve live decompiler sessions over MCP (stdio).",
    )
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        default=None,
        help="Optional export folder, folder export, binary, or database to open at start.",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=None,
        help="Database to open for TARGET instead of the export's own copy.",
    )
    parser.add_argument(
        "--backend", choices=("auto", "ida", "binja", "r2", "angr"), default=None
    )
    parser.add_argument(
        "--binja-dir",
        type=Path,
        default=None,
        help="Binary Ninja install folder for its Python API.",
    )
    parser.add_argument(
        "--read-only", action="store_true", help="No edit tools and no eval."
    )
    parser.add_argument("--no-eval", action="store_true", help="No eval tool.")
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=DEFAULT_MAX_SESSIONS,
        help=f"Workers kept alive at once (default {DEFAULT_MAX_SESSIONS}).",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=DEFAULT_IDLE_SECONDS,
        help="Seconds before an idle session is saved and closed (0: never).",
    )
    parser.add_argument(
        "--config",
        action="store_true",
        help="Print how to register this server with MCP clients, then exit.",
    )
    parser.add_argument(
        "--install",
        choices=("claude", "codex", "all"),
        default=None,
        help="Register this server with Claude Code (claude mcp add) and/or Codex (~/.codex/config.toml), then exit.",
    )
    parser.add_argument(
        "--call-timeout",
        type=float,
        default=DEFAULT_CALL_TIMEOUT,
        help="Default seconds per call before a stuck worker is stopped.",
    )
    return parser


def protect_stdout() -> BinaryIO:
    """Keep the real stdout for the protocol; send fd 1 to stderr.

    Backends print to fd 1 (IDA's console, r2's warnings); after this they
    land on stderr and can never corrupt the JSON-RPC stream.
    """
    sys.stdout.flush()
    protocol = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return protocol


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.config or args.install:
        from .setup import config_text, install_clients

        if args.config:
            print(config_text())
            return 0
        clients = ["claude", "codex"] if args.install == "all" else [args.install]
        try:
            for line in install_clients(clients):
                print(line)
        except ToCodeError as exc:
            print(f"tocode: {exc}", file=sys.stderr)
            return 1
        return 0
    protocol_out = protect_stdout()

    def log(message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    worker_options: dict[str, Any] = {
        "binja_dir": str(args.binja_dir) if args.binja_dir else None,
        "allow_eval": not (args.read_only or args.no_eval),
        "allow_edits": not args.read_only,
    }
    manager = SessionManager(
        max_sessions=args.max_sessions,
        idle_seconds=args.idle_timeout,
        call_timeout=args.call_timeout,
        worker_options=worker_options,
        log=log,
    )
    table = ToolTable(
        manager,
        allow_edits=not args.read_only,
        allow_eval=not (args.read_only or args.no_eval),
    )
    if args.target is not None:
        try:
            opened = manager.open(
                str(args.target),
                database=str(args.database) if args.database else None,
                backend=args.backend,
            )
            log(f"tocode mcp: opened {opened.get('session')}")
        except ToCodeError as exc:
            log(f"tocode mcp: could not open {args.target}: {exc}")
    app = McpApp(
        name="tocode",
        version=__version__,
        instructions=INSTRUCTIONS,
        list_tools=table.list,
        call_tool=table.call,
        on_shutdown=manager.shutdown,
    )
    server = StdioServer(app, sys.stdin.buffer, protocol_out, log=log)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        manager.shutdown()
    return 0
