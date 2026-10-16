"""`tocode sync`, `tocode skill install`, and MCP client registration."""

from __future__ import annotations

import argparse
from importlib import resources
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

from ..errors import ToCodeError

SKILL_NAME = "tocode"


# --------------------------------------------------------------------------
# tocode sync
# --------------------------------------------------------------------------


def sync_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="tocode sync",
        description="Update a ToCode export from its database (after editing it in IDA or Binary Ninja).",
    )
    parser.add_argument("export", type=Path, help="The export folder.")
    parser.add_argument(
        "--database",
        type=Path,
        default=None,
        help="Database to read instead of the export's own copy.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Re-render every function (edits made outside ToCode are not tracked).",
    )
    parser.add_argument("--binja-dir", type=Path, default=None)
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args(argv)

    from .targets import Target, resolve
    from .worker import LiveSession

    try:
        target = resolve(args.export, database=args.database)
        if not isinstance(target, Target) or target.export_dir is None:
            raise ToCodeError(f"{args.export} is not a single-binary export")
        live = LiveSession(
            target,
            log_path=target.export_dir / "tocode.log",
            binja_dir=str(args.binja_dir) if args.binja_dir else None,
        )
        try:
            report = live.dispatch("sync", {"mode": "full" if args.full else "auto"})
        finally:
            live.close(save=False)
    except ToCodeError as exc:
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(
            f"Synced {report['export_dir']}: {report['rerendered']} functions re-rendered, "
            f"{len(report['changed'])} changed, {len(report['added'])} added, "
            f"{len(report['removed'])} removed, {len(report['files_rewritten'])} files rewritten "
            f"in {report['seconds']}s"
        )
    return 0


# --------------------------------------------------------------------------
# MCP client registration
# --------------------------------------------------------------------------


def server_command() -> list[str]:
    """How MCP clients should start the server."""
    found = shutil.which("tocode")
    if found:
        return [found, "mcp"]
    return [sys.executable, "-m", "tocode", "mcp"]


def config_text() -> str:
    command = server_command()
    head, rest = command[0], command[1:]
    json_block = json.dumps(
        {"mcpServers": {"tocode": {"command": head, "args": rest}}}, indent=2
    )
    toml_args = ", ".join(json.dumps(item) for item in rest)
    return "\n".join(
        [
            "Claude Code:",
            f"  claude mcp add --scope user tocode -- {' '.join(command)}",
            "",
            "Codex (~/.codex/config.toml):",
            "  [mcp_servers.tocode]",
            f"  command = {json.dumps(head)}",
            f"  args = [{toml_args}]",
            "",
            "Other clients (Claude Desktop, Cursor, VS Code, ...):",
            *("  " + line for line in json_block.splitlines()),
        ]
    )


def install_clients(clients: list[str]) -> list[str]:
    done: list[str] = []
    command = server_command()
    if "claude" in clients:
        claude = shutil.which("claude")
        if claude is None:
            raise ToCodeError(
                "the `claude` CLI was not found; run the command from `tocode mcp --config`"
            )
        subprocess.run(
            [claude, "mcp", "remove", "--scope", "user", "tocode"],
            capture_output=True,
            check=False,
        )
        result = subprocess.run(
            [claude, "mcp", "add", "--scope", "user", "tocode", "--", *command],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise ToCodeError(
                f"claude mcp add failed: {(result.stderr or result.stdout).strip()}"
            )
        done.append(
            f"Claude Code: registered `tocode` (user scope) -> {' '.join(command)}"
        )
    if "codex" in clients:
        path = Path.home() / ".codex" / "config.toml"
        done.append(f"Codex: {_write_codex_config(path, command)} {path}")
    return done


def _write_codex_config(path: Path, command: list[str]) -> str:
    block = [
        "[mcp_servers.tocode]",
        f"command = {json.dumps(command[0])}",
        f"args = [{', '.join(json.dumps(item) for item in command[1:])}]",
    ]
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == "[mcp_servers.tocode]"),
        None,
    )
    if start is None:
        updated = lines + ([""] if lines and lines[-1].strip() else []) + block
        action = "added [mcp_servers.tocode] to"
    else:
        end = next(
            (
                i
                for i in range(start + 1, len(lines))
                if lines[i].lstrip().startswith("[")
            ),
            len(lines),
        )
        updated = lines[:start] + block + lines[end:]
        action = "updated [mcp_servers.tocode] in"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    return action


# --------------------------------------------------------------------------
# tocode skill install
# --------------------------------------------------------------------------


def skill_destinations(agent: str, *, project: bool, path: Path | None) -> list[Path]:
    if path is not None:
        return [path.expanduser().resolve() / SKILL_NAME]
    base = Path.cwd() if project else Path.home()
    targets: list[Path] = []
    if agent in ("claude", "all"):
        targets.append(base / ".claude" / "skills" / SKILL_NAME)
    if agent in ("codex", "all"):
        # The open Agent Skills location Codex (and other agents) read.
        targets.append(base / ".agents" / "skills" / SKILL_NAME)
    return targets


def _skill_files() -> dict[str, str]:
    root = resources.files("tocode") / "skill"
    files: dict[str, str] = {}

    def walk(node: Any, prefix: str) -> None:
        for child in node.iterdir():
            if child.is_dir():
                walk(child, f"{prefix}{child.name}/")
            elif child.name.endswith(".md"):
                files[f"{prefix}{child.name}"] = child.read_text(encoding="utf-8")

    walk(root, "")
    if "SKILL.md" not in files:
        raise ToCodeError("the ToCode skill is missing from this installation")
    return files


def install_skill(destinations: list[Path]) -> list[Path]:
    files = _skill_files()
    for destination in destinations:
        if destination.exists():
            shutil.rmtree(destination)
        for relative, text in files.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
    return destinations


def skill_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="tocode skill", description="Install the ToCode agent skill."
    )
    sub = parser.add_subparsers(dest="action", required=True)
    install = sub.add_parser(
        "install", help="Copy the skill where agents load skills from."
    )
    install.add_argument(
        "--agent",
        choices=("claude", "codex", "all"),
        default="all",
        help="claude: .claude/skills; codex: .agents/skills (Codex and other agents); all: both (default).",
    )
    install.add_argument(
        "--project",
        action="store_true",
        help="Install into the current folder instead of your home folder.",
    )
    install.add_argument(
        "--path",
        type=Path,
        default=None,
        help="Install into PATH/tocode instead (any other agent).",
    )
    sub.add_parser("show", help="Print SKILL.md.")
    args = parser.parse_args(argv)
    try:
        if args.action == "show":
            print(_skill_files()["SKILL.md"])
            return 0
        for path in install_skill(
            skill_destinations(args.agent, project=args.project, path=args.path)
        ):
            print(f"Installed the ToCode skill to {path}")
    except ToCodeError as exc:
        print(f"tocode: {exc}", file=sys.stderr)
        return 1
    return 0
