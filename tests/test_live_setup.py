"""The skill, MCP client registration, and `tocode sync` from the command line."""

from __future__ import annotations

from importlib import resources
import json
from pathlib import Path
import re

import pytest

from tocode import cli
from tocode.live import setup
from tocode.live.tools import build_tools, render_reference

SKILL = resources.files("tocode") / "skill"


def test_tools_reference_is_generated_from_the_tool_table() -> None:
    # Regenerate: python -m tocode.live.tools > src/tocode/skill/references/tools.md
    reference = (SKILL / "references" / "tools.md").read_text(encoding="utf-8")
    assert reference == render_reference()
    documented = set(re.findall(r"^### `(\w+)`", reference, re.M))
    assert documented == {tool.name for tool in build_tools()}


def test_skill_is_a_valid_agent_skill() -> None:
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    front = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert front is not None
    fields = dict(line.split(": ", 1) for line in front.group(1).splitlines())
    assert fields["name"] == "tocode"
    assert 100 < len(fields["description"]) <= 1536
    assert len(text.splitlines()) < 500
    for link in re.findall(r"\]\((references/[\w.]+)\)", text):
        assert (SKILL / link).is_file(), link


def test_skill_install_places_it_for_every_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert cli.main(["skill", "install"]) == 0
    for base in (".claude", ".agents"):
        installed = tmp_path / "home" / base / "skills" / "tocode"
        assert (installed / "SKILL.md").is_file()
        assert (installed / "references" / "eval.md").is_file()
    assert capsys.readouterr().out.count("Installed the ToCode skill") == 2

    monkeypatch.chdir(tmp_path)
    assert cli.main(["skill", "install", "--agent", "claude", "--project"]) == 0
    assert (tmp_path / ".claude" / "skills" / "tocode" / "SKILL.md").is_file()
    assert not (tmp_path / ".agents").exists()

    assert cli.main(["skill", "install", "--path", str(tmp_path / "custom")]) == 0
    assert (tmp_path / "custom" / "tocode" / "SKILL.md").is_file()


def test_codex_config_is_added_then_updated_in_place(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text('model = "x"\n\n[mcp_servers.other]\ncommand = "o"\n')
    setup._write_codex_config(config, ["/bin/tocode", "mcp"])
    first = config.read_text()
    assert '[mcp_servers.tocode]\ncommand = "/bin/tocode"\nargs = ["mcp"]' in first
    assert '[mcp_servers.other]\ncommand = "o"' in first

    setup._write_codex_config(config, ["/new/tocode", "mcp"])
    second = config.read_text()
    assert second.count("[mcp_servers.tocode]") == 1
    assert 'command = "/new/tocode"' in second and "/bin/tocode" not in second
    assert 'model = "x"' in second and "[mcp_servers.other]" in second


def test_mcp_config_prints_every_client(capsys) -> None:
    assert cli.main(["mcp", "--config"]) == 0
    out = capsys.readouterr().out
    assert "claude mcp add --scope user tocode --" in out
    assert "[mcp_servers.tocode]" in out
    assert '"mcpServers"' in out


def test_sync_command_updates_an_export(export: Path, capsys) -> None:
    assert cli.main(["sync", str(export)]) == 0
    assert "0 functions re-rendered" in capsys.readouterr().out
    assert cli.main(["sync", str(export), "--full", "-q"]) == 0
    assert cli.main(["sync", str(export.parent / "nope")]) == 1


def test_subcommand_names_do_not_hide_the_flat_cli(tmp_path: Path, capsys) -> None:
    # A file literally named like a subcommand is still exported with ./name.
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "--parallel-files" in capsys.readouterr().out


CORPUS = Path(__file__).resolve().parents[1] / "eval" / "corpus"
_COMMON = {
    "main",
    "argc",
    "argv",
    "line",
    "value",
    "count",
    "result",
    "error",
    "buffer",
    "length",
    "index",
    "next",
    "name",
    "type",
    "data",
    "size",
}


def _corpus_identifiers() -> set[str]:
    """Names a blind agent must not be told: the benchmark's functions,
    types, enum members, globals, and distinctive field names."""
    found: set[str] = set()
    for path in list(CORPUS.rglob("*.c")) + list(CORPUS.rglob("*.h")):
        text = path.read_text()
        found.update(
            re.findall(r"^\w[\w\s\*]*?\b([a-z_]\w*)\s*\([^;{)]*\)\s*\{", text, re.M)
        )
        found.update(re.findall(r"\b(?:struct|union|enum)\s+(\w+)\s*\{", text))
        for body in re.findall(r"\benum\s+\w*\s*\{([^}]*)\}", text):
            found.update(re.findall(r"\b([A-Z][A-Z0-9_]{2,})\b", body))
        found.update(re.findall(r"^(?:static\s+)?[\w\s\*]+?\b(g_\w+)", text, re.M))
        for body in re.findall(r"\bstruct\s+\w+\s*\{([^}]*)\}", text):
            found.update(
                n for n in re.findall(r"(\w+)\s*(?:\[[^\]]*\])?;", body) if "_" in n
            )
    return {name for name in found if name not in _COMMON and len(name) > 3}


def test_the_skill_never_names_the_benchmarks_answers() -> None:
    """The blind-recovery benchmark is only blind if the skill does not
    contain its programs' identifiers (examples must use other programs)."""
    identifiers = _corpus_identifiers()
    assert {"item_new", "inventory_add", "kv_entry"} <= identifiers
    from tocode.live.server import INSTRUCTIONS

    # Everything an agent is told: the skill, the tool descriptions, and the
    # server's instructions.
    text = "\n".join(
        [path.read_text(encoding="utf-8") for path in Path(str(SKILL)).rglob("*.md")]
        + [json.dumps(tool.schema()) for tool in build_tools()]
        + [INSTRUCTIONS]
    )
    leaked = sorted(
        name for name in identifiers if re.search(rf"\b{re.escape(name)}\b", text)
    )
    assert leaked == []
