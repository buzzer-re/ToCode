"""`tocode mcp` on .NET: the edit log, text edits, targets, and a real session.

The real-session test builds a small C# program and needs the .NET SDK plus
the decompiler libraries; it is skipped without them (CI has neither).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from live_client import LiveClient, ToolError
from tocode.live import targets
from tocode.live.dotnet_edits import EditLog, apply_text_edits


def _fake_live(tmp_path: Path, entries: list[dict]) -> Any:
    log = EditLog(path=tmp_path / "edits.json", entries=entries)
    return SimpleNamespace(
        edits=log,
        session=SimpleNamespace(assemblies=[SimpleNamespace(name="app")]),
    )


def test_text_edits_rename_locals_in_their_method_only(tmp_path: Path) -> None:
    text = "class A\n{\n    void F() { int v1 = 0; }\n    void G() { int v1 = 1; }\n}\n"
    live = _fake_live(
        tmp_path,
        [
            {
                "op": "rename_local",
                "assembly": "app",
                "token": "0x06000001",
                "old": "v1",
                "name": "count",
            }
        ],
    )
    out, ranges = apply_text_edits(
        live, 0, text, {0x06000001: (3, 3), 0x06000002: (4, 4)}, 0
    )
    assert "void F() { int count = 0; }" in out
    assert "void G() { int v1 = 1; }" in out
    assert ranges == {0x06000001: (3, 3), 0x06000002: (4, 4)}


def test_text_edits_insert_comments_and_shift_ranges(tmp_path: Path) -> None:
    header = "// ToCode header\n"
    body = "class A\n{\n    void F() { }\n    void G() { }\n}\n"
    live = _fake_live(
        tmp_path,
        [
            {
                "op": "comment",
                "assembly": "app",
                "token": "0x06000001",
                "text": "first\nsecond",
            },
            {
                "op": "comment",
                "assembly": "app",
                "token": "0x06000002",
                "text": "third",
            },
        ],
    )
    ranges = {0x02000002: (1, 5), 0x06000001: (3, 3), 0x06000002: (4, 4)}
    out, moved = apply_text_edits(live, 0, header + body, ranges, 1)
    lines = out.split("\n")
    assert lines[3:8] == [
        "    // first",
        "    // second",
        "    void F() { }",
        "    // third",
        "    void G() { }",
    ]
    # Ranges stay relative to the body (offset excluded); each member's range
    # now starts at its comment.
    assert moved[0x06000001] == (3, 5)
    assert moved[0x06000002] == (6, 7)
    assert moved[0x02000002] == (1, 8)
    assert lines[moved[0x06000002][1]] == "    void G() { }"  # +offset, 0-based


def test_edit_log_round_trip_and_latest_comment_wins(tmp_path: Path) -> None:
    log = EditLog.open(tmp_path / "missing.json")
    assert log.entries == [] and log.synced == 0
    log.entries = [
        {"op": "comment", "assembly": "app", "token": "0x06000001", "text": "old"},
        {"op": "comment", "assembly": "app", "token": "0x06000001", "text": "new"},
        {"op": "comment", "assembly": "app", "token": "0x06000002", "text": "gone"},
        {"op": "comment", "assembly": "app", "token": "0x06000002", "text": ""},
    ]
    log.synced = 3
    log.save()
    again = EditLog.open(tmp_path / "missing.json")
    assert again.synced == 3 and len(again.entries) == 4
    assert again.comments("app") == {0x06000001: "new"}


def test_a_dotnet_export_opens_with_its_edit_log(tmp_path: Path) -> None:
    binary = tmp_path / "App.dll"
    binary.write_bytes(b"MZ")
    export = tmp_path / "App_decompiler"
    export.mkdir()
    (export / "functions.json").write_text('{"functions": []}')
    (export / "project.json").write_text(
        json.dumps({"binary": str(binary), "backend": "dotnet"})
    )
    target = targets.resolve(export)
    assert isinstance(target, targets.Target)
    assert target.backend == "dotnet" and target.open_path == binary
    assert target.database == export / ".tocode" / "dotnet" / "edits.json"


# -- a real session -------------------------------------------------------------

PROGRAM = """
using System;
using System.Collections.Generic;
using System.Linq;

namespace Demo
{
    internal sealed class Ledger
    {
        private readonly List<int> _entries = new List<int>();
        public int Limit { get; set; } = 100;
        public void Record(int amount) => _entries.Add(amount);
        public int Balance() => _entries.Sum();
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            var ledger = new Ledger();
            ledger.Record(5);
            ledger.Record(7);
            Console.WriteLine($"balance={ledger.Balance()} limit={ledger.Limit}");
            return 0;
        }
    }
}
"""


def _toolchain() -> bool:
    if shutil.which("dotnet") is None:
        return False
    try:
        sdks = subprocess.run(
            ["dotnet", "--list-sdks"], capture_output=True, text=True, timeout=60
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    from tocode.backends import dotnet_libs
    from tocode.backends.dotnet import probe_dotnet

    return bool(sdks.strip()) and probe_dotnet()[0] and dotnet_libs.is_installed()


@pytest.fixture(scope="module")
def dotnet_export(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not _toolchain():
        pytest.skip(
            "needs the .NET SDK, a .NET 9+ runtime, and the decompiler libraries"
        )
    root = tmp_path_factory.mktemp("dotnet")
    project = root / "demo"
    project.mkdir()
    (project / "demo.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
        "<TargetFramework>net9.0</TargetFramework><RollForward>Major</RollForward>"
        "<AssemblyName>demo</AssemblyName><ImplicitUsings>disable</ImplicitUsings>"
        "</PropertyGroup></Project>"
    )
    (project / "Program.cs").write_text(PROGRAM)
    built = subprocess.run(
        [
            "dotnet",
            "build",
            "-c",
            "Release",
            "-o",
            str(root / "out"),
            "-nologo",
            "-v",
            "q",
        ],
        cwd=project,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if built.returncode != 0:
        pytest.skip(f"dotnet build failed here: {built.stdout[-400:]}")
    (root / "out" / "demo.pdb").unlink(missing_ok=True)
    export = root / "demo_decompiler"
    from tocode import cli

    assert cli.main([str(root / "out" / "demo.dll"), "-o", str(export), "-q"]) == 0
    return export


def test_dotnet_session_renames_and_syncs(dotnet_export: Path) -> None:
    raw = dotnet_export / "src" / "raw" / "demo" / "Demo"
    program_before = (raw / "Program.cs").read_bytes()
    with LiveClient(str(dotnet_export)) as client:
        info = client.call("info")
        assert info["backend"] == "dotnet"
        assert "Demo.Ledger::Balance" in {
            row["name"] for row in client.call("functions", kind="app")["items"]
        }
        assert (
            "_entries.Sum()"
            in client.call("decompile", target="Demo.Ledger::Balance")["code"]
        )
        assert "Demo.Program::Main" in [
            r["function"]
            for r in client.call("xrefs", target="Demo.Ledger::Record")["refs"]
        ]
        with pytest.raises(ToolError, match="not available for .NET"):
            client.call("declare_types", c_source="struct x { int a; };")

        # One batch: the method is named by its type's old name.
        batch = client.call(
            "rename_many",
            renames=[
                {"target": "Demo.Ledger", "name": "Account"},
                {"target": "Demo.Ledger::Record", "name": "Deposit"},
            ],
        )
        assert batch["renamed"] == 2 and batch["errors"] == []
        client.call("rename", target="Demo.Account::Limit", name="Ceiling")
        client.call(
            "rename_local", function="Demo.Account::Deposit", old="amount", new="cents"
        )
        many = client.call(
            "rename_many",
            renames=[
                {"target": "Demo.Account::Balance", "name": "Total"},
                {"target": "Nope::x", "name": "y"},
            ],
        )
        assert many["renamed"] == 1 and len(many["errors"]) == 1
        client.call(
            "set_comment", address="Demo.Account::Total", text="Sum of the deposits"
        )
        report = client.call("sync")
        assert report["moved"] == [
            {
                "from": "src/raw/demo/Demo/Ledger.cs",
                "to": "src/raw/demo/Demo/Account.cs",
            }
        ]
        assert set(report["changed"]) == {"Demo.Account", "Demo.Program"}

    account = (raw / "Account.cs").read_text()
    assert not (raw / "Ledger.cs").exists()
    assert "public void Deposit(int cents)" in account
    assert "// Sum of the deposits" in account and "public int Total()" in account
    assert "public int Ceiling" in account
    program = (raw / "Program.cs").read_text()
    assert program != program_before.decode()
    assert "Account" in program and ".Deposit(5)" in program and "Ceiling" in program
    names = {
        row["name"]
        for row in json.loads((dotnet_export / "functions.json").read_text())[
            "functions"
        ]
    }
    assert any("Demo.Account::Deposit" in name for name in names)
    assert (dotnet_export / "patched" / "demo" / "demo.dll").is_file()

    # Reopening replays the log: nothing pending, names already in place.
    with LiveClient(str(dotnet_export)) as client:
        assert client.call("status") == {"pending_types": [], "pending_edits": 0}
        assert (
            client.call("lookup", name="Deposit")["matches"][0]["name"]
            == "Demo.Account::Deposit"
        )
        assert client.call("sync")["files_rewritten"] == []

    # `tocode sync` from the command line opens .NET exports too.
    from tocode import cli

    assert cli.main(["sync", str(dotnet_export)]) == 0
