"""Edit tools and `sync`: the export follows the database, file by file."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from live_client import ToolError
from live_client import fake_client as _client

SOURCE_SUFFIXES = (".c", ".asm", ".summary")


def _snapshot(root: Path) -> dict[str, str]:
    files = {}
    for path in root.rglob("*"):
        if path.is_file() and ".tocode" not in path.parts:
            files[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return files


def _changed(before: dict[str, str], after: dict[str, str]) -> set[str]:
    return {
        key for key in set(before) | set(after) if before.get(key) != after.get(key)
    }


def _sources(changed: set[str]) -> set[str]:
    return {path for path in changed if path.endswith(SOURCE_SUFFIXES)}


def _source_text(root: Path) -> str:
    return "\n".join(
        path.read_text() for path in sorted((root / "src" / "raw").rglob("*.c"))
    )


def _file_of(root: Path, name: str) -> str:
    index = json.loads((root / "function-index.json").read_text())
    row = next(row for row in index["functions"] if row["name"] == name)
    return Path(row["c"]["path"]).stem


def test_sync_follows_edits_and_touches_only_what_changed(
    export: Path, tmp_path: Path
) -> None:
    with _client(tmp_path, str(export)) as client:
        before = _snapshot(export)
        quiet = client.call("sync")
        assert quiet["rerendered"] == 0 and quiet["files_rewritten"] == []
        assert _sources(_changed(before, _snapshot(export))) == set()

        # A rename reaches the caller's code.
        before = _snapshot(export)
        renamed = client.call("rename", target="helper", name="process_input")
        assert set(renamed["pending_sync"]) == {"0x401000", "0x401080"}
        assert client.call("status")["pending_functions"] == ["0x401000", "0x401080"]
        report = client.call("sync")
        assert report["renamed"] == [
            {"address": "0x401080", "old": "helper", "new": "process_input"}
        ]
        assert report["rerendered"] == 2
        text = _source_text(export)
        assert "process_input();" in text and "helper" not in text
        rows = {
            row["address"]: row
            for row in json.loads((export / "functions.json").read_text())["functions"]
        }
        assert rows["0x401080"]["name"] == "process_input"
        changed = _sources(_changed(before, _snapshot(export)))
        assert changed and all(
            _file_of(export, "process_input") in path for path in changed
        )
        assert client.call("status")["pending_functions"] == []

        # A prototype change re-renders the function and its caller.
        report = client.call(
            "set_type",
            target="process_input",
            c_decl="int process_input(char *line, int len)",
        )
        report = client.call("sync")
        assert report["retyped"] == ["0x401080"]
        assert "int process_input(char* line, int len)" in _source_text(export) or (
            "int process_input(char *line, int len)" in _source_text(export)
        )

        # A redefined struct reaches the function whose code uses it.
        client.call("declare_types", c_source="struct point { int x; int y; };")
        report = client.call("sync")
        assert "point" in report["types_modified"]
        assert "struct point *p; /* point has 2 fields */" in _source_text(export)
        before = _snapshot(export)
        client.call("declare_types", c_source="struct point { int x; int y; int z; };")
        report = client.call("sync")
        assert [item["name"] for item in report["changed"]] == ["process_input"]
        assert "point has 3 fields" in _source_text(export)
        assert "int z;" in (export / "include" / "sample.types.h").read_text()
        assert "types.json" in _changed(before, _snapshot(export))

        # Comments show up in the decompiled code.
        client.call(
            "set_comment",
            address="process_input",
            text="reads one line",
            kind="function",
        )
        client.call("sync")
        assert "// reads one line" in _source_text(export)


def test_new_functions_land_next_to_their_caller(export: Path, tmp_path: Path) -> None:
    with _client(tmp_path, str(export)) as client:
        home = _file_of(export, "helper")
        client.call("define_function", address="0x4010c0")
        report = client.call("sync")
        assert report["added"] == [{"address": "0x4010c0", "name": "sub_4010c0"}]
        assert _file_of(export, "sub_4010c0") == home  # helper calls it
        assert "sub_4010c0();" in _source_text(export)
        assert client.call("function", target="sub_4010c0")["export"]["c"].endswith(
            tuple(f"-{n}" for n in range(1, 500))
        )

        client.call("undefine", address="0x4010c0")
        report = client.call("sync")
        assert report["removed"] == ["0x4010c0"]
        assert "sub_4010c0" not in _source_text(export)


def test_data_renames_eval_touch_and_full_mode(export: Path, tmp_path: Path) -> None:
    with _client(tmp_path, str(export)) as client:
        renamed = client.call("rename", target="0x404000", name="g_counter")
        assert renamed["kind"] == "data" and renamed["pending_sync"] == ["0x401000"]
        client.call("sync")
        assert (
            client.call("lookup", name="g_counter")["matches"][0]["address"]
            == "0x404000"
        )

        touched = client.call("eval", code="touch('main')")
        assert touched["touched"] == ["0x401000"]
        assert client.call("sync")["rerendered"] == 1

        full = client.call("sync", mode="full")
        assert (
            full["rerendered"] == 2 and full["files_rewritten"] == []
        )  # nothing differs

        forced = client.call("sync", addresses=["helper"])
        assert forced["rerendered"] == 1


def test_edits_report_backend_errors(export: Path, tmp_path: Path) -> None:
    with _client(tmp_path, str(export)) as client:
        with pytest.raises(ToolError, match="not a valid name"):
            client.call("rename", target="main", name="not valid")
        with pytest.raises(ToolError, match="could not parse"):
            client.call("declare_types", c_source="this is not C")
        with pytest.raises(ToolError, match="no local variable"):
            client.call("rename_local", function="main", old="nope", new="x")
        client.call("rename_local", function="main", old="argc", new="count")
        client.call("sync")
        assert "int32_t main(int32_t count)" in _source_text(export)


def test_sync_updates_exports_made_before_sync_state(
    export: Path, tmp_path: Path
) -> None:
    shutil.rmtree(export / ".tocode" / "sync")  # an export from an older ToCode
    with _client(tmp_path, str(export)) as client:
        before = _snapshot(export)
        assert client.call("sync")["files_rewritten"] == []
        client.call("rename", target="helper", name="worker")
        report = client.call("sync")
        assert report["rerendered"] == 2
        assert "worker();" in _source_text(export)
        changed = _sources(_changed(before, _snapshot(export)))
        assert changed and all(_file_of(export, "worker") in path for path in changed)
    assert (export / ".tocode" / "sync" / "manifest.json").is_file()


def test_sync_saves_the_database_after_edits(export: Path, tmp_path: Path) -> None:
    database = export / "sample.bndb"
    stamp = database.stat().st_mtime_ns
    with _client(tmp_path, str(export)) as client:
        client.call("rename", target="helper", name="saved_helper")
        report = client.call("sync")
        assert report["database"]["saved"] is True
    assert database.stat().st_mtime_ns >= stamp
    log = (tmp_path / "binja.log").read_text()
    assert "save_auto_snapshot sample.bndb" in log


def test_export_tool_creates_a_project_for_a_plain_binary(
    tmp_path: Path, export: Path
) -> None:
    binary = tmp_path / "other.elf"
    binary.write_bytes(b"\x7fELF" + bytes(range(32)))
    with _client(tmp_path) as client:
        session = client.call("open", path=str(binary), backend="binja")["session"]
        with pytest.raises(ToolError, match="no export folder"):
            client.call("sync", session=session)
        made = client.call("export", session=session)
        assert made["functions"] == 2
        assert Path(made["export_dir"]).name == "other_decompiler"
        assert client.call("sync", session=session)["rerendered"] == 0
    assert os.path.isdir(tmp_path / "other_decompiler" / ".tocode" / "sync")
