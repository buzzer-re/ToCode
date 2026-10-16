"""`tocode mcp` over a folder export: one server, a session per binary."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest

from live_client import FAKE_DIR, ToolError, drop_binaryninja_modules, fake_client
from test_folder import _app
from tocode.apk_native import NativeOptions
from tocode.folder import FolderOptions, export_folder
from tocode.progress import Progress


@pytest.fixture
def folder_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    drop_binaryninja_modules()
    if importlib.util.find_spec("binaryninja") is not None:
        pytest.skip("a real Binary Ninja API is importable in this environment")
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.delenv("TOCODE_DISABLE_BINJA_HEADLESS", raising=False)
    monkeypatch.setenv("TOCODE_BINJA_DIR", str(FAKE_DIR))
    monkeypatch.setenv("TOCODE_BINJA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("TOCODE_FUNCTION_TIMEOUT_SECONDS", "0")
    root = _app(tmp_path / "app")
    out = tmp_path / "app_decompiled"
    summary = export_folder(
        root,
        options=FolderOptions(
            out_dir=out,
            parallel_files=1,
            native_options=NativeOptions(backend="binja", binja_dir=FAKE_DIR),
        ),
        progress=Progress(enabled=False),
    )
    assert summary.failed == 0, summary.errors
    drop_binaryninja_modules()
    return out


def test_folder_binaries_open_on_demand_and_sync_refreshes_links(
    folder_export: Path, tmp_path: Path
) -> None:
    with fake_client(tmp_path, "--max-sessions", "2", str(folder_export)) as client:
        listed = client.call("sessions")
        folder = listed["folders"][0]
        relpaths = {row["relpath"] for row in folder["binaries"]}
        assert {"bin/app", "lib/libfoo.so.1", "lib/libbar.so"} <= relpaths
        assert listed["sessions"] == []  # nothing opened until asked

        app = client.call("info", session="bin/app")
        assert app["relpath"] == "bin/app" and app["export_dir"].endswith("bin/app")
        assert (
            client.call("info", session="lib/libfoo.so.1")["relpath"]
            == "lib/libfoo.so.1"
        )
        # Folder-qualified names work too.
        assert (
            client.call("functions", session=f"{folder['session']}:bin/app")["total"]
            == 3
        )

        client.call("rename", session="bin/app", target="helper", name="parse_args")
        report = client.call("sync", session="bin/app")
        assert report["renamed"][0]["new"] == "parse_args"
        assert report["folder_links"]["refreshed"] is True
        source = "\n".join(
            path.read_text()
            for path in (folder_export / "bin" / "app" / "src" / "raw").rglob("*.c")
        )
        assert "parse_args();" in source
        assert json.loads((folder_export / "mappings.json").read_text())["links"]

        # A third binary with --max-sessions 2: the least recently used one
        # closes and reopens on demand.
        client.call("info", session="lib/libbar.so")
        alive = {
            row["relpath"]: row["alive"] for row in client.call("sessions")["sessions"]
        }
        assert sum(alive.values()) == 2
        assert client.call("info", session="bin/app")["relpath"] == "bin/app"

        with pytest.raises(ToolError, match="unknown session"):
            client.call("info", session="lib/missing.so")
