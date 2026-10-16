"""`tocode mcp`: protocol, targets, sessions, and the query tools.

End-to-end tests run the real server in a subprocess against the on-disk fake
Binary Ninja API (`tests/fake_binja`), which spawned workers import like a
real install.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from live_client import ToolError, fake_client as _client
from tocode.live import targets
from tocode.live.jsonrpc import McpApp, StdioServer, ToolCall

# -- transport -----------------------------------------------------------------


def _serve(
    *messages: dict[str, Any], app: McpApp | None = None
) -> list[dict[str, Any]]:
    app = app or McpApp(
        name="t",
        version="1",
        instructions="hi",
        list_tools=lambda: [{"name": "echo"}],
        call_tool=lambda call: {
            "content": [{"type": "text", "text": json.dumps(call.arguments)}]
        },
    )
    reader = io.BytesIO(
        b"".join(json.dumps(m).encode() + b"\n" for m in messages) + b"{bad\n"
    )
    writer = io.BytesIO()
    StdioServer(app, reader, writer).serve_forever()
    return [json.loads(line) for line in writer.getvalue().splitlines()]


def test_initialize_negotiates_the_protocol_version() -> None:
    replies = _serve(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": "1999-01-01"},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 4, "method": "nope"},
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"a": 1}},
        },
    )
    by_id = {reply.get("id"): reply for reply in replies}
    assert by_id[1]["result"]["protocolVersion"] == "2025-06-18"
    assert by_id[1]["result"]["serverInfo"]["name"] == "t"
    assert by_id[2]["result"]["protocolVersion"] == "2025-11-25"  # our latest
    assert by_id[3]["result"]["tools"] == [{"name": "echo"}]
    assert by_id[4]["error"]["code"] == -32601
    assert json.loads(by_id[5]["result"]["content"][0]["text"]) == {"a": 1}
    assert by_id[None]["error"]["code"] == -32700  # the bad line
    assert len(replies) == 6  # the notification got no reply


def test_progress_notifications_carry_the_token() -> None:
    def call_tool(call: ToolCall) -> dict[str, Any]:
        call.progress(1, 2, "half")
        return {"content": []}

    app = McpApp("t", "1", "", list_tools=list, call_tool=call_tool)
    replies = _serve(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "x", "arguments": {}, "_meta": {"progressToken": "p"}},
        },
        app=app,
    )
    note = next(r for r in replies if r.get("method") == "notifications/progress")
    assert note["params"] == {
        "progressToken": "p",
        "progress": 1,
        "total": 2,
        "message": "half",
    }


# -- targets -------------------------------------------------------------------


def test_export_target_uses_the_exports_own_database(
    export: Path, tmp_path: Path
) -> None:
    target = targets.resolve(export)
    assert isinstance(target, targets.Target)
    assert target.database == (export / "sample.bndb").resolve()
    assert target.open_path == target.database and target.backend == "binja"
    assert target.export_dir == export.resolve()

    other = tmp_path / "elsewhere.bndb"
    other.write_text((export / "sample.bndb").read_text())
    chosen = targets.resolve(export, database=other)
    assert isinstance(chosen, targets.Target)
    assert chosen.open_path == other.resolve()  # the agent's choice wins

    # A binary with its default export next to it gets that export attached.
    by_binary = targets.resolve(tmp_path / "sample.elf")
    assert isinstance(by_binary, targets.Target)
    assert by_binary.export_dir == export.resolve()


def test_unexported_folder_is_refused(tmp_path: Path) -> None:
    (tmp_path / "plain").mkdir()
    with pytest.raises(Exception, match="neither a ToCode export"):
        targets.resolve(tmp_path / "plain")


# -- end to end ----------------------------------------------------------------


def test_query_tools_over_a_live_session(export: Path, tmp_path: Path) -> None:
    with _client(tmp_path, str(export)) as client:
        assert client.initialize["serverInfo"]["name"] == "tocode"
        names = {tool["name"] for tool in client.tools()}
        assert {"open", "decompile", "xrefs", "eval", "save"} <= names

        info = client.call("info")
        assert info["backend"] == "binja" and info["session"] == "sample.elf"
        functions = client.call("functions", filter="main|helper")
        assert {row["name"] for row in functions["items"]} == {"main", "helper"}
        main = client.call("function", target="main")
        assert [callee["name"] for callee in main["callees"]][:1] == ["helper"]
        assert main["export"]["c"].startswith("src/raw/")
        code = client.call("decompile", target="0x401000")
        assert code["prototype"] == "int32_t main(int32_t argc)"
        assert "helper();" in code["code"]
        assert "push" in client.call("disassemble", target="main")["disassembly"]
        strings = client.call("strings", filter="hello")
        assert strings["items"][0]["used_by"] == ["main"]
        assert (
            client.call("read_bytes", address="0x401000", size=4)["hex"] == "00010203"
        )
        hits = client.call("search", pattern="00 01 02", kind="hex")["hits"]
        assert hits and hits[0]["address"] == "0x401000"
        assert client.call("lookup", name="help")["matches"][0]["name"] == "helper"
        point = client.call("type", name="point")
        assert "int32_t x;" in point["c_decl"]

        with pytest.raises(ToolError, match="no function or symbol"):
            client.call("decompile", target="missing_function")

        first = client.call("eval", code="count = len(bv.functions)\ncount")
        assert first["result"] == 3 and first["error"] is None
        assert client.call("eval", code="print('hi'); count + 1")["stdout"] == "hi\n"
        assert "ZeroDivisionError" in client.call("eval", code="1/0")["error"]
        assert client.call("save")["saved"] is True


def test_a_hung_call_is_stopped_and_the_session_reopens(
    export: Path, tmp_path: Path
) -> None:
    with _client(tmp_path, str(export)) as client:
        with pytest.raises(ToolError, match="timed out"):
            client.call("eval", code="import time; time.sleep(60)", timeout=2)
        assert client.call("info")["note"].startswith("reopened after: call timed out")
        with pytest.raises(ToolError, match="worker died"):
            client.call("eval", code="import os; os._exit(3)")
        assert client.call("functions")["total"] == 3  # reopened again


def test_session_cap_closes_the_least_recently_used(
    export: Path, tmp_path: Path
) -> None:
    copy = tmp_path / "copy.bndb"
    copy.write_text((export / "sample.bndb").read_text())
    with _client(tmp_path, "--max-sessions", "1") as client:
        first = client.call("open", path=str(export))["session"]
        second = client.call("open", path=str(copy))["session"]
        assert first != second
        alive = {
            row["session"]: row["alive"] for row in client.call("sessions")["sessions"]
        }
        assert alive == {first: False, second: True}
        assert client.call("info", session=first)["session"] == first  # reopens


def test_read_only_hides_edits_and_eval(export: Path, tmp_path: Path) -> None:
    with _client(tmp_path, "--read-only") as client:
        names = {tool["name"] for tool in client.tools()}
        assert "eval" not in names and "save" not in names
        assert "decompile" in names
        annotations = {tool["name"]: tool["annotations"] for tool in client.tools()}
        assert annotations["decompile"]["readOnlyHint"] is True


def test_stdout_noise_never_reaches_the_protocol(export: Path, tmp_path: Path) -> None:
    with _client(tmp_path, str(export)) as client:
        # A script printing to the real fd 1 must not corrupt the stream.
        client.call("eval", code="import os; os.write(1, b'noise\\n')")
        assert client.call("info")["session"] == "sample.elf"
