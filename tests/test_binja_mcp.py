"""Binary Ninja over its built-in MCP server, against an in-process fake."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any, Iterator

import pytest

from tocode.backends import binja_mcp
from tocode.backends.mcp_client import (
    McpClient,
    fenced_body,
    front_matter,
    markdown_tables,
    split_row,
)
from tocode.errors import BackendError


def _table(
    tool: str,
    headers: list[str],
    rows: list[list[str]],
    offset: int = 0,
    limit: int = 100,
) -> str:
    page = rows[offset : offset + limit]
    next_offset = offset + len(page) if offset + len(page) < len(rows) else None
    escaped = [[cell.replace("|", "\\|") for cell in row] for row in page]
    lines = [
        "---",
        f'tool: "{tool}"',
        f"offset: {offset}",
        f"limit: {limit}",
        f"count: {len(page)}",
        f"total: {len(rows)}",
        f"nextOffset: {'null' if next_offset is None else next_offset}",
        f"truncated: {'true' if next_offset is not None else 'false'}",
        "---",
        "",
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        *("| " + " | ".join(row) + " |" for row in escaped),
        "",
    ]
    return "\n".join(lines)


def _fenced(tool: str, lines: list[str], offset: int, limit: int, language: str) -> str:
    page = lines[offset : offset + limit]
    next_offset = offset + len(page) if offset + len(page) < len(lines) else None
    return (
        f'---\ntool: "{tool}"\noffset: {offset}\nlimit: {limit}\ncount: {len(page)}\n'
        f"total: {len(lines)}\nnextOffset: {'null' if next_offset is None else next_offset}\n---\n\n"
        f"````{language}\n" + "\n".join(page) + "\n````\n"
    )


MAIN = 0x401000
HELPER = 0x401100
STUB = 0x402000
DECOMPILE = {
    MAIN: [
        "🌐  int32_t main(int32_t argc, char** argv)",
        "",
        "{",
        "    helper(argc);",
        '    return puts("a|b");',
        "}",
    ],
    HELPER: ["  int32_t helper(int32_t arg1)", "", "{", "    return arg1 + 1;", "}"],
}


class FakeBinja:
    """State and tool handlers of a fake Binary Ninja MCP server."""

    def __init__(self) -> None:
        self.active = "view_2"
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.opened: list[str] = []

    def view(self, handle: str) -> dict[str, Any]:
        return {
            "handle": handle,
            "openItem": "item_1" if handle == "view_1" else "item_2",
            "viewType": "ELF",
            "architecture": "x86_64",
            "platform": "linux-x86_64",
            "addressSize": 8,
            "start": "0x400000",
            "end": "0x403000",
            "entryPoint": hex(MAIN),
        }

    def handle(
        self, name: str, args: dict[str, Any]
    ) -> tuple[str, dict[str, Any] | None, bool]:
        self.calls.append((name, args))
        offset, limit = args.get("offset", 0), args.get("limit", 100)
        views = [
            [
                "view_1",
                "item_1",
                "ELF",
                "true",
                "true" if self.active == "view_1" else "false",
                "true",
                "x86_64",
                "linux-x86_64",
                "8",
                "0x400000",
                hex(MAIN),
            ],
            [
                "view_1r",
                "item_1",
                "Raw",
                "true",
                "false",
                "true",
                "",
                "",
                "4",
                "0x0",
                "0x0",
            ],
            [
                "view_2",
                "item_2",
                "ELF",
                "true",
                "true" if self.active == "view_2" else "false",
                "true",
                "x86_64",
                "linux-x86_64",
                "8",
                "0x400000",
                hex(MAIN),
            ],
        ]
        if name == "bn_binary_view_list":
            return (
                _table(
                    name,
                    [
                        "binaryView",
                        "openItem",
                        "viewType",
                        "created",
                        "active",
                        "available",
                        "architecture",
                        "platform",
                        "addressSize",
                        "start",
                        "entryPoint",
                    ],
                    views,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_open_item_list":
            items = [
                ["item_1", "file", "/bins/app", "/bins/app"],
                ["item_2", "database", "/bins/other.bndb", "/bins/other.bndb"],
            ]
            items += [
                [f"item_{9 + i}", "file", path, path]
                for i, path in enumerate(self.opened)
            ]
            return (
                _table(
                    name,
                    ["openItem", "kind", "displayName", "path"],
                    items,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_binary_view_get_active":
            return "", {"binaryView": self.view(self.active)}, False
        if name == "bn_binary_view_set_active":
            self.active = args["binaryView"]
            return "", {"binaryView": self.view(self.active), "changed": True}, False
        if name == "bn_analysis_status":
            return "", {"analysis": {"state": "IdleState"}}, False
        if name == "bn_function_list":
            rows = [
                [
                    hex(MAIN),
                    "x86_64",
                    "main",
                    hex(MAIN),
                    hex(MAIN + 0x3F),
                    "int32_t(int32_t argc, char** argv)",
                    "3",
                ],
                [
                    hex(HELPER),
                    "x86_64",
                    "helper",
                    hex(HELPER),
                    hex(HELPER + 0xF),
                    "int32_t(int32_t arg1)",
                    "1",
                ],
                [
                    hex(STUB),
                    "x86_64",
                    "puts",
                    hex(STUB),
                    hex(STUB + 5),
                    "int32_t(char const* s)",
                    "1",
                ],
            ]
            return (
                _table(
                    name,
                    [
                        "function",
                        "arch",
                        "name",
                        "lowestAddress",
                        "highestAddress",
                        "definition",
                        "basicBlockCount",
                    ],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_import_list":
            rows = [
                [
                    hex(STUB),
                    "puts",
                    "ImportedFunctionSymbol",
                    "libc.so.6",
                    "0",
                    "NoBinding",
                ]
            ]
            return (
                _table(
                    name,
                    ["symbol", "name", "type", "namespace", "ordinal", "binding"],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_export_list":
            rows = [
                [
                    hex(MAIN),
                    "main",
                    "FunctionSymbol",
                    "BNINTERNALNAMESPACE",
                    "0",
                    "GlobalBinding",
                ]
            ]
            return (
                _table(
                    name,
                    ["symbol", "name", "type", "namespace", "ordinal", "binding"],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_symbol_list":
            rows = [
                [
                    hex(MAIN),
                    "main",
                    "FunctionSymbol",
                    "BNINTERNALNAMESPACE",
                    "0",
                    "GlobalBinding",
                    "main",
                ]
            ]
            return (
                _table(
                    name,
                    [
                        "symbol",
                        "name",
                        "type",
                        "namespace",
                        "ordinal",
                        "binding",
                        "fullName",
                    ],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_section_list":
            rows = [
                [".text", "0x401000", "0x402000", "0x1000", "PROGBITS"],
                [".plt", "0x402000", "0x402100", "0x100", "PROGBITS"],
            ]
            return (
                _table(
                    name,
                    ["section", "start", "end", "length", "typeName"],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_segment_list":
            rows = [["0x400000", "0x400000", "0x403000", "true", "false", "true"]]
            return (
                _table(
                    name,
                    ["segment", "start", "end", "readable", "writable", "executable"],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_string_list":
            rows = [["0x401f00", "AsciiString", "0x3", "a|b", "617c62", "false"]]
            return (
                _table(
                    name,
                    [
                        "string",
                        "type",
                        "length",
                        "previewEscaped",
                        "previewHex",
                        "previewTruncated",
                    ],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_relocation_list":
            rows = [
                [
                    "0x403000",
                    hex(STUB),
                    "x86_64",
                    hex(STUB),
                    "puts",
                    "ELFJumpSlotRelocationType",
                ]
            ]
            return (
                _table(
                    name,
                    [
                        "address",
                        "target",
                        "architecture",
                        "symbol",
                        "symbolName",
                        "type",
                    ],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_entry_point_list":
            return (
                _table(
                    name,
                    ["address", "function", "arch", "name"],
                    [[hex(MAIN), hex(MAIN), "x86_64", "main"]],
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_type_list":
            return (
                _table(
                    name,
                    ["type", "id", "class", "definition", "width"],
                    [["point", "x", "StructureTypeClass", "struct point", "8"]],
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_type_info":
            return (
                "",
                {
                    "type": {
                        "source": "struct point\n{\n    int32_t x;\n    int32_t y;\n};"
                    }
                },
                False,
            )
        if name == "bn_function_decompile":
            address = int(args["function"], 16)
            return (
                _fenced(
                    name,
                    DECOMPILE[address],
                    offset,
                    args.get("limit", 1000),
                    "bn-pseudoc",
                ),
                None,
                False,
            )
        if name == "bn_function_disassembly":
            address = int(args["function"], 16)
            lines = [
                "  int32_t f()",
                "",
                f"0x{address:x}  push    rbp",
                f"0x{address + 1:x}  call    helper",
            ]
            return (
                _fenced(name, lines, offset, args.get("limit", 1000), "asm"),
                None,
                False,
            )
        if name == "bn_function_callees":
            address = int(args["function"], 16)
            rows = (
                [
                    [
                        "0x401010",
                        "x86_64",
                        hex(HELPER),
                        f"helper ({hex(HELPER)} (x86_64))",
                    ],
                    ["0x401020", "x86_64", hex(STUB), f"puts ({hex(STUB)} (x86_64))"],
                ]
                if address == MAIN
                else []
            )
            return (
                _table(
                    name,
                    ["Callsite", "Architecture", "Callee Address", "Callee Functions"],
                    rows,
                    offset,
                    limit,
                ),
                None,
                False,
            )
        if name == "bn_memory_read":
            data = bytes([0x90]) * int(args["length"])
            return "", {"hex": data.hex(), "bytesRead": len(data)}, False
        if name == "bn_open_item_open":
            self.opened.append(args["path"])
            return "", {"openItem": {"handle": f"item_{8 + len(self.opened)}"}}, False
        return (
            json.dumps({"errorCode": "unknown_tool"}),
            {"errorCode": "unknown_tool", "errorMessage": name},
            True,
        )


@pytest.fixture
def server() -> Iterator[tuple[str, FakeBinja]]:
    fake = FakeBinja()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if "id" not in payload:
                self.send_response(202)
                self.end_headers()
                return
            method = payload["method"]
            if method == "initialize":
                result: dict[str, Any] = {
                    "serverInfo": {"name": "binaryninja_ui_mcp"},
                    "capabilities": {},
                }
            elif method == "tools/call":
                text, structured, error = fake.handle(
                    payload["params"]["name"], payload["params"]["arguments"]
                )
                result = {"content": [{"type": "text", "text": text}], "isError": error}
                if structured is not None:
                    result["structuredContent"] = structured
            else:
                result = {}
            body = json.dumps(
                {"jsonrpc": "2.0", "id": payload["id"], "result": result}
            ).encode()
            self.send_response(200)
            if payload["params"].get("name") == "bn_section_list":
                # Exercise the event-stream response form too.
                body = b"event: message\ndata: " + body + b"\n\n"
                self.send_header("Content-Type", "text/event-stream")
            else:
                self.send_header("Content-Type", "application/json")
            self.send_header("MCP-Session-Id", "s1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/mcp", fake
    finally:
        httpd.shutdown()


# -- client helpers -----------------------------------------------------------


def test_markdown_helpers_handle_escaped_pipes_and_front_matter() -> None:
    text = _table("t", ["a", "b"], [["x|y", "1"]])
    assert (
        front_matter(text)["tool"] == "t" and front_matter(text)["nextOffset"] is None
    )
    assert markdown_tables(text) == [[{"a": "x|y", "b": "1"}]]
    assert split_row("| a \\| b | c |") == ["a | b", "c"]
    assert fenced_body("````asm\nline\n````\n") == "line\n"


def test_client_rejects_a_server_that_is_not_binary_ninja(server) -> None:
    url, _fake = server
    client = McpClient(url).connect()
    assert client.session_id == "s1"
    with pytest.raises(BackendError, match="could not reach"):
        binja_mcp.connect("http://127.0.0.1:1/mcp", timeout=1)


# -- session ------------------------------------------------------------------


def test_session_maps_tools_and_restores_the_active_view(server) -> None:
    url, fake = server
    client = binja_mcp.connect(url)
    views = binja_mcp.list_views(client)
    assert [view.handle for view in views] == ["view_1", "view_2"]  # Raw skipped
    assert views[0].path == "/bins/app" and views[1].active

    session = binja_mcp.BinjaMcpSession(client, views[0])
    assert fake.active == "view_1"
    assert session.info()["bin"]["baddr"] == 0x400000

    functions = {row["addr"]: row for row in session.functions()}
    assert functions[MAIN]["signature"] == "int32_t main(int32_t argc, char** argv)"
    assert functions[MAIN]["params"] == [
        {"name": "argc", "type": "int32_t"},
        {"name": "argv", "type": "char**"},
    ]
    assert functions[STUB]["is_library"] and functions[STUB]["is_thunk"]
    assert functions[MAIN]["size"] == 0x40
    imports = session.imports()
    assert imports[0]["dll"] == "libc.so.6"
    assert session.strings()[0]["string"] == "a|b"
    assert session.sections()[0]["perm"] == "r-x"  # via the event-stream response
    assert "int32_t x;" in session.types()[0]["c_decl"]

    text = session.decompile(MAIN)
    assert text.startswith(
        "int32_t main(int32_t argc, char** argv)\n"
    )  # gutter glyph gone
    assert 'puts("a|b")' in text
    assert session.disasm(MAIN).splitlines()[0] == f"0x{MAIN:x}: push    rbp"

    class Routine:
        def __init__(self, name: str, imported: bool) -> None:
            self.name, self.imported = name, imported

    class Import:
        name = "puts"

    known = {
        MAIN: Routine("main", False),
        HELPER: Routine("helper", False),
        STUB: Routine("puts", True),
    }
    assert session.calls_from(MAIN, {STUB: Import()}, known) == ([HELPER], ["puts"])

    session.close()
    assert fake.active == "view_2"  # the user's view is active again


def test_decompile_follows_pagination(server, monkeypatch: pytest.MonkeyPatch) -> None:
    url, fake = server
    monkeypatch.setattr(binja_mcp, "PAGE", 2)
    client = binja_mcp.connect(url)
    session = binja_mcp.BinjaMcpSession(client, binja_mcp.list_views(client)[0])

    text = session.decompile(MAIN)

    assert text.count("\n") == len(DECOMPILE[MAIN])
    pages = [args for name, args in fake.calls if name == "bn_function_decompile"]
    assert [args["offset"] for args in pages] == [0, 2, 4]


def test_find_view_for_path_matches_files_and_databases(server) -> None:
    url, _fake = server
    views = binja_mcp.list_views(binja_mcp.connect(url))
    by_file = binja_mcp.find_view_for_path(views, Path("/bins/app"))
    by_database = binja_mcp.find_view_for_path(views, Path("/bins/other"))
    assert by_file is not None and by_file.handle == "view_1"
    assert by_database is not None and by_database.handle == "view_2"
    assert binja_mcp.find_view_for_path(views, Path("/bins/none")) is None


# -- CLI ------------------------------------------------------------------------


def test_cli_lists_views_over_mcp(server, capsys) -> None:
    from tocode.cli import main

    url, _fake = server
    assert main(["--backend", "binja", "--binja-mcp-url", url, "--list-binja"]) == 0
    out = capsys.readouterr().out
    assert (
        "[0] ELF x86_64 64-bit  /bins/app" in out and "[1]" in out and "[active]" in out
    )


def test_cli_exports_a_view_over_mcp(server, tmp_path: Path) -> None:
    from tocode.cli import main

    url, fake = server
    out = tmp_path / "out"
    code = main(
        [
            "--backend",
            "binja",
            "--binja-mcp-url",
            url,
            "--binja-view",
            "0",
            "-o",
            str(out),
            "-q",
        ]
    )

    assert code == 0
    sources = "".join(path.read_text() for path in (out / "src" / "raw").rglob("*.c"))
    assert (
        "int32_t main(int32_t argc, char** argv)" in sources
        and "helper(argc);" in sources
    )
    project = json.loads((out / "project.json").read_text())
    assert project["backend"] == "binja" and project["image_base"] == "0x400000"
    # Section bytes come from Binary Ninja's view, not from a local file.
    assert (out / "data" / "text.bin").read_bytes() == b"\x90" * 0x1000
    assert fake.active == "view_2"


def test_cli_falls_back_to_rpyc_when_mcp_is_down(monkeypatch, capsys) -> None:
    from tocode import cli
    from tocode.backends import binja as binja_backend

    seen = {}

    def fake_rpyc(host, port):
        seen["rpyc"] = (host, port)
        raise BackendError("no binja-headless")

    monkeypatch.setattr(binja_backend, "connect_rpyc", fake_rpyc)

    assert (
        cli.main(
            [
                "--backend",
                "binja",
                "--binja-mcp-url",
                "http://127.0.0.1:1/mcp",
                "--list-binja",
            ]
        )
        == 1
    )
    assert seen["rpyc"] == ("127.0.0.1", 18812)
    assert "trying binja-headless" in capsys.readouterr().err

    seen.clear()
    assert (
        cli.main(
            [
                "--backend",
                "binja",
                "--binja-transport",
                "mcp",
                "--binja-mcp-url",
                "http://127.0.0.1:1/mcp",
                "--list-binja",
            ]
        )
        == 1
    )
    assert "rpyc" not in seen  # forced MCP never falls back
