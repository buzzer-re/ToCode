"""The MCP tool table: names, schemas, annotations, and what each one runs."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Callable

from ..errors import ToCodeError
from .jsonrpc import ToolCall
from .sessions import SessionManager

SESSION = {
    "type": "string",
    "description": "Session id from `open` (or a folder binary's path such as "
    "`bin/app`; the only open session when omitted).",
}
TARGET = {
    "type": "string",
    "description": "Function or symbol: an address (`0x401000`) or a name.",
}
FILTER = {
    "type": "string",
    "description": "Case-insensitive regular expression (or substring) to match.",
}
OFFSET = {"type": "integer", "minimum": 0, "description": "First row to return."}
LIMIT = {
    "type": "integer",
    "minimum": 1,
    "maximum": 2000,
    "description": "Rows per page.",
}

QUERY, EDIT, EVAL, SESSIONS, PROJECT = "query", "edit", "eval", "sessions", "project"


@dataclass
class Tool:
    name: str
    description: str
    group: str
    properties: dict[str, Any] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    op: str | None = None  # worker operation (most tools)
    run: Callable[[SessionManager, dict[str, Any], ToolCall], Any] | None = None
    timeout: float | None = None
    destructive: bool = False
    text_field: str | None = None  # result field shown as plain text

    @property
    def read_only(self) -> bool:
        return self.group in (QUERY, SESSIONS) and not self.destructive

    def schema(self) -> dict[str, Any]:
        properties = dict(self.properties)
        if self.op is not None:
            properties = {"session": SESSION, **properties}
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": list(self.required),
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.read_only,
                "openWorldHint": False,
            },
        }


def _open(manager: SessionManager, args: dict[str, Any], _call: ToolCall) -> Any:
    return manager.open(
        str(args.get("path") or ""),
        database=args.get("database") or None,
        backend=args.get("backend") or None,
    )


def _sessions(manager: SessionManager, _args: dict[str, Any], _call: ToolCall) -> Any:
    return manager.describe()


def _close(manager: SessionManager, args: dict[str, Any], _call: ToolCall) -> Any:
    return manager.close(
        str(args.get("session") or ""), save=args.get("save", True) is not False
    )


def build_tools() -> list[Tool]:
    return [
        # -- sessions ---------------------------------------------------------
        Tool(
            "open",
            "Open a binary or database and keep it alive for the other tools. `path` "
            "is an export folder (made by `tocode <binary>`), a folder export, a "
            "binary, or a database (.i64/.idb/.bndb). By default an export's own "
            "database is used; pass `database` to edit another one. Returns the "
            "session id (a folder returns its binaries; address them as "
            "`session`=<relative path>).",
            SESSIONS,
            {
                "path": {
                    "type": "string",
                    "description": "Export folder, folder export, binary, or database.",
                },
                "database": {
                    "type": "string",
                    "description": "Database to open instead of the export's own copy.",
                },
                "backend": {
                    "type": "string",
                    "enum": ["auto", "ida", "binja", "r2", "angr"],
                    "description": "Backend for a plain binary (databases pick their own).",
                },
            },
            ["path"],
            run=_open,
            timeout=None,
        ),
        Tool("sessions", "List open sessions and folders.", SESSIONS, run=_sessions),
        Tool(
            "close",
            "Close a session (saving its database unless `save` is false).",
            SESSIONS,
            {"session": SESSION, "save": {"type": "boolean"}},
            ["session"],
            run=_close,
            destructive=False,
        ),
        Tool(
            "save",
            "Save the session's database so edits survive the session.",
            EDIT,
            op="save",
            timeout=1800,
        ),
        # -- queries ------------------------------------------------------------
        Tool(
            "info",
            "Binary facts, backend, counts, database and export folder.",
            QUERY,
            op="info",
        ),
        Tool(
            "functions",
            "List functions (address, name, size, signature, kind, caller/callee counts).",
            QUERY,
            {
                "filter": FILTER,
                "kind": {
                    "type": "string",
                    "enum": ["all", "app", "library", "import", "thunk", "runtime"],
                },
                "offset": OFFSET,
                "limit": LIMIT,
            },
            op="functions",
        ),
        Tool(
            "function",
            "One function: prototype, params, locals, callers, callees, imports it "
            "calls, and where it is in the export (file:lines).",
            QUERY,
            {"target": TARGET},
            ["target"],
            op="function",
        ),
        Tool(
            "decompile",
            "Decompile a function now, from the live database (reflects edits).",
            QUERY,
            {"target": TARGET},
            ["target"],
            op="decompile",
            timeout=180,
            text_field="code",
        ),
        Tool(
            "disassemble",
            "Disassemble a function from the live database.",
            QUERY,
            {"target": TARGET, "max_lines": {"type": "integer", "minimum": 1}},
            ["target"],
            op="disassemble",
            text_field="disassembly",
        ),
        Tool(
            "xrefs",
            "Cross-references: `to` (callers and data reads/writes of the target) or "
            "`from` (what a function calls).",
            QUERY,
            {"target": TARGET, "direction": {"type": "string", "enum": ["to", "from"]}},
            ["target"],
            op="xrefs",
        ),
        Tool(
            "strings",
            "Strings with the functions that use them.",
            QUERY,
            {"filter": FILTER, "offset": OFFSET, "limit": LIMIT},
            op="strings",
        ),
        Tool(
            "imports",
            "Imported symbols and their libraries.",
            QUERY,
            {"filter": FILTER, "offset": OFFSET, "limit": LIMIT},
            op="imports",
        ),
        Tool(
            "exports",
            "Exported symbols.",
            QUERY,
            {"filter": FILTER, "offset": OFFSET, "limit": LIMIT},
            op="exports",
        ),
        Tool(
            "sections",
            "Sections/segments with addresses, sizes and permissions.",
            QUERY,
            op="sections",
        ),
        Tool(
            "types",
            "Types in the database (structs, unions, enums, typedefs).",
            QUERY,
            {
                "filter": FILTER,
                "kind": {
                    "type": "string",
                    "enum": ["struct", "union", "enum", "typedef", "func"],
                },
                "offset": OFFSET,
                "limit": LIMIT,
            },
            op="types",
        ),
        Tool(
            "type",
            "One type's C declaration and members.",
            QUERY,
            {"name": {"type": "string"}},
            ["name"],
            op="type",
            text_field="c_decl",
        ),
        Tool(
            "read_bytes",
            "Read bytes at an address (hex and ASCII, at most 64 KiB).",
            QUERY,
            {
                "address": TARGET,
                "size": {"type": "integer", "minimum": 1, "maximum": 65536},
            },
            ["address"],
            op="read_bytes",
        ),
        Tool(
            "search",
            "Search the binary's sections for text, hex bytes (`de ad be ef`), or a "
            "byte regex; returns addresses and the functions containing them.",
            QUERY,
            {
                "pattern": {"type": "string"},
                "kind": {"type": "string", "enum": ["text", "hex", "regex"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
            ["pattern"],
            op="search",
        ),
        Tool(
            "lookup",
            "Find functions and symbols whose name contains `name`.",
            QUERY,
            {"name": {"type": "string"}, "limit": {"type": "integer", "minimum": 1}},
            ["name"],
            op="lookup",
        ),
        Tool(
            "status",
            "What the next `sync` will update (functions changed in this session).",
            QUERY,
            op="status",
        ),
        # -- edits ------------------------------------------------------------------
        Tool(
            "rename",
            "Rename a function or a global. Callers pick up the new name on the next `sync`.",
            EDIT,
            {
                "target": TARGET,
                "name": {"type": "string", "description": "New name (a C identifier)."},
            },
            ["target", "name"],
            op="rename",
        ),
        Tool(
            "set_type",
            "Set a function's prototype (`int parse(char *buf, size_t len)`) or a "
            "global's type (`struct config *g_config`).",
            EDIT,
            {"target": TARGET, "c_decl": {"type": "string"}},
            ["target", "c_decl"],
            op="set_type",
        ),
        Tool(
            "set_comment",
            "Comment an instruction (`line`) or a whole function (`function`).",
            EDIT,
            {
                "address": TARGET,
                "text": {"type": "string"},
                "kind": {"type": "string", "enum": ["line", "function"]},
            },
            ["address", "text"],
            op="set_comment",
        ),
        Tool(
            "declare_types",
            "Add or replace C types (structs, unions, enums, typedefs) in the "
            "database, e.g. `struct packet { uint16_t len; uint8_t type; uint8_t payload[]; };`.",
            EDIT,
            {"c_source": {"type": "string"}},
            ["c_source"],
            op="declare_types",
        ),
        Tool(
            "rename_local",
            "Rename a local variable or parameter of a function (as the decompiler names it).",
            EDIT,
            {"function": TARGET, "old": {"type": "string"}, "new": {"type": "string"}},
            ["function", "old", "new"],
            op="rename_local",
        ),
        Tool(
            "set_local_type",
            "Set the type of a function's local variable or parameter.",
            EDIT,
            {
                "function": TARGET,
                "name": {"type": "string"},
                "c_type": {"type": "string"},
            },
            ["function", "name", "c_type"],
            op="set_local_type",
        ),
        Tool(
            "define_function",
            "Create a function at an address the analysis missed.",
            EDIT,
            {"address": TARGET},
            ["address"],
            op="define_function",
            timeout=600,
        ),
        Tool(
            "undefine",
            "Delete the function (or undefine the data) at an address.",
            EDIT,
            {"address": TARGET},
            ["address"],
            op="undefine",
            destructive=True,
        ),
        # -- project ---------------------------------------------------------------
        Tool(
            "sync",
            "Update the export on disk from the database: new functions are added "
            "next to their callers, renamed/retyped functions and their callers and "
            "every function using a changed type are re-rendered, and only files "
            "whose content changed are rewritten (plus the JSON and headers). "
            "`mode`=`full` re-renders everything (after changes made outside this "
            "server, e.g. in the IDA UI); `addresses` forces some functions. Saves "
            "the database when it changed.",
            PROJECT,
            {
                "mode": {"type": "string", "enum": ["auto", "full"]},
                "addresses": {"type": "array", "items": {"type": "string"}},
            },
            op="sync",
            timeout=0,  # no limit: a big binary can take a while
        ),
        Tool(
            "export",
            "Write a ToCode export for a session opened on a plain binary (default "
            "folder: <binary>_decompiler next to it).",
            PROJECT,
            {"out_dir": {"type": "string"}},
            op="export",
            timeout=0,
        ),
        # -- eval -------------------------------------------------------------------
        Tool(
            "eval",
            "Run a script inside the database. Python by default: the last "
            "expression (or `result`) is returned and stdout is captured. Names: "
            "IDA `db` (ida-domain) plus idaapi/idc/ida_* modules; Binary Ninja "
            "`bv`, `bn`; r2 `r2` (`r2.cmd(...)`); angr `project`; everywhere "
            "`session`, `analysis`, `resolve(name)`, and `touch(addr, ...)` to mark "
            "functions your script changed for the next `sync`. Names you define "
            "persist between calls (`reset` clears them). `language`=`r2` runs an "
            "r2 command.",
            EVAL,
            {
                "code": {"type": "string"},
                "language": {"type": "string", "enum": ["python", "r2"]},
                "reset": {"type": "boolean"},
                "timeout": {
                    "type": "number",
                    "minimum": 1,
                    "description": "Seconds (default 300).",
                },
            },
            ["code"],
            op="eval",
            destructive=True,
            timeout=300,
        ),
    ]


class ToolTable:
    def __init__(
        self,
        manager: SessionManager,
        *,
        allow_edits: bool = True,
        allow_eval: bool = True,
        extra: list[Tool] | None = None,
    ) -> None:
        self.manager = manager
        tools = build_tools() + list(extra or [])
        # Read-only hides everything that changes the database; sync and
        # export stay (they only write the export folder from the database).
        self.tools = {
            tool.name: tool
            for tool in tools
            if not (tool.group == EDIT and not allow_edits)
            and not (tool.group == EVAL and not (allow_eval and allow_edits))
        }

    def list(self) -> list[dict[str, Any]]:
        return [tool.schema() for tool in self.tools.values()]

    def call(self, call: ToolCall) -> dict[str, Any]:
        tool = self.tools.get(call.name)
        if tool is None:
            return _error(f"unknown tool {call.name}")
        args = dict(call.arguments)
        try:
            if tool.run is not None:
                result = tool.run(self.manager, args, call)
            else:
                session = str(args.pop("session", "") or "")
                timeout = args.pop("timeout", None) if tool.group == EVAL else None
                result = self.manager.call(
                    session,
                    str(tool.op),
                    args,
                    timeout=float(timeout) if timeout else tool.timeout,
                )
        except ToCodeError as exc:
            return _error(str(exc))
        return _result(result, tool.text_field)


def _result(result: Any, text_field: str | None) -> dict[str, Any]:
    structured = result if isinstance(result, dict) else {"result": result}
    if (
        text_field
        and isinstance(result, dict)
        and isinstance(result.get(text_field), str)
    ):
        header = {k: v for k, v in result.items() if k != text_field}
        text = json.dumps(header, ensure_ascii=False) + "\n\n" + result[text_field]
    else:
        text = json.dumps(structured, ensure_ascii=False, indent=1)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
    }


def _error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


_GROUP_TITLES = {
    SESSIONS: "Sessions",
    QUERY: "Query",
    EDIT: "Edit",
    PROJECT: "Project",
    EVAL: "Script",
}


def render_reference() -> str:
    """`skill/references/tools.md`, generated from the tool table.

    Regenerate with `python -m tocode.live.tools > src/tocode/skill/references/tools.md`.
    """
    lines = [
        "# ToCode MCP tools",
        "",
        "Every tool except `open` and `sessions` takes `session`: the id `open` returned, a folder",
        "binary's relative path (`bin/app`, or `<folder>:bin/app`), or nothing when one session is open.",
        "Targets and addresses accept `0x...` addresses or names (auto names like `sub_401000` too).",
        "List tools page with `offset`/`limit` and return `total` and `next_offset`.",
        "",
    ]
    tools = build_tools()
    for group in (SESSIONS, QUERY, EDIT, PROJECT, EVAL):
        lines += [f"## {_GROUP_TITLES[group]}", ""]
        for tool in (item for item in tools if item.group == group):
            lines += [f"### `{tool.name}`", "", tool.description]
            arguments = [
                (name, spec)
                for name, spec in tool.properties.items()
                if name != "session"
            ]
            if arguments:
                lines.append("")
            for name, spec in arguments:
                kind = spec.get("type", "")
                if "enum" in spec:
                    kind = " | ".join(f"`{value}`" for value in spec["enum"])
                required = " (required)" if name in tool.required else ""
                line = f"- `{name}`{required}: {kind}. {spec.get('description', '')}"
                lines.append(line.rstrip(" ."))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":
    print(render_reference(), end="")
