"""Binary Ninja backend over Binary Ninja's built-in MCP server (6.0+).

Binary Ninja 6 ships an MCP server inside the UI (default
``http://127.0.0.1:24642/mcp``). This session drives it with plain tool calls:
the analysis, decompilation, and naming are Binary Ninja's own, nothing runs
inside the Binary Ninja process except its tools, and no extra Python package
is needed (the client is standard library only).

The server has one *active* binary view, shared with the user's UI and any
other MCP client. A session activates the view it exports, checks every few
hundred calls that it is still active (re-activating it if someone else
switched), and restores the previously active view when it closes.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Any, Iterator

from ..errors import BackendError
from .base import BackendName
from .binja import strip_gutter as _strip_gutter
from .mcp_client import (
    McpClient,
    ToolResult,
    fenced_body,
    front_matter,
    markdown_tables,
)

DEFAULT_MCP_URL = "http://127.0.0.1:24642/mcp"
PAGE = 1000
ACTIVE_CHECK_EVERY = 256
PROBE_TIMEOUT_SECONDS = 2.0
MAX_STRING_BYTES = 65536
MAX_TYPES = 50_000
_INTERNAL_NAMESPACE = "BNINTERNALNAMESPACE"
_DISASM_RX = re.compile(r"^(0x[0-9a-fA-F]+)\s+(.*)$")
_CALLEE_NAME_RX = re.compile(r"^(.*?) \(0x[0-9a-fA-F]+ \(")
# Same runtime/thunk classification as the RPyc backend.
_RUNTIME_PREFIXES = (
    "__libc_csu_",
    "__scrt_",
    "_scrt_",
    "__crt",
    "_crt",
    "_global__sub_i_",
)
_RUNTIME_NAMES = frozenset(
    {
        "_init", "_fini", "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
        "frame_dummy", "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux",
    }
)  # fmt: skip


def mcp_url() -> str:
    return os.environ.get("TOCODE_BINJA_MCP_URL", "").strip() or DEFAULT_MCP_URL


def connect(
    url: str | None = None, *, timeout: float | None = PROBE_TIMEOUT_SECONDS
) -> McpClient:
    """Connect to Binary Ninja's MCP server; raises BackendError when absent."""
    client = McpClient(url or mcp_url())
    client.connect(timeout=timeout)
    name = str(client.server_info.get("name", ""))
    if "binaryninja" not in name.lower():
        raise BackendError(
            f"the MCP server at {client.url} is {name or 'unknown'}, not Binary Ninja"
        )
    return client


def _int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text)
    except ValueError:
        return default


def _bool(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def call(client: McpClient, tool: str, **arguments: Any) -> ToolResult:
    result = client.call(
        tool, {key: value for key, value in arguments.items() if value is not None}
    )
    if result.is_error:
        message = result.text
        if result.structured:
            message = str(result.structured.get("errorMessage") or message)
        raise BackendError(f"Binary Ninja {tool} failed: {message[:300]}")
    return result


def paged(client: McpClient, tool: str, **arguments: Any) -> Iterator[dict[str, str]]:
    """Every row of a paginated list tool."""
    offset = 0
    while True:
        result = call(client, tool, offset=offset, limit=PAGE, **arguments)
        tables = markdown_tables(result.text)
        yield from tables[0] if tables else []
        next_offset = front_matter(result.text).get("nextOffset")
        if next_offset is None or next_offset <= offset:
            return
        offset = int(next_offset)


def paged_text(client: McpClient, tool: str, **arguments: Any) -> str:
    """The full fenced body of a paginated text tool (decompile/disassembly)."""
    chunks: list[str] = []
    offset = 0
    while True:
        result = call(client, tool, offset=offset, limit=PAGE, **arguments)
        body = fenced_body(result.text)
        if body is not None:
            chunks.append(body if body.endswith("\n") else body + "\n")
        next_offset = front_matter(result.text).get("nextOffset")
        if next_offset is None or next_offset <= offset:
            return "".join(chunks)
        offset = int(next_offset)


# --------------------------------------------------------------------------
# Views
# --------------------------------------------------------------------------


@dataclass(slots=True)
class McpView:
    handle: str
    open_item: str
    view_type: str
    architecture: str
    platform: str
    address_size: int
    start: int
    entry_point: int
    path: str
    active: bool
    created: bool

    def describe(self) -> str:
        bits = self.address_size * 8
        arch = self.architecture or "?"
        flag = "  [active]" if self.active else ""
        return f"{self.view_type} {arch} {bits}-bit  {self.path or '<unnamed>'}{flag}"


def list_views(client: McpClient) -> list[McpView]:
    """Analyzable views (Raw views are skipped), in Binary Ninja's order."""
    paths = {
        row.get("openItem", ""): row.get("path", "")
        for row in paged(client, "bn_open_item_list")
    }
    views: list[McpView] = []
    for row in paged(client, "bn_binary_view_list"):
        view_type = row.get("viewType", "")
        if view_type == "Raw" or not _bool(row.get("available", "true")):
            continue
        views.append(
            McpView(
                handle=row.get("binaryView", ""),
                open_item=row.get("openItem", ""),
                view_type=view_type,
                architecture=row.get("architecture", ""),
                platform=row.get("platform", ""),
                address_size=_int(row.get("addressSize")),
                start=_int(row.get("start")),
                entry_point=_int(row.get("entryPoint")),
                path=paths.get(row.get("openItem", ""), ""),
                active=_bool(row.get("active")),
                created=_bool(row.get("created")),
            )
        )
    return views


def active_handle(client: McpClient) -> str | None:
    result = call(client, "bn_binary_view_get_active")
    view = (result.structured or {}).get("binaryView") or {}
    return str(view.get("handle")) if view.get("handle") else None


def set_active(client: McpClient, handle: str) -> None:
    call(client, "bn_binary_view_set_active", binaryView=handle)


def find_view_for_path(views: list[McpView], path: Path) -> McpView | None:
    """The view of an already open file (or of its .bndb database)."""
    wanted = {str(path), str(path.resolve())}
    database = {f"{item}.bndb" for item in wanted} | {
        str(path.with_suffix(".bndb")),
        str(path.resolve().with_suffix(".bndb")),
    }
    for view in views:
        if view.path in wanted:
            return view
    for view in views:
        if view.path in database:
            return view
    return None


def open_path(client: McpClient, path: Path) -> McpView:
    """Open ``path`` in Binary Ninja and return its main view.

    The file stays open afterwards: Binary Ninja's UI only closes a file whose
    analysis changed it through its save prompt, which must not pop up from a
    batch export.
    """
    result = call(
        client, "bn_open_item_open", path=str(path), kind="file", setActive=False
    )
    payload = result.structured or {}
    item = str((payload.get("openItem") or {}).get("handle") or "")
    for view in list_views(client):
        if view.open_item == item:
            return view
    raise BackendError(f"Binary Ninja opened {path} but created no analyzable view")


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------


class BinjaMcpSession:
    """DecompilerSession driving Binary Ninja through its MCP server."""

    backend_name: BackendName = "binja"
    backend_label = "Binary Ninja (MCP)"
    decompiler_label = "Binary Ninja (Pseudo C)"
    analysis_command: str | None = None
    parallel_safe = False  # one server-wide active view: render serially

    def __init__(self, client: McpClient, view: McpView) -> None:
        self.client = client
        self.view = view
        self._previous = active_handle(client)
        self._calls = 0
        set_active(client, view.handle)
        self._functions: dict[int, dict[str, Any]] | None = None
        self._imports: set[int] = set()
        self._segments: list[tuple[int, int, str]] | None = None
        self._disasm_cache: dict[int, str] = {}

    # -- plumbing -----------------------------------------------------------

    def _call(self, tool: str, **arguments: Any) -> ToolResult:
        self._ensure_active()
        return call(self.client, tool, **arguments)

    def _paged(self, tool: str, **arguments: Any) -> Iterator[dict[str, str]]:
        self._ensure_active()
        return paged(self.client, tool, **arguments)

    def _ensure_active(self) -> None:
        self._calls += 1
        if self._calls % ACTIVE_CHECK_EVERY:
            return
        if active_handle(self.client) != self.view.handle:
            # Another MCP client (or the user) switched views mid-export.
            set_active(self.client, self.view.handle)

    # -- lifecycle ----------------------------------------------------------

    def analyze(self) -> None:
        status = self._call("bn_analysis_status").structured or {}
        state = str((status.get("analysis") or {}).get("state", ""))
        if state and state != "IdleState":
            # Analysis of a freshly opened file runs in Binary Ninja; wait for it.
            self.client.call("bn_analysis_update_and_wait", {}, timeout=None)

    def close(self) -> None:
        try:
            if self._previous and self._previous != self.view.handle:
                set_active(self.client, self._previous)
        except BackendError:
            pass

    def ensure_decompiler(self) -> None:
        return None  # Pseudo C always ships with Binary Ninja

    # -- metadata -------------------------------------------------------------

    def info(self) -> dict[str, Any]:
        view = self.view
        os_name = view.platform.split("-", 1)[0] if view.platform else "unknown"
        return {
            "bin": {
                "arch": view.architecture or "unknown",
                "bits": view.address_size * 8,
                "baddr": view.start,
                "os": os_name,
                "format": view.view_type,
                "class": view.view_type,
                "type": view.view_type,
            },
            "tocode": {"input_path": view.path},
        }

    def entries(self) -> list[dict[str, Any]]:
        seen: set[int] = set()
        rows: list[dict[str, Any]] = []
        if self.view.entry_point:
            seen.add(self.view.entry_point)
            rows.append({"vaddr": self.view.entry_point})
        for row in self._paged("bn_entry_point_list"):
            address = _int(row.get("function") or row.get("address"))
            if address and address not in seen:
                seen.add(address)
                rows.append({"vaddr": address})
        return rows

    def _segment_list(self) -> list[tuple[int, int, str]]:
        if self._segments is None:
            self._segments = [
                (
                    _int(row.get("start")),
                    _int(row.get("end")),
                    ("r" if _bool(row.get("readable")) else "-")
                    + ("w" if _bool(row.get("writable")) else "-")
                    + ("x" if _bool(row.get("executable")) else "-"),
                )
                for row in self._paged("bn_segment_list")
            ]
        return self._segments

    def _perms_at(self, address: int) -> str:
        for start, end, perms in self._segment_list():
            if start <= address < end:
                return perms
        return "---"

    def sections(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for row in self._paged("bn_section_list"):
            start = _int(row.get("start"))
            length = _int(row.get("length"))
            rows.append(
                {
                    "name": row.get("section") or f"sec_{start:x}",
                    "size": length,
                    "vsize": length,
                    "type": row.get("typeName", ""),
                    "perm": self._perms_at(start),
                    "paddr": start,
                    "vaddr": start,
                }
            )
        return rows

    def imports(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for row in self._paged("bn_import_list"):
            address = _int(row.get("symbol"))
            name = row.get("name", "")
            if not name or (address, name) in seen:
                continue
            seen.add((address, name))
            namespace = row.get("namespace", "")
            library = (
                None if not namespace or namespace == _INTERNAL_NAMESPACE else namespace
            )
            self._imports.add(address)
            rows.append(
                {
                    "plt": address,
                    "name": name,
                    "bind": library,
                    "dll": library,
                    "type": "import",
                    "delay": False,
                }
            )
        return rows

    def exports(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[int] = set()
        for row in self._paged("bn_export_list"):
            if row.get("binding") not in ("GlobalBinding", "WeakBinding"):
                continue
            address = _int(row.get("symbol"))
            if address in seen:
                continue
            seen.add(address)
            ordinal = _int(row.get("ordinal"))
            rows.append(
                {
                    "name": row.get("name", ""),
                    "vaddr": address,
                    "bind": "GLOBAL"
                    if row.get("binding") == "GlobalBinding"
                    else "WEAK",
                    "type": "export",
                    "ordinal": ordinal or None,
                    "is_forwarder": False,
                    "forwarder_target": None,
                }
            )
        return rows

    def symbols(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for row in self._paged("bn_symbol_list"):
            address = _int(row.get("symbol"))
            name = row.get("name", "")
            kind = row.get("type", "")
            rows.append(
                {
                    "name": name,
                    "flagname": name,
                    "realname": row.get("fullName") or name,
                    "size": 0,
                    "type": kind,
                    "vaddr": address,
                    "paddr": address,
                    "is_imported": "Import" in kind,
                }
            )
        return rows

    def relocations(self) -> list[dict[str, Any]]:
        return [
            {
                "name": row.get("symbolName", ""),
                "type": row.get("type", ""),
                "vaddr": _int(row.get("address")),
                "paddr": _int(row.get("address")),
                "is_ifunc": False,
            }
            for row in self._paged("bn_relocation_list")
        ]

    def strings(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        sections = [
            (row["vaddr"], row["vaddr"] + row["size"], row["name"])
            for row in self.sections()
        ]
        for row in self._paged("bn_string_list", previewBytes=256):
            address = _int(row.get("string"))
            length = _int(row.get("length"))
            kind = row.get("type", "AsciiString")
            try:
                raw = bytes.fromhex(row.get("previewHex", "") or "")
            except ValueError:
                raw = (row.get("previewEscaped", "") or "").encode("utf-8")
            if _bool(row.get("previewTruncated")) and length > len(raw):
                raw = self._read(address, min(length, MAX_STRING_BYTES)) or raw
            rows.append(
                {
                    "vaddr": address,
                    "paddr": address,
                    "size": length,
                    "length": length,
                    "section": next(
                        (
                            name
                            for start, end, name in sections
                            if start <= address < end
                        ),
                        "",
                    ),
                    "type": kind,
                    "string": _decode_string(raw, kind),
                }
            )
        return rows

    def read_bytes(self, address: int, size: int) -> bytes | None:
        """Section bytes from Binary Ninja's view (the input may be a .bndb)."""
        chunks: list[bytes] = []
        offset = 0
        while offset < size:
            chunk = self._read(address + offset, min(MAX_STRING_BYTES, size - offset))
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks) + b"\0" * (size - offset) if chunks else None

    def _read(self, address: int, length: int) -> bytes | None:
        try:
            result = self._call(
                "bn_memory_read", address=f"0x{address:x}", length=length
            )
        except BackendError:
            return None
        hex_text = (result.structured or {}).get("hex")
        return bytes.fromhex(hex_text) if isinstance(hex_text, str) else None

    def flags(self) -> list[dict[str, Any]]:
        return []

    def _function_rows(self) -> dict[int, dict[str, Any]]:
        if self._functions is None:
            if not self._imports:
                self.imports()
            rows: dict[int, dict[str, Any]] = {}
            for row in self._paged("bn_function_list"):
                address = _int(row.get("function"))
                if address in rows:
                    continue  # same start in another architecture (thumb/arm)
                rows[address] = row
            self._functions = rows
        return self._functions

    def functions(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for address, row in self._function_rows().items():
            name = row.get("name") or f"sub_{address:x}"
            definition = row.get("definition", "")
            return_type, params = _split_definition(definition)
            is_import = address in self._imports
            is_thunk = is_import or name.startswith("j_")
            size = max(
                _int(row.get("highestAddress")) - _int(row.get("lowestAddress")) + 1, 0
            )
            rows.append(
                {
                    "addr": address,
                    "name": name,
                    "size": size,
                    "signature": _signature(name, return_type, params),
                    "calltype": None,
                    "noreturn": False,
                    "stackframe": 0,
                    "nlocals": 0,
                    "nargs": len(params),
                    "outdegree": 0,
                    "indegree": 0,
                    "is_library": is_import,
                    "is_thunk": is_thunk,
                    "source_kind": _classify(
                        name, is_import=is_import, is_thunk=is_thunk
                    ),
                    "return_type": return_type,
                    "params": params,
                }
            )
        return rows

    def types(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for index, row in enumerate(self._paged("bn_type_list")):
            if index >= MAX_TYPES:
                break
            name = row.get("type", "")
            if not name:
                continue
            c_decl = row.get("definition", "")
            try:
                info = (self._call("bn_type_info", type=name).structured or {}).get(
                    "type"
                ) or {}
                c_decl = str(info.get("source") or c_decl)
            except BackendError:
                pass
            rows.append(
                {
                    "name": name,
                    "kind": _type_kind(row.get("class", "")),
                    "size": _int(row.get("width")) or None,
                    "c_decl": c_decl,
                }
            )
        return rows

    # -- per function -------------------------------------------------------

    def disasm(self, address: int) -> str:
        address = int(address)
        if address not in self._disasm_cache:
            body = paged_text(
                self.client, "bn_function_disassembly", function=f"0x{address:x}"
            )
            self._ensure_active()
            lines = []
            for line in body.splitlines():
                match = _DISASM_RX.match(line.strip())
                if match:
                    lines.append(f"{match.group(1)}: {match.group(2)}".rstrip())
            self._disasm_cache[address] = "\n".join(lines)
        return self._disasm_cache[address]

    def decompile(self, address: int) -> str:
        address = int(address)
        self._ensure_active()
        try:
            body = paged_text(
                self.client, "bn_function_decompile", function=f"0x{address:x}"
            )
        except BackendError as exc:
            row = self._function_rows().get(address, {})
            name = row.get("name") or f"sub_{address:x}"
            return f"int {name}()\n{{\n    /* Binary Ninja: {exc} */\n}}\n"
        text = _strip_gutter(body).strip("\n")
        if not text.strip():
            row = self._function_rows().get(address, {})
            name = row.get("name") or f"sub_{address:x}"
            return_type, params = _split_definition(row.get("definition", ""))
            return f"{_signature(name, return_type, params)}\n{{\n}}\n"
        return text + "\n"

    def function_summary(self, address: int) -> str:
        address = int(address)
        row = self._function_rows().get(address)
        if row is None:
            return f"signature: sub_{address:x}\naddress: 0x{address:x}\nargs: 0\nlocals: 0"
        name = row.get("name") or f"sub_{address:x}"
        return_type, params = _split_definition(row.get("definition", ""))
        size = max(
            _int(row.get("highestAddress")) - _int(row.get("lowestAddress")) + 1, 0
        )
        return "\n".join(
            [
                f"signature: {_signature(name, return_type, params)}",
                f"address: 0x{address:x}",
                f"size: {size} bytes",
                f"basic blocks: {row.get('basicBlockCount', '?')}",
                f"args: {len(params)}",
                "locals: 0",
            ]
        )

    def calls_from(
        self, address: int, imports: Any, functions: Any
    ) -> tuple[list[int], list[str]]:
        address = int(address)
        edges: set[int] = set()
        imported: set[str] = set()
        try:
            rows = list(self._paged("bn_function_callees", function=f"0x{address:x}"))
        except BackendError:
            return [], []
        for row in rows:
            target = _int(row.get("Callee Address"))
            if target == address or not target:
                continue
            routine = functions.get(target)
            if routine is not None and not getattr(routine, "imported", False):
                edges.add(target)
                continue
            if target in imports:
                imported.add(imports[target].name)
            elif routine is not None:
                imported.add(routine.name)
            else:
                match = _CALLEE_NAME_RX.match(row.get("Callee Functions", ""))
                imported.add(match.group(1) if match else f"sub_{target:x}")
        return sorted(edges), sorted(imported)

    def data_xrefs(self, addresses: Any) -> dict[int, list[tuple[int, bool]]]:
        return {}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _split_definition(definition: str) -> tuple[str | None, list[dict[str, str]]]:
    """``"int32_t(char* arg1, int32_t arg2)"`` -> return type, parameters."""
    text = definition.strip()
    if not text.endswith(")"):
        return (text or None), []
    depth = 0
    for index in range(len(text) - 1, -1, -1):
        char = text[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return_type = text[:index].strip() or None
                inner = text[index + 1 : -1]
                return return_type, _parameters(inner)
    return (text or None), []


def _parameters(text: str) -> list[dict[str, str]]:
    if not text.strip() or text.strip() == "void":
        return []
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "(<[":
            depth += 1
        elif char in ")>]":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    parts.append("".join(current).strip())
    params: list[dict[str, str]] = []
    for index, part in enumerate(parts):
        if part == "...":
            params.append({"name": "...", "type": "..."})
            continue
        match = re.match(r"^(.*?[\s*&])([A-Za-z_][A-Za-z0-9_]*)$", part)
        if match:
            params.append({"name": match.group(2), "type": match.group(1).strip()})
        else:
            params.append({"name": f"arg{index + 1}", "type": part})
    return params


def _signature(name: str, return_type: str | None, params: list[dict[str, str]]) -> str:
    args = ", ".join(
        "..." if item["name"] == "..." else f"{item['type']} {item['name']}".strip()
        for item in params
    )
    return f"{return_type or 'int'} {name}({args or 'void'})"


def _classify(name: str, *, is_import: bool, is_thunk: bool) -> str:
    if is_thunk:
        return "thunk"
    if is_import:
        return "library"
    lowered = name.lower()
    if lowered in _RUNTIME_NAMES or lowered.startswith(_RUNTIME_PREFIXES):
        return "runtime"
    return "app"


def _type_kind(type_class: str) -> str:
    return {
        "StructureTypeClass": "struct",
        "EnumerationTypeClass": "enum",
        "NamedTypeReferenceClass": "typedef",
        "FunctionTypeClass": "func",
        "IntegerTypeClass": "base",
        "FloatTypeClass": "base",
        "BoolTypeClass": "base",
        "PointerTypeClass": "typedef",
        "ArrayTypeClass": "typedef",
    }.get(type_class, "type")


def _decode_string(raw: bytes, kind: str) -> str:
    lowered = kind.lower()
    if "utf16" in lowered or "wide" in lowered:
        return raw.decode("utf-16-le", errors="replace").rstrip("\0")
    if "utf32" in lowered:
        return raw.decode("utf-32-le", errors="replace").rstrip("\0")
    return raw.decode("utf-8", errors="replace").rstrip("\0")
