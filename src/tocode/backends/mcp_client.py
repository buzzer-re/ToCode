"""Minimal MCP client (JSON-RPC over streamable HTTP), standard library only.

Enough of the Model Context Protocol to call tools on a local server such as
Binary Ninja's built-in MCP: ``initialize``, ``notifications/initialized``,
``tools/list``, and ``tools/call``. Responses may come back as plain JSON or
as a server-sent event stream; both are handled.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any
import urllib.error
import urllib.request

from ..errors import BackendError

PROTOCOL_VERSION = "2025-11-25"
CLIENT_INFO = {"name": "tocode", "version": "1"}


@dataclass(slots=True)
class ToolResult:
    text: str
    structured: dict[str, Any] | None
    is_error: bool


class McpClient:
    def __init__(self, url: str, *, timeout: float | None = 600.0) -> None:
        self.url = url
        self.timeout = timeout
        self.session_id: str | None = None
        self.server_info: dict[str, Any] = {}
        self.instructions: str = ""
        self._next_id = 0

    # -- protocol -------------------------------------------------------------

    def connect(self, *, timeout: float | None = None) -> "McpClient":
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
            timeout=timeout,
        )
        self.server_info = dict(result.get("serverInfo") or {})
        self.instructions = str(result.get("instructions") or "")
        self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            timeout=timeout,
        )
        return self

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            result = self._request("tools/list", params)
            tools.extend(result.get("tools") or [])
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> ToolResult:
        result = self._request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
            timeout=timeout,
        )
        texts = [
            str(item.get("text", ""))
            for item in result.get("content") or []
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        structured = result.get("structuredContent")
        return ToolResult(
            text="\n".join(texts),
            structured=structured if isinstance(structured, dict) else None,
            is_error=bool(result.get("isError", False)),
        )

    # -- transport ------------------------------------------------------------

    def _request(
        self, method: str, params: dict[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        messages = self._post(payload, timeout=timeout)
        for message in messages:
            if message.get("id") != request_id:
                continue
            if "error" in message:
                error = message["error"] or {}
                raise BackendError(
                    f"MCP {method} failed: {error.get('message', error)}"
                )
            result = message.get("result")
            return result if isinstance(result, dict) else {}
        raise BackendError(f"MCP server sent no response to {method}")

    def _post(
        self, payload: dict[str, Any], *, timeout: float | None = None
    ) -> list[dict[str, Any]]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout if timeout is None else timeout
            ) as response:
                session = response.headers.get("MCP-Session-Id")
                if session:
                    self.session_id = session
                content_type = response.headers.get("Content-Type", "")
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise BackendError(
                f"MCP server at {self.url} returned HTTP {exc.code}: {detail}"
            ) from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise BackendError(
                f"could not reach the MCP server at {self.url}: {exc}"
            ) from exc
        if not body.strip():
            return []
        if "text/event-stream" in content_type:
            return _sse_messages(body)
        try:
            decoded = json.loads(body)
        except ValueError as exc:
            raise BackendError(f"MCP server sent invalid JSON: {body[:200]}") from exc
        if isinstance(decoded, list):
            return [item for item in decoded if isinstance(item, dict)]
        return [decoded] if isinstance(decoded, dict) else []


def _sse_messages(body: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    data: list[str] = []
    for line in body.splitlines() + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif not line.strip() and data:
            try:
                decoded = json.loads("\n".join(data))
            except ValueError:
                decoded = None
            if isinstance(decoded, dict):
                messages.append(decoded)
            data = []
    return messages


# --------------------------------------------------------------------------
# Text result helpers (Binary Ninja renders lists as Markdown tables)
# --------------------------------------------------------------------------

_FRONT_MATTER_RX = re.compile(r"^---\n(.*?)\n---\n", re.S)


def front_matter(text: str) -> dict[str, Any]:
    """The ``---`` YAML-ish header of a tool result (simple ``key: value`` lines)."""
    match = _FRONT_MATTER_RX.match(text)
    if match is None:
        return {}
    meta: dict[str, Any] = {}
    for line in match.group(1).splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        meta[key.strip()] = _scalar(value.strip())
    return meta


def _scalar(value: str) -> Any:
    if value in ("null", "~", ""):
        return None
    if value in ("true", "false"):
        return value == "true"
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except ValueError:
            return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def split_row(line: str) -> list[str]:
    """Cells of a Markdown table row; ``\\|`` is a literal pipe."""
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|") and not text.endswith("\\|"):
        text = text[:-1]
    cells: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in "|\\":
            current.append(text[index + 1])
            index += 2
            continue
        if char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    cells.append("".join(current).strip())
    return cells


def markdown_tables(text: str) -> list[list[dict[str, str]]]:
    """Every table in ``text`` as a list of ``{header: cell}`` rows."""
    tables: list[list[dict[str, str]]] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines) - 1:
        line = lines[index]
        divider = lines[index + 1].strip()
        if (
            line.lstrip().startswith("|")
            and divider.startswith("|")
            and set(divider) <= set("|-: ")
        ):
            headers = split_row(line)
            rows: list[dict[str, str]] = []
            index += 2
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                cells = split_row(lines[index])
                rows.append(
                    dict(zip(headers, cells + [""] * (len(headers) - len(cells))))
                )
                index += 1
            tables.append(rows)
            continue
        index += 1
    return tables


_FENCE_RX = re.compile(r"^(`{3,}|~{3,})[^\n]*\n(.*?)^\1\s*$", re.S | re.M)


def fenced_body(text: str) -> str | None:
    """The content of the first fenced code block, or None."""
    match = _FENCE_RX.search(text)
    return match.group(2) if match else None
