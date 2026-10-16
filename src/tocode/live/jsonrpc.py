"""MCP over stdio: newline-delimited JSON-RPC 2.0, standard library only.

Requests are answered on worker threads so a slow call on one session does
not hold up the others; responses are written whole, one per line, under a
lock. Only protocol messages reach the protocol stream: the caller hands in
a private copy of the original stdout (see ``server.protect_stdout``).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import json
import threading
import traceback
from typing import Any, BinaryIO, Callable

SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


@dataclass
class ToolCall:
    """What a tool handler gets besides its arguments."""

    name: str
    arguments: dict[str, Any]
    progress_token: Any = None
    notify: Callable[[str, dict[str, Any]], None] = lambda _method, _params: None

    def progress(self, done: float, total: float | None, message: str = "") -> None:
        if self.progress_token is None:
            return
        params: dict[str, Any] = {
            "progressToken": self.progress_token,
            "progress": done,
        }
        if total is not None:
            params["total"] = total
        if message:
            params["message"] = message
        self.notify("notifications/progress", params)


@dataclass
class McpApp:
    """The server's identity and tool table, independent of the transport."""

    name: str
    version: str
    instructions: str
    list_tools: Callable[[], list[dict[str, Any]]]
    call_tool: Callable[[ToolCall], dict[str, Any]]
    on_shutdown: Callable[[], None] = lambda: None
    handlers: dict[str, Callable[[dict[str, Any]], Any]] = field(default_factory=dict)


class StdioServer:
    def __init__(
        self,
        app: McpApp,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        max_workers: int = 8,
        log: Callable[[str], None] = lambda _message: None,
    ) -> None:
        self.app = app
        self.reader = reader
        self.writer = writer
        self.log = log
        self._write_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="tocode-mcp"
        )
        self._initialized = False

    # -- transport -------------------------------------------------------------

    def serve_forever(self) -> None:
        try:
            for raw in self.reader:
                line = raw.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    self._send_error(None, PARSE_ERROR, "invalid JSON")
                    continue
                if isinstance(message, list):
                    # Batches were removed from MCP; answer each element.
                    for item in message:
                        self._dispatch(item)
                else:
                    self._dispatch(message)
        finally:
            self._pool.shutdown(wait=True, cancel_futures=False)
            self.app.on_shutdown()

    def send(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with self._write_lock:
            self.writer.write(data.encode("utf-8") + b"\n")
            self.writer.flush()

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def _send_result(self, request_id: Any, result: Any) -> None:
        self.send({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _send_error(
        self, request_id: Any, code: int, message: str, data: Any = None
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        self.send({"jsonrpc": "2.0", "id": request_id, "error": error})

    # -- dispatch ----------------------------------------------------------------

    def _dispatch(self, message: Any) -> None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            self._send_error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
            return
        method = message.get("method")
        request_id = message.get("id")
        if method is None:
            return  # a response to something we never send
        params = message.get("params") or {}
        if "id" not in message:
            self._notification(str(method), params)
            return
        if method in ("initialize", "ping", "tools/list"):
            # Cheap and ordered: answer inline.
            self._answer(request_id, str(method), params)
            return
        self._pool.submit(self._answer, request_id, str(method), params)

    def _notification(self, method: str, params: dict[str, Any]) -> None:
        if method == "notifications/initialized":
            self._initialized = True
        # notifications/cancelled and others: nothing to undo; the call
        # finishes and its late response is ignored by the client.

    def _answer(self, request_id: Any, method: str, params: dict[str, Any]) -> None:
        try:
            result = self._handle(method, params)
        except RpcError as exc:
            self._send_error(request_id, exc.code, exc.message, exc.data)
        except Exception as exc:  # noqa: BLE001 - never let a handler kill the server
            self.log(f"mcp: {method} failed: {traceback.format_exc()}")
            self._send_error(request_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
        else:
            self._send_result(request_id, result)

    def _handle(self, method: str, params: dict[str, Any]) -> Any:
        if method == "initialize":
            requested = str(params.get("protocolVersion") or "")
            version = (
                requested
                if requested in SUPPORTED_PROTOCOL_VERSIONS
                else LATEST_PROTOCOL_VERSION
            )
            return {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.app.name, "version": self.app.version},
                "instructions": self.app.instructions,
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self.app.list_tools()}
        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str):
                raise RpcError(INVALID_PARAMS, "tools/call needs a tool name")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise RpcError(INVALID_PARAMS, "tool arguments must be an object")
            meta = params.get("_meta") or {}
            call = ToolCall(
                name=name,
                arguments=arguments,
                progress_token=meta.get("progressToken")
                if isinstance(meta, dict)
                else None,
                notify=self.notify,
            )
            return self.app.call_tool(call)
        handler = self.app.handlers.get(method)
        if handler is not None:
            return handler(params)
        raise RpcError(METHOD_NOT_FOUND, f"unknown method {method}")
