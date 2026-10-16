"""A minimal MCP stdio client for driving `tocode mcp` in tests and by hand.

python tests/live_client.py <export-or-binary> [tool json-args]...
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any

SRC = Path(__file__).resolve().parents[1] / "src"


class LiveClient:
    def __init__(self, *args: str, env: dict[str, str] | None = None) -> None:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(SRC), environment.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        environment.update(env or {})
        self.process = subprocess.Popen(
            [sys.executable, "-m", "tocode", "mcp", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self.stderr: list[str] = []
        self._next = 0
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self.initialize = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        )
        self.notify("notifications/initialized", {})

    def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        for raw in self.process.stderr:
            self.stderr.append(raw.decode("utf-8", "replace").rstrip())

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _send(self, payload: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(payload).encode() + b"\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next += 1
        request_id = self._next
        self._send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        assert self.process.stdout is not None
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError(
                    "server closed stdout:\n" + "\n".join(self.stderr[-30:])
                )
            message = json.loads(line)
            if message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message["result"]

    def tools(self) -> list[dict[str, Any]]:
        return self.request("tools/list", {})["tools"]

    def call(self, tool: str, /, **arguments: Any) -> dict[str, Any]:
        """structuredContent of a successful call; raises on a tool error."""
        result = self.request("tools/call", {"name": tool, "arguments": arguments})
        if result.get("isError"):
            raise ToolError(result["content"][0]["text"])
        return result.get("structuredContent") or {}

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def __enter__(self) -> "LiveClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class ToolError(RuntimeError):
    pass


FAKE_DIR = Path(__file__).resolve().parent / "fake_binja"


def fake_client(tmp_path: Path, *args: str) -> LiveClient:
    """`tocode mcp` running against the on-disk fake Binary Ninja API."""
    return LiveClient(
        *args,
        env={
            "TOCODE_BINJA_DIR": str(FAKE_DIR),
            "TOCODE_DISABLE_BINJA_HEADLESS": "",
            "TOCODE_BINJA_CACHE_DIR": str(tmp_path / "cache"),
            "FAKE_BINJA_LOG": str(tmp_path / "binja.log"),
            "TOCODE_FUNCTION_TIMEOUT_SECONDS": "0",
        },
    )


def drop_binaryninja_modules() -> None:
    for name in [
        m for m in sys.modules if m == "binaryninja" or m.startswith("binaryninja.")
    ]:
        sys.modules.pop(name, None)


def make_fake_export(tmp_path: Path) -> Path:
    """A ToCode export of the fake program, with its own .bndb.

    The caller sets TOCODE_BINJA_DIR (and friends) for this process first.
    """
    from tocode.analysis import create_analyzer
    from tocode.exporter import export_binary
    from tocode.progress import Progress

    drop_binaryninja_modules()
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"\x7fELF" + bytes(range(64)))
    out = tmp_path / "sample_decompiler"
    with create_analyzer(
        binary, backend="binja", binja_dir=FAKE_DIR, progress=Progress(enabled=False)
    ) as analyzer:
        export_binary(analyzer, out_dir=out, jobs=1)
    drop_binaryninja_modules()
    return out


if __name__ == "__main__":
    with LiveClient(sys.argv[1]) as client:
        for spec in sys.argv[2:]:
            name, _, raw = spec.partition("=")
            print(f"== {name}")
            print(
                json.dumps(
                    client.call(name, **(json.loads(raw) if raw else {})), indent=1
                )[:4000]
            )
