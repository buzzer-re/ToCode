from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_native_memory_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exports in tests must not wait for free RAM on the host running them."""
    monkeypatch.setenv("TOCODE_NATIVE_MIN_FREE_MB", "0")
