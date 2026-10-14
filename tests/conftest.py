from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_native_memory_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exports in tests must not wait for free RAM on the host running them."""
    monkeypatch.setenv("TOCODE_NATIVE_MIN_FREE_MB", "0")


@pytest.fixture(autouse=True)
def _no_local_binary_ninja(monkeypatch: pytest.MonkeyPatch) -> None:
    """`auto` must not depend on a Binary Ninja installed on the test machine;
    tests that exercise the headless backend clear this explicitly."""
    monkeypatch.setenv("TOCODE_DISABLE_BINJA_HEADLESS", "1")
    # The CLI's --binja-license writes this variable; restore it after each test.
    monkeypatch.setenv("TOCODE_BINJA_LICENSE", "")
