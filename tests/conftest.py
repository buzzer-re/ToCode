from __future__ import annotations

from pathlib import Path

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


@pytest.fixture
def export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A ToCode export of the fake Binary Ninja program, with its own .bndb."""
    import importlib.util
    import sys

    from live_client import FAKE_DIR, drop_binaryninja_modules, make_fake_export

    drop_binaryninja_modules()
    if importlib.util.find_spec("binaryninja") is not None:
        pytest.skip("a real Binary Ninja API is importable in this environment")
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.delenv("TOCODE_DISABLE_BINJA_HEADLESS", raising=False)
    monkeypatch.setenv("TOCODE_BINJA_DIR", str(FAKE_DIR))
    monkeypatch.setenv("TOCODE_BINJA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("TOCODE_FUNCTION_TIMEOUT_SECONDS", "0")
    return make_fake_export(tmp_path)
