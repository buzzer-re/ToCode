"""Reproduction and regression tests for the Windows atomic-write crash (#11).

`write_text_atomic` renames a temp file over the destination. On Windows that
rename fails with ``PermissionError`` (``WinError 5`` access-denied, or ``32``
sharing-violation) whenever another process — antivirus, the search indexer,
OneDrive — briefly holds the destination or the temp file open without
``FILE_SHARE_DELETE``. Under ``-j 8`` the checkpoint is rewritten on every
completed function, so such a collision eventually aborts the whole export.

The portable test reproduces the mechanism on any platform by monkeypatching the
rename; the Windows test reproduces the exact production failure with a real lock.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tocode.metadata import write_text_atomic


def _win_permission_error(winerror: int) -> PermissionError:
    exc = PermissionError(winerror, "Access is denied")
    # Mirror the OSError.winerror attribute CPython sets on Windows so the code
    # under test can distinguish transient lock errors from real ones.
    exc.winerror = winerror  # type: ignore[attr-defined]
    return exc


def _tmp_siblings(path: Path) -> list[Path]:
    return [p for p in path.parent.iterdir() if p.name != path.name]


def test_replace_retries_past_transient_lock(tmp_path, monkeypatch) -> None:
    """A few transient WinError 5 failures must not abort the write."""
    target = tmp_path / "checkpoint.json"
    real_replace = Path.replace
    calls = {"n": 0}

    def flaky_replace(self: Path, dst):
        calls["n"] += 1
        if calls["n"] <= 3:  # transient lock clears after a few attempts
            raise _win_permission_error(5)
        return real_replace(self, dst)

    monkeypatch.setattr(Path, "replace", flaky_replace)
    monkeypatch.setattr("tocode.metadata.time.sleep", lambda _s: None)

    write_text_atomic(target, "payload\n")

    assert calls["n"] == 4  # 3 failures + 1 success
    assert target.read_text(encoding="utf-8") == "payload\n"
    # No orphan .tmp left behind.
    assert _tmp_siblings(target) == []


def test_replace_gives_up_and_cleans_tmp_when_lock_never_clears(
    tmp_path, monkeypatch
) -> None:
    """A permanent lock still raises, but must not litter .tmp orphans."""
    target = tmp_path / "checkpoint.json"

    def always_locked(self: Path, dst):
        raise _win_permission_error(5)

    monkeypatch.setattr(Path, "replace", always_locked)
    monkeypatch.setattr("tocode.metadata.time.sleep", lambda _s: None)

    with pytest.raises(PermissionError):
        write_text_atomic(target, "payload\n")

    assert not target.exists()
    assert _tmp_siblings(target) == []


def test_non_windows_permission_error_is_not_retried(tmp_path, monkeypatch) -> None:
    """A PermissionError without a transient winerror re-raises immediately."""
    target = tmp_path / "checkpoint.json"
    calls = {"n": 0}

    def denied(self: Path, dst):
        calls["n"] += 1
        raise PermissionError(13, "Permission denied")  # e.g. read-only dir

    monkeypatch.setattr(Path, "replace", denied)
    monkeypatch.setattr("tocode.metadata.time.sleep", lambda _s: None)

    with pytest.raises(PermissionError):
        write_text_atomic(target, "payload\n")

    assert calls["n"] == 1  # not retried


# --- Faithful Windows reproduction with a real file lock ------------------

_WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32", reason="reproduces a Windows file-sharing error"
)


def _open_read_share_no_delete(path: Path):
    """Open ``path`` the way a scanner does: read-share, no delete-share.

    Returns a Windows HANDLE that blocks anyone from replacing/deleting the file
    until it is closed. Mirrors antivirus / OneDrive real-time access.
    """
    import ctypes
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.restype = wintypes.HANDLE
    handle = CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ,  # deliberately no FILE_SHARE_DELETE
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def _close_handle(handle) -> None:
    import ctypes

    ctypes.windll.kernel32.CloseHandle(handle)


@_WINDOWS_ONLY
def test_windows_permanent_lock_reproduces_winerror5(tmp_path) -> None:
    target = tmp_path / "checkpoint.json"
    target.write_text("old\n", encoding="utf-8")
    handle = _open_read_share_no_delete(target)
    try:
        with pytest.raises(PermissionError) as info:
            write_text_atomic(target, "new\n")
        assert getattr(info.value, "winerror", None) in (5, 32)
    finally:
        _close_handle(handle)


@_WINDOWS_ONLY
def test_windows_transient_lock_recovers(tmp_path) -> None:
    import threading
    import time

    target = tmp_path / "checkpoint.json"
    target.write_text("old\n", encoding="utf-8")
    handle = _open_read_share_no_delete(target)

    # Release the lock shortly after the write starts, as a scanner would.
    threading.Timer(0.15, lambda: _close_handle(handle)).start()

    started = time.monotonic()
    write_text_atomic(target, "new\n")  # retries until the lock clears
    assert target.read_text(encoding="utf-8") == "new\n"
    assert time.monotonic() - started >= 0.1
    assert _tmp_siblings(target) == []
