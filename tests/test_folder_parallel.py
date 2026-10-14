"""Folder exports with several binaries at once (--parallel-files)."""

from __future__ import annotations

import json
from pathlib import Path
import threading
import time
from typing import Any

import pytest

from test_folder import FakeExporter, _app
from tocode import apk_native, cli
from tocode import folder as folder_module
from tocode.apk_native import ExportKilledError, NativeLib, NativeRunner
from tocode.errors import ToCodeError
from tocode.folder import DONE, PENDING, FolderOptions, export_folder
from tocode.parallel import choose_parallel_files
from tocode.progress import Progress


# -- sizing ------------------------------------------------------------------


def test_explicit_values_are_honored() -> None:
    assert choose_parallel_files(
        pending=10, requested_files=3, requested_jobs=4, cpu_count=2
    ) == (3, None)
    # Never more files at once than are left to export.
    assert choose_parallel_files(
        pending=2, requested_files=8, requested_jobs=None, cpu_count=16
    ) == (2, 8)


def test_auto_splits_cpus_between_files() -> None:
    # -j auto: one file per CPU, each allowed two workers for a big binary.
    assert choose_parallel_files(
        pending=50, requested_files=None, requested_jobs=None, cpu_count=8
    ) == (8, 2)
    # At most MAX_AUTO_PARALLEL_FILES; the spare CPUs go to each file's workers.
    assert choose_parallel_files(
        pending=50, requested_files=None, requested_jobs=None, cpu_count=64
    ) == (16, 4)
    # -j 4: one file per four CPUs, -j is left alone.
    assert choose_parallel_files(
        pending=50, requested_files=None, requested_jobs=4, cpu_count=16
    ) == (4, None)
    # One file at a time keeps the export's own worker choice.
    assert choose_parallel_files(
        pending=50, requested_files=None, requested_jobs=None, cpu_count=1
    ) == (1, None)


def test_auto_is_capped_by_free_memory() -> None:
    assert choose_parallel_files(
        pending=50,
        requested_files=None,
        requested_jobs=None,
        cpu_count=64,
        available_memory_mb=3000,
        file_memory_mb=1024,
    ) == (2, 32)


# -- runner -------------------------------------------------------------------


def _libs(tmp_path: Path, count: int) -> list[NativeLib]:
    return [
        NativeLib(
            abi="x",
            name=f"lib{index}.so",
            entry=f"lib{index}.so",
            source_apk="folder",
            size=index,
            sha256="",
            path=tmp_path / f"lib{index}.so",
            export_dir=tmp_path / "out" / f"lib{index}",
        )
        for index in range(count)
    ]


class SlowExporter:
    """Records how many exports run at once; ``kill`` names fail like an OOM kill."""

    def __init__(self, seconds: float = 0.05, kill: dict[str, int] | None = None):
        self.seconds = seconds
        self.kill = dict(kill or {})
        self.lock = threading.Lock()
        self.active: set[str] = set()
        self.peak = 0
        self.calls: list[str] = []

    def __call__(self, lib: NativeLib, out_dir: Path, progress: Progress):
        with self.lock:
            self.calls.append(lib.entry)
            self.active.add(lib.entry)
            self.peak = max(self.peak, len(self.active))
        try:
            time.sleep(self.seconds)
            with self.lock:
                left = self.kill.get(lib.entry, 0)
                if left:
                    self.kill[lib.entry] = left - 1
            if left:
                raise ExportKilledError("export process was killed by signal 9")
            return ("fake", "fake", 1, 0)
        finally:
            with self.lock:
                self.active.discard(lib.entry)


def _run(
    tmp_path: Path, libs: list[NativeLib], exporter, **kwargs: Any
) -> NativeRunner:
    runner = NativeRunner(
        libs=libs,
        root=tmp_path,
        progress=Progress(enabled=False),
        exporter=exporter,
        mirror_logs=False,
        quiet=True,
        poll_seconds=0.01,
        **kwargs,
    )
    runner.start()
    runner.join()
    return runner


def test_runner_keeps_the_slots_full(tmp_path: Path) -> None:
    libs = _libs(tmp_path, 7)
    exporter = SlowExporter()
    _run(tmp_path, libs, exporter, parallel=3)
    assert exporter.peak == 3
    assert all(lib.status == "done" for lib in libs)
    assert sorted(exporter.calls) == sorted(lib.entry for lib in libs)


def test_runner_holds_back_while_memory_is_short(tmp_path: Path) -> None:
    libs = _libs(tmp_path, 4)
    exporter = SlowExporter()
    # 150 MB free: one export (100 MB) fits, a second beside a starting one
    # (2 x 100 MB) does not.
    _run(
        tmp_path,
        libs,
        exporter,
        parallel=4,
        min_free_mb=100,
        available_memory=lambda: 150,
    )
    assert exporter.peak == 1
    assert all(lib.status == "done" for lib in libs)


def test_killed_export_is_retried_alone_once(tmp_path: Path) -> None:
    libs = _libs(tmp_path, 4)
    exporter = SlowExporter(kill={"lib0.so": 1})
    _run(tmp_path, libs, exporter, parallel=4)
    assert exporter.calls.count("lib0.so") == 2
    assert all(lib.status == "done" for lib in libs)

    # Killed again alone: a real failure, not another retry.
    libs = _libs(tmp_path, 3)
    exporter = SlowExporter(kill={"lib0.so": 5})
    runner = _run(tmp_path, libs, exporter, parallel=3)
    assert exporter.calls.count("lib0.so") == 2
    assert libs[0].status.startswith("failed: export process was killed")
    assert runner.errors


def test_retry_waits_for_the_others_and_runs_alone(tmp_path: Path) -> None:
    libs = _libs(tmp_path, 3)
    seen: list[tuple[str, int]] = []
    exporter = SlowExporter(kill={"lib1.so": 1})
    original = exporter.__call__

    def recording(lib: NativeLib, out_dir: Path, progress: Progress):
        with exporter.lock:
            seen.append((lib.entry, len(exporter.active)))
        return original(lib, out_dir, progress)

    _run(tmp_path, libs, recording, parallel=3)
    retry = [active for entry, active in seen if entry == "lib1.so"][-1]
    assert retry == 0  # nothing else was running when the retry started
    assert all(lib.status == "done" for lib in libs)


def test_sequential_runner_never_retries(tmp_path: Path) -> None:
    libs = _libs(tmp_path, 2)
    exporter = SlowExporter(kill={"lib0.so": 1})
    _run(tmp_path, libs, exporter, parallel=1)
    assert exporter.calls.count("lib0.so") == 1
    assert libs[0].status.startswith("failed")


# -- folder -------------------------------------------------------------------


class SlowFakeExporter(FakeExporter):
    def __init__(self, seconds: float = 0.05) -> None:
        super().__init__()
        self.seconds = seconds
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0

    def __call__(self, lib: NativeLib, out_dir: Path, progress: Progress):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.seconds)
            return super().__call__(lib, out_dir, progress)
        finally:
            with self.lock:
                self.active -= 1


def _export(root: Path, tmp_path: Path, exporter, **kwargs: Any):
    options = FolderOptions(out_dir=tmp_path / "out", **kwargs)
    return export_folder(
        root, options=options, progress=Progress(enabled=False), exporter=exporter
    )


def test_folder_exports_files_in_parallel_biggest_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _app(tmp_path / "app")
    sizes = {
        relpath: (root / relpath).stat().st_size
        for relpath in ("bin/app", "lib/libfoo.so.1", "lib/libbar.so")
    }
    queued: list[list[str]] = []

    class Recording(NativeRunner):
        def start(self) -> None:
            queued.append([lib.entry for lib in self.libs])
            super().start()

    monkeypatch.setattr(folder_module, "NativeRunner", Recording)
    exporter = SlowFakeExporter()
    summary = _export(root, tmp_path, exporter, parallel_files=3)

    assert exporter.peak > 1
    assert all(job.status == DONE for job in summary.jobs if job.relpath in sizes)
    order = [entry for entry in queued[0] if entry in sizes]
    assert order == sorted(sizes, key=lambda relpath: -sizes[relpath])
    state = json.loads((tmp_path / "out/.tocode-folder/state.json").read_text())
    assert {relpath for relpath in sizes} <= set(state["jobs"])
    assert all(state["jobs"][relpath]["status"] == DONE for relpath in sizes)
    # The links are joined after every export finished, as before.
    mappings = json.loads((tmp_path / "out/mappings.json").read_text())
    assert any(row["symbol"] == "foo_add" for row in mappings["links"])


def test_one_file_at_a_time_keeps_load_order(tmp_path: Path) -> None:
    root = _app(tmp_path / "app")
    exporter = FakeExporter()
    _export(root, tmp_path, exporter, parallel_files=1)
    assert exporter.calls[0] == "bin/app"  # executables first, as before


def test_interrupt_keeps_running_exports_pending_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _app(tmp_path / "app")
    killed = threading.Event()
    started = threading.Event()

    class Blocking(FakeExporter):
        def __call__(self, lib: NativeLib, out_dir: Path, progress: Progress):
            if lib.entry == "bin/app":
                return super().__call__(lib, out_dir, progress)
            started.set()
            # Runs until Ctrl-C kills it, like a real export process.
            killed.wait(5)
            raise ToCodeError("export process was killed by signal 9")

    monkeypatch.setattr(apk_native, "terminate_active_native_children", killed.set)
    real_refresh = folder_module.FolderDisplay.refresh

    def refresh(self, runner) -> None:
        real_refresh(self, runner)
        if started.is_set() and any(job.status == DONE for job in self.jobs):
            raise KeyboardInterrupt

    monkeypatch.setattr(folder_module.FolderDisplay, "refresh", refresh)
    monkeypatch.setattr(folder_module, "DISPLAY_REFRESH_SECONDS", 0.01)
    summary = _export(root, tmp_path, Blocking(), parallel_files=3)

    assert summary.interrupted
    statuses = {job.relpath: job.status for job in summary.jobs}
    assert statuses["bin/app"] == DONE
    # Killed by the interrupt: pending, never recorded as failed.
    assert statuses["lib/libfoo.so.1"] == PENDING
    assert statuses["lib/libbar.so"] == PENDING
    state = json.loads((tmp_path / "out/.tocode-folder/state.json").read_text())
    assert set(state["jobs"]) == {"bin/app"}

    monkeypatch.setattr(folder_module.FolderDisplay, "refresh", real_refresh)
    again = FakeExporter()
    summary = _export(root, tmp_path, again, parallel_files=3)
    assert sorted(again.calls) == ["lib/libbar.so", "lib/libfoo.so.1"]
    assert not summary.interrupted


def test_cli_passes_parallel_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[FolderOptions] = []

    def fake_export_folder(folder, *, options, progress):
        seen.append(options)
        raise ToCodeError("stop here")

    monkeypatch.setattr(folder_module, "export_folder", fake_export_folder)
    root = _app(tmp_path / "app")
    assert cli.main([str(root), "--parallel-files", "4", "-j", "2", "-q"]) == 1
    assert seen[0].parallel_files == 4 and seen[0].jobs == 2
    assert cli.main([str(root), "-pf", "3", "-q"]) == 1
    assert seen[1].parallel_files == 3


def test_cli_rejects_parallel_files_for_one_file(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF" + bytes(64))
    with pytest.raises(SystemExit):
        cli.main([str(binary), "--parallel-files", "2"])
    assert "--parallel-files applies to folder input" in capsys.readouterr().err
