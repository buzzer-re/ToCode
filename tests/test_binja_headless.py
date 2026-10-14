"""Binary Ninja headless (the ``binaryninja`` API in process), against a fake API.

The fake lives in ``tests/fake_binja`` and is found through ``TOCODE_BINJA_DIR``
like a real install, so spawned render workers import it too.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

from tocode import analysis as analysis_module
from tocode import cli
from tocode.analysis import create_analyzer
from tocode.backends import base, binja_headless
from tocode.backends.base import (
    choose_backend,
    discover_binja_dir,
    probe_binja_headless,
)
from tocode.backends.binja_headless import (
    BinjaHeadlessSession,
    cached_database,
    headless_problem,
)
from tocode.errors import BackendError, ToCodeError
from tocode.exporter import TIMEOUT_WORKER_BACKENDS, export_binary
from tocode.parallel import choose_jobs
from tocode.progress import Progress

FAKE_DIR = Path(__file__).parent / "fake_binja"


def _drop_binaryninja_modules() -> None:
    for name in [
        m for m in sys.modules if m == "binaryninja" or m.startswith("binaryninja.")
    ]:
        sys.modules.pop(name, None)


@pytest.fixture
def fake_binja(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _drop_binaryninja_modules()
    if importlib.util.find_spec("binaryninja") is not None:
        pytest.skip("a real Binary Ninja API is importable in this environment")
    # bootstrap_binja prepends the API folder to sys.path; undo it afterwards.
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.delenv("TOCODE_DISABLE_BINJA_HEADLESS", raising=False)
    monkeypatch.setenv("TOCODE_BINJA_DIR", str(FAKE_DIR))
    monkeypatch.setenv("TOCODE_BINJA_CACHE_DIR", str(tmp_path / "cache"))
    log = tmp_path / "binja.log"
    monkeypatch.setenv("FAKE_BINJA_LOG", str(log))
    yield SimpleNamespace(dir=FAKE_DIR, log=log)
    _drop_binaryninja_modules()


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.elf"
    path.write_bytes(b"\x7fELF" + bytes(range(64)))
    return path


def _events(log: Path, *, probes: bool = False) -> list[tuple[int, str]]:
    """(pid, event) per fake API call, in order; without the save probe's
    child process unless ``probes``."""
    if not log.exists():
        return []
    rows = []
    for line in log.read_text(encoding="utf-8").splitlines():
        pid, event = line.split(" ", 1)
        rows.append((int(pid), event))
    if probes:
        return rows
    probe_pids = {pid for pid, event in rows if event.startswith("load probe.bin")}
    return [(pid, event) for pid, event in rows if pid not in probe_pids]


def _quiet() -> Progress:
    return Progress(enabled=False)


# -- backend selection -------------------------------------------------------


def test_auto_prefers_ida_then_binja_then_r2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "probe_binja_headless", lambda *_: True)
    monkeypatch.setattr(base, "probe_r2", lambda: True)
    monkeypatch.setattr(base, "probe_ida", lambda **_: base.IdaProbe(True, "found"))
    assert choose_backend("auto").selected == "ida"
    monkeypatch.setattr(base, "probe_ida", lambda **_: base.IdaProbe(False, "missing"))
    assert choose_backend("auto").selected == "binja"
    assert choose_backend("auto", skip=frozenset({"binja"})).selected == "r2"


def test_bndb_input_requires_binja() -> None:
    assert choose_backend("auto", input_path=Path("app.bndb")).selected == "binja"
    with pytest.raises(ToCodeError, match="bndb"):
        choose_backend("ida", input_path=Path("app.bndb"))


def test_headless_renders_in_workers() -> None:
    assert "binja-headless" in TIMEOUT_WORKER_BACKENDS
    assert BinjaHeadlessSession.parallel_safe is True
    assert BinjaHeadlessSession.backend_name == "binja"


def test_probe_honors_disable_switch(
    fake_binja, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert probe_binja_headless() is True
    monkeypatch.setenv("TOCODE_DISABLE_BINJA_HEADLESS", "1")
    assert probe_binja_headless() is False


def test_discover_binja_dir_from_install_folder(tmp_path: Path) -> None:
    package = tmp_path / "binaryninja" / "python" / "binaryninja"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    assert discover_binja_dir(tmp_path / "binaryninja") == package.parent.resolve()


def test_discover_binja_dir_from_install_api_pth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("TOCODE_BINJA_DIR", "BN_INSTALL_DIR", "BINJA_DIR", "APPDATA"):
        monkeypatch.delenv(name, raising=False)
    python_dir = tmp_path / "install" / "python"
    (python_dir / "binaryninja").mkdir(parents=True)
    (python_dir / "binaryninja" / "__init__.py").write_text("")
    site = tmp_path / "home" / ".local" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "binaryninja.pth").write_text(f"{python_dir}\n")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert discover_binja_dir() == python_dir.resolve()


def test_choose_jobs_caps_binja_workers_by_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TOCODE_BINJA_WORKER_MEMORY_MB", raising=False)

    def jobs(available_memory_mb: int, measured: int | None = None) -> int:
        return choose_jobs(
            function_count=5000,
            analysis_seconds=30.0,
            requested=None,
            backend="binja-headless",
            cpu_count=32,
            job_limit=64,
            available_memory_mb=available_memory_mb,
            measured_worker_memory_mb=measured,
        )

    assert jobs(64 * 1024) == 4
    assert jobs(2500) == 2
    # What the analyzing process peaked at wins over the static estimate.
    assert jobs(5000, measured=1800) == 2
    assert jobs(5000, measured=200) == 4


# -- the API itself ----------------------------------------------------------


def test_api_not_found_names_the_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    _drop_binaryninja_modules()
    if importlib.util.find_spec("binaryninja") is not None:
        pytest.skip("a real Binary Ninja API is importable in this environment")
    monkeypatch.setattr(base, "discover_binja_dir", lambda *_: None)
    problem = headless_problem()
    assert problem is not None and "--binja-dir" in problem


def test_refused_license_is_reported(fake_binja, tmp_path: Path, monkeypatch) -> None:
    assert headless_problem() is None
    monkeypatch.setenv("FAKE_BINJA_LICENSE", "invalid")
    problem = headless_problem()
    assert problem is not None and "License is not valid" in problem
    with pytest.raises(BackendError, match="license"):
        BinjaHeadlessSession(_binary(tmp_path))


def _license(tmp_path: Path, text: str = "FAKE-LICENSE") -> Path:
    path = tmp_path / "license.dat"
    path.write_text(text, encoding="utf-8")
    return path


def test_license_file_is_handed_to_the_core(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_BINJA_LICENSE", "invalid")  # no usable default license
    monkeypatch.setenv("TOCODE_BINJA_LICENSE", str(_license(tmp_path)))
    assert headless_problem() is None
    BinjaHeadlessSession(_binary(tmp_path)).close()
    # Set once per process, before the first core call; contents never logged.
    events = [event for _, event in _events(fake_binja.log)]
    assert events[0] == "core_set_license"
    assert events.count("core_set_license") == 1
    assert "FAKE-LICENSE" not in fake_binja.log.read_text()


def test_license_file_the_core_rejects_is_reported(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOCODE_BINJA_LICENSE", str(_license(tmp_path, "expired")))
    problem = headless_problem()
    assert problem is not None and "License is not valid" in problem
    assert "expired" not in problem


def test_missing_license_file_is_reported(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOCODE_BINJA_LICENSE", str(tmp_path / "missing.dat"))
    problem = headless_problem()
    assert problem is not None and "cannot read the Binary Ninja license" in problem


# -- session: database cache ---------------------------------------------------


def test_analysis_is_cached_as_a_database(fake_binja, tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    session = BinjaHeadlessSession(binary)
    session.analyze()
    cache = cached_database(binary)
    assert cache.is_file()
    assert session.database_path() == cache
    session.close()

    again = BinjaHeadlessSession(binary)
    again.analyze()
    again.close()
    assert [event for _, event in _events(fake_binja.log)] == [
        "load sample.elf update_analysis=False",
        f"create_database {cache.name}",
        f"load {cache.name} update_analysis=False",
    ]


def test_save_probe_runs_once_per_core(fake_binja, tmp_path: Path) -> None:
    for _ in range(2):
        cached_database(_binary(tmp_path)).unlink(missing_ok=True)
        session = BinjaHeadlessSession(_binary(tmp_path))
        session.analyze()
        session.close()
    probes = [e for _, e in _events(fake_binja.log, probes=True) if "probe.bin" in e]
    assert probes == ["load probe.bin update_analysis=False"]


def test_core_that_crashes_saving_renders_in_process(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_BINJA_SAVE", "crash")
    binary = _binary(tmp_path)
    out = tmp_path / "out"
    with create_analyzer(
        binary, backend="binja", binja_dir=FAKE_DIR, progress=_quiet()
    ) as analyzer:
        summary = export_binary(analyzer, out_dir=out, jobs=2)
        assert not analyzer.supports_parallel
    assert summary.function_count == 2 and not summary.failed_functions
    assert not cached_database(binary).exists()
    assert not list(out.glob("*.bndb"))
    sources = "\n".join(path.read_text() for path in (out / "src" / "raw").rglob("*.c"))
    assert "helper();" in sources
    # Only the probe child crashed; this process never called create_database
    # and no render worker was spawned.
    events = _events(fake_binja.log)
    assert {pid for pid, _ in events} == {events[0][0]}
    assert not any(event.startswith("create_database") for _, event in events)


def test_purge_cache_rebuilds_the_database(fake_binja, tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    first = BinjaHeadlessSession(binary)
    first.analyze()
    first.close()
    purged = BinjaHeadlessSession(binary, purge_cache=True)
    purged.analyze()
    purged.close()
    events = [event for _, event in _events(fake_binja.log)]
    assert events.count("load sample.elf update_analysis=False") == 2
    assert sum(event.startswith("create_database") for event in events) == 2


def test_unreadable_cache_is_rebuilt(fake_binja, tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    cache = cached_database(binary)
    cache.parent.mkdir(parents=True)
    cache.write_text("half-written database")
    log = tmp_path / "tocode.log"
    session = BinjaHeadlessSession(
        binary, progress=Progress(enabled=False, log_path=log)
    )
    session.analyze()
    session.close()
    assert "Discarding unreadable cached Binary Ninja database" in log.read_text()
    assert cache.read_text().startswith("FAKEBNDB")


def test_empty_cache_from_a_crashed_save_is_rebuilt(fake_binja, tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    cache = cached_database(binary)
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"")  # what a save that crashed leaves behind
    out = tmp_path / "out"
    with create_analyzer(
        binary, backend="binja", binja_dir=FAKE_DIR, progress=_quiet()
    ) as analyzer:
        summary = export_binary(analyzer, out_dir=out, jobs=1)
    assert summary.function_count == 2
    assert list((out / "src" / "raw").rglob("*.c"))
    assert cache.read_text().startswith("FAKEBNDB")
    assert (out / "sample.bndb").read_text().startswith("FAKEBNDB")


def test_empty_database_input_is_an_error(fake_binja, tmp_path: Path) -> None:
    database = tmp_path / "app.bndb"
    database.write_bytes(b"")
    with pytest.raises(BackendError, match="empty or incomplete"):
        BinjaHeadlessSession(database)


def test_analysis_progress_is_shown(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(binja_headless, "ANALYSIS_POLL_SECONDS", 0.02)
    monkeypatch.setenv("FAKE_BINJA_ANALYSIS_SECONDS", "0.5")
    session = BinjaHeadlessSession(_binary(tmp_path), progress=Progress())
    session.analyze()
    session.close()
    assert "binja analyzing" in capsys.readouterr().err


def test_ctrl_c_aborts_the_analysis(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(binja_headless, "ANALYSIS_POLL_SECONDS", 0.02)
    monkeypatch.setenv("FAKE_BINJA_ANALYSIS_SECONDS", "60")

    def interrupt(bar, bv) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(binja_headless, "_show_analysis_progress", interrupt)
    session = BinjaHeadlessSession(_binary(tmp_path), progress=Progress())
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        session.analyze()
    session.close()
    assert time.monotonic() - started < 10
    assert "abort_analysis" in [event for _, event in _events(fake_binja.log)]


def test_worker_memory_is_measured_after_analysis(fake_binja, tmp_path: Path) -> None:
    session = BinjaHeadlessSession(_binary(tmp_path))
    assert session.worker_memory_mb() is None
    session.analyze()
    if sys.platform != "win32":
        measured = session.worker_memory_mb()
        assert measured is not None and measured > 0
    session.close()


def test_database_input_is_opened_in_place(fake_binja, tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    database = tmp_path / "sample.bndb"
    database.write_text(f"FAKEBNDB\n{binary}")
    session = BinjaHeadlessSession(database)
    session.analyze()
    assert session.database_path() == database
    assert session.info()["tocode"]["input_path"] == str(binary)
    session.close()
    events = [event for _, event in _events(fake_binja.log)]
    assert events == ["load sample.bndb update_analysis=False"]
    assert not (tmp_path / "cache").exists()


def test_read_bytes_reopens_the_view_after_workers(fake_binja, tmp_path: Path) -> None:
    session = BinjaHeadlessSession(_binary(tmp_path))
    session.analyze()
    session.release_parallel_resources()
    assert session.read_bytes(0x401000, 4) == b"\x00\x01\x02\x03"
    session.close()
    cache = cached_database(_binary(tmp_path))
    assert _events(fake_binja.log)[-1][1] == f"load {cache.name} update_analysis=True"


def test_types_and_data_xrefs(fake_binja, tmp_path: Path) -> None:
    session = BinjaHeadlessSession(_binary(tmp_path))
    session.analyze()
    types = {row["name"]: row for row in session.types()}
    assert types["point"]["kind"] == "struct"
    assert types["point"]["size"] == 8
    assert "int32_t x;" in types["point"]["c_decl"]
    assert types["score_t"]["c_decl"] == "typedef int32_t score_t;"
    assert session.data_xrefs({0x403000, 0x404000, 0x999}) == {
        0x403000: [(0x401004, False)],
        0x404000: [(0x401008, True)],
    }
    session.close()


# -- create_analyzer -----------------------------------------------------------


class _FakeR2:
    backend_name = "r2"

    def __init__(self, binary, analysis_command=None) -> None:
        self.binary = binary

    def close(self) -> None:
        return None


def test_auto_falls_back_when_license_refuses_headless(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_BINJA_LICENSE", "invalid")
    monkeypatch.setattr(base, "probe_ida", lambda **_: base.IdaProbe(False, "missing"))
    monkeypatch.setattr(base, "probe_r2", lambda: True)
    monkeypatch.setattr(analysis_module, "R2Session", _FakeR2)
    with create_analyzer(_binary(tmp_path), progress=_quiet()) as analyzer:
        assert isinstance(analyzer.session, _FakeR2)


def test_explicit_binja_reports_refused_license(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_BINJA_LICENSE", "invalid")
    with pytest.raises(BackendError, match="License is not valid"):
        create_analyzer(_binary(tmp_path), backend="binja", progress=_quiet())


def test_export_renders_in_workers_from_the_cached_database(
    fake_binja, tmp_path: Path
) -> None:
    binary = _binary(tmp_path)
    out = tmp_path / "out"
    with create_analyzer(
        binary, backend="binja", binja_dir=FAKE_DIR, progress=_quiet()
    ) as analyzer:
        assert isinstance(analyzer.session, BinjaHeadlessSession)
        summary = export_binary(analyzer, out_dir=out, jobs=2)

    assert summary.function_count == 2  # main and helper; the puts stub is an import
    assert not summary.failed_functions
    # The finished analysis ships with the export, like IDA's .i64.
    assert (out / "sample.bndb").read_text().startswith("FAKEBNDB")
    sources = "\n".join(path.read_text() for path in (out / "src" / "raw").rglob("*.c"))
    assert "int32_t main(int32_t argc)" in sources
    assert "helper();" in sources
    types_header = next((out / "include").glob("*.types.h")).read_text()
    assert "struct point" in types_header
    # Section bytes come from the view, which the parent reopened after the
    # workers finished (it closes its own view while they render).
    assert (out / "data" / "text.bin").read_bytes() == bytes(
        (0x401000 + index) & 0xFF for index in range(0x100)
    )
    strings = json.dumps(json.loads((out / "strings.json").read_text()))
    assert '"function": "main"' in strings and '"access": "read"' in strings
    variables = json.dumps(json.loads((out / "data" / "variables.json").read_text()))
    assert '"access": "write"' in variables
    assert json.loads((out / "project.json").read_text())["backend"] == "binja"

    cache = cached_database(binary).name
    events = _events(fake_binja.log)
    parent = events[0][0]
    worker_loads = [event for pid, event in events if pid != parent]
    assert worker_loads and all(
        event == f"load {cache} update_analysis=False" for event in worker_loads
    )
    assert (parent, f"load {cache} update_analysis=True") in events


# -- CLI -------------------------------------------------------------------------


def _record_run_binja(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []

    def fake_run_binja(args, progress, parser, argv):
        calls.append(args)
        return 0

    monkeypatch.setattr(cli, "_run_binja", fake_run_binja)
    return calls


def test_cli_exports_a_file_headless(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _record_run_binja(monkeypatch)
    monkeypatch.setenv("TOCODE_FUNCTION_TIMEOUT_SECONDS", "0")  # render in process
    out = tmp_path / "out"
    assert (
        cli.main(["--backend", "binja", str(_binary(tmp_path)), "-o", str(out), "-q"])
        == 0
    )
    assert not calls
    assert (out / "sample.bndb").is_file()
    assert (out / "functions.json").is_file()


def test_cli_auto_transport_falls_back_to_running_binja(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _record_run_binja(monkeypatch)
    monkeypatch.setenv("FAKE_BINJA_LICENSE", "invalid")
    assert cli.main(["--backend", "binja", str(_binary(tmp_path)), "-q"]) == 0
    assert len(calls) == 1


def test_cli_headless_transport_reports_refused_license(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    calls = _record_run_binja(monkeypatch)
    monkeypatch.setenv("FAKE_BINJA_LICENSE", "invalid")
    argv = [
        "--backend",
        "binja",
        "--binja-transport",
        "headless",
        str(_binary(tmp_path)),
        "-q",
    ]
    assert cli.main(argv) == 1
    assert not calls
    assert "License is not valid" in capsys.readouterr().err


def test_cli_routes_database_input_to_binja(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _record_run_binja(monkeypatch)
    database = tmp_path / "app.bndb"
    database.write_text("db")
    assert cli.main([str(database), "-q"]) == 0  # no API here: a running Binary Ninja
    assert len(calls) == 1
    assert calls[0].backend == "binja"


def test_cli_license_reaches_render_workers(
    fake_binja, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _record_run_binja(monkeypatch)
    monkeypatch.setenv("FAKE_BINJA_LICENSE", "invalid")
    out = tmp_path / "out"
    argv = [
        "--backend",
        "binja",
        "--binja-transport",
        "headless",
        "--binja-license",
        str(_license(tmp_path)),
        str(_binary(tmp_path)),
        "-o",
        str(out),
        "-j",
        "2",
        "-q",
    ]
    assert cli.main(argv) == 0
    assert not calls
    assert (out / "sample.bndb").is_file()
    events = _events(fake_binja.log)
    # Every process that loaded a view (the parent and each spawned worker)
    # set the license first.
    loaders = {pid for pid, event in events if event.startswith("load ")}
    licensed = {pid for pid, event in events if event == "core_set_license"}
    assert len(loaders) > 1 and loaders <= licensed
    assert "FAKE-LICENSE" not in (out / "tocode.log").read_text()


def test_cli_rejects_a_missing_license_file(tmp_path: Path, capsys) -> None:
    argv = ["--binja-license", str(tmp_path / "missing.dat"), str(_binary(tmp_path))]
    with pytest.raises(SystemExit):
        cli.main(argv)
    assert "--binja-license" in capsys.readouterr().err
