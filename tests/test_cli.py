import pytest

from tocode.cli import _format_duration, build_parser, parse_jobs


def test_format_duration_uses_seconds_then_minutes() -> None:
    assert _format_duration(4.27) == "4.3s"
    assert _format_duration(75) == "1m 15s"
    assert _format_duration(3600) == "60m 0s"


def test_parse_jobs_accepts_auto_and_positive_ints() -> None:
    assert parse_jobs("auto") is None
    assert parse_jobs("3") == 3


def test_parse_jobs_rejects_zero() -> None:
    with pytest.raises(Exception):
        parse_jobs("0")


def test_parser_uses_tree_as_opt_in_flag() -> None:
    parser = build_parser()

    default_args = parser.parse_args(["sample.bin"])
    tree_args = parser.parse_args(["--tree", "sample.bin"])

    assert default_args.tree is False
    assert tree_args.tree is True


def test_parser_accepts_short_quiet_flag() -> None:
    args = build_parser().parse_args(["-q", "sample.bin"])

    assert args.quiet is True


def test_parser_uses_entropy_as_opt_in_flag() -> None:
    parser = build_parser()

    assert parser.parse_args(["sample.bin"]).entropy is False
    assert parser.parse_args(["--entropy", "sample.bin"]).entropy is True


def test_parser_has_apk_flags() -> None:
    parser = build_parser()

    default_args = parser.parse_args(["app.apk"])
    apk_args = parser.parse_args(["--no-native", "--no-splits", "app.apk"])

    assert default_args.no_native is False and default_args.no_splits is False
    assert apk_args.no_native is True and apk_args.no_splits is True


def test_main_rejects_binja_backend_for_apk_input(tmp_path) -> None:
    from tocode.cli import main

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x05\x06" + b"\x00" * 18)

    with pytest.raises(SystemExit) as info:
        main(["--backend", "binja", str(apk)])

    assert info.value.code == 2


def test_main_routes_apk_input_to_apk_export(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    from tocode import cli

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    seen = {}

    def fake_export(binary, *, options, progress):
        seen["binary"] = binary
        seen["options"] = options
        return SimpleNamespace(
            root_dir=tmp_path / "out",
            package="com.example",
            class_count=1,
            method_count=2,
            failed_classes=[],
            native_total=1,
            native_done=1,
            native_errors=[],
        )

    monkeypatch.setattr(cli, "export_apk", fake_export)

    assert cli.main(["--no-native", "-j", "3", "--backend", "r2", "-q", str(apk)]) == 0
    assert seen["binary"] == apk.resolve()
    assert seen["options"].native is False
    assert seen["options"].jobs == 3
    assert seen["options"].native_options.backend == "r2"
    assert seen["options"].native_options.jobs == 3


def test_package_installs_a_tocode_console_script() -> None:
    """The PyPI distribution is `tocode-cli`, but the command stays `tocode`."""
    import importlib.metadata as metadata

    try:
        distribution = metadata.distribution("tocode-cli")
    except metadata.PackageNotFoundError:  # pragma: no cover - not installed
        pytest.skip("tocode-cli is not installed in this environment")

    scripts = {
        entry.name: entry.value
        for entry in distribution.entry_points
        if entry.group == "console_scripts"
    }

    assert scripts == {"tocode": "tocode.cli:main"}


def test_parser_has_dotnet_flags() -> None:
    args = build_parser().parse_args(["--as-native", "--include-framework", "app.dll"])

    assert args.as_native is True and args.include_framework is True
    assert build_parser().parse_args(["app.dll"]).as_native is False


def test_main_routes_dotnet_input_to_dotnet_export(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    from dotnet_fixtures import managed_pe

    from tocode import cli, dotnet

    binary = tmp_path / "App.dll"
    binary.write_bytes(managed_pe())
    seen = {}

    def fake_export(path, *, options, progress):
        seen["path"] = path
        seen["options"] = options
        return SimpleNamespace(
            root_dir=tmp_path / "out",
            kind="assembly",
            assemblies=["App"],
            type_count=1,
            method_count=1,
            failed_types=[],
            native_total=0,
            native_done=0,
            native_errors=[],
        )

    monkeypatch.setattr(dotnet, "export_dotnet", fake_export)
    from tocode.backends import dotnet_libs

    monkeypatch.setattr(dotnet_libs, "ensure_libraries", lambda **_kwargs: tmp_path)

    assert (
        cli.main(["--include-framework", "--no-native", "-j", "2", "-q", str(binary)])
        == 0
    )
    assert seen["path"] == binary.resolve()
    assert seen["options"].include_framework is True
    assert seen["options"].native is False
    assert seen["options"].jobs == 2


def test_main_as_native_skips_the_dotnet_backend(tmp_path, monkeypatch) -> None:
    from dotnet_fixtures import managed_pe

    from tocode import cli

    binary = tmp_path / "App.dll"
    binary.write_bytes(managed_pe())
    called = {}

    def fake_run_one(path, *, args, progress, out_dir):
        called["path"] = path
        raise cli.ToCodeError("stop here")

    monkeypatch.setattr(cli, "_run_one", fake_run_one)

    assert cli.main(["--as-native", "-q", str(binary)]) == 1
    assert called["path"] == binary.resolve()


def test_main_rejects_binja_backend_for_dotnet_input(tmp_path) -> None:
    from dotnet_fixtures import managed_pe

    from tocode.cli import main

    binary = tmp_path / "App.dll"
    binary.write_bytes(managed_pe())

    with pytest.raises(SystemExit) as info:
        main(["--backend", "binja", str(binary)])

    assert info.value.code == 2


def test_parser_has_setup_dotnet_flag() -> None:
    assert build_parser().parse_args(["--setup-dotnet"]).setup_dotnet is True
    assert build_parser().parse_args(["app.dll"]).setup_dotnet is False


def test_main_setup_dotnet_runs_without_an_input(monkeypatch) -> None:
    from tocode import cli
    from tocode.backends import dotnet_libs

    calls = []
    monkeypatch.setattr(dotnet_libs, "setup", lambda **kwargs: calls.append(kwargs))

    assert cli.main(["--setup-dotnet"]) == 0
    assert len(calls) == 1


def test_main_dotnet_input_without_libraries_explains_setup(
    tmp_path, monkeypatch, capsys
) -> None:
    from dotnet_fixtures import managed_pe

    from tocode import cli

    monkeypatch.setenv("TOCODE_DOTNET_LIB_DIR", str(tmp_path / "libs"))
    binary = tmp_path / "App.dll"
    binary.write_bytes(managed_pe())

    # pytest's stdin is not a terminal, so this must fail fast, not prompt.
    assert cli.main(["-q", str(binary)]) == 1
    assert "tocode --setup-dotnet" in capsys.readouterr().err


def test_parser_has_folder_flags() -> None:
    args = build_parser().parse_args(
        ["--only", "**/a.dylib", "--only", "b*", "--exclude", "x", "--no-managed",
         "--arch", "arm64", "--plan", "--links-only", "dir"]
    )  # fmt: skip

    assert args.only == ["**/a.dylib", "b*"] and args.exclude == ["x"]
    assert args.no_managed and args.arch == "arm64" and args.plan and args.links_only
    assert build_parser().parse_args(["dir"]).only == []


def test_main_routes_a_directory_to_the_folder_export(tmp_path, monkeypatch) -> None:
    from tocode import cli, folder

    seen = {}

    def fake_export(path, *, options, progress):
        seen["path"] = path
        seen["options"] = options
        return folder.FolderSummary(
            root_dir=tmp_path / "out", input_dir=path, binaries=0, jobs=[],
            edges=0, links=0, bound=0, mapped=0,
        )  # fmt: skip

    monkeypatch.setattr(folder, "export_folder", fake_export)

    code = cli.main(
        [
            "--only",
            "*.dll",
            "--no-native",
            "--include-framework",
            "-j",
            "2",
            "-q",
            str(tmp_path),
        ]
    )

    assert code == 0
    assert seen["path"] == tmp_path.resolve()
    options = seen["options"]
    assert options.only == ["*.dll"] and options.native is False
    assert options.include_framework is True and options.jobs == 2
    assert options.ensure_dotnet is not None


def test_main_rejects_binja_backend_for_folder_input(tmp_path) -> None:
    from tocode.cli import main

    with pytest.raises(SystemExit) as info:
        main(["--backend", "binja", str(tmp_path)])

    assert info.value.code == 2


def test_main_plans_a_folder_without_writing(tmp_path, capsys) -> None:
    from link_fixtures import elf, write

    from tocode.cli import main

    write(tmp_path / "app/app", elf(executable=True))

    assert main(["--plan", str(tmp_path / "app")]) == 0
    assert "1. app" in capsys.readouterr().out
    assert not (tmp_path / "app_decompiled").exists()
