from __future__ import annotations

from pathlib import Path
import zipfile

import pytest

from tocode.backends.asc import (
    ApkSet,
    class_java_relpath,
    discover_apk_set,
    is_apk_bundle,
    is_apk_input,
    java_type,
    method_descriptor,
    scan_bytecode_refs,
)
from tocode.errors import ToCodeError


def _write_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def test_java_type_converts_descriptors() -> None:
    assert java_type("Lcom/foo/Bar$Baz;") == "com.foo.Bar$Baz"
    assert java_type("[I") == "int[]"
    assert java_type("[[Ljava/lang/String;") == "java.lang.String[][]"
    assert java_type("V") == "void"


def test_method_descriptor_round_trips_signature() -> None:
    assert (
        method_descriptor("Lcom/foo/Bar;", "run", ["I", "Ljava/lang/String;"], "V")
        == "Lcom/foo/Bar;->run(ILjava/lang/String;)V"
    )


def test_class_java_relpath_uses_package_folders() -> None:
    assert class_java_relpath("Lcom/foo/Bar;") == Path("com/foo/Bar.java")
    assert class_java_relpath("Lcom/foo/Bar$Inner;") == Path("com/foo/Bar$Inner.java")
    assert class_java_relpath("LNoPackage;") == Path("NoPackage.java")
    assert class_java_relpath("La/b/c/ünïcode;") == Path("a/b/c/n_code.java")


def test_apk_input_detection() -> None:
    assert is_apk_input(Path("app.APK"))
    assert is_apk_input(Path("bundle.apks"))
    assert is_apk_input(Path("bundle.xapk"))
    assert is_apk_bundle(Path("bundle.apks"))
    assert not is_apk_bundle(Path("app.apk"))
    assert not is_apk_input(Path("libfoo.so"))


def test_discover_apk_set_picks_up_sibling_splits(tmp_path: Path) -> None:
    base = _write_zip(tmp_path / "base.apk", {"AndroidManifest.xml": b"x"})
    _write_zip(tmp_path / "split_config.en.apk", {"AndroidManifest.xml": b"x"})
    _write_zip(tmp_path / "split_config.arm64_v8a.apk", {"AndroidManifest.xml": b"x"})
    (tmp_path / "split_broken.apk").write_bytes(b"not a zip")
    _write_zip(tmp_path / "other.apk", {"AndroidManifest.xml": b"x"})

    apk_set = discover_apk_set(base, workdir=tmp_path / "work")

    assert apk_set.primary == base.resolve()
    assert [item.name for item in apk_set.apks] == [
        "base.apk",
        "split_config.arm64_v8a.apk",
        "split_config.en.apk",
    ]
    assert apk_set.workdir is None
    assert apk_set.is_split


def test_discover_apk_set_can_ignore_splits(tmp_path: Path) -> None:
    base = _write_zip(tmp_path / "base.apk", {"AndroidManifest.xml": b"x"})
    _write_zip(tmp_path / "split_config.en.apk", {"AndroidManifest.xml": b"x"})

    apk_set = discover_apk_set(base, splits=False, workdir=tmp_path / "work")

    assert apk_set.apks == [base.resolve()]
    assert not apk_set.is_split


def test_discover_apk_set_exports_standalone_split_alone(tmp_path: Path) -> None:
    _write_zip(tmp_path / "base.apk", {"AndroidManifest.xml": b"x"})
    split = _write_zip(tmp_path / "split_config.en.apk", {"AndroidManifest.xml": b"x"})

    apk_set = discover_apk_set(split, workdir=tmp_path / "work")

    assert apk_set.apks == [split.resolve()]


def test_discover_apk_set_unpacks_bundles(tmp_path: Path) -> None:
    inner_base = _write_zip(tmp_path / "inner_base.apk", {"AndroidManifest.xml": b"b"})
    inner_split = _write_zip(
        tmp_path / "inner_split.apk", {"AndroidManifest.xml": b"s"}
    )
    bundle = _write_zip(
        tmp_path / "app.apks",
        {
            "split_config.en.apk": inner_split.read_bytes(),
            "base.apk": inner_base.read_bytes(),
            "nested/ignored.apk": inner_split.read_bytes(),
            "toc.pb": b"meta",
        },
    )
    workdir = tmp_path / "work"

    apk_set = discover_apk_set(bundle, workdir=workdir)

    assert apk_set.workdir == workdir
    assert [item.name for item in apk_set.apks] == ["base.apk", "split_config.en.apk"]
    assert apk_set.primary == workdir / "base.apk"
    assert all(item.parent == workdir for item in apk_set.apks)


def test_discover_apk_set_rejects_non_zip_and_empty_bundle(tmp_path: Path) -> None:
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"nope")
    with pytest.raises(ToCodeError):
        discover_apk_set(bad, workdir=tmp_path / "work")
    empty = _write_zip(tmp_path / "empty.apks", {"toc.pb": b""})
    with pytest.raises(ToCodeError):
        discover_apk_set(empty, workdir=tmp_path / "work2")


def test_apk_set_is_picklable_for_spawned_workers(tmp_path: Path) -> None:
    import pickle

    apk_set = ApkSet(primary=tmp_path / "base.apk", apks=[tmp_path / "base.apk"])
    assert pickle.loads(pickle.dumps(apk_set)) == apk_set


def test_scan_bytecode_refs_reads_constant_pool_indices() -> None:
    pytest.importorskip("droidasc")
    bytecode = bytes.fromhex(
        "1a000500"  # const-string v0, string@5
        "6e10020100 00"  # invoke-virtual {v0}, method@0x102
        "62000300"  # sget-object v0, field@3
        "1c000700"  # const-class v0, type@7
        "1b0078563412"  # const-string/jumbo v0, string@0x12345678
        "0e00"  # return-void
    )

    refs = scan_bytecode_refs(bytecode)

    assert refs == [
        ("string", 5),
        ("method", 0x102),
        ("field", 3),
        ("type", 7),
        ("string", 0x12345678),
    ]


def test_scan_bytecode_refs_stops_at_switch_payload() -> None:
    pytest.importorskip("droidasc")
    bytecode = bytes.fromhex(
        "2b0003000000"  # packed-switch v0, +3 (payload starts at byte 6)
        "00011a000900"  # payload bytes: must not be decoded as const-string
    )

    assert scan_bytecode_refs(bytecode) == []
