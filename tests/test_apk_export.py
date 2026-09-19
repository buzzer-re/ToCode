from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time
from typing import Any
import zipfile

import pytest

from tocode import apk as apk_module
from tocode import apk_metadata as meta
from tocode.apk import ApkExportOptions, assign_method_lines, export_apk
from tocode.apk_native import (
    NativeLib,
    NativeRunner,
    classify_native_entry,
    extract_native_libs,
)
from tocode.backends.asc import (
    AscSession,
    ClassRecord,
    DecompiledClass,
    DexImage,
    FieldRecord,
    MethodRecord,
    StringRecord,
)
from tocode.errors import ToCodeError
from tocode.progress import Progress


SAMPLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="48" android:versionName="4.5" package="com.example.app">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-feature android:name="android.hardware.camera" android:required="false"/>
  <application android:name=".App" android:debuggable="true" android:allowBackup="false">
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name="com.example.app.Hidden" android:exported="false"/>
    <service android:name=".Svc" android:exported="true" android:permission="com.example.P"/>
    <receiver android:name=".Boot">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <provider android:name=".Prov" android:authorities="com.example.app.files"/>
  </application>
</manifest>
"""

SAMPLE_JAVA = """package com.example.app;
public class MainActivity extends android.app.Activity {
    private int counter;

    public MainActivity()
    {
        return;
    }

    @Override
    protected void onCreate(android.os.Bundle p1)
    {
        this.counter = 1;
        return;
    }

    private native int nativeAdd(int p1, int p2);

    public int add(int p1)
    {
        return p1;
    }

    public int add(int p1, int p2)
    {
        return (p1 + p2);
    }
}
"""


def _method(
    id_: int,
    cls: str,
    name: str,
    params: list[str],
    ret: str,
    flags: int = 0x1,
    code: int = 0,
) -> MethodRecord:
    return MethodRecord(
        id=id_,
        dex="classes.dex",
        index=id_,
        class_descriptor=cls,
        name=name,
        return_type=ret,
        params=params,
        access_flags=flags,
        is_direct=False,
        code_offset=code,
        code_size=8 if code else 0,
        registers=len(params) + 2,
    )


def _main_activity_record() -> ClassRecord:
    cls = "Lcom/example/app/MainActivity;"
    return ClassRecord(
        descriptor=cls,
        dex="classes.dex",
        index=0,
        access_flags=0x1,
        superclass="Landroid/app/Activity;",
        interfaces=[],
        source_file="MainActivity.java",
        methods=[
            _method(0, cls, "<init>", [], "V", 0x10001, code=0x100),
            _method(1, cls, "onCreate", ["Landroid/os/Bundle;"], "V", 0x4, code=0x120),
            _method(2, cls, "nativeAdd", ["I", "I"], "I", 0x102),
            _method(3, cls, "add", ["I"], "I", 0x1, code=0x140),
            _method(4, cls, "add", ["I", "I"], "I", 0x1, code=0x160),
        ],
        fields=[FieldRecord("classes.dex", 0, cls, "counter", "I", 0x2)],
    )


def _helper_record() -> ClassRecord:
    cls = "Lcom/example/util/Helper;"
    return ClassRecord(
        descriptor=cls,
        dex="classes.dex",
        index=1,
        access_flags=0x11,
        superclass="Ljava/lang/Object;",
        interfaces=["Ljava/lang/Runnable;"],
        source_file=None,
        methods=[_method(5, cls, "run", [], "V", 0x1, code=0x200)],
        fields=[],
    )


class FakeSession(AscSession):
    """Inventory built by hand: no droidasc, no real DEX."""

    def load(self) -> None:
        self.images = [
            DexImage("classes.dex", self.apk_set.primary, "classes.dex", b"dex", None)
        ]
        self._images_by_name = {}
        self.classes = [_main_activity_record(), _helper_record()]
        self.methods = [m for record in self.classes for m in record.methods]
        self._by_descriptor = {record.descriptor: record for record in self.classes}
        self._method_by_descriptor = {m.descriptor: m for m in self.methods}
        self.strings = [
            StringRecord("classes.dex", 0, "https://api.example.com/v1", 0x10),
            StringRecord("classes.dex", 1, "hello", 0x30),
        ]
        # onCreate -> add(int); add(int) -> Helper.run; run -> external
        self.methods[1].callees = [3]
        self.methods[3].callers = [1]
        self.methods[3].callees = [5]
        self.methods[5].callers = [3]
        self.methods[5].external_calls = ["Ljava/lang/Thread;->start()V"]
        self.methods[1].string_ref_count = 1
        self.string_xrefs = {("classes.dex", 0): [1]}


class FakeDecompiler:
    def __init__(self, session: AscSession) -> None:
        self.session = session

    def decompile(self, record: ClassRecord) -> DecompiledClass:
        if record.descriptor.endswith("Helper;"):
            return DecompiledClass(record.descriptor, None, "boom", {})
        return DecompiledClass(record.descriptor, SAMPLE_JAVA, None, {})


def _build_apk(path: Path, *, libs: bool = True) -> Path:
    entries: dict[str, bytes] = {
        "AndroidManifest.xml": b"\x03\x00\x08\x00binary",
        "classes.dex": b"dex\n035\x00" + b"\x00" * 64,
        "assets/config.json": b"{}",
        "res/values/strings.xml": b"<resources/>",
        "resources.arsc": b"garbage",
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0",
    }
    if libs:
        entries["lib/arm64-v8a/libfoo.so"] = b"\x7fELF" + b"\x00" * 32
        entries["lib/armeabi-v7a/libfoo.so"] = b"\x7fELF" + b"\x01" * 32
        entries["assets/hidden.so"] = b"\x7fELF" + b"\x02" * 32
        entries["assets/plain.so"] = b"not an elf"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


@pytest.fixture
def fake_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_module, "AscSession", FakeSession)
    monkeypatch.setattr(apk_module, "manifest_xml", lambda apk: SAMPLE_MANIFEST)


def _fake_native_exporter(fail_name: str | None = None) -> Any:
    calls: list[tuple[str, str, Path]] = []

    def run(
        lib: NativeLib, out_dir: Path, progress: Progress
    ) -> tuple[str, str, int, int]:
        calls.append((lib.abi, lib.name, out_dir))
        if fail_name and lib.name == fail_name and lib.abi == "armeabi-v7a":
            raise ToCodeError("no decompiler backend available")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "functions.json").write_text("{}", encoding="utf-8")
        progress.log("fake native export")
        return ("r2", "radare2 pdc", 12, 1)

    run.calls = calls  # type: ignore[attr-defined]
    return run


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------


def test_parse_manifest_extracts_package_components_and_permissions() -> None:
    info = meta.parse_manifest(SAMPLE_MANIFEST, apk_name="base.apk")

    assert info.package == "com.example.app"
    assert info.version_code == "48" and info.version_name == "4.5"
    assert info.min_sdk == "24" and info.target_sdk == "34"
    assert info.permissions == [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
    ]
    assert info.main_activities == [".MainActivity"]
    kinds = [(item.kind, item.name, item.exported) for item in info.components]
    assert ".MainActivity" in [k[1] for k in kinds]
    exported = {item.name: item.exported for item in info.components}
    assert exported[".MainActivity"] is True  # intent filter => exported
    assert exported["com.example.app.Hidden"] is False
    assert exported[".Svc"] is True
    assert exported[".Prov"] is None
    assert info.application["android:debuggable"] == "true"


def test_manifest_json_resolves_relative_component_names() -> None:
    info = meta.parse_manifest(SAMPLE_MANIFEST, apk_name="base.apk")
    doc = meta.manifest_json(info, [], xml_path=Path("AndroidManifest.xml"))

    assert doc["main_activities"] == ["com.example.app.MainActivity"]
    names = {item["name"]: item for item in doc["components"]}
    assert names["com.example.app.Boot"]["descriptor"] == "Lcom/example/app/Boot;"
    assert names["com.example.app.Svc"]["permission"] == "com.example.P"
    assert [item["name"] for item in doc["exported_components"]] == [
        "com.example.app.MainActivity",
        "com.example.app.Svc",
        "com.example.app.Boot",
    ]
    assert doc["dangerous_permissions"] == ["android.permission.READ_SMS"]


def test_parse_manifest_reports_parse_errors() -> None:
    info = meta.parse_manifest("<manifest", apk_name="x.apk")
    assert info.parse_error
    assert info.package == ""


def test_jni_symbol_mangles_names() -> None:
    method = _method(0, "Lcom/ex_ample/Main$Inner;", "do_it", ["I"], "V", 0x100)
    assert meta.jni_symbol(method) == "Java_com_ex_1ample_Main_00024Inner_do_1it"


# --------------------------------------------------------------------------
# method line mapping
# --------------------------------------------------------------------------


def test_assign_method_lines_maps_constructors_overloads_and_natives() -> None:
    record = _main_activity_record()
    assign_method_lines(record, SAMPLE_JAVA)
    lines = {
        m.name + str(len(m.params)): (m.line_start, m.line_end) for m in record.methods
    }

    assert lines["<init>0"] == (5, 8)
    assert lines["onCreate1"] == (10, 15)  # includes the @Override line
    assert lines["nativeAdd2"] == (17, 17)
    assert lines["add1"] == (19, 22)
    assert lines["add2"] == (24, 27)


# --------------------------------------------------------------------------
# native libs
# --------------------------------------------------------------------------


def test_classify_native_entry_detects_abis_and_elf_magic() -> None:
    assert classify_native_entry("lib/arm64-v8a/libx.so", b"\x7fELF") == (
        "arm64-v8a",
        "libx.so",
    )
    assert classify_native_entry("lib/x86/libx.so", b"") == ("x86", "libx.so")
    assert classify_native_entry("assets/arm64-v8a/libhidden.so", b"\x7fELF") == (
        "arm64-v8a",
        "libhidden.so",
    )
    assert classify_native_entry("assets/hidden.so", b"\x7fELF") == (
        "unknown",
        "hidden.so",
    )
    assert classify_native_entry("assets/plain.so", b"not") is None
    assert classify_native_entry("res/raw/data.bin", b"\x7fELF") == (
        "unknown",
        "data.bin",
    )
    assert classify_native_entry("assets/config.json", b"{}") is None


def test_extract_native_libs_writes_every_abi_once(tmp_path: Path) -> None:
    apk = _build_apk(tmp_path / "base.apk")
    dup = _build_apk(tmp_path / "split_config.arm64_v8a.apk")
    root = tmp_path / "out"

    libs = extract_native_libs([apk, dup], root, sha256=lambda path: "h")

    assert [(lib.abi, lib.name) for lib in libs] == [
        ("arm64-v8a", "libfoo.so"),
        ("armeabi-v7a", "libfoo.so"),
        ("unknown", "hidden.so"),
    ]
    assert (
        (root / "lib" / "arm64_v8a" / "libfoo.so").read_bytes().startswith(b"\x7fELF")
    )
    assert all(lib.source_apk == "base.apk" for lib in libs)


def test_native_runner_isolates_failures(tmp_path: Path) -> None:
    libs = [
        NativeLib(
            "arm64-v8a",
            "libfoo.so",
            "lib/arm64-v8a/libfoo.so",
            "base.apk",
            1,
            "h",
            tmp_path / "a.so",
        ),
        NativeLib(
            "armeabi-v7a",
            "libfoo.so",
            "lib/armeabi-v7a/libfoo.so",
            "base.apk",
            1,
            "h",
            tmp_path / "b.so",
        ),
    ]
    runner = NativeRunner(
        libs=libs,
        root=tmp_path,
        progress=Progress(enabled=False),
        exporter=_fake_native_exporter(fail_name="libfoo.so"),
    )
    runner.start()
    runner.join()

    assert libs[0].status == "done"
    assert libs[0].backend == "r2" and libs[0].function_count == 12
    assert libs[0].export_dir == tmp_path / "native" / "arm64_v8a" / "libfoo"
    assert libs[1].status == "failed: no decompiler backend available"
    assert runner.errors == [
        "armeabi-v7a/libfoo.so: failed: no decompiler backend available"
    ]


# --------------------------------------------------------------------------
# end-to-end export with fakes
# --------------------------------------------------------------------------


def test_export_apk_writes_full_tree(tmp_path: Path, fake_backend: None) -> None:
    apk = _build_apk(tmp_path / "base.apk")
    exporter = _fake_native_exporter(fail_name="libfoo.so")

    summary = export_apk(
        apk,
        options=ApkExportOptions(out_dir=tmp_path / "export", jobs=1),
        progress=Progress(enabled=False),
        native_exporter=exporter,
        decompiler_factory=FakeDecompiler,
    )

    root = summary.root_dir
    assert root == tmp_path / "export"
    assert summary.package == "com.example.app"
    assert summary.class_count == 2 and summary.method_count == 6
    assert summary.failed_classes == [("Lcom/example/util/Helper;", "boom")]
    assert summary.native_total == 3 and summary.native_done == 2

    for name in (
        "AndroidManifest.xml",
        "manifest.json",
        "classes.json",
        "functions.json",
        "function-index.json",
        "strings.json",
        "imports.json",
        "exports.json",
        "sections.json",
        "reachable.json",
        "triage.json",
        "package-graph.json",
        "native-libs.json",
        "project.json",
        "export-manifest.json",
        "AGENTS.md",
        "CLAUDE.md",
        "tocode.log",
        "data/resources.json",
    ):
        assert (root / name).is_file(), name

    java = root / "src" / "raw" / "com" / "example" / "app" / "MainActivity.java"
    assert java.is_file()
    text = java.read_text(encoding="utf-8")
    assert text.startswith("// ToCode: Lcom/example/app/MainActivity; from classes.dex")
    assert "protected void onCreate" in text
    stub = root / "src" / "raw" / "com" / "example" / "util" / "Helper.java"
    assert "decompilation failed: boom" in stub.read_text(encoding="utf-8")
    assert "public void run();" in stub.read_text(encoding="utf-8")

    # extracted entries and native libs
    assert (
        root / "data" / "apk" / "base" / "assets" / "config.json"
    ).read_text() == "{}"
    assert not (root / "data" / "apk" / "base" / "classes.dex").exists()
    assert (root / "lib" / "arm64_v8a" / "libfoo.so").is_file()
    assert (root / "lib" / "armeabi_v7a" / "libfoo.so").is_file()
    assert (root / "lib" / "unknown" / "hidden.so").is_file()
    assert (root / "native" / "arm64_v8a" / "libfoo" / "functions.json").is_file()
    assert (root / "native" / "arm64_v8a" / "libfoo" / "tocode.log").is_file()
    assert {(abi, name) for abi, name, _ in exporter.calls} == {
        ("arm64-v8a", "libfoo.so"),
        ("armeabi-v7a", "libfoo.so"),
        ("unknown", "hidden.so"),
    }

    libs = json.loads((root / "native-libs.json").read_text(encoding="utf-8"))
    assert libs["count"] == 3 and libs["done"] == 2
    statuses = {(item["abi"], item["name"]): item["status"] for item in libs["libs"]}
    assert statuses[("arm64-v8a", "libfoo.so")] == "done"
    assert statuses[("armeabi-v7a", "libfoo.so")].startswith("failed:")
    done = next(item for item in libs["libs"] if item["status"] == "done")
    assert done["export_dir"].startswith("native/")
    assert done["backend"] == "r2" and done["function_count"] == 12

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["package"] == "com.example.app"
    assert manifest["main_activities"] == ["com.example.app.MainActivity"]

    functions = json.loads((root / "functions.json").read_text(encoding="utf-8"))
    rows = {row["name"]: row for row in functions["functions"]}
    on_create = rows["Lcom/example/app/MainActivity;->onCreate(Landroid/os/Bundle;)V"]
    assert on_create["address"] == "classes.dex:0x120"
    assert on_create["callees"] == ["classes.dex:0x140"]
    assert on_create["string_ref_count"] == 1
    assert on_create["source_file"] == "src/raw/com/example/app/MainActivity.java"
    assert on_create["source_line_start"] == 11 and on_create["source_line_end"] == 16
    assert on_create["dead_code"] is False
    run = rows["Lcom/example/util/Helper;->run()V"]
    assert run["callees_imports"] == ["Ljava/lang/Thread;->start()V"]
    assert run["callers"] == ["classes.dex:0x140"]
    assert run["source_line_start"] == 1  # failure stub covers the whole file
    assert rows["Lcom/example/app/MainActivity;->nativeAdd(II)I"]["native"] is True

    index = json.loads((root / "function-index.json").read_text(encoding="utf-8"))
    assert index["schema_version"] == 2 and index["language"] == "java"
    entry = next(
        item for item in index["functions"] if item["name"].endswith("add(II)I")
    )
    assert entry["c"] == {
        "path": "src/raw/com/example/app/MainActivity.java",
        "line_start": 25,
        "line_end": 28,
    }
    assert entry["asm"] is None

    imports = json.loads((root / "imports.json").read_text(encoding="utf-8"))
    assert imports["imports"][0]["dll"] == "java.lang"
    assert (
        imports["imports"][0]["functions"][0]["name"] == "Ljava/lang/Thread;->start()V"
    )

    exports = json.loads((root / "exports.json").read_text(encoding="utf-8"))
    kinds = [(item["kind"], item["name"]) for item in exports["exports"]]
    assert ("activity", "com.example.app.MainActivity") in kinds
    jni = next(item for item in exports["exports"] if item["kind"] == "jni")
    assert jni["forwarder_target"] == "Java_com_example_app_MainActivity_nativeAdd"

    strings = json.loads((root / "strings.json").read_text(encoding="utf-8"))
    url = next(item for item in strings["strings"] if item["value"].startswith("https"))
    assert url["xrefs"][0]["address"] == "classes.dex:0x120"

    reachable = json.loads((root / "reachable.json").read_text(encoding="utf-8"))
    depths = {item["name"]: item["depth"] for item in reachable["reachable"]}
    assert depths["Lcom/example/util/Helper;->run()V"] == 1
    assert reachable["unreachable_count"] == 0

    triage = json.loads((root / "triage.json").read_text(encoding="utf-8"))
    assert triage["binary_type"] == "apk"
    assert triage["dangerous_permissions"] == ["android.permission.READ_SMS"]
    assert (
        triage["native_methods"][0]["jni_symbol"]
        == "Java_com_example_app_MainActivity_nativeAdd"
    )
    assert triage["strings_of_interest"][0]["value"] == "https://api.example.com/v1"
    assert len(triage["native_libs"]) == 3

    sections = json.loads((root / "sections.json").read_text(encoding="utf-8"))
    kinds_by_name = {item["name"]: item["type"] for item in sections["sections"]}
    assert kinds_by_name["classes.dex"] == "dex"
    assert kinds_by_name["lib/arm64-v8a/libfoo.so"] == "native"
    assert kinds_by_name["assets/config.json"] == "asset"
    assert kinds_by_name["resources.arsc"] == "arsc"

    graph = json.loads((root / "package-graph.json").read_text(encoding="utf-8"))
    app = next(
        item for item in graph["packages"] if item["package"] == "com.example.app"
    )
    assert app["calls_packages"] == [{"package": "com.example.util", "calls": 1}]

    project = json.loads((root / "project.json").read_text(encoding="utf-8"))
    assert project["backend"] == "asc" and project["package"] == "com.example.app"
    assert project["native_enabled"] is True
    manifest_doc = json.loads(
        (root / "export-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest_doc["format"] == "apk"
    assert manifest_doc["failures"] == [
        {"address": None, "name": "Lcom/example/util/Helper;", "error": "boom"}
    ]
    assert manifest_doc["native_errors"] == [
        "armeabi-v7a/libfoo.so: failed: no decompiler backend available"
    ]
    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
    assert "com.example.app" in agents and "native/<abi>/<lib>/" in agents
    assert (root / "CLAUDE.md").read_text(encoding="utf-8") == "@./AGENTS.md\n"
    log = (root / "tocode.log").read_text(encoding="utf-8")
    assert "Native decompilation finished: 2/3" in log
    assert "export Lcom/example/util/Helper; failed: boom" in log


def test_export_apk_no_native_only_extracts_libs(
    tmp_path: Path, fake_backend: None
) -> None:
    apk = _build_apk(tmp_path / "base.apk")
    exporter = _fake_native_exporter()

    summary = export_apk(
        apk,
        options=ApkExportOptions(out_dir=tmp_path / "export", jobs=1, native=False),
        progress=Progress(enabled=False),
        native_exporter=exporter,
        decompiler_factory=FakeDecompiler,
    )

    assert exporter.calls == []
    assert summary.native_done == 0 and summary.native_total == 3
    root = summary.root_dir
    assert (root / "lib" / "arm64_v8a" / "libfoo.so").is_file()
    assert not (root / "native").exists()
    libs = json.loads((root / "native-libs.json").read_text(encoding="utf-8"))
    assert {item["status"] for item in libs["libs"]} == {"skipped: --no-native"}
    assert "--no-native" in (root / "AGENTS.md").read_text(encoding="utf-8")
    project = json.loads((root / "project.json").read_text(encoding="utf-8"))
    assert project["native_enabled"] is False


def test_export_apk_default_out_dir_uses_package_name(
    tmp_path: Path, fake_backend: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TOCODE_DEFAULT_OUT_ROOT", raising=False)
    apk = _build_apk(tmp_path / "base.apk", libs=False)

    summary = export_apk(
        apk,
        options=ApkExportOptions(jobs=1),
        progress=Progress(enabled=False),
        decompiler_factory=FakeDecompiler,
    )

    assert summary.root_dir == tmp_path / "com_example_app_decompiler"
    assert summary.native_total == 0


def test_export_apk_merges_sibling_splits_and_bundles(
    tmp_path: Path, fake_backend: None
) -> None:
    _build_apk(tmp_path / "base.apk", libs=False)
    with zipfile.ZipFile(tmp_path / "split_config.arm64_v8a.apk", "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        archive.writestr("lib/arm64-v8a/libsplit.so", b"\x7fELF" + b"\x00" * 8)
    with zipfile.ZipFile(tmp_path / "app.apks", "w") as bundle:
        bundle.write(tmp_path / "base.apk", "base.apk")
        bundle.write(
            tmp_path / "split_config.arm64_v8a.apk", "split_config.arm64_v8a.apk"
        )

    exporter = _fake_native_exporter()
    merged = export_apk(
        tmp_path / "base.apk",
        options=ApkExportOptions(out_dir=tmp_path / "merged", jobs=1),
        progress=Progress(enabled=False),
        native_exporter=exporter,
        decompiler_factory=FakeDecompiler,
    )
    assert [item.name for item in merged.apks] == [
        "base.apk",
        "split_config.arm64_v8a.apk",
    ]
    assert merged.native_total == 1 and merged.native_done == 1
    manifest = json.loads(
        (merged.root_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert [item["apk"] for item in manifest["splits"]] == [
        "split_config.arm64_v8a.apk"
    ]
    assert (
        merged.root_dir
        / "data"
        / "apk"
        / "split_config_arm64_v8a"
        / "AndroidManifest.xml"
    ).is_file()

    alone = export_apk(
        tmp_path / "base.apk",
        options=ApkExportOptions(out_dir=tmp_path / "alone", jobs=1, splits=False),
        progress=Progress(enabled=False),
        native_exporter=exporter,
        decompiler_factory=FakeDecompiler,
    )
    assert [item.name for item in alone.apks] == ["base.apk"]
    assert alone.native_total == 0

    bundled = export_apk(
        tmp_path / "app.apks",
        options=ApkExportOptions(out_dir=tmp_path / "bundled", jobs=1),
        progress=Progress(enabled=False),
        native_exporter=exporter,
        decompiler_factory=FakeDecompiler,
    )
    assert [item.name for item in bundled.apks] == [
        "base.apk",
        "split_config.arm64_v8a.apk",
    ]
    assert bundled.native_total == 1
    assert not any(item.exists() for item in bundled.apks)  # bundle workdir cleaned


def test_export_apk_rejects_missing_or_invalid_input(tmp_path: Path) -> None:
    with pytest.raises(ToCodeError):
        export_apk(tmp_path / "missing.apk", progress=Progress(enabled=False))
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"nope")
    with pytest.raises(ToCodeError):
        export_apk(bad, progress=Progress(enabled=False))


def test_export_apk_removes_stale_java_files(
    tmp_path: Path, fake_backend: None
) -> None:
    apk = _build_apk(tmp_path / "base.apk", libs=False)
    stale = tmp_path / "export" / "src" / "raw" / "old" / "Gone.java"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale", encoding="utf-8")

    export_apk(
        apk,
        options=ApkExportOptions(out_dir=tmp_path / "export", jobs=1),
        progress=Progress(enabled=False),
        decompiler_factory=FakeDecompiler,
    )

    assert not stale.exists()


@pytest.mark.skipif(
    not os.environ.get("TOCODE_TEST_APK"), reason="set TOCODE_TEST_APK to a real APK"
)
def test_export_real_apk_with_asc(tmp_path: Path) -> None:
    pytest.importorskip("droidasc")
    apk = Path(os.environ["TOCODE_TEST_APK"])

    summary = export_apk(
        apk,
        options=ApkExportOptions(
            out_dir=tmp_path / "export", native=False, splits=False
        ),
        progress=Progress(enabled=False),
    )

    assert summary.class_count > 0
    classes = json.loads(
        (summary.root_dir / "classes.json").read_text(encoding="utf-8")
    )
    assert classes["count"] == summary.class_count
    assert (
        len(list((summary.root_dir / "src" / "raw").rglob("*.java")))
        == summary.class_count
    )


class _FakeProcess:
    def __init__(self, exitcode: int) -> None:
        self.exitcode = exitcode
        self.joined = False
        self.pid: int | None = None

    def is_alive(self) -> bool:
        return False

    def join(self) -> None:
        self.joined = True


class _FakeQueue:
    def __init__(self, item: Any = None) -> None:
        self.item = item

    def get(self, timeout: float | None = None) -> Any:
        import queue

        if self.item is None:
            raise queue.Empty
        return self.item


def test_collect_child_result_reports_a_killed_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tocode import apk_native
    from tocode.apk_native import collect_child_result

    killed: list[int | None] = []
    monkeypatch.setattr(apk_native, "kill_process_group", killed.append)
    process = _FakeProcess(-9)
    process.pid = 4242
    with pytest.raises(ToCodeError) as info:
        collect_child_result(process, _FakeQueue(), poll_seconds=0.01)

    assert "killed by signal 9" in str(info.value)
    assert "--no-native" in str(info.value)
    assert process.joined
    assert killed == [4242]  # the child's leftover worker pool is reaped too


def test_collect_child_result_passes_through_errors_and_results() -> None:
    from tocode.apk_native import collect_child_result

    with pytest.raises(ToCodeError, match="no decompiler backend"):
        collect_child_result(
            _FakeProcess(1), _FakeQueue(("error", "no decompiler backend available"))
        )
    with pytest.raises(ToCodeError, match="exited with code 3"):
        collect_child_result(_FakeProcess(3), _FakeQueue(), poll_seconds=0.01)

    assert collect_child_result(
        _FakeProcess(0), _FakeQueue(("ok", ("r2", "radare2 pdc", 12, 1)))
    ) == ("r2", "radare2 pdc", 12, 1)


def test_native_runner_waits_for_free_memory(tmp_path: Path) -> None:
    libs = [
        NativeLib(
            "arm64-v8a",
            "libfoo.so",
            "lib/arm64-v8a/libfoo.so",
            "base.apk",
            1,
            "h",
            tmp_path / "a.so",
        )
    ]
    readings = iter([100, 200, 4096])
    seen: list[int | None] = []

    def available() -> int | None:
        value = next(readings, 4096)
        seen.append(value)
        return value

    runner = NativeRunner(
        libs=libs,
        root=tmp_path,
        progress=Progress(enabled=False),
        exporter=_fake_native_exporter(),
        min_free_mb=1024,
        available_memory=available,
        poll_seconds=0.01,
    )
    runner.start()
    runner.join()

    assert seen == [100, 200, 4096]  # waited until there was headroom
    assert libs[0].status == "done"


def test_native_runner_memory_gate_is_off_without_a_floor(tmp_path: Path) -> None:
    libs = [
        NativeLib(
            "x86",
            "libfoo.so",
            "lib/x86/libfoo.so",
            "base.apk",
            1,
            "h",
            tmp_path / "a.so",
        )
    ]
    calls = 0

    def available() -> int | None:
        nonlocal calls
        calls += 1
        return 0

    runner = NativeRunner(
        libs=libs,
        root=tmp_path,
        progress=Progress(enabled=False),
        exporter=_fake_native_exporter(),
        available_memory=available,
    )
    runner.start()
    runner.join()

    assert calls == 0 and libs[0].status == "done"


def test_nested_log_tail_mirrors_lines_and_counts_functions(tmp_path: Path) -> None:
    from tocode.apk_native import NestedLogTail

    main = Progress(enabled=False)
    main.set_log_path(tmp_path / "main.log")
    nested = tmp_path / "nested.log"
    nested.write_text(
        "2026-09-19T20:41:14 Analyzing with IDA Domain auto-analysis\n",
        encoding="utf-8",
    )
    lib = NativeLib(
        "arm64-v8a",
        "libfoo.so",
        "lib/arm64-v8a/libfoo.so",
        "base.apk",
        1,
        "h",
        tmp_path / "libfoo.so",
    )
    tail = NestedLogTail(nested, lib, main, poll_seconds=0.01)
    tail.start()
    with nested.open("a", encoding="utf-8") as handle:
        handle.write(
            "2026-09-19T20:41:15 Rendering and writing 3 functions in 1 clusters\n"
        )
        handle.write("2026-09-19T20:41:15 export sub_1000 0x1000 - 10 bytes done\n")
        handle.write("2026-09-19T20:41:15 export sub_2000 0x2000 - 10 bytes done\n")
        handle.write("2026-09-19T20:41:15 export sub_3000 0x3000 - 10 bytes\n")  # start
        handle.write("plain backend stderr line\n")
        handle.write("2026-09-19T20:41:16 partial line without newline")
    tail.stop()

    assert tail.total == 3 and tail.rendered == 2
    assert tail.status() == "2/3 functions"
    mirrored = (tmp_path / "main.log").read_text(encoding="utf-8")
    assert "native[libfoo.so]: Analyzing with IDA Domain auto-analysis" in mirrored
    assert "native[libfoo.so]: Rendering and writing 3 functions" in mirrored
    assert "native[libfoo.so]: plain backend stderr line" in mirrored
    assert "export sub_1000" not in mirrored  # per-function lines feed the bar only
    assert (
        "export sub_3000" not in mirrored
    )  # start lines are neither counted nor shown
    assert "partial line" not in mirrored


def test_native_runner_describe_current_reports_progress(tmp_path: Path) -> None:
    from tocode import apk_native

    lib = NativeLib(
        "arm64-v8a",
        "libfoo.so",
        "lib/arm64-v8a/libfoo.so",
        "base.apk",
        1,
        "h",
        tmp_path / "a.so",
    )
    started = threading.Event()
    release = threading.Event()

    def slow(
        lib_: NativeLib, out_dir: Path, progress: Progress
    ) -> tuple[str, str, int, int]:
        progress.log("Rendering and writing 5 functions in 1 clusters")
        started.set()
        release.wait(5)
        return ("ida", "Hex-Rays", 5, 0)

    runner = apk_native.NativeRunner(
        libs=[lib], root=tmp_path, progress=Progress(enabled=False), exporter=slow
    )
    assert runner.describe_current() is None
    runner.start()
    assert started.wait(5)
    deadline = time.monotonic() + 5
    while runner.current_tail is not None and runner.current_tail.total is None:
        if time.monotonic() > deadline:
            break
        time.sleep(0.01)
    status = runner.describe_current()
    release.set()
    runner.join()

    assert status is not None
    assert status.startswith("native: libfoo.so (arm64-v8a) 0/5 functions")
    assert "0/1 libraries finished" in status
    assert runner.describe_current() is None


def test_describe_origin_names_the_apk_package(tmp_path: Path) -> None:
    from tocode.apk_native import describe_origin

    lib = NativeLib(
        "arm64-v8a",
        "libfoo.so",
        "lib/arm64-v8a/libfoo.so",
        "base.apk",
        1,
        "abc",
        tmp_path / "libfoo.so",
        package="com.example.app",
    )

    text = describe_origin(lib)

    assert text.startswith(
        "This is a decompiled native library from the `com.example.app` APK: "
        "`libfoo.so` (arm64-v8a, `lib/arm64-v8a/libfoo.so` in `base.apk`, sha256 `abc`)."
    )
    assert "Java_<package>_<Class>_<method>" in text
    assert "an Android app" in describe_origin(
        NativeLib("x86", "l.so", "lib/x86/l.so", "a.apk", 1, "h", tmp_path / "l.so")
    )


def test_export_apk_tags_native_libs_with_the_package(
    tmp_path: Path, fake_backend: None
) -> None:
    apk = _build_apk(tmp_path / "base.apk")
    seen: list[str] = []

    def exporter(
        lib: NativeLib, out_dir: Path, progress: Progress
    ) -> tuple[str, str, int, int]:
        seen.append(lib.package)
        return ("r2", "radare2 pdc", 1, 0)

    export_apk(
        apk,
        options=ApkExportOptions(out_dir=tmp_path / "export", jobs=1),
        progress=Progress(enabled=False),
        native_exporter=exporter,
        decompiler_factory=FakeDecompiler,
    )

    assert seen == ["com.example.app"] * 3
