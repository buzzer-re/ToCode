from __future__ import annotations

import json
from pathlib import Path
import struct
import zipfile

import pytest

from dotnet_fixtures import managed_pe, native_elf, single_file_bundle, write
from tocode.backends import dotnet as backend
from tocode.backends.dotnet import (
    discover_dotnet_input,
    il_method_ranges,
    is_dotnet_input,
    is_framework_assembly,
    is_framework_native,
    native_arch,
    pinvoke_neighbours,
)
from tocode.backends.dotnet_pe import (
    COMIMAGE_FLAGS_32BITREQUIRED,
    COMIMAGE_FLAGS_ILONLY,
    COMIMAGE_FLAGS_STRONGNAMESIGNED,
    ONE_BYTE_OPCODES,
    TWO_BYTE_OPCODES,
    extract_bundle_entry,
    is_apphost_launcher,
    iter_user_strings,
    method_body,
    parse_bundle,
    parse_pe,
    read_bundle,
    read_pe_info,
    scan_il_tokens,
)
from tocode.errors import ToCodeError


# --------------------------------------------------------------------------
# PE / CLR headers
# --------------------------------------------------------------------------


def test_parse_pe_reads_clr_header_and_metadata_streams() -> None:
    data = managed_pe(
        strings=["hello", "https://example.invalid/api"],
        cor_flags=COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_STRONGNAMESIGNED,
    )

    info = parse_pe(data)

    assert info is not None
    assert info.is_managed and info.il_only and not info.mixed_mode
    assert info.machine == "x86_64" and info.pe32_plus
    assert info.image_base == 0x180000000
    assert info.runtime_version == "v4.0.30319"
    assert info.entry_point_token == 0x06000001
    assert info.cor_flag_names == ["ILOnly", "StrongNameSigned"]
    assert [stream.name for stream in info.streams] == ["#~", "#US"]
    assert info.sections[0].name == ".text" and info.sections[0].perms == "r-x"
    heap = info.stream("#US")
    assert heap is not None
    assert [
        value
        for _, value in iter_user_strings(data[heap.offset : heap.offset + heap.size])
    ] == [
        "hello",
        "https://example.invalid/api",
    ]


def test_mixed_mode_versus_ready_to_run() -> None:
    mixed = parse_pe(managed_pe(cor_flags=COMIMAGE_FLAGS_32BITREQUIRED))
    r2r = parse_pe(managed_pe(cor_flags=0, ready_to_run=True))

    assert mixed is not None and mixed.mixed_mode and not mixed.ready_to_run
    # ReadyToRun clears ILONLY too, but its native code is precompiled IL.
    assert r2r is not None and r2r.ready_to_run and not r2r.mixed_mode


def test_parse_pe_rejects_non_pe_input() -> None:
    assert parse_pe(b"\x7fELF" + b"\x00" * 64) is None
    assert parse_pe(b"MZ" + b"\x00" * 10) is None
    assert parse_pe(b"") is None


def test_rva_to_offset_maps_into_sections() -> None:
    info = parse_pe(managed_pe())
    assert info is not None
    assert info.rva_to_offset(0x2010) == 0x210
    assert info.rva_to_offset(0x9000) is None


def test_user_strings_handle_multibyte_lengths() -> None:
    from dotnet_fixtures import user_string_heap

    long_value = "x" * 300  # 601 bytes -> 2-byte compressed length
    heap = user_string_heap(["a", long_value, "ñandú"])
    values = iter_user_strings(heap)

    assert [value for _, value in values] == ["a", long_value, "ñandú"]
    assert values[0][0] == 1


# --------------------------------------------------------------------------
# IL bodies and token scan
# --------------------------------------------------------------------------


def test_method_body_reads_tiny_and_fat_headers() -> None:
    tiny = bytes([(3 << 2) | 0x2, 0x02, 0x2A, 0x00])
    fat = struct.pack("<HHII", 0x3013, 8, 4, 0x11000001) + b"\x00\x01\x02\x03"

    assert method_body(tiny, 0) == b"\x02\x2a\x00"
    assert method_body(fat, 0) == b"\x00\x01\x02\x03"
    assert method_body(b"\x00", 0) is None


def test_scan_il_tokens_reads_operands_and_skips_switch_tables() -> None:
    code = bytes.fromhex(
        "72"
        "01000070"  # ldstr string 1
        "28"
        "0a00000a"  # call memberref
        "45"
        "02000000"
        "00000000"
        "00000000"  # switch with 2 targets
        "fe06"
        "0300002b"  # ldftn methodspec
        "7b"
        "05000004"  # ldfld field
        "20"
        "ffffffff"  # ldc.i4 (no token)
        "fe0c"
        "0100"  # ldloc 1 (2-byte operand)
        "8d"
        "0100001b"  # newarr typespec
        "d0"
        "02000002"  # ldtoken typedef
        "2a"  # ret
    )

    assert scan_il_tokens(code) == [
        ("string", 0x70000001),
        ("method", 0x0A00000A),
        ("method", 0x2B000003),
        ("field", 0x04000005),
        ("type", 0x1B000001),
        ("token", 0x02000002),
    ]


def test_scan_il_tokens_stops_at_invalid_opcode() -> None:
    # 0x24 is unassigned: an encrypted/garbled body must not be misread.
    assert scan_il_tokens(bytes.fromhex("72010000702428020000062a")) == [
        ("string", 0x70000001)
    ]


def test_opcode_tables_leave_only_the_unassigned_ecma_codes_out() -> None:
    unassigned = (
        {0x24, 0x77, 0x78, 0xC4, 0xC5}
        | set(range(0xA6, 0xB3))
        | set(range(0xBB, 0xC2))
        | set(range(0xC7, 0xD0))
    )
    assert {code for code in range(0xE1) if code not in ONE_BYTE_OPCODES} == unassigned
    assert {code for code in range(0x1F) if code not in TWO_BYTE_OPCODES} == {
        0x08,
        0x10,
        0x1B,
    }
    assert TWO_BYTE_OPCODES[0x06] == "method" and TWO_BYTE_OPCODES[0x16] == "type"


# --------------------------------------------------------------------------
# Single-file bundles
# --------------------------------------------------------------------------


def _bundle(tmp_path: Path) -> Path:
    deps = {
        "targets": {
            ".NETCoreApp,Version=v10.0/linux-arm64": {
                "runtimepack.Microsoft.NETCore.App.Runtime.linux-arm64/10.0.0": {
                    "runtime": {"System.Private.CoreLib.dll": {}},
                    "native": {"libcoreclr.so": {}},
                }
            }
        },
        "libraries": {
            "runtimepack.Microsoft.NETCore.App.Runtime.linux-arm64/10.0.0": {
                "type": "runtimepack"
            }
        },
    }
    return write(
        tmp_path / "App",
        single_file_bundle(
            [
                ("App.dll", 1, managed_pe(strings=["app"]), True),
                (
                    "System.Private.CoreLib.dll",
                    1,
                    managed_pe(strings=["corelib"]),
                    False,
                ),
                ("Vendor.Lib.dll", 1, managed_pe(strings=["vendor"]), True),
                ("libcoreclr.so", 2, native_elf(), False),
                ("libcustom.so", 2, native_elf(0x3E), True),
                ("App.deps.json", 3, json.dumps(deps).encode(), False),
                ("App.runtimeconfig.json", 4, b"{}", False),
            ]
        ),
    )


def test_parse_bundle_lists_entries_and_extracts_compressed_data(
    tmp_path: Path,
) -> None:
    path = _bundle(tmp_path)

    manifest = read_bundle(path)

    assert manifest is not None
    assert (manifest.major, manifest.minor, manifest.bundle_id) == (
        6,
        0,
        "testbundle01",
    )
    assert [(entry.path, entry.kind) for entry in manifest.entries][:4] == [
        ("App.dll", "assembly"),
        ("System.Private.CoreLib.dll", "assembly"),
        ("Vendor.Lib.dll", "assembly"),
        ("libcoreclr.so", "native"),
    ]
    first = manifest.entries[0]
    assert first.compressed_size and first.compressed_size < first.size
    extract_bundle_entry(path, first, tmp_path / "out" / "App.dll")
    assert (tmp_path / "out" / "App.dll").read_bytes() == managed_pe(strings=["app"])
    assert not is_apphost_launcher(path)


def test_plain_apphost_is_a_launcher_not_a_bundle(tmp_path: Path) -> None:
    host = write(tmp_path / "Tool", single_file_bundle([], launcher=True))

    assert parse_bundle(host.read_bytes()) is None
    assert is_apphost_launcher(host)
    assert not is_dotnet_input(host)  # no Tool.dll next to it
    write(tmp_path / "Tool.dll", managed_pe())
    assert is_dotnet_input(host)

    found = discover_dotnet_input(host, workdir=tmp_path / "work")
    assert found.kind == "apphost"
    assert [item.path.name for item in found.assemblies] == ["Tool.dll"]


def test_discover_bundle_splits_app_framework_and_natives(tmp_path: Path) -> None:
    path = _bundle(tmp_path)

    found = discover_dotnet_input(path, workdir=tmp_path / "work")

    assert found.kind == "bundle"
    assert {item.entry: item.include for item in found.assemblies} == {
        "App.dll": True,
        "System.Private.CoreLib.dll": False,
        "Vendor.Lib.dll": True,
    }
    assert {item.name: item.framework for item in found.natives} == {
        "libcoreclr.so": True,
        "libcustom.so": False,
    }
    assert {item.name: item.arch for item in found.natives}["libcustom.so"] == "x86_64"
    assert {extra.kind for extra in found.extras} == {"deps-json", "runtime-config"}
    assert found.search_dirs == [tmp_path / "work" / "bundle"]

    everything = discover_dotnet_input(
        path, workdir=tmp_path / "work2", include_framework=True
    )
    assert all(item.include for item in everything.assemblies)


# --------------------------------------------------------------------------
# NuGet packages and plain assemblies
# --------------------------------------------------------------------------


def test_discover_nupkg_prefers_the_newest_target_framework(tmp_path: Path) -> None:
    package = tmp_path / "Vendor.Lib.1.0.0.nupkg"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("Vendor.Lib.nuspec", "<package/>")
        archive.writestr(
            "lib/netstandard2.0/Vendor.Lib.dll", managed_pe(strings=["ns20"])
        )
        archive.writestr("lib/net8.0/Vendor.Lib.dll", managed_pe(strings=["net8"]))
        archive.writestr("lib/net48/Vendor.Lib.dll", managed_pe(strings=["net48"]))
        archive.writestr("ref/net8.0/Vendor.Lib.dll", managed_pe(strings=["ref"]))
        archive.writestr("runtimes/linux-x64/native/libvendor.so", native_elf(0x3E))

    found = discover_dotnet_input(package, workdir=tmp_path / "work")

    assert found.kind == "nupkg"
    chosen = [item.entry for item in found.included]
    assert chosen == ["lib/net8.0/Vendor.Lib.dll"]
    skipped = {item.entry: item.reason for item in found.assemblies if not item.include}
    assert set(skipped) == {
        "lib/netstandard2.0/Vendor.Lib.dll",
        "lib/net48/Vendor.Lib.dll",
        "ref/net8.0/Vendor.Lib.dll",
    }
    assert [(item.name, item.arch) for item in found.natives] == [
        ("libvendor.so", "linux-x64")
    ]
    assert [extra.entry for extra in found.extras] == ["Vendor.Lib.nuspec"]


def test_tfm_ranking_prefers_modern_targets() -> None:
    from tocode.backends.dotnet import _tfm_rank

    newtonsoft = [
        "net20",
        "net35",
        "net40",
        "net45",
        "net6.0",
        "netstandard1.0",
        "netstandard1.3",
        "netstandard2.0",
    ]
    assert max(newtonsoft, key=_tfm_rank) == "net6.0"
    assert sorted(
        ["net48", "net472", "netcoreapp3.1", "net10.0-windows", "netstandard2.1"],
        key=_tfm_rank,
    ) == [
        "net472",
        "net48",
        "netstandard2.1",
        "netcoreapp3.1",
        "net10.0-windows",
    ]


def test_discover_plain_assembly_and_mixed_mode(tmp_path: Path) -> None:
    plain = write(tmp_path / "Plain.dll", managed_pe())
    mixed = write(
        tmp_path / "Mixed.dll", managed_pe(cor_flags=COMIMAGE_FLAGS_32BITREQUIRED)
    )

    assert discover_dotnet_input(plain, workdir=tmp_path / "w1").natives == []
    found = discover_dotnet_input(mixed, workdir=tmp_path / "w2")
    assert [(item.name, item.path) for item in found.natives] == [("Mixed.dll", mixed)]


def test_is_dotnet_input_rejects_native_and_garbage(tmp_path: Path) -> None:
    assert not is_dotnet_input(write(tmp_path / "libfoo.so", native_elf()))
    assert not is_dotnet_input(write(tmp_path / "junk.bin", b"hello"))
    assert is_dotnet_input(write(tmp_path / "App.exe", managed_pe()))
    with pytest.raises(ToCodeError):
        discover_dotnet_input(tmp_path / "libfoo.so", workdir=tmp_path / "w")


def test_pinvoke_neighbours_finds_platform_named_libraries(tmp_path: Path) -> None:
    write(tmp_path / "libnative_helper.so", native_elf())
    write(tmp_path / "crypto.dll", managed_pe())  # managed: not a native target
    write(tmp_path / "libzstd.so", native_elf())

    found = pinvoke_neighbours(
        tmp_path, {"native_helper", "crypto", "libzstd.so", "libc"}
    )

    assert sorted((module, path.name) for module, path in found) == [
        ("libzstd.so", "libzstd.so"),
        ("native_helper", "libnative_helper.so"),
    ]


def test_framework_name_heuristics() -> None:
    assert is_framework_assembly("System.Private.CoreLib.dll")
    assert is_framework_assembly("mscorlib.dll")
    assert is_framework_assembly("Microsoft.CSharp.dll")
    assert not is_framework_assembly("Microsoft.Build.dll")
    assert not is_framework_assembly("Newtonsoft.Json.dll")
    assert is_framework_native("libcoreclr.so")
    assert is_framework_native("libSystem.Native.so")
    assert is_framework_native("clrjit.dll")
    assert not is_framework_native("libsqlite3.so")


def test_native_arch_reads_elf_and_pe_machines(tmp_path: Path) -> None:
    assert native_arch(write(tmp_path / "a.so", native_elf(0xB7))) == "arm64"
    assert native_arch(write(tmp_path / "b.so", native_elf(0x3E))) == "x86_64"
    assert native_arch(write(tmp_path / "c.dll", managed_pe(machine=0x14C))) == "x86"


def test_read_pe_info_on_missing_file(tmp_path: Path) -> None:
    assert read_pe_info(tmp_path / "missing.dll") is None


# --------------------------------------------------------------------------
# Decompiler output parsing and runtime discovery
# --------------------------------------------------------------------------


def test_il_method_ranges_follow_method_blocks() -> None:
    text = "\n".join(
        [
            ".class /* 02000002 */ public C",
            "{",
            "    .method /* 06000001 */ public hidebysig",
            "        instance void M () cil managed",
            "    {",
            "        IL_0000: ret",
            "    } // end of method C::M",
            "",
            "    .method /* 0600000A */ private static",
            "        void N () cil managed",
            "    {",
            "    } // end of method C::N",
            "} // end of class C",
        ]
    )

    assert il_method_ranges(text) == {0x06000001: (3, 7), 0x0600000A: (9, 12)}


def test_find_runtime_requires_net9_or_newer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "dotnet"
    for version in ("8.0.10", "9.0.4", "10.0.12"):
        folder = root / "shared" / "Microsoft.NETCore.App" / version
        folder.mkdir(parents=True)
        (folder / "System.Private.CoreLib.dll").write_bytes(b"MZ")
    monkeypatch.setattr(backend, "dotnet_root_candidates", lambda: [root])
    assert backend.find_runtime() == (root, "10.0.12")

    for version in ("9.0.4", "10.0.12"):
        (
            root
            / "shared"
            / "Microsoft.NETCore.App"
            / version
            / "System.Private.CoreLib.dll"
        ).unlink()
    assert backend.find_runtime() is None


def _runtime_available() -> bool:
    from tocode.backends import dotnet_libs

    try:
        return backend.probe_dotnet()[0] and dotnet_libs.is_installed()
    except Exception:  # pragma: no cover
        return False


@pytest.mark.skipif(
    not _runtime_available(), reason="needs a .NET 9+ runtime and pythonnet"
)
def test_opcode_tables_agree_with_dnlib() -> None:
    backend.load_runtime()
    from dnlib.DotNet.Emit import OpCodes, OperandType  # type: ignore[import-not-found]

    token_kinds = {
        int(OperandType.InlineMethod): "method",
        int(OperandType.InlineField): "field",
        int(OperandType.InlineType): "type",
        int(OperandType.InlineString): "string",
        int(OperandType.InlineSig): "sig",
        int(OperandType.InlineTok): "token",
        int(OperandType.InlineSwitch): "switch",
    }
    sizes = {
        int(OperandType.InlineNone): "none",
        int(OperandType.ShortInlineBrTarget): "i1",
        int(OperandType.ShortInlineI): "i1",
        int(OperandType.ShortInlineVar): "i1",
        int(OperandType.InlineVar): "i2",
        int(OperandType.InlineBrTarget): "i4",
        int(OperandType.InlineI): "i4",
        int(OperandType.ShortInlineR): "i4",
        int(OperandType.InlineI8): "i8",
        int(OperandType.InlineR): "i8",
    }
    for table, ours in (
        (OpCodes.OneByteOpCodes, ONE_BYTE_OPCODES),
        (OpCodes.TwoByteOpCodes, TWO_BYTE_OPCODES),
    ):
        for index, opcode in enumerate(table):
            if str(opcode.Name).startswith("prefix"):
                continue  # reserved prefix bytes, not instructions
            if str(opcode.Name).startswith("UNKNOWN"):
                assert index not in ours, hex(index)
                continue
            if index == 0xFE and table is OpCodes.OneByteOpCodes:
                continue  # prefix byte
            kind = int(opcode.OperandType)
            assert ours.get(index) == token_kinds.get(kind, sizes.get(kind)), (
                str(opcode.Name),
                hex(index),
            )
