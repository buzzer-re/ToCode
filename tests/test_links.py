"""Link facts: binary parsers, loader rules, and symbol binding."""

from __future__ import annotations

from pathlib import Path

from link_fixtures import (
    CPU_ARM64,
    CPU_X86_64,
    EM_X86_64,
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    Metadata,
    elf,
    fat,
    macho,
    managed,
    pe,
    write,
)
import pytest

from tocode.links.analyze import link_folder
from tocode.links.binfmt_dotnet import parse_dotnet_links
from tocode.links.binfmt_elf import parse_elf
from tocode.links.binfmt_macho import parse_macho, parse_macho_file
from tocode.links.binfmt_pe import parse_pe_links
from tocode.links.inventory import scan
from tocode.links.names import c_tokens, itanium_hints, link_key
from tocode.links.sniff import JAVA_CLASS, MACHO_FAT, classify_bytes


def _links(root: Path):
    inventory = scan(root)
    return inventory, link_folder(inventory)


def _edge(result, source: str, name: str):
    return next(
        edge
        for edge in result.resolution.edges
        if edge.source == source and edge.name == name
    )


def _link(result, importer: str, symbol: str):
    return next(
        link
        for link in result.links
        if link.importer == importer and link.symbol == symbol
    )


# -- sniffing -----------------------------------------------------------------


def test_sniff_tells_fat_mach_o_from_java_class() -> None:
    universal = fat([(CPU_ARM64, macho())])
    java = b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\x00" * 32  # class file v65

    assert classify_bytes(universal).kind == MACHO_FAT
    assert classify_bytes(java).kind == JAVA_CLASS


# -- parsers ------------------------------------------------------------------


def test_elf_reads_needed_paths_and_versioned_symbols() -> None:
    facts = parse_elf(
        elf(
            soname="libfoo.so.1",
            needed=["libbar.so", "libc.so.6"],
            runpath="$ORIGIN",
            exports=[("foo_add", 0x1000, "FOO_1.0"), ("foo_raw", 0x1010, None)],
            imports=[("bar_mul", None, None), ("puts", "GLIBC_2.17", "libc.so.6")],
        )
    )

    assert facts.kind == "library" and facts.identity == "libfoo.so.1"
    assert [lib.name for lib in facts.libraries] == ["libbar.so", "libc.so.6"]
    assert facts.runpaths == ["$ORIGIN"] and facts.rpaths == []
    imports = {item.name: item for item in facts.imports}
    assert imports["bar_mul"].library is None  # unversioned: global lookup
    assert imports["puts"].version == "GLIBC_2.17" and imports["puts"].library == 1
    exports = {item.name: item for item in facts.exports}
    assert (
        exports["foo_add"].address == 0x1000 and exports["foo_add"].version == "FOO_1.0"
    )


def test_elf_pie_is_an_executable() -> None:
    assert parse_elf(elf(executable=True)).kind == "executable"


def test_pe_reads_imports_delay_imports_ordinals_and_forwarders() -> None:
    facts = parse_pe_links(
        pe(
            name="core.dll",
            exports=[
                ("core_add", 1, 0x1000),
                (None, 42, 0x1010),
                ("fwd", 3, "mathx.mathx_mul"),
            ],
            imports={"KERNEL32.dll": ["Sleep", 7]},
            delay={"lazy.dll": ["lazy_log"]},
        )
    )

    assert facts.kind == "library" and facts.identity == "core.dll"
    assert [(lib.name, lib.kind) for lib in facts.libraries] == [
        ("KERNEL32.dll", "needed"),
        ("lazy.dll", "delay"),
    ]
    by_name = {item.name: item for item in facts.imports}
    assert by_name["#7"].ordinal == 7
    # IAT slots are consecutive pointers from the image base.
    sleep_slot, ordinal_slot = by_name["Sleep"].slot, by_name["#7"].slot
    assert sleep_slot is not None and sleep_slot > 0x180000000
    assert ordinal_slot == sleep_slot + 8
    exports = {item.name: item for item in facts.exports}
    assert exports["#42"].ordinal == 42 and exports["#42"].address == 0x180001010
    assert (
        exports["fwd"].forwarder == "mathx.mathx_mul" and exports["fwd"].address is None
    )


@pytest.mark.parametrize("imports_format", [1, 2, 3])
def test_macho_chained_imports_keep_two_level_ordinals(imports_format: int) -> None:
    facts = parse_macho(
        macho(
            install_name="@rpath/a.dylib",
            libraries=[
                ("@rpath/b.dylib", LC_LOAD_DYLIB),
                ("/usr/lib/libSystem.B.dylib", LC_LOAD_DYLIB),
            ],
            rpaths=["@loader_path"],
            imports=[
                ("_b_fn", 1),
                ("_puts", 2),
                ("_weak", -3),
                ("_main_sym", -1),
                ("_self", 0),
            ],
            exports=[("_a_fn", 0x4000), ("_re", 1, "_b_fn")],
            imports_format=imports_format,
        )
    )

    assert facts.identity == "@rpath/a.dylib" and facts.rpaths == ["@loader_path"]
    rows = {item.name: (item.library, item.special) for item in facts.imports}
    assert rows == {
        "_b_fn": (0, None),
        "_puts": (1, None),
        "_weak": (None, "weak_lookup"),
        "_main_sym": (None, "main_executable"),
        "_self": (None, "self"),
    }
    exports = {item.name: item for item in facts.exports}
    assert exports["_a_fn"].address == 0x4000
    assert (
        exports["_re"].reexport_library == 0 and exports["_re"].reexport_name == "_b_fn"
    )


def test_macho_bind_opcodes_give_slots() -> None:
    facts = parse_macho(
        macho(
            libraries=[("@rpath/b.dylib", LC_LOAD_DYLIB)],
            imports=[("_x", 1), ("_y", -1)],
            exports=[("_e", 0x10)],
            bind_opcodes=True,
        )
    )

    assert [(item.name, item.library, item.special) for item in facts.imports] == [
        ("_x", 0, None),
        ("_y", None, "main_executable"),
    ]
    first_slot = facts.imports[0].slot
    assert first_slot is not None and facts.imports[1].slot == first_slot + 8
    assert [(item.name, item.address) for item in facts.exports] == [("_e", 0x10)]


def test_macho_fat_file_yields_one_facts_per_slice() -> None:
    data = fat(
        [
            (CPU_X86_64, macho(cputype=CPU_X86_64, exports=[("_a", 0x10)])),
            (CPU_ARM64, macho(exports=[("_a", 0x20)])),
        ]
    )

    slices = parse_macho_file(data)
    assert [(item.arch, item.exports[0].address) for item in slices] == [
        ("x86_64", 0x10),
        ("arm64", 0x20),
    ]
    assert [item.arch for item in parse_macho_file(data, arch="arm64")] == ["arm64"]


def _lib_metadata() -> Metadata:
    md = Metadata()
    md.add(0x00, 0, md.string("MathLib.dll"), 1, 0, 0)  # Module
    md.add(0x02, 0, md.string("<Module>"), 0, 0, 1, 1)
    md.add(0x02, 0x100001, md.string("Calc"), md.string("MathLib"), 0, 1, 1)
    int_sig = md.blob(bytes([0x00, 2, 0x08, 0x08, 0x08]))  # static int (int,int)
    double_sig = md.blob(
        bytes([0x00, 2, 0x0D, 0x0D, 0x0D])
    )  # static double (double,double)
    md.add(0x06, 0, 0, 0x16, md.string("Add"), int_sig, 1)
    md.add(0x06, 0, 0, 0x16, md.string("Add"), double_sig, 1)
    md.add(0x20, 0x8004, 1, 0, 0, 0, 0, 0, md.string("MathLib"), 0)  # Assembly
    return md


def _app_metadata() -> Metadata:
    md = Metadata()
    md.add(0x00, 0, md.string("App.dll"), 1, 0, 0)
    md.add(0x23, 1, 0, 0, 0, 0, 0, md.string("MathLib"), 0, 0)  # AssemblyRef 1
    scope = (1 << 2) | 2  # ResolutionScope: AssemblyRef #1
    md.add(0x01, scope, md.string("Calc"), md.string("MathLib"))  # TypeRef 1
    parent = (1 << 3) | 1  # MemberRefParent: TypeRef #1
    md.add(0x0A, parent, md.string("Add"), md.blob(bytes([0x00, 2, 0x0D, 0x0D, 0x0D])))
    md.add(0x02, 0, md.string("<Module>"), 0, 0, 1, 1)
    md.add(0x02, 0x100001, md.string("Program"), 0, 0, 1, 1)
    md.add(0x06, 0, 0, 0x16, md.string("Main"), md.blob(bytes([0x00, 0, 0x01])), 1)
    md.add(0x1A, md.string("nativemath"))  # ModuleRef 1
    md.add(
        0x06,
        0,
        0x80,
        0x2016,
        md.string("Square"),
        md.blob(bytes([0x00, 1, 0x08, 0x08])),
        1,
    )
    md.add(
        0x1C, 0, (2 << 1) | 1, md.string("native_square"), 1
    )  # ImplMap -> MethodDef 2
    md.add(0x20, 0x8004, 1, 0, 0, 0, 0, 0, md.string("App"), 0)
    return md


def test_dotnet_reads_member_refs_with_signatures_callers_and_pinvoke() -> None:
    # call MathLib.Calc::Add(double,double) (MemberRef 0x0A000001), ret
    body = bytes([0x28]) + (0x0A000001).to_bytes(4, "little") + bytes([0x2A])
    facts = parse_dotnet_links(managed(_app_metadata(), bodies={1: body}))

    assert facts.format == "dotnet" and facts.identity == "App"
    assert [(lib.name, lib.kind) for lib in facts.libraries] == [
        ("MathLib", "assembly"),
        ("nativemath", "pinvoke"),
    ]
    member = next(item for item in facts.imports if item.kind == "method")
    assert member.name == "MathLib.Calc::Add"
    assert member.signature == "double (double,double)"
    assert member.callers == [0x06000001]
    pinvoke = next(item for item in facts.imports if item.kind == "pinvoke")
    assert pinvoke.name == "native_square" and pinvoke.owner == "Program::Square"

    library = parse_dotnet_links(managed(_lib_metadata()))
    signatures = {(item.name, item.signature): item.token for item in library.exports}
    assert signatures[("MathLib.Calc::Add", "double (double,double)")] == 0x06000002


# -- resolution and binding ---------------------------------------------------


def test_elf_rpath_runpath_versions_and_name_only_libraries(tmp_path: Path) -> None:
    root = tmp_path / "app"
    write(
        root / "bin/app",
        elf(
            executable=True,
            needed=["libfoo.so.1", "libbar.so", "libbaz.so"],
            rpath="$ORIGIN/../lib",
            imports=[
                ("foo_add", "FOO_1.0", "libfoo.so.1"),
                ("bar_mul", None, None),
                ("baz_hi", None, None),
            ],
        ),
    )
    write(
        root / "lib/libfoo.so.1",
        elf(
            soname="libfoo.so.1",
            needed=["libbar.so"],
            runpath="$ORIGIN",
            exports=[("foo_add", 0x700, "FOO_1.0")],
            imports=[("bar_mul", None, None)],
        ),
    )
    write(
        root / "lib/libbar.so",
        elf(soname="libbar.so", exports=[("bar_mul", 0x500, None)]),
    )
    write(
        root / "plugins/libbaz.so",
        elf(soname="libbaz.so", exports=[("baz_hi", 0x600, None)]),
    )

    inventory, result = _links(root)

    assert inventory.roots == ["bin/app"]
    foo = _edge(result, "bin/app", "libfoo.so.1")
    assert (foo.status, foo.target) == ("in_folder", "lib/libfoo.so.1")
    assert "DT_RPATH $ORIGIN/../lib of bin/app" in foo.via
    bar = _edge(result, "lib/libfoo.so.1", "libbar.so")
    assert bar.status == "in_folder" and "SONAME already loaded" in bar.via[0]
    baz = _edge(result, "bin/app", "libbaz.so")
    assert (baz.status, baz.target) == ("name_match_unreachable", "plugins/libbaz.so")

    versioned = _link(result, "bin/app", "foo_add")
    assert (versioned.status, versioned.resolution, versioned.address) == (
        "bound",
        "versioned",
        0x700,
    )
    scoped = _link(result, "bin/app", "bar_mul")
    assert (scoped.target, scoped.resolution) == ("lib/libbar.so", "global_scope")
    name_only = _link(result, "bin/app", "baz_hi")
    assert name_only.target == "plugins/libbaz.so" and name_only.status == "bound"


def test_elf_runpath_is_not_inherited(tmp_path: Path) -> None:
    root = tmp_path / "app"
    write(root / "app", elf(executable=True, needed=["liba.so"], runpath="$ORIGIN/lib"))
    write(root / "lib/liba.so", elf(soname="liba.so", needed=["libb.so"]))
    write(root / "lib/libb.so", elf(soname="libb.so"))

    _inventory, result = _links(root)

    assert _edge(result, "app", "liba.so").status == "in_folder"
    # DT_RUNPATH of the executable does not apply to liba's own dependencies.
    inherited = _edge(result, "lib/liba.so", "libb.so")
    assert inherited.status == "name_match_unreachable"


def test_macho_rpath_stack_loader_path_reexports_and_weak(tmp_path: Path) -> None:
    root = tmp_path / "Game.app/Contents"
    write(
        root / "Info.plist",
        b'<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>Game</string></dict></plist>',
    )
    write(
        root / "MacOS/Game",
        macho(
            filetype="executable",
            libraries=[
                ("@rpath/core.dylib", LC_LOAD_DYLIB),
                ("@rpath/opt.dylib", LC_LOAD_WEAK_DYLIB),
            ],
            rpaths=["@executable_path/../Frameworks"],
            imports=[("_core_fn", 1), ("_umbrella_fn", 1), ("_inline_fn", -3)],
            exports=[("_inline_fn", 0x100000400)],
        ),
    )
    write(
        root / "Frameworks/core.dylib",
        macho(
            install_name="@rpath/core.dylib",
            libraries=[
                ("@loader_path/impl.dylib", LC_REEXPORT_DYLIB),
                ("@rpath/util.dylib", LC_LOAD_DYLIB),
            ],
            imports=[("_util_fn", 2)],
            exports=[("_core_fn", 0x1000)],
        ),
    )
    write(
        root / "Frameworks/impl.dylib",
        macho(
            install_name="@loader_path/impl.dylib", exports=[("_umbrella_fn", 0x2000)]
        ),
    )
    # util.dylib is found through the executable's LC_RPATH (inherited stack).
    write(
        root / "Frameworks/util.dylib",
        macho(install_name="@rpath/util.dylib", exports=[("_util_fn", 0x3000)]),
    )

    inventory, result = _links(tmp_path / "Game.app")

    assert inventory.roots == ["Contents/MacOS/Game"]
    assert inventory.entry("Contents/MacOS/Game").main
    assert (
        _edge(result, "Contents/MacOS/Game", "@rpath/core.dylib").target
        == "Contents/Frameworks/core.dylib"
    )
    assert (
        _edge(result, "Contents/MacOS/Game", "@rpath/opt.dylib").status
        == "weak_missing"
    )
    util = _edge(result, "Contents/Frameworks/core.dylib", "@rpath/util.dylib")
    assert util.target == "Contents/Frameworks/util.dylib"
    assert any("of Contents/MacOS/Game" in step for step in util.via)

    assert _link(result, "Contents/MacOS/Game", "_core_fn").address == 0x1000
    umbrella = _link(result, "Contents/MacOS/Game", "_umbrella_fn")
    assert (umbrella.target, umbrella.resolution) == (
        "Contents/Frameworks/impl.dylib",
        "reexport",
    )
    weak = _link(result, "Contents/MacOS/Game", "_inline_fn")
    assert (weak.target, weak.resolution) == ("Contents/MacOS/Game", "weak_lookup")


def test_fat_library_links_the_executable_architecture(tmp_path: Path) -> None:
    root = tmp_path / "app"
    write(
        root / "Game",
        macho(
            filetype="executable",
            libraries=[("@executable_path/lib.dylib", LC_LOAD_DYLIB)],
            imports=[("_f", 1)],
        ),
    )
    write(
        root / "lib.dylib",
        fat(
            [
                (CPU_X86_64, macho(cputype=CPU_X86_64, exports=[("_f", 0x10)])),
                (CPU_ARM64, macho(exports=[("_f", 0x20)])),
            ]
        ),
    )

    inventory, result = _links(root)

    assert inventory.arch == "arm64" and inventory.entry("lib.dylib").arch == "arm64"
    assert _link(result, "Game", "_f").address == 0x20


def test_pe_app_directory_forwarders_ordinals_and_arch(tmp_path: Path) -> None:
    root = tmp_path / "game"
    write(
        root / "app.exe",
        pe(
            dll=False,
            image_base=0x140000000,
            imports={
                "core.dll": ["core_add", "core_mul2", 42],
                "KERNEL32.dll": ["Sleep"],
                "api-ms-win-crt-runtime-l1-1-0.dll": ["exit"],
            },
            delay={"lazy.dll": ["lazy_log"]},
        ),
    )
    write(
        root / "core.dll",
        pe(
            name="core.dll",
            exports=[
                ("core_add", 1, 0x1000),
                ("core_mul2", 2, "mathx.mathx_mul"),
                (None, 42, 0x1010),
            ],
        ),
    )
    write(
        root / "mathx.dll",
        pe(
            name="mathx.dll", image_base=0x190000000, exports=[("mathx_mul", 1, 0x1000)]
        ),
    )
    write(
        root / "plugins/lazy.dll",
        pe(name="lazy.dll", exports=[("lazy_log", 1, 0x1000)]),
    )
    write(
        root / "tool32.exe",
        pe(
            dll=False,
            machine=0x14C,
            image_base=0x400000,
            imports={"mathx.dll": ["mathx_mul"]},
        ),
    )

    _inventory, result = _links(root)

    assert _edge(result, "app.exe", "core.dll").target == "core.dll"
    assert _edge(result, "app.exe", "KERNEL32.dll").status == "system"
    assert (
        _edge(result, "app.exe", "api-ms-win-crt-runtime-l1-1-0.dll").status == "apiset"
    )
    lazy = _edge(result, "app.exe", "lazy.dll")
    assert (lazy.kind, lazy.status) == ("delay", "name_match_unreachable")
    assert _edge(result, "tool32.exe", "mathx.dll").status == "arch_mismatch"

    forwarded = _link(result, "app.exe", "core_mul2")
    assert (forwarded.target, forwarded.export, forwarded.resolution) == (
        "mathx.dll",
        "mathx_mul",
        "forwarder",
    )
    assert forwarded.address == 0x190001000
    by_ordinal = _link(result, "app.exe", "#42")
    assert (by_ordinal.resolution, by_ordinal.address) == ("ordinal", 0x180001010)


def test_dotnet_assembly_refs_and_pinvoke_bind(tmp_path: Path) -> None:
    root = tmp_path / "dn"
    body = bytes([0x28]) + (0x0A000001).to_bytes(4, "little") + bytes([0x2A])
    write(root / "App.dll", managed(_app_metadata(), bodies={1: body}, dll=False))
    write(root / "MathLib.dll", managed(_lib_metadata()))
    write(
        root / "libnativemath.so",
        elf(
            soname="libnativemath.so",
            machine=EM_X86_64,
            exports=[("native_square", 0x500, None)],
        ),
    )

    _inventory, result = _links(root)

    assert _edge(result, "App.dll", "MathLib").target == "MathLib.dll"
    member = _link(result, "App.dll", "MathLib.Calc::Add")
    assert (member.status, member.token) == ("bound", 0x06000002)  # the double overload
    native = _link(result, "App.dll", "native_square")
    assert (native.target, native.address) == ("libnativemath.so", 0x500)


def test_cycles_are_reported(tmp_path: Path) -> None:
    root = tmp_path / "c"
    write(root / "app", elf(executable=True, needed=["liba.so"], rpath="$ORIGIN"))
    write(root / "liba.so", elf(soname="liba.so", needed=["libb.so"], rpath="$ORIGIN"))
    write(root / "libb.so", elf(soname="libb.so", needed=["liba.so"], rpath="$ORIGIN"))

    _inventory, result = _links(root)

    assert result.resolution.cycles == [["liba.so", "libb.so"]]


# -- names --------------------------------------------------------------------


def test_link_keys_strip_backend_decorations() -> None:
    for raw in (
        "sym.imp.printf",
        "printf@@GLIBC_2.17",
        ".printf",
        "__imp_printf",
        "_printf",
        "j_printf",
    ):
        assert link_key(raw) == "printf"
    assert "foo__FOO_1_0" in c_tokens("foo", "FOO_1.0")
    assert "new Counter" in c_tokens("MathLib.Counter::.ctor")


def test_itanium_hints_cover_simple_shapes_only() -> None:
    assert itanium_hints("__ZN1r6StringD2Ev") == ["String::~String"]
    assert itanium_hints("__ZNK1r4Mesh4sizeEv") == ["Mesh::size"]
    assert itanium_hints("__Z16GetAsyncKeyStatei") == ["GetAsyncKeyState"]
    assert itanium_hints("_ZNSt6vectorIiE9push_backEi") == []
