"""Tests for the Binary Ninja backend.

A real Binary Ninja is never required: ``BinjaSession`` only ever touches a
``bv``/``bn`` through attribute access, so small duck-typed fakes stand in for
both. The fakes also mimic the netref behavior of the headless (RPyc) path --
plain attribute access and method calls -- so these tests cover both modes.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from tocode import cli
from tocode.analysis import create_analyzer
from tocode.backends.base import choose_backend
from tocode.backends.binja import (
    BinjaSession,
    describe_view,
    focused_view,
    open_views,
    view_source_path,
)
from tocode.exporter import TIMEOUT_WORKER_BACKENDS


# -- fakes -----------------------------------------------------------------


class FakeSymbolType:
    ImportedFunctionSymbol = "T:ImportedFunctionSymbol"
    ImportAddressSymbol = "T:ImportAddressSymbol"
    ImportedDataSymbol = "T:ImportedDataSymbol"
    FunctionSymbol = "T:FunctionSymbol"
    DataSymbol = "T:DataSymbol"


class FakeSymbolBinding:
    GlobalBinding = "B:Global"
    WeakBinding = "B:Weak"
    LocalBinding = "B:Local"


class FakeDisassemblySettings:
    def set_option(self, option, value):  # noqa: D401 - test stub
        return None


class FakeDisassemblyOption:
    ShowAddress = "ShowAddress"
    WaitForIL = "WaitForIL"


class FakeLine:
    def __init__(self, text: str, address: int) -> None:
        self._text = text
        self.contents = types.SimpleNamespace(address=address)

    def __str__(self) -> str:
        return self._text


class FakeLinearViewObject:
    @classmethod
    def language_representation(cls, bv, settings, language=None):
        return types.SimpleNamespace(bv=bv, language=language)


class FakeLinearViewCursor:
    def __init__(self, obj) -> None:
        self.obj = obj
        self.address = 0
        self.done = False

    def seek_to_address(self, address: int) -> None:
        self.address = int(address)


class FakeBN:
    SymbolType = FakeSymbolType
    SymbolBinding = FakeSymbolBinding
    DisassemblySettings = FakeDisassemblySettings
    DisassemblyOption = FakeDisassemblyOption
    LinearViewObject = FakeLinearViewObject
    LinearViewCursor = FakeLinearViewCursor


class FakeVar:
    def __init__(self, name: str, type_: str, identifier: int) -> None:
        self.name = name
        self.type = type_
        self.identifier = identifier


class FakeFunc:
    def __init__(
        self,
        start: int,
        name: str,
        *,
        total_bytes: int = 32,
        symbol_type: str = FakeSymbolType.FunctionSymbol,
        params=(),
        local_vars=(),
        callees=(),
        callers=(),
        return_type: str = "int32_t",
        can_return: bool = True,
        hlil=object(),
        instructions=(),
    ) -> None:
        self.start = start
        self.name = name
        self.total_bytes = total_bytes
        self.symbol = types.SimpleNamespace(type=symbol_type)
        self.parameter_vars = list(params)
        self.vars = list(params) + list(local_vars)
        self.callees = list(callees)
        self.callers = list(callers)
        self.return_type = return_type
        self.can_return = can_return
        self.calling_convention = types.SimpleNamespace(name="cdecl")
        self.hlil = hlil
        self.instructions = list(instructions)
        self.is_thunk = False
        self.highest_address = start + total_bytes - 1


class FakeBV:
    def __init__(
        self, *, functions, sections, segments, symbols, strings, linear
    ) -> None:
        self.functions = list(functions)
        self.sections = sections
        self._segments = list(segments)
        self._symbols = list(symbols)
        self._strings = list(strings)
        self._linear = dict(linear)
        self.arch = types.SimpleNamespace(name="x86_64")
        self.address_size = 8
        self.platform = types.SimpleNamespace(name="linux-x86_64")
        self.view_type = "ELF"
        self.start = 0x400000
        self.entry_point = 0x401000
        self.entry_functions = [f for f in functions if f.name == "main"]
        self.file = types.SimpleNamespace(filename="/tmp/sample.bin")
        self._index = {f.start: f for f in functions}
        self.analyzed = False

    def update_analysis_and_wait(self) -> None:
        self.analyzed = True

    def get_function_at(self, address):
        return self._index.get(int(address))

    def get_symbols_of_type(self, symbol_type):
        return [s for s in self._symbols if s.type == symbol_type]

    def get_symbols(self):
        return list(self._symbols)

    def get_strings(self):
        return list(self._strings)

    def get_segment_at(self, address):
        for seg in self._segments:
            if seg.start <= address < seg.start + seg.length:
                return seg
        return None

    def get_sections_at(self, address):
        return [
            sec
            for sec in self.sections.values()
            if sec.start <= address < sec.start + sec.length
        ]

    def get_next_linear_disassembly_lines(self, cursor):
        if cursor.done:
            return []
        cursor.done = True
        return self._linear.get(cursor.address, [])


def _sample_bv() -> FakeBV:
    main = FakeFunc(
        0x401000,
        "main",
        params=[FakeVar("argc", "int32_t", 1)],
        local_vars=[FakeVar("result", "int64_t", 2)],
        return_type="int32_t",
        instructions=[(["push", " ", "rbp"], 0x401000), (["ret"], 0x401010)],
    )
    helper = FakeFunc(0x401100, "helper", return_type="void")
    main.callees = [helper]
    helper.callers = [main]
    puts = types.SimpleNamespace(
        address=0x402000,
        name="puts",
        short_name="puts",
        type=FakeSymbolType.ImportedFunctionSymbol,
        binding=FakeSymbolBinding.GlobalBinding,
        namespace=types.SimpleNamespace(name="libc.so.6"),
        ordinal=None,
    )
    main_sym = types.SimpleNamespace(
        address=0x401000,
        name="main",
        short_name="main",
        type=FakeSymbolType.FunctionSymbol,
        binding=FakeSymbolBinding.GlobalBinding,
        namespace=types.SimpleNamespace(name=None),
        ordinal=None,
    )
    text = types.SimpleNamespace(
        name=".text", start=0x401000, length=0x1000, type="PROGBITS"
    )
    sections = {".text": text}
    segments = [
        types.SimpleNamespace(
            start=0x401000,
            length=0x1000,
            readable=True,
            writable=False,
            executable=True,
        )
    ]
    strings = [
        types.SimpleNamespace(start=0x403000, value="hello", length=5, type="ascii")
    ]
    linear = {
        0x401000: [
            FakeLine("int32_t main(int32_t argc)", 0x401000),
            FakeLine("{", 0x401000),
            FakeLine("    return 0;", 0x401005),
            FakeLine("}", 0x401010),
        ]
    }
    return FakeBV(
        functions=[main, helper],
        sections=sections,
        segments=segments,
        symbols=[puts, main_sym],
        strings=strings,
        linear=linear,
    )


def _session() -> BinjaSession:
    return BinjaSession(bv=_sample_bv(), bn=FakeBN())


# -- identity / selection --------------------------------------------------


def test_backend_identity() -> None:
    assert BinjaSession.backend_name == "binja"
    assert BinjaSession.parallel_safe is False
    assert BinjaSession.analysis_command is None


def test_binja_excluded_from_timeout_workers() -> None:
    # Renders against a live, non-picklable session, so it must stay off the
    # spawned-worker path.
    assert "binja" not in TIMEOUT_WORKER_BACKENDS


def test_choose_backend_explicit_binja() -> None:
    choice = choose_backend("binja")
    assert choice.selected == "binja"


def test_create_analyzer_routes_injected_bv_to_binja() -> None:
    bv = _sample_bv()
    with create_analyzer(
        Path("/tmp/sample.bin"), backend="binja", binja_bv=bv, binja_bn=FakeBN()
    ) as analyzer:
        assert isinstance(analyzer.session, BinjaSession)
        assert analyzer.supports_parallel is False


# -- metadata shaping ------------------------------------------------------


def test_info_shape() -> None:
    info = _session().info()
    binary = info["bin"]
    assert binary["arch"] == "x86_64"
    assert binary["bits"] == 64
    assert binary["os"] == "linux"
    assert info["tocode"]["input_path"] == "/tmp/sample.bin"


def test_collections_are_lists_of_dicts() -> None:
    session = _session()
    for rows in (
        session.entries(),
        session.sections(),
        session.imports(),
        session.exports(),
        session.symbols(),
        session.relocations(),
        session.strings(),
        session.flags(),
        session.functions(),
        session.types(),
    ):
        assert isinstance(rows, list)
        assert all(isinstance(row, dict) for row in rows)


def test_sections_have_required_keys() -> None:
    required = {"name", "size", "vsize", "type", "perm", "paddr", "vaddr"}
    for row in _session().sections():
        assert required <= row.keys()
        assert len(row["perm"]) == 3
    assert _session().sections()[0]["perm"] == "r-x"


def test_imports_carry_library() -> None:
    rows = _session().imports()
    assert rows
    puts = rows[0]
    assert puts["name"] == "puts"
    assert puts["plt"] == 0x402000
    assert puts["dll"] == "libc.so.6"


def test_functions_have_required_keys() -> None:
    rows = {row["name"]: row for row in _session().functions()}
    required = {
        "addr",
        "name",
        "size",
        "noreturn",
        "is_library",
        "is_thunk",
        "source_kind",
    }
    for row in rows.values():
        assert required <= row.keys()
        assert isinstance(row["addr"], int)
    main = rows["main"]
    assert main["return_type"] == "int32_t"
    assert main["params"] == [{"name": "argc", "type": "int32_t"}]
    assert main["locals"] == [{"name": "result", "type": "int64_t"}]
    assert main["nargs"] == 1
    assert main["nlocals"] == 1
    assert main["outdegree"] == 1
    assert main["source_kind"] == "app"


def test_disasm_and_summary() -> None:
    session = _session()
    disasm = session.disasm(0x401000)
    assert "0x401000:" in disasm
    summary = session.function_summary(0x401000)
    assert "args: 1" in summary
    assert "locals: 1" in summary
    assert "callees: 1" in summary


def test_decompile_renders_pseudo_c() -> None:
    text = _session().decompile(0x401000)
    # The exporter parses the prototype before the opening brace.
    assert "int32_t main(int32_t argc)" in text
    assert "{" in text and "return 0;" in text


def test_decompile_falls_back_without_hlil() -> None:
    bv = _sample_bv()
    bv.get_function_at(0x401100).hlil = None  # helper has no high-level IL
    session = BinjaSession(bv=bv, bn=FakeBN())
    text = session.decompile(0x401100)
    assert "helper" in text
    assert "no high-level IL" in text


def test_calls_from_classifies_internal_and_imported() -> None:
    session = _session()

    class _Routine:
        def __init__(self, name: str, imported: bool) -> None:
            self.name = name
            self.imported = imported

    functions = {0x401100: _Routine("helper", False)}
    imports = {0x402000: _Routine("puts", True)}
    targets, imported = session.calls_from(0x401000, imports, functions)
    assert targets == [0x401100]
    assert isinstance(imported, list)


def test_analyze_is_idempotent_noop() -> None:
    bv = _sample_bv()
    session = BinjaSession(bv=bv, bn=FakeBN())
    session.analyze()
    session.analyze()
    assert bv.analyzed is True


# -- headless view enumeration ---------------------------------------------


def _fake_view(
    path: str, *, view_type: str = "ELF", start: int = 0x400000, nfuncs: int = 3
):
    return types.SimpleNamespace(
        file=types.SimpleNamespace(filename=path),
        view_type=view_type,
        start=start,
        address_size=8,
        functions=[object()] * nfuncs,
    )


class FakeViewFrame:
    def __init__(self, bv) -> None:
        self._bv = bv

    def getCurrentBinaryView(self):
        return self._bv

    def getData(self):
        return self._bv


class FakeUIContext:
    def __init__(self, tabs) -> None:
        # tabs: list of (tab_token, frame_or_None)
        self._tabs = list(tabs)

    def getTabs(self):
        return [tab for tab, _ in self._tabs]

    def getViewFrameForTab(self, tab):
        for token, frame in self._tabs:
            if token is tab:
                return frame
        return None


def _fake_ui(contexts):
    return types.SimpleNamespace(
        UIContext=types.SimpleNamespace(allContexts=lambda: contexts)
    )


class FakeRoot:
    def __init__(self, bv, ui) -> None:
        self.binaryninja = FakeBN()
        self.bv = bv
        self._ui = ui

    def eval(self, cmd):
        assert "binaryninjaui" in cmd
        return self._ui


class FakeConn:
    def __init__(self, *, bv=None, ui=None) -> None:
        self.root = FakeRoot(bv, ui if ui is not None else _fake_ui([]))
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_focused_view_attribute_and_callable() -> None:
    bv = _fake_view("/a.elf")
    assert focused_view(FakeConn(bv=bv)) is bv
    # Older binja-headless builds expose bv as a method.
    assert focused_view(FakeConn(bv=lambda: bv)) is bv


def test_open_views_enumerates_filters_none_and_dedupes() -> None:
    a = _fake_view("/a.elf")
    b = _fake_view("/b.elf")
    ctx = FakeUIContext(
        [
            ("tabA", FakeViewFrame(a)),
            ("tabB", None),  # empty tab -> skipped
            ("tabC", FakeViewFrame(a)),  # duplicate of /a.elf -> deduped
            ("tabD", FakeViewFrame(b)),
        ]
    )
    views = open_views(FakeConn(ui=_fake_ui([ctx])))
    assert [view_source_path(v) for v in views] == ["/a.elf", "/b.elf"]


def test_describe_view() -> None:
    text = describe_view(_fake_view("/x.elf", view_type="ELF", nfuncs=5))
    assert "ELF" in text
    assert "/x.elf" in text
    assert "5 functions" in text


# -- CLI flag validation ---------------------------------------------------


def test_parser_allows_binja_without_binary() -> None:
    args = cli.build_parser().parse_args(["--backend", "binja", "--list-binja"])
    assert args.binary is None
    assert args.list_binja is True


def test_binja_only_flags_require_binja_backend() -> None:
    with pytest.raises(SystemExit):
        cli.main(["foo", "--list-binja"])  # backend defaults to auto


def test_binja_view_and_all_views_conflict() -> None:
    with pytest.raises(SystemExit):
        cli.main(["--backend", "binja", "--all-views", "--binja-view", "0"])
