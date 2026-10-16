"""A stand-in for the Binary Ninja Python API, for ToCode's tests.

It lives on disk (not in ``sys.modules``) so that spawned render workers import
it through ``--binja-dir`` exactly as they would a real install. Every view is the
same small x86-64 ELF-like program, whatever file is loaded. Environment:

- ``FAKE_BINJA_LOG``: file that gets one line per ``load``/``create_database``.
- ``FAKE_BINJA_LICENSE=invalid``: the core refuses headless use, like a
  personal license does, unless ``core_set_license`` was given ``FAKE-LICENSE``.
- ``FAKE_BINJA_SAVE=crash``: ``create_database`` kills the process, as some
  headless builds do.
- ``FAKE_BINJA_ANALYSIS_SECONDS``: how long analysis takes (ten progress steps;
  ``abort_analysis`` ends it early).

A database written by ``create_database`` is the magic line plus the original
file name; loading any other ``.bndb`` fails like a corrupt database.
"""

from __future__ import annotations

import enum
import os
import re
from pathlib import Path
import signal
import threading
from types import SimpleNamespace

_MAGIC = "FAKEBNDB\n"


def _note(line: str) -> None:
    path = os.environ.get("FAKE_BINJA_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{os.getpid()} {line}\n")


_license_data: str | None = None


def _check_license() -> None:
    if _license_data is not None and _license_data.strip() == "FAKE-LICENSE":
        return
    if _license_data is not None or os.environ.get("FAKE_BINJA_LICENSE") == "invalid":
        raise RuntimeError("License is not valid. Please supply a valid license.")


def core_set_license(licenseData: str) -> None:
    global _license_data
    _note("core_set_license")  # never the contents
    _license_data = licenseData


def disable_default_log() -> None:
    return None


def core_version() -> str:
    return "0.0.0"


def core_product() -> str:
    _check_license()
    return "Binary Ninja Fake"


class SymbolType:
    ImportedFunctionSymbol = "ImportedFunctionSymbol"
    ImportAddressSymbol = "ImportAddressSymbol"
    ImportedDataSymbol = "ImportedDataSymbol"
    FunctionSymbol = "FunctionSymbol"
    DataSymbol = "DataSymbol"


class SymbolBinding:
    GlobalBinding = "GlobalBinding"
    WeakBinding = "WeakBinding"
    LocalBinding = "LocalBinding"


class LowLevelILOperation:
    LLIL_STORE = "LLIL_STORE"
    LLIL_SET_REG = "LLIL_SET_REG"


class TokenEscapingType(enum.IntEnum):
    NoTokenEscapingType = 0
    BackticksTokenEscapingType = 1


class AnalysisState(enum.IntEnum):
    IdleState = 2
    AnalyzeState = 5


class AnalysisProgress:
    def __init__(self, state: AnalysisState, count: int, total: int) -> None:
        self.state = state
        self.count = count
        self.total = total

    def __str__(self) -> str:
        if self.state == AnalysisState.AnalyzeState:
            return f"Analyzing ({self.count}/{self.total})"
        return "Idle"


class TypeClass(enum.Enum):
    StructureTypeClass = 1
    IntegerTypeClass = 2
    EnumerationTypeClass = 3


class DisassemblyOption:
    ShowAddress = "ShowAddress"
    WaitForIL = "WaitForIL"


class DisassemblySettings:
    def set_option(self, option, value) -> None:
        return None


class LinearViewObject:
    @classmethod
    def language_representation(cls, bv, settings, language=None):
        return SimpleNamespace(bv=bv, language=language)


class LinearViewCursor:
    def __init__(self, obj) -> None:
        self.obj = obj
        self.address = 0
        self.done = False

    def seek_to_address(self, address: int) -> None:
        self.address = int(address)


class QualifiedName:
    def __init__(self, name) -> None:
        self.name = str(name)

    def __str__(self) -> str:
        return self.name


class _Line:
    def __init__(self, text: str, address: int) -> None:
        self._text = text
        self.contents = SimpleNamespace(address=address)

    def __str__(self) -> str:
        return self._text


class _Var:
    def __init__(self, name: str, type_: str, identifier: int) -> None:
        self.name = name
        self.type = type_
        self.identifier = identifier


class _Function:
    def __init__(
        self,
        view,
        start: int,
        name: str,
        *,
        size: int,
        symbol_type: str,
        params=(),
        local_vars=(),
        return_type="int32_t",
        hlil=True,
        llil=None,
    ) -> None:
        self._view = view
        self.start = start
        self.name = name
        self.total_bytes = size
        self.highest_address = start + size - 1
        self.symbol = SimpleNamespace(type=symbol_type)
        self.is_thunk = False
        self.parameter_vars = list(params)
        self.vars = list(params) + list(local_vars)
        self.return_type = return_type
        self.can_return = True
        self.calling_convention = SimpleNamespace(name="sysv")
        self.hlil = object() if hlil else None
        self.callees: list[_Function] = []
        self.callers: list[_Function] = []
        self._llil = dict(llil or {})

    @property
    def instructions(self):
        self._view._check_open()
        return [((["push", " ", "rbp"]), self.start), ((["ret"]), self.highest_address)]

    def get_llil_at(self, address: int):
        operation = self._llil.get(int(address))
        return None if operation is None else SimpleNamespace(operation=operation)

    # -- edits (the subset ToCode's live tools use) ----------------------------

    comment = ""

    def set_user_type(self, type_obj) -> None:
        """Takes a `_ParsedType` of `ret name(type a, ...)`."""
        match = re.match(r"\s*(.+?)\s*\b(\w+)\s*\((.*)\)\s*$", type_obj.decl)
        if match is None:
            raise ValueError(f"not a function type: {type_obj.decl}")
        self.return_type = match.group(1).strip()
        params = []
        for index, part in enumerate(
            p for p in match.group(3).split(",") if p.strip() and p.strip() != "void"
        ):
            words = part.strip().rsplit(" ", 1)
            name = words[1].lstrip("*") if len(words) == 2 else f"a{index + 1}"
            ptype = (
                (words[0] + "*" * (len(words[1]) - len(words[1].lstrip("*"))))
                if len(words) == 2
                else part.strip()
            )
            params.append(_Var(name, ptype, 100 + index))
        locals_ = [var for var in self.vars if var not in self.parameter_vars]
        self.parameter_vars = params
        self.vars = params + locals_

    def set_comment_at(self, address: int, text: str) -> None:
        self._view._comments[int(address)] = text

    def create_user_var(self, var, type_, name) -> None:
        var.name = name
        var.type = str(getattr(type_, "decl", type_))


class _ParsedType:
    """What `parse_type_string` returns: keeps the declaration text."""

    def __init__(self, decl: str) -> None:
        self.decl = decl.strip().rstrip(";")

    def __str__(self) -> str:
        return self.decl


class _UserType:
    """A struct/union/enum declared through `define_user_type`."""

    width = 8

    def __init__(self, source: str) -> None:
        self.source = source.strip()
        kind = self.source.split(None, 1)[0]
        self.type_class = (
            TypeClass.EnumerationTypeClass
            if kind == "enum"
            else TypeClass.StructureTypeClass
        )
        self.type = (
            "StructureVariant.UnionStructureType"
            if kind == "union"
            else "StructureVariant.StructStructureType"
        )

    def __str__(self) -> str:
        return self.source


class _StructType:
    type_class = TypeClass.StructureTypeClass
    type = "StructureVariant.StructStructureType"
    width = 8

    def __str__(self) -> str:
        return "struct point"


class _IntType:
    type_class = TypeClass.IntegerTypeClass
    width = 4

    def __str__(self) -> str:
        return "int32_t"


class FileMetadata:
    def __init__(self, filename: str, original: str) -> None:
        self.filename = filename
        self.original_filename = original
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def save_auto_snapshot(self, progress_func=None, settings=None) -> bool:
        """Saves into the .bndb the view was opened from."""
        _note(f"save_auto_snapshot {Path(self.filename).name}")
        Path(self.filename).write_text(
            _MAGIC + self.original_filename, encoding="utf-8"
        )
        return True


class BinaryView:
    def __init__(self, filename: str, original: str) -> None:
        self.file = FileMetadata(filename, original)
        self.arch = SimpleNamespace(name="x86_64")
        self.address_size = 8
        self.platform = SimpleNamespace(name="linux-x86_64")
        self.view_type = "ELF"
        self.start = 0x400000
        self.entry_point = 0x401000
        self.analyzed = False
        self.analysis_progress = AnalysisProgress(AnalysisState.IdleState, 0, 0)
        self._aborted = threading.Event()
        text = SimpleNamespace(
            name=".text", start=0x401000, length=0x100, type="PROGBITS"
        )
        rodata = SimpleNamespace(
            name=".rodata", start=0x403000, length=0x20, type="PROGBITS"
        )
        data = SimpleNamespace(
            name=".data", start=0x404000, length=0x10, type="PROGBITS"
        )
        self.sections = {".text": text, ".rodata": rodata, ".data": data}
        self._segments = [
            SimpleNamespace(
                start=0x401000,
                length=0x100,
                readable=True,
                writable=False,
                executable=True,
            ),
            SimpleNamespace(
                start=0x403000,
                length=0x20,
                readable=True,
                writable=False,
                executable=False,
            ),
            SimpleNamespace(
                start=0x404000,
                length=0x10,
                readable=True,
                writable=True,
                executable=False,
            ),
        ]
        main = _Function(
            self,
            0x401000,
            "main",
            size=0x40,
            symbol_type=SymbolType.FunctionSymbol,
            params=[_Var("argc", "int32_t", 1)],
            local_vars=[_Var("total", "int64_t", 2)],
            llil={
                0x401004: LowLevelILOperation.LLIL_SET_REG,
                0x401008: LowLevelILOperation.LLIL_STORE,
            },
        )
        helper = _Function(
            self,
            0x401080,
            "helper",
            size=0x20,
            symbol_type=SymbolType.FunctionSymbol,
            return_type="void",
        )
        puts = _Function(
            self,
            0x402000,
            "puts",
            size=0x10,
            symbol_type=SymbolType.ImportedFunctionSymbol,
            hlil=False,
        )
        main.callees = [helper, puts]
        helper.callers = [main]
        puts.callers = [main]
        self.functions = [main, helper, puts]
        self.entry_functions = [main]
        self._by_start = {func.start: func for func in self.functions}
        self._symbols = [
            SimpleNamespace(
                address=0x402000,
                name="puts",
                short_name="puts",
                type=SymbolType.ImportedFunctionSymbol,
                binding=SymbolBinding.GlobalBinding,
                namespace=SimpleNamespace(name="libc.so.6"),
                ordinal=None,
            ),
            SimpleNamespace(
                address=0x401000,
                name="main",
                short_name="main",
                type=SymbolType.FunctionSymbol,
                binding=SymbolBinding.GlobalBinding,
                namespace=SimpleNamespace(name=None),
                ordinal=None,
            ),
            SimpleNamespace(
                address=0x401080,
                name="helper",
                short_name="helper",
                type=SymbolType.FunctionSymbol,
                binding=SymbolBinding.LocalBinding,
                namespace=SimpleNamespace(name=None),
                ordinal=None,
            ),
            SimpleNamespace(
                address=0x404000,
                name="counter",
                short_name="counter",
                type=SymbolType.DataSymbol,
                binding=SymbolBinding.GlobalBinding,
                namespace=SimpleNamespace(name=None),
                ordinal=None,
            ),
        ]
        self._strings = [
            SimpleNamespace(start=0x403000, value="hello", length=5, type="AsciiString")
        ]
        self._code_refs = {
            0x403000: [SimpleNamespace(function=main, address=0x401004)],
            0x404000: [SimpleNamespace(function=main, address=0x401008)],
        }
        self.types = {"point": _StructType(), "score_t": _IntType()}
        self.type_container = SimpleNamespace(name="container")
        self._comments: dict[int, str] = {}
        self._data_vars: dict[int, object] = {}
        self._main, self._helper, self._puts = main, helper, puts

    # -- pseudo C, rendered from the current names, types and comments --------

    def _prototype(self, func) -> str:
        params = ", ".join(f"{var.type} {var.name}" for var in func.parameter_vars)
        return f"{func.return_type} {func.name}({params})"

    def _pseudo_c(self, func) -> list[str]:
        body: list[str] = []
        if func.comment:
            body.append(f"    // {func.comment}")
        for address in sorted(self._comments):
            if func.start <= address <= func.highest_address:
                body.append(f"    // {self._comments[address]}")
        for var in func.vars:
            if var not in func.parameter_vars and var.name != "total":
                body.append(f"    {var.type} {var.name};")
        if func is self._main:
            body += [
                f"    {self._helper.name}();",
                f'    return {self._puts.name}("hello");',
            ]
        elif func is self._helper:
            point = self.types.get("point")
            fields = point.source.count(";") - 1 if isinstance(point, _UserType) else 2
            body.append(f"    struct point *p; /* point has {fields} fields */")
            body += [f"    {callee.name}();" for callee in func.callees]
            body.append("    return;")
        else:
            body.append("    return 0;")
        return [self._prototype(func), "{", *body, "}"]

    # -- edits ------------------------------------------------------------------

    def parse_type_string(self, decl: str):
        match = re.search(r"(\w+)\s*(?:\(|$|\[)", decl.strip().rstrip(";"))
        return _ParsedType(decl), (match.group(1) if match else "")

    def parse_types_from_string(self, source: str):
        found = {}
        for match in re.finditer(
            r"\b(struct|union|enum)\s+(\w+)\s*\{[^}]*\}\s*;", source
        ):
            found[match.group(2)] = _UserType(match.group(0))
        if not found:
            raise SyntaxError("no type declarations")
        return SimpleNamespace(types=found, variables={}, functions={})

    def define_user_type(self, name, type_obj) -> None:
        _note(f"define_user_type {name}")
        self.types[str(name)] = type_obj

    def define_user_symbol(self, symbol) -> None:
        for existing in self._symbols:
            if existing.address == symbol.address:
                existing.name = existing.short_name = symbol.name
                return
        self._symbols.append(
            SimpleNamespace(
                address=symbol.address,
                name=symbol.name,
                short_name=symbol.name,
                type=symbol.type,
                binding=SymbolBinding.GlobalBinding,
                namespace=SimpleNamespace(name=None),
                ordinal=None,
            )
        )

    def define_user_data_var(self, address, type_obj) -> None:
        self._data_vars[int(address)] = type_obj

    def undefine_user_data_var(self, address) -> None:
        self._data_vars.pop(int(address), None)

    def set_comment_at(self, address, text) -> None:
        self._comments[int(address)] = text

    def add_user_function(self, address) -> None:
        address = int(address)
        if address in self._by_start:
            return
        func = _Function(
            self,
            address,
            f"sub_{address:x}",
            size=0x10,
            symbol_type=SymbolType.FunctionSymbol,
        )
        # The fake's discovered function is called by helper.
        self._helper.callees.append(func)
        func.callers = [self._helper]
        self.functions.append(func)
        self._by_start[address] = func
        _note(f"add_user_function 0x{address:x}")

    def remove_user_function(self, func) -> None:
        self.functions = [item for item in self.functions if item is not func]
        self._by_start.pop(func.start, None)
        for item in self.functions:
            item.callees = [callee for callee in item.callees if callee is not func]

    @property
    def segments(self):
        return list(self._segments)

    def _check_open(self) -> None:
        if self.file.closed:
            raise RuntimeError("use of a closed BinaryView")

    def update_analysis_and_wait(self) -> None:
        self._check_open()
        seconds = float(os.environ.get("FAKE_BINJA_ANALYSIS_SECONDS") or 0)
        for step in range(10):
            if self._aborted.is_set():
                break
            self.analysis_progress = AnalysisProgress(
                AnalysisState.AnalyzeState, step, 10
            )
            self._aborted.wait(seconds / 10)
        self.analysis_progress = AnalysisProgress(AnalysisState.IdleState, 0, 0)
        self.analyzed = not self._aborted.is_set()

    def abort_analysis(self) -> None:
        _note("abort_analysis")
        self._aborted.set()

    def create_database(self, filename: str, progress_func=None, settings=None) -> bool:
        self._check_open()
        _note(f"create_database {Path(filename).name}")
        if os.environ.get("FAKE_BINJA_SAVE") == "crash":
            os.kill(os.getpid(), signal.SIGSEGV)
        Path(filename).write_text(
            _MAGIC + self.file.original_filename, encoding="utf-8"
        )
        return True

    def read(self, addr: int, length: int) -> bytes:
        self._check_open()
        return bytes((addr + index) & 0xFF for index in range(length))

    def get_function_at(self, address: int):
        self._check_open()
        return self._by_start.get(int(address))

    def get_symbols_of_type(self, symbol_type):
        return [sym for sym in self._symbols if sym.type == symbol_type]

    def get_symbols(self):
        return list(self._symbols)

    def get_strings(self):
        return list(self._strings)

    def get_segment_at(self, address: int):
        for segment in self._segments:
            if segment.start <= address < segment.start + segment.length:
                return segment
        return None

    def get_sections_at(self, address: int):
        return [
            s for s in self.sections.values() if s.start <= address < s.start + s.length
        ]

    def get_code_refs(self, addr: int, length=None, max_items=None):
        return iter(self._code_refs.get(int(addr), []))

    def get_next_linear_disassembly_lines(self, cursor):
        self._check_open()
        if cursor.done:
            return []
        cursor.done = True
        func = self._by_start.get(cursor.address)
        if func is None or func.hlil is None:
            return []
        return [_Line(text, cursor.address) for text in self._pseudo_c(func)]


class Symbol:
    def __init__(self, sym_type, address, name) -> None:
        self.type = sym_type
        self.address = int(address)
        self.name = name


def load(source, update_analysis: bool = True, progress_func=None, options=None):
    _check_license()
    path = Path(source)
    if path.suffix == ".bndb":
        text = path.read_text(encoding="utf-8", errors="replace")
        if not text:
            # Like Binary Ninja, an empty .bndb opens as a view with nothing
            # mapped and no functions instead of failing.
            _note(f"load {path.name} update_analysis={update_analysis}")
            view = BinaryView(str(path), "")
            view._segments, view.functions = [], []
            return view
        if not text.startswith(_MAGIC):
            raise Exception(f"{path} is not a valid Binary Ninja database")
        original = text[len(_MAGIC) :]
    else:
        path.stat()
        original = str(path)
    _note(f"load {path.name} update_analysis={update_analysis}")
    view = BinaryView(str(path), original)
    if update_analysis:
        view.update_analysis_and_wait()
    return view
