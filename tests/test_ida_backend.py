from __future__ import annotations

from typing import Any

from pathlib import Path

from tocode.backends.ida import IdaSession, _is_unpacked, _purge_database


def test_is_unpacked_detects_open_database(tmp_path: Path) -> None:
    db = tmp_path / "abcdef.v2.i64"
    db.write_bytes(b"packed")
    # A lone .i64 is a cleanly closed (packed) database.
    assert _is_unpacked(db) is False
    # An unpacked component beside it means the database is open / interrupted.
    db.with_suffix(".id0").write_bytes(b"open")
    assert _is_unpacked(db) is True


def test_purge_database_removes_unpacked_components(tmp_path: Path) -> None:
    # A killed analysis can leave the .i64 plus unpacked component files; purge
    # must remove all of them so the database can be rebuilt cleanly.
    db = tmp_path / "abcdef.v2.i64"
    components = [db.with_suffix(s) for s in (".i64", ".id0", ".id1", ".nam", ".til")]
    for component in components:
        component.write_bytes(b"stub")
    _purge_database(db)
    assert not any(c.exists() for c in components)


class _FakeFunction:
    def __init__(self, start: int, end: int) -> None:
        self.start_ea = start
        self.end_ea = end


class _FakeFunctions:
    def __init__(self) -> None:
        self.main = _FakeFunction(0x1000, 0x1030)
        self.callee = _FakeFunction(0x2000, 0x2020)
        self.local_variable_calls = 0

    def get_at(self, _address: int) -> _FakeFunction:
        return self.main

    def get_signature(self, _func: _FakeFunction) -> str:
        return "int main(void)"

    def get_name(self, func: _FakeFunction) -> str:
        if func is self.main:
            return "main"
        return "callee"

    def get_callers(self, _func: _FakeFunction) -> list[_FakeFunction]:
        return [self.callee, self.callee]

    def get_callees(self, _func: _FakeFunction) -> list[_FakeFunction]:
        return [self.callee]

    def does_return(self, _func: _FakeFunction) -> bool:
        return True

    def get_local_variables(self, _func: _FakeFunction) -> list[Any]:
        self.local_variable_calls += 1
        raise AssertionError("function_summary must not recover local variables")


class _FakeDatabase:
    def __init__(self) -> None:
        self.functions = _FakeFunctions()


def test_ida_function_summary_does_not_recover_local_variables() -> None:
    session = IdaSession.__new__(IdaSession)
    database = _FakeDatabase()
    session._db = database
    session._resolve_thunk = lambda func: func  # type: ignore[method-assign]

    summary = session.function_summary(0x1000)

    assert "signature: int main(void)" in summary
    assert "size: 48 bytes" in summary
    assert "callers: 2" in summary
    assert "callees: 1" in summary
    assert "callee_names: callee" in summary
    assert "args:" not in summary
    assert "locals:" not in summary
    assert database.functions.local_variable_calls == 0


# --- source/type extraction against the documented IDA API surface ---------
# IDA cannot run in CI, so these drive IdaSession with fakes whose method
# shapes mirror the real ida_lines / ida_nalt / ida_typeinf / ida_domain APIs.
# They guard against calling methods that do not exist (e.g. tinfo_t._print).

_BADADDR = 0xFFFFFFFFFFFFFFFF


class _FakeLines:
    def __init__(self, by_ea: dict[int, str]) -> None:
        self._by_ea = by_ea

    def get_sourcefile(self, ea: int, bounds: Any = None) -> str:
        return self._by_ea.get(ea, "")


class _FakeNalt:
    def __init__(self, lines_by_ea: dict[int, int]) -> None:
        self._lines = lines_by_ea

    def get_source_linnum(self, ea: int) -> int:
        return self._lines.get(ea, _BADADDR)

    def get_srcdbg_paths(self) -> str:
        return ""


class _FakeBytes:
    def next_head(self, ea: int, maxea: int) -> int:
        return ea + 4


def test_ida_apply_source_scans_heads_when_entry_not_tagged() -> None:
    session = IdaSession.__new__(IdaSession)
    # Entry head (0x1000) has no annotation; the next head does.
    session._ida_lines = _FakeLines({0x1004: "net/socket.cpp"})
    session._ida_nalt = _FakeNalt({0x1004: 73})
    session._ida_bytes = _FakeBytes()  # type: ignore[assignment]
    session._srcdbg_dir = None

    row: dict[str, Any] = {}
    session._apply_source(row, _FakeFunction(0x1000, 0x1030))

    assert row["source_file"] == "net/socket.cpp"
    assert row["source_dir"] == "net"
    assert row["source_line"] == 73


def test_ida_apply_source_absent_leaves_row_unset() -> None:
    session = IdaSession.__new__(IdaSession)
    session._ida_lines = _FakeLines({})
    session._ida_nalt = _FakeNalt({})
    session._ida_bytes = _FakeBytes()  # type: ignore[assignment]
    session._srcdbg_dir = None

    row: dict[str, Any] = {}
    session._apply_source(row, _FakeFunction(0x1000, 0x1010))

    assert "source_file" not in row
    assert "source_line" not in row


class _FakeTinfo:
    def __init__(self, name: str, decl: str) -> None:
        self._name = name
        self._decl = decl

    def get_type_name(self) -> str:
        return self._name

    def dstr(self) -> str:
        return self._decl

    def serialize(self) -> Any:  # force the dstr() fallback path
        raise RuntimeError("no serialization in this fake")

    def is_struct(self) -> bool:
        return True

    def is_union(self) -> bool:
        return False

    def is_enum(self) -> bool:
        return False

    def is_typedef(self) -> bool:
        return False

    def get_size(self) -> int:
        return 8


class _FakeTypeinf:
    PRTYPE_MULTI = 1
    PRTYPE_TYPE = 2
    PRTYPE_DEF = 32
    PRTYPE_SEMI = 8


class _FakeTypesDb:
    def __init__(self, tinfos: list[Any]) -> None:
        self.types = tinfos


def test_ida_types_iterates_named_types_and_renders_decls() -> None:
    session = IdaSession.__new__(IdaSession)
    session._ida_typeinf = _FakeTypeinf()
    session._db = _FakeTypesDb([_FakeTinfo("conn", "struct conn { int fd; }")])

    rows = session.types()

    assert len(rows) == 1
    assert rows[0]["name"] == "conn"
    assert rows[0]["kind"] == "struct"
    assert rows[0]["size"] == 8
    assert rows[0]["c_decl"] == "struct conn { int fd; };"


class _FakeFuncType:
    def __init__(self, ret: str, args: list[tuple[str, str]]) -> None:
        self.rettype = _TypeStr(ret)
        self._args = [(_n, _TypeStr(_t)) for _n, _t in args]

    def __iter__(self):
        for name, type_obj in self._args:
            yield _FakeArg(name, type_obj)


class _TypeStr:
    def __init__(self, text: str) -> None:
        self._text = text

    def dstr(self) -> str:
        return self._text


class _FakeArg:
    def __init__(self, name: str, type_obj: Any) -> None:
        self.name = name
        self.type = type_obj


class _FakeFuncTinfo:
    def get_func_details(self, fi: _FakeFuncType) -> bool:
        fi.rettype = _TypeStr("int")
        fi._args = [("c", _TypeStr("conn *")), ("fd", _TypeStr("int"))]
        return True


def test_ida_apply_prototype_uses_func_details() -> None:
    session = IdaSession.__new__(IdaSession)

    class _TI:
        @staticmethod
        def func_type_data_t() -> _FakeFuncType:
            return _FakeFuncType("void", [])

    session._ida_typeinf = _TI()
    session._function_tinfo = lambda ea: _FakeFuncTinfo()  # type: ignore[method-assign]

    row: dict[str, Any] = {}
    session._apply_prototype(row, 0x1000)

    assert row["return_type"] == "int"
    assert row["params"] == [
        {"name": "c", "type": "conn *"},
        {"name": "fd", "type": "int"},
    ]
