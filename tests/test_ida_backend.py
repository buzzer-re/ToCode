from __future__ import annotations

from typing import Any

from tocode.backends.ida import IdaSession


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
