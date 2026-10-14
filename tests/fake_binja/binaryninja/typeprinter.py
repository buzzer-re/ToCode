"""``binaryninja.typeprinter`` for the fake API: one C definition per type."""

from __future__ import annotations


class _Printer:
    def get_type_lines(
        self, type, container, name, padding_cols=64, collapsed=False, escaping=1
    ):
        if escaping != 0:
            raise AssertionError("ToCode asks for unescaped C names")
        if str(type) == "struct point":
            return [f"struct {name}", "{", "    int32_t x;", "    int32_t y;", "};"]
        return [f"typedef {type} {name};"]


class TypePrinter:
    default = _Printer()
