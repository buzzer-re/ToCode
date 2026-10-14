"""Match backend function names against linker symbol names.

Backends decorate names differently: IDA writes ``.printf``/``j_printf``
thunks and keeps ``name@@VERSION`` on ELF imports, radare2 uses
``sym.imp.printf``/``sym.printf``, PE imports appear as ``__imp_X``, and
Mach-O symbols carry a leading underscore that some backends strip. A link
key removes exactly those decorations so the same symbol compares equal
across the linker's tables and a backend's ``functions.json``. Keys are only
used to find the backend's function for a symbol the linker tables already
bound; they never create links themselves.
"""

from __future__ import annotations

import re

_VERSION_RX = re.compile(r"(?<=[^@])@@?[A-Za-z0-9_.]+$")
_PREFIXES = (
    "sym.imp.",
    "sym.",
    "imp.",
    "reloc.",
    "__imp__",
    "__imp_",
    "_imp__",
    "j_",
    "loc.",
)


def link_key(name: str) -> str:
    text = name.strip()
    text = _VERSION_RX.sub("", text)
    changed = True
    while changed:
        changed = False
        for prefix in _PREFIXES:
            if text.startswith(prefix) and len(text) > len(prefix):
                text = text[len(prefix) :]
                changed = True
        if text.startswith(".") and len(text) > 1:  # IDA thunk ".printf"
            text = text[1:]
            changed = True
    return text.lstrip("_") or text


def c_tokens(name: str, version: str | None = None) -> list[str]:
    """Identifiers a decompiler may print for ``name`` in C output."""
    key = link_key(name)
    tokens = [name, key, f"_{key}", f"__imp_{key}", f"j_{key}"]
    if version:  # "foo@@V1.0" printed as foo__V1_0
        tokens.extend([f"{name}@@{version}", f"{name}@{version}"])
    phrases: list[str] = []
    if "::" in name:  # .NET Type::Member -> Member, or "new Type" for a constructor
        owner, _, member = name.rpartition("::")
        type_name = owner.rpartition(".")[2].rpartition("/")[2].split("`")[0]
        if member == ".ctor":
            phrases.append(f"new {type_name}")
        elif member != ".cctor":
            tokens.append(member)
    seen: dict[str, None] = {}
    for token in tokens:
        cleaned = re.sub(r"[^0-9A-Za-z_]", "_", token)
        if cleaned and not cleaned.isdigit():
            seen.setdefault(cleaned, None)
    phrases.extend(itanium_hints(name))
    for phrase in phrases:
        seen.setdefault(phrase, None)
    return list(seen)


_CV = "rVKRO"


def itanium_hints(name: str) -> list[str]:
    """``Class::method`` as a decompiler prints a mangled C++ symbol.

    Only the simple shapes are handled (nested names without templates or
    substitutions); anything else yields nothing rather than a guess.
    """
    text = name.lstrip("_")
    if not text.startswith("Z") or len(text) < 3:
        return []
    pos = 1
    parts: list[str] = []
    special: str | None = None
    if text[pos] == "N":
        pos += 1
        while pos < len(text) and text[pos] in _CV:
            pos += 1
        if text.startswith("St", pos):
            parts.append("std")
            pos += 2
        while pos < len(text) and text[pos] != "E":
            char = text[pos]
            if char.isdigit():
                end = pos
                while end < len(text) and text[end].isdigit():
                    end += 1
                length = int(text[pos:end])
                parts.append(text[end : end + length])
                pos = end + length
            elif char in "CD" and pos + 1 < len(text) and text[pos + 1] in "0123459":
                special = "~" if char == "D" else ""
                pos += 2
            else:
                return []  # templates, substitutions, operators: not handled
        if pos >= len(text) or not parts:
            return []
    elif text[pos].isdigit():
        end = pos
        while end < len(text) and text[end].isdigit():
            end += 1
        parts.append(text[end : end + int(text[pos:end])])
    else:
        return []
    if special is not None:
        parts.append(special + parts[-1])
    if len(parts) == 1:
        return [parts[0]] if len(parts[0]) > 3 else []
    return ["::".join(parts[-2:])]
