"""Line-stable ``tocode-link:`` comments in decompiled source.

A call into another file of the folder gets a trailing comment on the line
that uses the imported symbol, pointing at the file and line range of its
definition. Comments are only appended at the end of existing lines, never as
new lines, so every line number in ``functions.json``/``function-index.json``
stays valid. Previous annotations are stripped first, which makes the pass
idempotent.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .metadata import write_text_atomic

MARK = "tocode-link:"
MAX_PER_LINE = 3
_TRAILING_RX = re.compile(r" /\* tocode-link: .*? \*/(?= /\* tocode-link: | ?$)")
_METADATA_RX = re.compile(r"^(/\* metadata:)( tocode-link: .*)?$")


@dataclass(slots=True)
class Annotation:
    source_file: str  # master-relative
    line_start: int  # the calling function's range (1-based, inclusive)
    line_end: int
    tokens: list[str]
    text: str  # "symbol -> file:a-b"


def strip_annotations(line: str) -> str:
    match = _METADATA_RX.match(line)
    if match is not None:
        return match.group(1)
    if MARK not in line:
        return line
    previous = None
    while previous != line:
        previous = line
        line = _TRAILING_RX.sub("", line)
    return line


def _code_mask(lines: list[str]) -> list[bool]:
    """Per line: True when the line ends outside comments and strings."""
    mask: list[bool] = []
    in_block = False
    for line in lines:
        index = 0
        in_string: str | None = None
        while index < len(line):
            char = line[index]
            pair = line[index : index + 2]
            if in_block:
                if pair == "*/":
                    in_block = False
                    index += 2
                    continue
            elif in_string:
                if char == "\\":
                    index += 2
                    continue
                if char == in_string:
                    in_string = None
            elif pair == "/*":
                in_block = True
                index += 2
                continue
            elif pair == "//":
                break
            elif char in "\"'":
                in_string = char
            index += 1
        mask.append(not in_block and in_string is None and not line.endswith("\\"))
    return mask


def _code_has_token(line: str, pattern: re.Pattern[str]) -> bool:
    # Drop string literals and comments before looking for the identifier.
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    text = re.sub(r"/\*.*?\*/", " ", text)
    text = text.split("//", 1)[0]
    return pattern.search(text) is not None


def annotate_file(path: Path, annotations: list[Annotation]) -> int:
    """Rewrite one source file; returns how many lines carry a link comment."""
    try:
        original = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return 0
    lines = original.split("\n")
    cleaned = [strip_annotations(line) for line in lines]
    mask = _code_mask(cleaned)
    notes: dict[int, list[str]] = {}
    for item in annotations:
        start = max(item.line_start, 1)
        end = min(item.line_end, len(cleaned))
        if not item.tokens or start > end:
            continue
        pattern = re.compile(
            r"(?<![0-9A-Za-z_])("
            + "|".join(map(re.escape, item.tokens))
            + r")(?![0-9A-Za-z_])"
        )
        placed = False
        for number in range(start, end + 1):
            line = cleaned[number - 1]
            if not mask[number - 1] or not _code_has_token(line, pattern):
                continue
            bucket = notes.setdefault(number, [])
            if item.text not in bucket:
                bucket.append(item.text)
            placed = True
        if not placed:
            # The decompiler printed the call differently (demangled C++ name,
            # through a pointer): note it in the function's metadata header.
            for number in range(start, end + 1):
                if cleaned[number - 1].startswith("/* metadata:"):
                    bucket = notes.setdefault(number, [])
                    if item.text not in bucket:
                        bucket.append(item.text)
                    break
    result = list(cleaned)
    for number, texts in notes.items():
        line = result[number - 1]
        shown = texts[:MAX_PER_LINE]
        more = (
            f" (+{len(texts) - MAX_PER_LINE} more in functions.json)"
            if len(texts) > MAX_PER_LINE
            else ""
        )
        if line.startswith("/* metadata:"):
            # Inside an open comment: no "*/" here.
            result[number - 1] = f"{line} {MARK} " + "; ".join(shown) + more
        else:
            suffix = "".join(
                f" /* {MARK} {text.replace('*/', '* /')} */" for text in shown
            )
            if more:
                suffix = suffix[:-3] + more + " */"
            result[number - 1] = line + suffix
    if len(result) != len(lines):  # pragma: no cover - invariant
        raise AssertionError("annotation changed the line count")
    text = "\n".join(result)
    if text != original:
        write_text_atomic(path, text)
    return len(notes)
