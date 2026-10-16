#!/usr/bin/env python3
"""Blind source recovery: can an agent with only ToCode recover a program's source?

For each program in eval/corpus: build it with debug info (the ground truth,
never shown to the agent) and stripped (the agent's input), export the
stripped binary with ToCode, and start a headless agent whose only tools are
the ToCode MCP server and file tools confined away from the corpus. The agent
renames, retypes, declares structs, syncs, and writes recovered/*.c. A judge
then scores names, prototypes, types and globals against the source, asks an
LLM to grade each function, and runs the recovered program against the
original on the program's test inputs.

    uv run python eval/recover.py run inventory --backend ida
    uv run python eval/recover.py judge /tmp/tocode-eval/inventory-ida-20261016-120000
    uv run python eval/recover.py all --backend ida
    uv run python eval/recover.py report
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "eval" / "corpus"
DEFAULT_RUNS = Path(os.environ.get("TOCODE_EVAL_RUNS") or Path(tempfile.gettempdir()) / "tocode-eval")
TOCODE = [sys.executable, "-m", "tocode"]
AGENT_TOOLS = "Read,Grep,Glob,Write,Edit,Skill,TodoWrite"
INFORMATIVE_TOOLS = ("Read", "Grep", "Glob", "Skill")

TASK = """\
You are reverse engineering `./{binary}`, a stripped {arch} program. Its ToCode \
export is `./{export}` and the `tocode` MCP server is connected with that export \
open (session `{session}`).

Goal: recover the original C source code as faithfully as you can: the real \
function names, parameter names and types, the structs, unions and enums the \
program uses, and the names and types of its globals.

Work in the database with the ToCode tools (rename, set_type, declare_types, \
rename_local, set_local_type, set_comment, eval) and call `sync` regularly so \
the export reflects what you learned. Use the `tocode` skill.

When you are done, write the recovered program to `./recovered/` as C source \
and header files, as close to the original as you can and compilable with gcc. \
You cannot run programs, and the original source is not available to you; do \
not look for it."""

JUDGE = """\
You are grading a reverse-engineering result. An agent saw only a stripped \
binary and tried to recover its source. Compare the RECOVERED code with the \
ORIGINAL source.

Score every function of the ORIGINAL (by its original name), each 0-5:
- semantics: does the recovered function do the same thing?
- naming: are the function, parameter and local names equivalent in meaning?
- types: are parameter, return, struct and enum types equivalent?
Then score the whole result 0-5 for readability and completeness, and set \
`leakage` to true only if the recovered code contains things the binary \
could not reveal, such as original comments verbatim. Names that follow from \
the binary's file name, its strings, its imports, or the behaviour are \
legitimate inferences, even when they match exactly.

The binary's file name: {binary}
Its printable strings: {strings}

Answer with only a JSON object:
{{"functions": {{"<original name>": {{"recovered_as": "<name or null>", \
"semantics": 0, "naming": 0, "types": 0}}}}, "readability": 0, \
"completeness": 0, "leakage": false, "notes": "<two sentences>"}}

ORIGINAL SOURCE
{original}

RECOVERED CODE
{recovered}"""


# --------------------------------------------------------------------------
# Running an agent blind
# --------------------------------------------------------------------------


@dataclass
class Program:
    name: str
    directory: Path
    sources: list[str]
    headers: list[str]
    cflags: list[str]
    tests: list[dict[str, Any]]

    @classmethod
    def load(cls, name: str) -> "Program":
        directory = CORPUS / name
        spec = json.loads((directory / "program.json").read_text())
        return cls(
            name=name,
            directory=directory,
            sources=list(spec["sources"]),
            headers=list(spec.get("headers", [])),
            cflags=list(spec.get("cflags", ["-O0"])),
            tests=list(spec.get("tests", [])),
        )

    def source_text(self) -> str:
        return "\n".join(
            f"// file: {name}\n" + (self.directory / name).read_text()
            for name in self.headers + self.sources
        )


def _run(command: list[str], *, cwd: Path | None = None, **kwargs: Any) -> subprocess.CompletedProcess:
    print("$", " ".join(str(part) for part in command), file=sys.stderr)
    return subprocess.run(command, cwd=cwd, check=True, **kwargs)


def build(program: Program, private: Path, work: Path) -> tuple[Path, Path]:
    debug = private / f"{program.name}.debug"
    stripped = work / program.name
    _run(
        ["gcc", *program.cflags, "-g", "-o", str(debug), *program.sources],
        cwd=program.directory,
    )
    _run(["strip", "--strip-all", "-o", str(stripped), str(debug)])
    return debug, stripped


def run(
    program_name: str,
    *,
    backend: str,
    model: str | None,
    runs: Path,
    timeout: float,
    budget: float | None,
    prepare_only: bool = False,
) -> Path:
    program = Program.load(program_name)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    root = runs / f"{program.name}-{backend}-{stamp}"
    private, work = root / "private", root / "work"
    private.mkdir(parents=True)
    work.mkdir(parents=True)
    debug, stripped = build(program, private, work)

    started = time.monotonic()
    _run([*TOCODE, str(debug), "-o", str(private / "truth"), "--backend", backend, "-q"])
    export = work / f"{program.name}_decompiler"
    _run([*TOCODE, str(stripped), "-o", str(export), "--backend", backend, "-q"])
    _run([*TOCODE, "skill", "install", "--agent", "claude", "--project"], cwd=work)
    export_seconds = time.monotonic() - started

    mcp = private / "mcp.json"
    mcp.write_text(
        json.dumps({"mcpServers": {"tocode": {"command": TOCODE[0], "args": [*TOCODE[1:], "mcp", str(export)]}}}, indent=2)
    )
    settings = private / "settings.json"
    denied = [private, CORPUS, REPO]
    settings.write_text(
        json.dumps(
            {
                "permissions": {
                    # Deny wins over allow: nothing outside the work folder is readable.
                    "deny": [f"Read(/{path}/**)" for path in denied],
                    "allow": ["mcp__tocode", *AGENT_TOOLS.split(",")],
                }
            },
            indent=2,
        )
    )
    arch = json.loads((export / "project.json").read_text()).get("backend", backend)
    prompt = TASK.format(binary=program.name, export=export.name, session=program.name, arch=_arch(export) or arch)
    claude = shutil.which("claude")
    if claude is None:
        raise SystemExit("the `claude` CLI is needed for the blind agent")
    command = [
        claude,
        "-p",
        prompt,
        "--output-format",
        "stream-json",
        "--verbose",
        "--mcp-config",
        str(mcp),
        "--strict-mcp-config",
        "--settings",
        str(settings),
        "--setting-sources",
        "project",
        "--tools",
        AGENT_TOOLS,
        "--allowedTools",
        "mcp__tocode",
        *AGENT_TOOLS.split(","),
        "--permission-mode",
        "acceptEdits",
    ]
    if model:
        command += ["--model", model]
    if budget:
        command += ["--max-budget-usd", str(budget)]
    transcript = private / "transcript.jsonl"
    (private / "agent-command.json").write_text(json.dumps(command, indent=1))
    agent_started = time.monotonic()
    exit_code: int | None = None
    with transcript.open("w") as handle:
        if prepare_only:
            exit_code = 0  # baseline: the export as ToCode wrote it, no agent
        else:
            try:
                completed = subprocess.run(command, cwd=work, stdout=handle, stderr=subprocess.STDOUT, timeout=timeout)
                exit_code = completed.returncode
            except subprocess.TimeoutExpired:
                exit_code = None
    final = _final_message(transcript)
    (root / "run.json").write_text(
        json.dumps(
            {
                "program": program.name,
                "backend": backend,
                "model": model,
                "export_seconds": round(export_seconds, 1),
                "agent_seconds": round(time.monotonic() - agent_started, 1),
                "agent_exit": exit_code,
                "timed_out": exit_code is None and not prepare_only,
                "agent": not prepare_only,
                "turns": final.get("num_turns"),
                "cost_usd": final.get("total_cost_usd"),
            },
            indent=2,
        )
    )
    print(f"run finished: {root}", file=sys.stderr)
    return root


def _arch(export: Path) -> str:
    try:
        return str(json.loads((export / "triage.json").read_text()).get("arch") or "")
    except (OSError, ValueError):
        return ""


def _final_message(transcript: Path) -> dict[str, Any]:
    final: dict[str, Any] = {}
    for line in transcript.read_text(errors="replace").splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("type") == "result":
            final = message
    return final


# --------------------------------------------------------------------------
# Judging
# --------------------------------------------------------------------------

_DEF_RX = re.compile(
    r"^(?P<ret>[A-Za-z_][\w\s\*]*?[\s\*])(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{)]*)\)\s*\{",
    re.M,
)
_TYPE_RX = re.compile(r"\b(?P<kind>struct|union|enum)\s+(?P<name>\w+)\s*\{(?P<body>[^}]*)\}", re.S)


def source_functions(text: str) -> dict[str, dict[str, Any]]:
    functions: dict[str, dict[str, Any]] = {}
    for match in _DEF_RX.finditer(text):
        name = match.group("name")
        if name in ("if", "while", "for", "switch", "return", "sizeof"):
            continue
        params = [p.strip() for p in match.group("params").split(",") if p.strip() and p.strip() != "void"]
        functions[name] = {
            "return": _norm_type(match.group("ret").replace("static", "").replace("inline", "")),
            "params": [_split_param(p) for p in params],
        }
    return functions


def _split_param(text: str) -> tuple[str, str]:
    match = re.match(r"(.*?)(\w+)\s*(\[[^\]]*\])?$", text.strip())
    if match is None:
        return (_norm_type(text), "")
    ptype = match.group(1) + ("*" if match.group(3) else "")
    return (_norm_type(ptype), match.group(2))


_TYPE_ALIASES = {
    "int32_t": "int",
    "uint32_t": "unsigned int",
    "int64_t": "long",
    "uint64_t": "unsigned long",
    "__int64": "long",
    "unsigned __int64": "unsigned long",
    "size_t": "unsigned long",
    "_DWORD": "int",
    "_QWORD": "long",
    "int8_t": "char",
    "uint8_t": "unsigned char",
    "_BYTE": "char",
}


def _norm_type(text: str) -> str:
    text = re.sub(r"\b(const|volatile|static|__fastcall|__cdecl|register)\b", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s*\*\s*", "*", text)
    base = text.rstrip("*")
    stars = text[len(base) :]
    base = _TYPE_ALIASES.get(base.strip(), base.strip())
    return f"{base}{stars}"


def source_types(text: str) -> dict[str, dict[str, Any]]:
    types: dict[str, dict[str, Any]] = {}
    for match in _TYPE_RX.finditer(text):
        body = match.group("body")
        if match.group("kind") == "enum":
            members = re.findall(r"(\w+)\s*(?:=[^,}]*)?(?:,|$)", body.strip())
        else:
            members = re.findall(r"(\w+)\s*(?:\[[^\]]*\])?\s*;", body)
            members += re.findall(r"\(\s*\*\s*(\w+)\s*\)", body)  # function pointers
        types[match.group("name")] = {"kind": match.group("kind"), "members": [m for m in members if m]}
    return types


def _recovered_types(export: Path) -> dict[str, dict[str, Any]]:
    try:
        rows = json.loads((export / "types.json").read_text()).get("types", [])
    except (OSError, ValueError):
        return {}
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        parsed = source_types(str(row.get("c_decl") or ""))
        for name, item in parsed.items():
            found[name] = item
        if not parsed and row.get("name"):
            found.setdefault(str(row["name"]), {"kind": row.get("kind"), "members": []})
    return found


def _norm_name(name: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _functions_by_address(export: Path) -> dict[int, dict[str, Any]]:
    try:
        rows = json.loads((export / "functions.json").read_text()).get("functions", [])
    except (OSError, ValueError):
        return {}
    return {int(row["address"], 16): row for row in rows}


def _variables(export: Path) -> dict[int, str]:
    try:
        rows = json.loads((export / "data" / "variables.json").read_text()).get("variables", {})
    except (OSError, ValueError):
        return {}
    return {int(row["va"], 16): name for name, row in rows.items() if isinstance(row, dict) and row.get("va")}


def judge(root: Path, *, model: str | None, skip_llm: bool = False) -> dict[str, Any]:
    run_info = json.loads((root / "run.json").read_text())
    program = Program.load(run_info["program"])
    private, work = root / "private", root / "work"
    export = work / f"{program.name}_decompiler"
    source = program.source_text()
    truth_functions = source_functions(source)
    truth_by_address = {
        address: row
        for address, row in _functions_by_address(private / "truth").items()
        if row.get("name") in truth_functions
    }
    recovered = _functions_by_address(export)

    names = prototypes = params_named = touched = 0
    rows = []
    for address, truth in sorted(truth_by_address.items()):
        name = truth["name"]
        got = recovered.get(address, {})
        expected = truth_functions[name]
        got_params = [(_norm_type(p.get("type", "")), p.get("name", "")) for p in got.get("params") or []]
        name_ok = _norm_name(got.get("name")) == _norm_name(name)
        arity_ok = len(got_params) == len(expected["params"])
        types_ok = arity_ok and [t for t, _ in got_params] == [t for t, _ in expected["params"]] and _norm_type(
            str(got.get("return_type") or "")
        ) == expected["return"]
        param_names_ok = arity_ok and [_norm_name(n) for _, n in got_params] == [_norm_name(n) for _, n in expected["params"]]
        renamed = bool(got.get("name")) and not re.match(r"(sub|fun|FUN)_[0-9a-fA-F]+$", str(got.get("name")))
        names += name_ok
        prototypes += types_ok
        params_named += param_names_ok
        touched += renamed
        rows.append(
            {
                "address": hex(address),
                "original": name,
                "recovered": got.get("name"),
                "name": name_ok,
                "prototype": types_ok,
                "param_names": param_names_ok,
            }
        )
    count = max(1, len(rows))

    truth_types = source_types(source)
    got_types = _recovered_types(export)
    type_rows = []
    member_hits = member_total = 0
    for name, item in truth_types.items():
        match_name = name if name in got_types else _best_type(item, got_types)
        got_members = got_types.get(match_name, {}).get("members", []) if match_name else []
        hits = sum(1 for a, b in zip(item["members"], got_members) if _norm_name(a) == _norm_name(b))
        member_hits += hits
        member_total += len(item["members"])
        type_rows.append(
            {
                "original": f"{item['kind']} {name}",
                "recovered": match_name,
                "name": match_name == name,
                "members": f"{hits}/{len(item['members'])}",
                "count_match": len(got_members) == len(item["members"]),
            }
        )

    truth_globals = {
        address: name
        for address, name in _variables(private / "truth").items()
        if re.search(rf"\b{re.escape(name)}\b", source)
    }
    got_globals = _variables(export)
    global_hits = sum(1 for a, n in truth_globals.items() if _norm_name(got_globals.get(a)) == _norm_name(n))

    report: dict[str, Any] = {
        **run_info,
        "functions": rows,
        "types": type_rows,
        "scores": {
            "function_names": round(names / count, 3),
            "prototypes": round(prototypes / count, 3),
            "parameter_names": round(params_named / count, 3),
            "functions_renamed": round(touched / count, 3),
            "type_members": round(member_hits / max(1, member_total), 3),
            "type_names": round(sum(r["name"] for r in type_rows) / max(1, len(type_rows)), 3),
            "globals": round(global_hits / max(1, len(truth_globals)), 3) if truth_globals else None,
        },
        "behaviour": behaviour(program, private, work),
        "leakage": leakage(private / "transcript.jsonl", [private, CORPUS, REPO]),
        "provenance": provenance(
            private / "transcript.jsonl",
            _identifiers(source, truth_functions, truth_types, truth_globals),
            work / program.name,
        ),
    }
    if not skip_llm:
        report["llm"] = llm_judge(
            source,
            _recovered_text(work, export, truth_by_address),
            model=model,
            binary=work / program.name,
        )
    (root / "judge.json").write_text(json.dumps(report, indent=2))
    (root / "report.md").write_text(render_report([report]))
    return report


def _best_type(item: dict[str, Any], candidates: dict[str, dict[str, Any]]) -> str | None:
    best, best_score = None, 0
    wanted = {_norm_name(m) for m in item["members"]}
    for name, other in candidates.items():
        if other.get("kind") != item["kind"]:
            continue
        score = len(wanted & {_norm_name(m) for m in other.get("members", [])})
        if score > best_score:
            best, best_score = name, score
    return best


def _recovered_text(work: Path, export: Path, functions: dict[int, dict[str, Any]]) -> str:
    folder = work / "recovered"
    files = sorted(folder.rglob("*.[ch]")) if folder.is_dir() else []
    if files:
        return "\n".join(f"// file: {path.name}\n{path.read_text(errors='replace')}" for path in files)
    # No recovered files: grade the export's code for the program's functions.
    index = json.loads((export / "function-index.json").read_text()).get("functions", [])
    wanted = {hex(address) for address in functions}
    parts = []
    for row in index:
        if row["address"] in wanted:
            lines = Path(row["c"]["path"]).read_text(errors="replace").splitlines()
            parts.append("\n".join(lines[row["c"]["line_start"] - 1 : row["c"]["line_end"]]))
    return "\n\n".join(parts)


def behaviour(program: Program, private: Path, work: Path) -> dict[str, Any]:
    if not program.tests:
        return {"status": "no tests (the program runs forever)"}
    sources = sorted(str(path) for path in (work / "recovered").glob("*.c")) if (work / "recovered").is_dir() else []
    if not sources:
        return {"status": "no recovered source"}
    binary = private / "recovered.bin"
    compiled = subprocess.run(
        ["gcc", "-O0", "-w", "-o", str(binary), *sources, "-I", str(work / "recovered")],
        capture_output=True,
        text=True,
    )
    if compiled.returncode != 0:
        return {"status": "does not compile", "errors": compiled.stderr[-2000:]}
    original = private / f"{program.name}.debug"
    passed = 0
    cases = []
    for test in program.tests:
        expected = _execute(original, test)
        got = _execute(binary, test)
        ok = expected == got
        passed += ok
        cases.append({"test": test, "pass": ok, "expected": expected, "got": got})
    return {"status": "ran", "passed": passed, "total": len(program.tests), "cases": cases}


def _execute(binary: Path, test: dict[str, Any]) -> list[Any]:
    try:
        result = subprocess.run(
            [str(binary), *test.get("args", [])],
            input=test.get("stdin", ""),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return [result.returncode, result.stdout]
    except subprocess.TimeoutExpired:
        return ["timeout", ""]


def leakage(transcript: Path, forbidden: list[Path]) -> dict[str, Any]:
    """Tool calls that named a forbidden path, and how many were refused."""
    attempts = []
    if transcript.is_file():
        for line in transcript.read_text(errors="replace").splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            for block in (message.get("message") or {}).get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                text = json.dumps(block.get("input"))
                if any(str(path) in text for path in forbidden):
                    attempts.append({"tool": block.get("name"), "input": text[:300]})
    return {"forbidden_path_attempts": len(attempts), "examples": attempts[:5]}


def binary_strings(path: Path, minimum: int = 4) -> list[str]:
    data = path.read_bytes()
    return [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)]


def _identifiers(
    source: str,
    functions: dict[str, Any],
    types: dict[str, dict[str, Any]],
    globals_: dict[int, str],
) -> set[str]:
    names = set(functions) | set(types) | set(globals_.values())
    for item in types.values():
        names.update(item["members"])
    return {name for name in names if len(name) > 3 and name != "main"}


def provenance(transcript: Path, identifiers: set[str], binary: Path) -> dict[str, Any]:
    """Where each original name first reached the conversation.

    A name the agent wrote before any tool showed it to the agent was its own
    inference. A name a tool showed first is leakage, unless the binary itself
    carries it (its strings or file name).
    """
    in_binary = " ".join(binary_strings(binary)) + " " + binary.name
    first: dict[str, str] = {}
    calls: dict[str, str] = {}  # tool_use id -> tool name
    if transcript.is_file():
        for line in transcript.read_text(errors="replace").splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            for block in (message.get("message") or {}).get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    calls[str(block.get("id"))] = str(block.get("name"))
                if block.get("type") == "tool_result":
                    tool = calls.get(str(block.get("tool_use_id")), "")
                    # Only results that carry information in: ToCode, reads,
                    # searches, the skill. Write/Edit acknowledgements are the
                    # harness echoing the agent's own work.
                    if not (tool.startswith("mcp__") or tool in INFORMATIVE_TOOLS):
                        continue
                    kind = "tool"
                else:
                    kind = "agent"
                text = json.dumps(block)
                for name in identifiers:
                    if name not in first and re.search(rf"\b{re.escape(name)}\b", text):
                        first[name] = kind
    suspicious = sorted(
        name
        for name, kind in first.items()
        if kind == "tool" and not re.search(rf"\b{re.escape(name)}\b", in_binary)
    )
    return {
        "inferred_by_agent": sorted(n for n, k in first.items() if k == "agent"),
        "seen_in_binary": sorted(
            n for n, k in first.items() if k == "tool" and n not in suspicious
        ),
        "suspicious": suspicious,
    }


def llm_judge(
    original: str, recovered: str, *, model: str | None, binary: Path
) -> dict[str, Any]:
    claude = shutil.which("claude")
    if claude is None:
        return {"error": "the `claude` CLI is needed for the LLM judge"}
    strings = [s for s in binary_strings(binary) if not s.startswith(("GLIBC", "GCC", "."))]
    prompt = JUDGE.format(
        original=original,
        recovered=recovered or "(nothing recovered)",
        binary=binary.name,
        strings=json.dumps(strings[:200]),
    )
    command = [claude, "-p", prompt, "--output-format", "json", "--tools", "", "--strict-mcp-config", "--setting-sources", "project"]
    if model:
        command += ["--model", model]
    with tempfile.TemporaryDirectory() as scratch:
        result = subprocess.run(command, cwd=scratch, capture_output=True, text=True, timeout=1800)
    try:
        text = json.loads(result.stdout).get("result", "")
        payload = json.loads(re.search(r"\{.*\}", text, re.S).group(0))  # type: ignore[union-attr]
    except (ValueError, AttributeError):
        return {"error": "the judge did not return JSON", "raw": result.stdout[-2000:]}
    functions = payload.get("functions") or {}
    for key in ("semantics", "naming", "types"):
        values = [float(item.get(key, 0)) for item in functions.values() if isinstance(item, dict)]
        payload[f"mean_{key}"] = round(sum(values) / len(values), 2) if values else None
    return payload


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------


def render_report(reports: list[dict[str, Any]]) -> str:
    lines = [
        "# Blind source recovery",
        "",
        "| Program | Backend | Names | Prototypes | Param names | Type members | Globals | LLM semantics | LLM naming | LLM types | Behaviour | Leakage | Agent time |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for report in reports:
        scores = report["scores"]
        llm = report.get("llm") or {}
        behaviour_row = report.get("behaviour", {})
        ran = (
            f"{behaviour_row['passed']}/{behaviour_row['total']}"
            if behaviour_row.get("status") == "ran"
            else behaviour_row.get("status", "")
        )
        leak = report.get("leakage", {}).get("forbidden_path_attempts", 0) + len(
            (report.get("provenance") or {}).get("suspicious", [])
        )
        lines.append(
            f"| {report['program']} | {report['backend']} | {_pct(scores['function_names'])} | "
            f"{_pct(scores['prototypes'])} | {_pct(scores['parameter_names'])} | {_pct(scores['type_members'])} | "
            f"{_pct(scores['globals'])} | {llm.get('mean_semantics', '-')} | {llm.get('mean_naming', '-')} | "
            f"{llm.get('mean_types', '-')} | {ran} | {'yes' if leak else 'no'}{' (judge suspects)' if llm.get('leakage') and not leak else ''} | "
            f"{report.get('agent_seconds', '-')}s |"
        )
    return "\n".join(lines) + "\n"


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{round(value * 100)}%"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "all"):
        command = sub.add_parser(name)
        if name == "run":
            command.add_argument("program", choices=sorted(p.name for p in CORPUS.iterdir() if p.is_dir()))
        command.add_argument("--backend", default="ida", choices=("ida", "binja", "r2", "angr"))
        command.add_argument("--model", default=None, help="Model for the blind agent.")
        command.add_argument("--judge-model", default=None, help="Model for the LLM judge.")
        command.add_argument("--runs", type=Path, default=DEFAULT_RUNS)
        command.add_argument("--timeout", type=float, default=3600, help="Seconds the agent may work.")
        command.add_argument("--budget", type=float, default=None, help="--max-budget-usd for the agent.")
        command.add_argument("--no-llm", action="store_true", help="Skip the LLM judge.")
        command.add_argument(
            "--prepare-only",
            action="store_true",
            help="Build and export but start no agent (the baseline score of a plain export).",
        )
    judging = sub.add_parser("judge")
    judging.add_argument("run_dir", type=Path)
    judging.add_argument("--judge-model", default=None)
    judging.add_argument("--no-llm", action="store_true")
    reporting = sub.add_parser("report")
    reporting.add_argument("runs", type=Path, nargs="?", default=DEFAULT_RUNS)
    args = parser.parse_args(argv)

    if args.command == "judge":
        report = judge(args.run_dir, model=args.judge_model, skip_llm=args.no_llm)
        print(render_report([report]))
        return 0
    if args.command == "report":
        reports = [json.loads(path.read_text()) for path in sorted(args.runs.glob("*/judge.json"))]
        print(render_report(reports))
        return 0
    programs = [args.program] if args.command == "run" else sorted(p.name for p in CORPUS.iterdir() if p.is_dir())
    reports = []
    for program in programs:
        root = run(
            program,
            backend=args.backend,
            model=args.model,
            runs=args.runs,
            timeout=args.timeout,
            budget=args.budget,
            prepare_only=args.prepare_only,
        )
        reports.append(judge(root, model=args.judge_model, skip_llm=args.no_llm))
    print(render_report(reports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
