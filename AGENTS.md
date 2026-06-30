# AGENTS

This repository contains ToCode, a Python-only binary exporter. ToCode takes one binary or IDA database path and writes one source-like project directory for reverse-engineering agents.

## Scope

- Keep the project focused on the exporter CLI and Python library modules.
- Do not add web UI, server, container wrapper, shortcut, installer, or background service behavior.
- Do not add chat, report generation, or secondary analysis stages.
- Export one project tree from one binary or IDA database: raw decompiler output, assembly, summaries, section data, JSON metadata, optional IDA database, and optional scanner-friendly C.
- Generated export trees must include their own `AGENTS.md` for agents analyzing that exported binary.

## Project Layout

- `src/tocode/cli.py`: command-line entry point for `tocode`.
- `src/tocode/__init__.py`: package version and `export_from_binaryview()`, the in-UI Binary Ninja library entry.
- `src/tocode/analysis.py`: backend-neutral binary inventory and call graph normalization.
- `src/tocode/backends/`: IDA Domain, radare2, angr, and Binary Ninja (`binja.py`) session adapters.
- `src/tocode/exporter.py`: project writer, function rendering, worker-session rendering, generated export `AGENTS.md`.
- `src/tocode/metadata.py`: JSON metadata and triage documents.
- `src/tocode/cluster.py`: call-graph clustering.
- `src/tocode/parallel.py`: worker-count selection.
- `src/tocode/schema.py`: dataclasses shared across the exporter.
- `tests/`: unit tests for algorithms, CLI helpers, and export tree generation.

## Export Contract

The CLI accepts a regular binary file or IDA database and writes a project directory containing:

- `src/raw/**/*.c`
- `src/raw/**/*.asm`
- `src/raw/**/*.summary`
- `include/*.h`
- `data/*.bin`
- `data/variables.json`
- `data/variables_interesting.json`
- `function-index.json`
- `functions.json`
- `sections.json`
- `strings.json`
- `imports.json`
- `exports.json`
- `relocations.json`
- `reachable.json`
- `cluster-graph.json`
- `triage.json`
- `project.json`
- `export-manifest.json`
- `tocode.log`
- generated export `AGENTS.md`
- generated export `CLAUDE.md`

When the IDA backend is used, the export also contains:

- `<binary>.i64` or `<binary>.idb`

When `--tree` is passed, the export also contains:

- `src/tree/**/*.c`
- `function-index-tree.json`

## Development

- Prefer `uv` for local commands.
- Package entry point: `tocode`.
- Keep generated text, environment variables, and user-visible strings branded as ToCode.
- Keep status output concise but informative. Progress bars are handled by `tqdm` through `Progress.bar(...)`.
- Use `apply_patch` for manual edits.
- Do not commit generated export directories such as `here/`, `ls/`, or `*_decompiler/`.

## Dependencies

- Runtime dependencies belong in `pyproject.toml` and `uv.lock`.
- IDA Domain is the preferred backend when available.
- radare2/r2pipe is a fallback backend.
- angr is the optional pure-Python fallback backend (`[angr]` extra).
- Binary Ninja is an opt-in backend (`--backend binja`, never auto-selected). The
  `binaryninja` module is supplied by the Binary Ninja install (in-UI) or the
  remote VM, so it is not a pip dependency. `rpyc`, the client used for the
  headless path via [binja-headless](https://github.com/hugsy/binja-headless),
  is a core runtime dependency so the backend works out of the box.
- Pin new dependencies exactly (`==`) and capture them in `uv.lock`.
- Keep dependencies minimal and tied to exporting a project.

## Binary Ninja backend

- Headless (no enterprise license): run binja-headless inside a running Binary
  Ninja, then `tocode --backend binja --binja-host <ip>`. It exports an already
  **loaded** view (the binary positional is optional). Configure the connection
  with `--binja-host`/`--binja-port` or `TOCODE_BINJA_HOST` / `TOCODE_BINJA_PORT`
  (defaults `127.0.0.1:18812`).
- Choosing the view (headless): default is the focused view (the one binja-headless
  exposes as `conn.root.bv`). `--list-binja` prints every open view with an index;
  `--binja-view N` exports that index; `--all-views` exports every open view, each
  into its own folder under `-o` (or the cwd). Active-context lookup is Qt-main-
  thread bound and unavailable over RPyc, so the focused view comes from
  `conn.root.bv`; open views are enumerated through `binaryninjaui.UIContext` via
  the service's remote `eval`. If no view is open, a binary path argument is
  remote-loaded as a fallback.
- In the Binary Ninja UI: call `tocode.export_from_binaryview(bv, out_dir)` from
  the scripting console (`bv` is the live view; `binaryninja` is imported
  locally). It runs the same export pipeline as the CLI.
- The backend renders serially against the live view (`parallel_safe = False` and
  excluded from `exporter.TIMEOUT_WORKER_BACKENDS`): a `BinaryView` / RPyc
  connection cannot be pickled into a worker process. Do not add it to the
  spawned-worker path.

## Verification

Run focused checks after changes:

```bash
uv run --extra dev pytest -q
python3 -m compileall src tests
```

Run the full local CI/quality gate when changing shared behavior:

```bash
./ci-local.sh
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\ci-local.ps1
```

For backend-sensitive changes, also run a real export when IDA is available:

```bash
uv run tocode /bin/true -o /tmp/tocode-check --backend auto -j 2
```

Confirm the generated project matches the export contract above.
