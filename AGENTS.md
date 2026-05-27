# AGENTS

This repository contains ToCode, a Python-only binary exporter. ToCode takes one binary path and writes one source-like project directory for reverse-engineering agents.

## Scope

- Keep the project focused on the exporter CLI and Python library modules.
- Do not add web UI, server, container wrapper, shortcut, installer, or background service behavior.
- Do not add chat, report generation, or secondary analysis stages.
- Export one project tree from one binary: raw decompiler output, assembly, summaries, section data, and JSON metadata.
- Generated export trees must include their own `AGENTS.md` for agents analyzing that exported binary.

## Project Layout

- `src/tocode/cli.py`: command-line entry point for `tocode`.
- `src/tocode/analysis.py`: backend-neutral binary inventory and call graph normalization.
- `src/tocode/backends/`: IDA Domain and radare2 session adapters.
- `src/tocode/exporter.py`: project writer, function rendering, worker-session rendering, generated export `AGENTS.md`.
- `src/tocode/metadata.py`: JSON metadata and triage documents.
- `src/tocode/cluster.py`: call-graph clustering.
- `src/tocode/parallel.py`: worker-count selection.
- `src/tocode/schema.py`: dataclasses shared across the exporter.
- `tests/`: unit tests for algorithms, CLI helpers, and export tree generation.

## Export Contract

The CLI accepts a regular binary file and writes a project directory containing:

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
- generated export `AGENTS.md`

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
- Keep dependencies minimal and tied to exporting a project.

## Verification

Run focused checks after changes:

```bash
$HOME/.local/bin/uv run --extra dev pytest -q
python3 -m compileall src tests
```

For backend-sensitive changes, also run a real export when IDA is available:

```bash
$HOME/.local/bin/uv run tocode /bin/true -o /tmp/tocode-check --backend auto -j 2
```

Confirm the generated project matches the export contract above.
