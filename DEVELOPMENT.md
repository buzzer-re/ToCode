# Developing ToCode

ToCode was built with agentic coding, and contributing the same way works
well. Agents (and humans) should read [AGENTS.md](AGENTS.md) first: it is the
project's instruction file, with the layout, export contract, dependency
rules, and per-backend notes.

## Setup

You need Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/buzzer-re/ToCode
cd ToCode
uv sync --locked --extra dev        # project + pytest in .venv
uv run tocode --help                # run the CLI from the checkout
```

`uv tool install --force --editable .` installs a `tocode` command that
follows your working tree.

## Backends for local testing

The unit tests need none of these; real exports do. Install what matches the
area you are changing:

| Backend | What to install | Notes |
| --- | --- | --- |
| IDA | IDA Pro 9 with idalib | `ida-domain`/`idapro` come with ToCode; IDA is found via `IDADIR`, `--idadir`, or common install paths. |
| radare2 | `r2` plus r2ghidra (`r2pm -ci r2ghidra r2ghidra-sleigh`) | Used by `--backend r2` and as the `auto` fallback. |
| angr | `uv sync --extra angr` | Large; tests in `tests/test_angr_backend.py` skip without it. |
| Binary Ninja | Binary Ninja with binja-headless | See the Binary Ninja section of the README. |
| Android | nothing extra (`droidasc` is a core dependency) | Real APK test: set `TOCODE_TEST_APK=/path/to/app.apk`. |
| .NET | a .NET 9+ runtime, then `uv run tocode --setup-dotnet` | The SDK (`dotnet-sdk-10.0`) lets you build test assemblies. Real test: `TOCODE_TEST_DOTNET=/path/to/App.dll`. |

Tests that need a backend, runtime, or sample skip themselves when it is
missing, so the suite always runs. CI installs only the Python dependencies
(no IDA, radare2, angr, Binary Ninja, or .NET runtime).

## Tests and the quality gate

```bash
uv run --extra dev pytest -q                       # all tests
uv run --extra dev pytest -q tests/test_cli.py     # one file
uv run --extra dev pytest -q -k dotnet             # by keyword
```

Before opening a PR, run the same checks as CI:

```bash
./ci-local.sh          # ruff format, ruff lint, mypy, pytest, compileall
./ci-local.sh --fix    # apply ruff formatting and safe lint fixes first
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\ci-local.ps1        # add -Fix to auto-fix
```

Write tests so they do not depend on the machine running them: no network,
no installed backend or runtime, and no particular amount of free memory.
`tests/dotnet_fixtures.py` builds synthetic .NET files, and
`tests/test_apk_export.py` / `tests/test_dotnet_export.py` show how to drive a
whole export with fake sessions.

## Checking a change on real inputs

After touching an export path, run a real export and read the result:

```bash
uv run tocode /bin/true -o /tmp/tocode-check --backend auto -j 2
```

Confirm the tree matches the export contract in `AGENTS.md`, `tocode.log` has
no tracebacks, and `export-manifest.json` reports no unexpected failures. Never
commit export directories (`*_decompiler/` and similar).

## Dependencies

- Runtime dependencies go in `pyproject.toml` with exact pins (`==`); run
  `uv lock` and commit `uv.lock` (CI uses `--locked`).
- Keep dependencies few and tied to exporting a project.
- Do not commit or package binaries. The .NET libraries are downloaded on
  demand with pinned hashes (`src/tocode/backends/dotnet_libs.py`); to update
  one, change its version and both hashes there.

## Releasing

The version lives only in `src/tocode/__init__.py` (`__version__`).

```bash
uv build                    # sdist + wheel in dist/
uvx twine check dist/*      # metadata and README rendering
uvx twine upload dist/*     # needs a PyPI token
```

The PyPI package is `tocode-cli`; the installed command is `tocode`.
