# ToCode

ToCode exports a binary or IDA database into a source-like project tree: raw recovered C, matching assembly, function summaries, section data, optional IDA database, and metadata that coding agents can read directly.

## Why

AI models are strong at coding, especially when they can traverse large codebases and accumulate context with subagents and other strategies. When we use these agents to assist with reverse engineering, we usually provide tools through MCP or other means so the coding agent can learn and build strategies around tools such as IDA and r2. This approach adds limitations and constraints to how the agent behaves, and it increases the need for deep, complex reasoning.

There should be a better way to improve this scenario so that even smaller models can perform well on this kind of work.

The idea behind ToCode is simple: use a disassembler such as IDA to create a source-code-like project for a given binary, with a pre-built `AGENTS.md` so most coding agents start with precomputed context. ToCode also produces rich `.json` files with important metadata.

With this approach, even tiny models can perform well without being connected to MCP-like tool calls, because ToCode provides exactly what coding agents are good at working with: code.

### Export layout

The exported project contains the following structure:

```text
sample_decompiler/
  AGENTS.md
  CLAUDE.md
  src/raw/**/*.c
  src/raw/**/*.asm
  src/raw/**/*.summary
  include/*.h
  data/*.bin
  data/variables.json
  data/variables_interesting.json
  function-index.json
  functions.json
  sections.json
  strings.json
  imports.json
  exports.json
  relocations.json
  reachable.json
  cluster-graph.json
  triage.json
  project.json
  export-manifest.json
```

| Path | Description |
| --- | --- |
| `src/raw` | Decompiled C-like output, assembly, and summaries grouped by cluster. |
| `include` | Generated headers for the exported project. |
| `data` | Raw section dumps and variable metadata. |
| `*.json` | Functions, sections, strings, imports, exports, relocations, reachability, clusters, triage, project metadata, and export manifest. |
| `AGENTS.md` / `CLAUDE.md` | Instructions for agents analyzing the exported binary. |
| `src/tree` | Optional scanner-friendly C output when `--tree` is used. |


### Supported backends

Three backends are supported, selected with `--backend` (default `auto`, which prefers them in this order):

1. **IDA** – uses the ida-domain/idapro Python libraries (best decompilation quality).
2. **radare2** – uses r2pipe with the r2ghidra decompiler.
3. **angr** – a pure-Python fallback with no external tooling, so ToCode still runs when neither IDA nor radare2 is available. It is an optional extra (it is large: ~450 MB of native dependencies), so it is not installed by default. Get it in any of these ways:

   ```bash
   bash ./install.sh --full          # recommended: installs every backend
   pip install tocode-cli[angr]      # or, with pip directly
   uv sync --extra angr              # or, in a local checkout
   ```

   The angr export is structurally identical to the others (same files and metadata); its pseudo-C is lower quality than Hex-Rays or r2ghidra.

Other disassemblers may be added in the future.

### Using

ToCode supports Windows, Linux, and macOS with Python 3.10 or newer.

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

On Linux or macOS:

```bash
bash ./install.sh
```

Add `--full` (PowerShell: `-Full`) to also install the angr fallback backend, so ToCode works out-of-the-box even without IDA or radare2:

```bash
bash ./install.sh --full
```

Manual setup (requires [uv](https://docs.astral.sh/uv/)):

```bash
git clone https://github.com/buzzer-re/ToCode
cd ToCode
uv sync --locked
uv tool install --force --editable .
```

### Example

```
tocode firmwareX.bin -o firmwareX_decompiled/
cd firmwareX_decompiled/
codex 

# Inside your agent shell, type your goals, e.g.: "Give me a brief overview of the boot process of this firmware."
``` 

#### From an ongoing RE work
```
tocode firmwareX.bin.i64 -o firmwareX_decompiled/
...
```

## Development

This tool was built using agentic coding, so if you plan to help, I strongly advise doing the same.

Before changing ToCode, have Python, uv, ruff, mypy, pytest, and compileall available. For backend work, also have IDA or radare2 installed, depending on what you are touching.

The main instructions for agents are in `AGENTS.md`. Read it before starting, and make sure the local quality gate passes before proceeding.

### Quality Gate

Run the local CI gate before opening a PR:

```bash
./ci-local.sh
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\ci-local.ps1
```
