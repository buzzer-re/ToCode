# ToCode

ToCode exports a binary or IDA database into a source-like project tree: raw recovered C, matching assembly, function summaries, section data, optional IDA database, and metadata that coding agents can read directly.

```bash
tocode ./sample.bin -o ./sample_decompiler
```

## Why

Most recent AI models are strong at coding, especially when they can traverse large codebases and accumulate context with subagents and other strategies. When we use these agents to assist with reverse engineering, we usually provide tools through MCP or other means so the coding agent can learn and build strategies around tools such as IDA and r2. This approach adds limitations and constraints to how the agent behaves, and it increases the need for deep, complex reasoning. There should be a better way to improve this scenario so even smaller models can perform well on this kind of work.

The idea behind ToCode is simple: use a disassembler such as IDA to create a source-code-like project for a given binary, with a pre-built `AGENTS.md` so most coding agents start with precomputed context. ToCode also produces rich `.json` files with important metadata. The goal is to provide exactly what coding agents are good at working with: code.

### Export layout

The exported binary contains the following structure:

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

### Example

As an example, we can see how even smaller models can solve crackmes. The following example was taken from the [binary cartography](https://github.com/mrphrazer/binary-cartography) repository by [mrphrazer](https://github.com/mrphrazer):

#### 1 - Decompile the crackme



#### 2 - Point your coding agent and ask it to solve 



### Supported backends

Currently, IDA (using the ida-domain/idapro Python libraries) and radare2 are supported. Other disassemblers may be added in the future.

### Installing

Install ToCode from PyPI:

```bash
pip install tocode-cli
```

Then run it with the `tocode` command:

```bash
tocode ./sample.bin -o ./sample_decompiler
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
