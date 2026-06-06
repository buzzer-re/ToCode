# ToCode

ToCode exports a binary or IDA database into a source-like project tree: raw recovered C, matching assembly, function summaries, section data, optional IDA database, and metadata that coding agents can read directly.

```bash
tocode ./sample.bin -o ./sample_decompiler
```

The exporter prefers IDA Domain when available and can fall back to radare2 plus r2ghidra. By default it writes `src/raw` for decompiler evidence. Use `--tree` to also write `src/tree` for tree-sitter/Semgrep-style scanning.

## Quality Gate

Run the local CI gate before opening a PR:

```bash
./ci-local.sh
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\ci-local.ps1
```
