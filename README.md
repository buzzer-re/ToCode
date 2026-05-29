# ToCode

ToCode exports a binary into a source-like project tree: scanner-friendly C, raw recovered C, matching assembly, function summaries, section data, and metadata that coding agents can read directly.

```bash
tocode ./sample.bin -o ./sample_decompiler
```

The exporter prefers IDA Domain when available and can fall back to radare2 plus r2ghidra. By default it writes `src/tree` for tree-sitter/Semgrep-style scanning and `src/raw` for decompiler evidence. Use `--no-tree` to skip the scanner-oriented source tree.
