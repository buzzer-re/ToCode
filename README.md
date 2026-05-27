# ToCode

ToCode exports a binary into a source-like project tree: recovered C, matching assembly, function summaries, section data, and metadata that coding agents can read directly.

```bash
tocode ./sample.bin -o ./sample_decompiler
```

The exporter prefers IDA Domain when available and can fall back to radare2 plus r2ghidra. It is intentionally limited to the Python exporter path.
