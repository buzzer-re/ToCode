# Vulnerability Toy

This fixture is for end-to-end scanner verification:

```bash
gcc -O0 -fno-stack-protector -no-pie -o /tmp/tocode-vuln-toy examples/vuln-toy/vuln_toy.c
strip /tmp/tocode-vuln-toy
$HOME/.local/bin/uv run tocode /tmp/tocode-vuln-toy -o /tmp/tocode-vuln-toy-export --backend auto -j 2
semgrep --config examples/vuln-toy/semgrep.yml /tmp/tocode-vuln-toy-export/src/tree
```

Semgrep should report the recovered `strcpy(...)` call in `src/tree`.
