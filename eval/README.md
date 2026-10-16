# Blind source recovery

The benchmark for ToCode as an agentic RE tool: an agent that sees only a
stripped binary and ToCode (its export, the `tocode` MCP server, and the
skill) tries to recover the original C source. A judge then scores the result
against the real source.

```bash
uv run python eval/recover.py run inventory --backend ida     # one program
uv run python eval/recover.py all --backend binja             # the whole corpus
uv run python eval/recover.py run calc --prepare-only --no-llm # baseline: the plain export, no agent
uv run python eval/recover.py judge /tmp/tocode-eval/<run>    # grade a run again
uv run python eval/recover.py report                          # table of every judged run
```

Each program in `corpus/` has its sources and a `program.json` (compiler
flags, and test inputs for the behaviour check). A run builds it twice: with
debug info (the ground truth, kept in the run's `private/` folder) and
stripped (the agent's input, in `work/`). The agent runs headless (`claude -p`)
in `work/` with only the ToCode MCP server and file tools; reading the
corpus, this repository, or `private/` is denied, and it has no shell or web
access.

The judge reports:

- function names, prototypes, and parameter names, against the source;
- struct, union, and enum recovery (members in order) and global names;
- an LLM grade per function (semantics, naming, types, 0 to 5) and a leakage flag;
- behaviour: `recovered/*.c` is compiled and run against the original on the
  test inputs (programs that run forever are scored on names and types only);
- leakage, from evidence: every tool call that named a forbidden path, and the
  provenance of each original name (did the agent write it first, or did a
  tool show it to the agent without the binary itself containing it). The
  LLM judge's own suspicion is shown separately; it sees the binary's file
  name and strings so it does not mistake good inference for leakage.

Runs live in `$TOCODE_EVAL_RUNS` (default `/tmp/tocode-eval`), outside the
repository so the agent cannot reach the corpus through it.
