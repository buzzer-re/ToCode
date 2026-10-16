---
name: tocode
description: Reverse engineer compiled programs with ToCode. It exports a binary, IDA/Binary Ninja database, APK, .NET assembly, or whole app folder into a source-like C project, and its MCP server (`tocode mcp`) keeps IDA, Binary Ninja, radare2, or angr open so you can decompile, cross-reference, rename, retype, declare structs and enums, run scripts in the database, and sync every improvement back into the exported source. Use for reverse engineering, binary or malware or firmware analysis, CTF reversing, recovering source code from stripped binaries, or whenever a folder holds a ToCode export (an AGENTS.md that mentions ToCode, functions.json, src/raw/).
---

# ToCode

ToCode turns a binary into a project you can read like source code, and keeps
the decompiler session alive so you can improve it. You read files; the
database is the source of truth; `sync` regenerates the files from it.

## 1. Get an export

```bash
tocode ./program              # -> program_decompiler/ (default backend: IDA, then Binary Ninja, r2, angr)
tocode ./program.i64          # an existing IDA or Binary Ninja (.bndb) database
tocode ./App/                 # a whole folder: every binary, with the links between them
```

An export folder contains:

| Path | What it is |
| --- | --- |
| `AGENTS.md` | Read first: layout and conventions for this binary |
| `src/raw/<folder>/*.c` | Decompiled C, grouped by call graph (or by original source file with debug info) |
| `src/raw/<folder>/*.asm` / `*.summary` | Matching assembly and per-function summaries |
| `functions.json` | Every function: address, name, prototype, params, locals, callers, callees, file and line range |
| `function-index.json` | Address -> file:lines, for jumping straight to a function |
| `triage.json` | Entry points, interesting functions, suspicious imports and strings: start here |
| `strings.json`, `imports.json`, `exports.json`, `types.json` | Strings with their users, imports, exports, recovered types |
| `include/*.h`, `include/*.types.h` | Prototypes and type definitions |
| `<binary>.i64` / `<binary>.bndb` | The database the live tools edit |

Read with your normal file tools (grep, open at a line range). Use the MCP
tools when you need something the files cannot tell you, or to change the
analysis.

## 2. Connect the live tools

If the `tocode` MCP tools are not available, register the server once:

```bash
claude mcp add --scope user tocode -- tocode mcp     # Claude Code
tocode mcp --install codex                           # Codex (~/.codex/config.toml)
tocode mcp --config                                  # snippets for other clients
```

Then `open` the export folder (or a folder export, a binary, a database). It
returns a `session`; pass it to every other tool. With one session open you
may omit it. For a folder export, address a binary as `session="bin/app"`.

`open` uses the export's own database. Pass `database` to work on another
`.i64`/`.bndb` instead.

## 3. The loop

1. **Orient.** Read `AGENTS.md`, `triage.json`, and the C for entry points and
   `main`. `strings`, `imports`, and `xrefs` tell you what code does what.
2. **Query live.** `decompile`, `disassemble`, `function`, `xrefs`,
   `read_bytes`, `search`, `types`, `lookup` answer from the database now,
   including your edits.
3. **Improve the database.** `rename`, `set_type`, `declare_types`,
   `rename_local`, `set_local_type`, `set_comment`, `define_function`.
   Each one names what it makes stale (`pending_sync`).
4. **Sync.** Call `sync` after a batch of edits. It re-renders what changed
   (and callers of renamed or retyped functions, and every function using a
   changed type or global), rewrites only files whose content changed, updates
   the JSON and headers, and saves the database. The report lists what moved.
5. **Re-read** the changed files and continue. Better names and types make
   the decompiler output better everywhere; iterate.

Sync after every few edits rather than once at the end: you then read code
that already reflects what you learned.

## 4. Tools

| Group | Tools |
| --- | --- |
| Sessions | `open`, `sessions`, `close`, `save` |
| Query | `info`, `functions`, `function`, `decompile`, `disassemble`, `xrefs`, `strings`, `imports`, `exports`, `sections`, `types`, `type`, `read_bytes`, `search`, `lookup`, `status` |
| Edit | `rename`, `set_type`, `set_comment`, `declare_types`, `rename_local`, `set_local_type`, `define_function`, `undefine` |
| Script | `eval` (Python in the database; `language="r2"` for r2 commands) |
| Project | `sync`, `export` |

Targets accept an address (`"0x401000"`) or a name; auto names such as
`sub_401000`, `qword_20020`, `DAT_00403000` work too. Full arguments:
[references/tools.md](references/tools.md).

## 5. Recovering source code

To reconstruct the original program (names, types, structs) work bottom-up:

1. **Map the program.** List app functions (`functions` with `kind="app"`),
   find `main` and entry points, and note the strings and imports each
   function uses. Name obvious functions first: a function that only calls
   `fopen`/`fread` on a path from argv is a file loader.
2. **Name leaves before callers.** A leaf's role is clearest from the
   library calls and constants it uses; once named, callers read better.
3. **Recover structs from field accesses.** Repeated `*(ptr + 0x18)` patterns
   on the same pointer are a struct. Collect offsets and sizes from every user
   (`xrefs` to the allocator, `decompile` its callers), write the struct with
   `declare_types` (pad unknown gaps: `char _pad_0x10[8];`), then `set_type`
   the functions and globals that hold it and `set_local_type` the locals.
   The decompiler then prints `pkt->payload_len` instead of offsets.
4. **Enums from constants** compared or switched on; `declare_types` an
   `enum` and set it on the parameter or field.
5. **Globals**: `rename` and `set_type` them (`struct session *g_sessions`).
6. **Prototypes**: `set_type` with real parameter names and types; callers
   then show meaningful arguments.
7. `sync`, re-read, repeat until the code reads like source.
8. If asked for source files, write them from the synced export, adding
   includes and reordering into a buildable program.

Details and a worked example: [references/workflows.md](references/workflows.md).

## 6. .NET

`tocode App.dll` (also apphosts, single-file bundles, `.nupkg`) exports C#
and IL, one `.cs`/`.il` file per type. The same tools work after `open`:

- Targets: `Assembly!0x06000012` (a metadata token: 02 type, 04 field,
  06 method, 17 property, 14 event), `Namespace.Type`, or
  `Namespace.Type::Member`. An ambiguous name lists the candidates.
- Edits: `rename` (types, methods, fields, properties, events),
  `rename_many`, `rename_local` (parameters, and locals as the decompiled C#
  names them), `set_comment`. Types come from metadata, so `set_type`,
  `declare_types`, `set_local_type`, `define_function`, and `undefine` do not
  apply.
- The database is an edit log in the export; ToCode also writes renamed
  assemblies to `patched/` (open them in dnSpy/ILSpy, or run them).
- `sync` rewrites the types the edits touched; a renamed type's file moves.
- Obfuscated code: start at the entry point, `strings`, and `imports`; name
  methods from the APIs they call, work outward, rename in batches with
  `rename_many`, `sync`, and re-read. `eval` has the dnlib modules (`modules`)
  and `decompile(target)`.

## 7. Rules of thumb

- Prefer the dedicated edit tools over `eval`: they report exactly what to
  re-render. After changing things in `eval`, call `touch(addr, ...)` for the
  functions you changed (or `sync` with `mode="full"`).
- `eval` runs inside the analysis process. Keep scripts bounded; a call that
  runs past its timeout stops the session's worker, and unsaved edits since
  the last `save`/`sync` are lost. Recipes per backend:
  [references/eval.md](references/eval.md).
- Edits that the user made in the IDA or Binary Ninja UI are not tracked:
  run `sync` with `mode="full"`, or `tocode sync <export> --full` from a shell.
- Never edit files under `src/raw/` by hand to record findings; put them in
  the database (names, types, comments) and `sync`. Hand edits are
  overwritten when that file is regenerated.
- Backends: IDA and Binary Ninja support every edit; radare2 a subset; angr is
  query-only. Some Binary Ninja builds cannot save databases headless; `save`
  says so and edits then last for the session.
- A tool error explains what to do (wrong name, unsupported, timed out). Read
  it before retrying.
