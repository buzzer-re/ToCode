# ToCode

ToCode exports a binary, IDA database, Android APK, .NET assembly, or a whole application folder into a source-like project tree: raw recovered C (Java for APKs, C# and IL for .NET), matching assembly, function summaries, section data, optional IDA database, and metadata that coding agents can read directly.

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
  src/raw/<package>/**/*.java      # Only for APK files (replaces the .c/.asm/.summary tree)
  src/raw/<Assembly>/<Namespace>/**/*.cs   # Only for .NET files (replaces the .c/.asm/.summary tree)
  src/raw/<Assembly>/<Namespace>/**/*.il   # Only for .NET files: IL with RVA + raw bytecode per instruction
  src/raw/<Assembly>/Properties/*  # Only for .NET files: AssemblyInfo.cs and the Manifest.il
  src/raw/<Assembly>/*.csproj      # Only for .NET files: recovered project file
  include/*.h
  include/*.types.h
  data/*.bin
  data/variables.json
  data/variables_interesting.json
  data/apk/<apk>/**                # Only for APK files: every non-code APK entry, verbatim
  data/res/<apk>/**/*.xml          # Only for APK files: binary XML resources decoded to text
  data/resources.json              # Only for APK files: decoded resources.arsc
  data/resources/<Assembly>/*      # Only for .NET files: embedded resources (.resources decoded to JSON)
  data/assemblies/*                # Only for .NET files: assemblies extracted from bundles/packages
  lib/<abi>/*.so                   # Only for APK and .NET files: extracted native libraries
  native/<abi>/<lib>/              # Only for APK and .NET files: full nested ToCode export per native library
  AndroidManifest.xml              # Only for APK files
  manifest.json                    # Only for APK files
  classes.json                     # Only for APK files
  package-graph.json               # Only for APK files (replaces cluster-graph.json)
  native-libs.json                 # Only for APK and .NET files
  assemblies.json                  # Only for .NET files
  namespace-graph.json             # Only for .NET files (replaces cluster-graph.json)
  resources.json                   # Only for .NET files
  container.json                   # Only for .NET files: bundle / NuGet package layout
  function-index.json
  functions.json
  types.json
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
  tocode.log
```

| Path | Description |
| --- | --- |
| `src/raw` | Decompiled C-like output, assembly, and summaries. Grouped by call-graph cluster, or by the original source file/directory when the binary has debug info (DWARF). |
| `src/raw/<package>/**/*.java` | **Only for APK files.** Decompiled Java (ASC + androguard DAD), one file per class, folders follow Java packages; inner classes are `Outer$Inner.java`. No clustering, no `.summary` files. |
| `include` | Generated headers, including `*.types.h` with the structs/enums/typedefs recovered from the binary. Not written for APK files. |
| `data` | Raw section dumps and variable metadata. |
| `data/apk`, `data/res`, `data/resources.json` | **Only for APK files.** Every non-code entry of each APK in the set verbatim, `res/**/*.xml` decoded from binary XML, and the decoded `resources.arsc` tables. |
| `src/raw/<Assembly>/<Namespace>/**/*.cs` and `*.il` | **Only for .NET files.** Decompiled C# (ICSharpCode.Decompiler) and IL disassembly (RVA, raw bytecode, metadata tokens) per top-level type, nested types inside, folders follow assemblies and namespaces like a dnSpy/ILSpy project export. `Properties/AssemblyInfo.cs`, `Properties/Manifest.il`, and a `<Assembly>.csproj` per assembly. |
| `data/resources/<Assembly>`, `data/assemblies` | **Only for .NET files.** Embedded resources (`.resources` decoded to JSON) and the assemblies extracted from single-file bundles or NuGet packages. |
| `lib/<abi>/*.so` | **Only for APK and .NET files.** Every native library found (APK: all ABIs; .NET: mixed-mode code, bundled libraries, P/Invoke targets next to the input), always extracted. |
| `native/<abi>/<lib>/` | **Only for APK and .NET files.** A complete nested ToCode export for each native library (own `AGENTS.md` with an Origin section naming the APK or .NET program, `src/raw/*.c`, `functions.json`, `exports.json`, ...). Skipped with `--no-native`. |
| `AndroidManifest.xml` / `manifest.json` | **Only for APK files.** Decoded manifest and its parsed form: package, versions, SDKs, permissions, components with intent filters and exported state, application attributes, split manifests. |
| `classes.json` | **Only for APK files.** Every class with superclass, interfaces, access flags, fields, methods, source file, and Java file/line ranges. |
| `package-graph.json` | **Only for APK files.** Inter-package call graph (the APK counterpart of `cluster-graph.json`). |
| `native-libs.json` | **Only for APK and .NET files.** ABI/arch, hash, source, export directory, and decompilation status of every native library. |
| `assemblies.json` | **Only for .NET files.** Every assembly found: version, target framework, entry point, CLR flags, ReadyToRun/mixed-mode, references, resources, obfuscation hints, and why skipped ones were not decompiled. |
| `namespace-graph.json` | **Only for .NET files.** Inter-namespace and inter-assembly call graph (the .NET counterpart of `cluster-graph.json`). |
| `resources.json` / `container.json` | **Only for .NET files.** Embedded/linked resources index; layout of the bundle, package, or assembly and where each entry was extracted. |
| `types.json` | Catalog of types recovered from the binary's debug info or type library, with C declarations. |
| `*.json` | Functions (with recovered types and original source decl file/line), sections, strings, imports, exports, relocations, reachability, clusters, triage, project metadata, and export manifest. For APK files the same documents describe DEX methods, strings, framework imports, exported components/JNI methods, and reachability from manifest components; `relocations.json`, `cluster-graph.json`, and `types.json` are not written. For .NET files they describe methods (address `<Assembly>!0x<token>`, C# and IL line ranges), the user-string heap, cross-assembly and P/Invoke imports, entry points/public API, and `types.json` lists .NET types with members; `relocations.json` and `cluster-graph.json` are not written. |
| `tocode.log` | Export log with checkpoint, resume, and per-function render history. For APK files it also carries the native library export status. |
| `AGENTS.md` / `CLAUDE.md` | Instructions for agents analyzing the exported binary. |
| `src/tree` | Optional scanner-friendly C output when `--tree` is used. |


### Supported backends

Four backends are supported, selected with `--backend` (default `auto`, which prefers them in this order):

1. **IDA** – uses the ida-domain/idapro Python libraries (best decompilation quality).
2. **Binary Ninja** – uses the Binary Ninja Python API when your license allows headless use. `--backend binja` can also export what you have open in a running Binary Ninja (any license). See [Binary Ninja](#binary-ninja) below.
3. **radare2** – uses r2pipe with the r2ghidra decompiler.
4. **angr** – a pure-Python fallback with no external tooling, so ToCode still runs when neither IDA nor radare2 is available. It is an optional extra (it is large: ~450 MB of native dependencies), so it is not installed by default. Get it in any of these ways:

   ```bash
   bash ./install.sh --all                        # recommended: installs every backend
   pip install tocode-cli[angr]                   # or, with pip directly
   uv tool install --force --editable '.[angr]'   # or, from a local checkout
   ```

   The angr export is structurally identical to the others (same files and metadata); its pseudo-C is lower quality than Hex-Rays or r2ghidra.

Other disassemblers may be added in the future.

### .NET assemblies

ToCode decompiles .NET assemblies (`.dll`, `.exe`), single-file bundles, apphost launchers, and NuGet packages to C#, and writes the IL of each type next to it. You need a .NET 9 or newer runtime.

Decompilation uses [dnlib](https://github.com/0xd4d/dnlib) and [ICSharpCode.Decompiler](https://github.com/icsharpcode/ILSpy), which ToCode doesn't include. The first .NET export asks once whether to download them from nuget.org and checks them against pinned SHA-256 hashes. Scripts and agents can't answer that prompt, so run `tocode --setup-dotnet` beforehand. The files are stored per user (`~/.local/share/tocode/dotnet` on Linux, or `TOCODE_DOTNET_LIB_DIR`); delete that folder to reset.

Native code in the program (mixed-mode assemblies, bundled libraries, P/Invoke libraries next to the input) goes to the native backend unless you pass `--no-native`. Bundles and packages carry the .NET runtime itself, which is skipped unless you add `--include-framework`. `--as-native` treats a .NET file as a plain PE.

```bash
tocode App.dll
tocode publish/App               # single-file bundle or apphost
tocode Vendor.Lib.1.0.0.nupkg
```

### Android APKs

`tocode app.apk` (also `.apks`/`.xapk` bundles) uses [ASC](https://github.com/MG1937/ASC) (`droidasc`, a core dependency) for the DEX side and the regular native backends for every shared object in the package:

- `src/raw/<package>/<Class>.java`: one decompiled Java file per class, folders follow Java packages (no clustering, no summaries).
- `AndroidManifest.xml` + `manifest.json`: decoded and parsed manifest (permissions, components with intent filters and exported state, application attributes, split manifests).
- `classes.json`, `functions.json`, `function-index.json`, `strings.json`, `imports.json`, `exports.json` (exported components + JNI methods), `reachable.json` (from manifest components), `package-graph.json`, `sections.json`, `triage.json`.
- `lib/<abi>/*.so`: every native library extracted; `native/<abi>/<lib>/`: a complete nested ToCode export per library (all ABIs), produced on a background thread while the DEX side decompiles. `native-libs.json` records the status of each (each library runs in its own process; one failing or being OOM-killed never fails the APK export, and the native thread waits for `TOCODE_NATIVE_MIN_FREE_MB`, default 1024 MB, of free memory before each library). Pass `--no-native` to skip the native decompilation (libraries are still extracted). `--backend` picks the native backend (`auto`/`ida`/`binja`/`r2`/`angr`; `binja` needs the headless API here).
- `data/apk/**`: every other APK entry verbatim; `data/res/**/*.xml` and `data/resources.json`: decoded binary XML and `resources.arsc`.

`base.apk` automatically merges sibling `split_*.apk` files (config and ABI splits) into the same project; `--no-splits` exports it alone. The default output directory is `<manifest package>_decompiler`.

```bash
tocode base.apk                     # DEX + all splits + native libs (IDA/r2/angr)
tocode app.apks --no-native -j 4    # bundle, DEX/Android side only
```


### Folders

Point `tocode` at a directory (a game folder, a Linux app, a macOS `.app` bundle, a .NET publish folder) and it exports every binary in it, then links them together.

The links come from the binaries themselves: import and load tables, resolved with each platform's loader rules (`@rpath`/`@loader_path` on macOS, `RPATH`/`RUNPATH` and symbol versions on Linux, the application directory and forwarders on Windows, AssemblyRef/MemberRef signatures and P/Invoke for .NET). ToCode never matches by name similarity. When the executable calls `foo` from `libfoo.so`, the link tells you which file defines it and the file and line range of that function in the library's export.

```text
Game_decompiled/
  AGENTS.md, CLAUDE.md, project.json, export-manifest.json, tocode.log
  inventory.json          # every file: kind, arch, hash, export status
  dependency-graph.json   # which file loads which, and the loader rule used
  mappings.json           # every import -> defining file, function, line range; its call sites
  bin/game/               # one regular export per binary, mirroring the folder
  lib/libengine.so/
```

Inside each export, `imports.json` and `functions.json` carry the same links, and calls into other files get a trailing comment in the decompiled source: `/* tocode-link: foo -> lib/libfoo.so/src/raw/app/x.c:23-45 */`. The comments never add lines, so all line numbers stay valid.

Binaries are exported one at a time, executables first and then the libraries they load. Each runs in its own process, so a crash or out-of-memory kill only fails that file. Re-running the same command skips finished binaries and resumes the rest. Bundled runtimes (VC++/MinGW/libstdc++ copies, the .NET framework) are linked but only decompiled with `--include-framework`. Universal Mach-O files use the main executable's architecture (`--arch` to override).

```bash
tocode --plan Game/                          # list binaries, export order, and links; decompile nothing
tocode Game/ --only 'bin/*' --only '**/libengine.so'   # export a subset; the rest stays linked
tocode Game/ --exclude '*.dll'               # skip matches
tocode Game/ --links-only                    # recompute links over existing exports
```

### Using

ToCode supports Windows, Linux, and macOS with Python 3.10 or newer.

Install it from PyPI:

```bash
pip install tocode-cli              # or: uv tool install tocode-cli
pip install "tocode-cli[angr]"      # also install the angr fallback backend
```

The command is `tocode`. You still need a backend (IDA, radare2, angr, or Binary Ninja); see [Supported backends](https://github.com/buzzer-re/ToCode#supported-backends).

To install from a clone of the repository instead, on Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

On Linux or macOS:

```bash
bash ./install.sh
```

Add `--all` or `--full` (PowerShell: `-Full`) to also install the angr fallback backend, so ToCode works out-of-the-box even without IDA or radare2:

```bash
bash ./install.sh --all
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

Interrupted exports save progress automatically. Rerun the same command to resume from cached function renders, or add `--restart` to ignore the saved checkpoint and start over.
tocode firmwareX.bin.i64 -o firmwareX_decompiled/
...
```

### Binary Ninja

The Binary Ninja backend uses Binary Ninja's own analysis and Pseudo C. ToCode reaches Binary Ninja in one of three ways, tried in this order (`--binja-transport headless`, `mcp` or `rpyc` forces one):

1. **Headless**: the Binary Ninja Python API runs inside ToCode. Needs a license that allows headless use.
2. **MCP**: Binary Ninja 6's built-in MCP server exports what you have open in the UI. Any license.
3. **RPC bridge**: a small server in Binary Ninja's Python console, for older versions. Any license.

**Headless.** With a license that allows headless use, Binary Ninja works like the other backends: it takes a file, and `auto` picks it when IDA isn't available.

```bash
tocode ./program --backend binja -o out/
tocode ./program.bndb -o out/            # a Binary Ninja database always goes to Binary Ninja
tocode ./firmware/ --backend binja       # folders, APK native libraries, and .NET native code too
```

ToCode finds the API through `--binja-dir` or `TOCODE_BINJA_DIR` (the install folder or its `python/` folder), `BN_INSTALL_DIR`, the `binaryninja.pth` written by Binary Ninja's `scripts/install_api.py`, or the default install locations. The finished analysis is cached as a `.bndb` (in `~/.cache/tocode/binja`, or `TOCODE_BINJA_CACHE_DIR`), so a re-run and every render worker open it instead of analyzing again; `--purge-cache` rebuilds it. The export includes it as `<binary>.bndb`, like IDA's `.i64`. Each worker loads Binary Ninja and the database, so free memory caps the worker count (`TOCODE_BINJA_WORKER_MEMORY_MB`, default 1024 per worker).

If the license refuses headless use, ToCode moves on: `--backend binja` to a running Binary Ninja, `auto` to radare2 or angr. `TOCODE_DISABLE_BINJA_HEADLESS=1` skips the API altogether.

**MCP (Binary Ninja 6 and newer).** Turn on the MCP server in Binary Ninja, then:

```bash
tocode --backend binja --list-binja              # open views, with an index
tocode --backend binja -o out/                   # export the active view
tocode --backend binja --binja-view 1 -o out/    # export one view by index
tocode --backend binja --all-views -o out/       # every open view, one folder each
tocode --backend binja ./program -o out/         # export that file (opened in Binary Ninja if it isn't)
```

With a headless license, a file argument is exported headless; add `--binja-transport mcp` to export it through the UI instead.

ToCode connects to `http://127.0.0.1:24642/mcp` by default; set `--binja-mcp-url` or `TOCODE_BINJA_MCP_URL` to change it. MCP has one active view shared with the UI. ToCode switches it to the view it exports and switches it back when done. A file ToCode opens for you stays open in Binary Ninja, because Binary Ninja only closes analyzed files through its save prompt. Section data (`data/*.bin`) is read from Binary Ninja's view, so exporting a `.bndb` works.

**RPC bridge (older versions).** If the MCP server doesn't answer, ToCode falls back to the bridge automatically. Run this once in Binary Ninja's Python console to start the bridge:

```python
import threading, rpyc, binaryninja
from rpyc.utils.server import ThreadedServer

class ToCodeService(rpyc.Service):
    exposed_binaryninja = binaryninja
    def exposed_bv(self):
        return bv  # the currently focused view
    def exposed_eval(self, cmd):
        return eval(cmd)

server = ThreadedServer(
    ToCodeService,
    hostname="127.0.0.1",
    port=18812,
    protocol_config={"allow_all_attrs": True},
)
threading.Thread(target=server.start, daemon=True).start()
print("ToCode RPC server listening on 127.0.0.1:18812")
```

It exposes the whole Binary Ninja Python VM with no authentication, so keep it bound to `127.0.0.1`. The [binja-headless](https://github.com/hugsy/binja-headless) plugin exposes the same interface if you prefer a packaged option.

The same commands work over the bridge (the default view is the focused one). Use `--binja-host` / `--binja-port` (or `TOCODE_BINJA_HOST` / `TOCODE_BINJA_PORT`; default `127.0.0.1:18812`) to reach Binary Ninja on another machine.

Already scripting inside Binary Ninja? Skip the server and export the live view directly:

```python
import sys; sys.path.insert(0, "/path/to/ToCode/src")
from tocode import export_from_binaryview
export_from_binaryview(bv, "out/")
```

## Development

See [DEVELOPMENT.md](https://github.com/buzzer-re/ToCode/blob/main/DEVELOPMENT.md) for setup, tests, the local quality gate, and release steps.
