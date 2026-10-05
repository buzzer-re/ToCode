# ToCode

ToCode exports a binary, IDA database, Android APK, or .NET assembly into a source-like project tree: raw recovered C (Java for APKs, C# and IL for .NET), matching assembly, function summaries, section data, optional IDA database, and metadata that coding agents can read directly.

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

Three backends are supported, selected with `--backend` (default `auto`, which prefers them in this order):

1. **IDA** – uses the ida-domain/idapro Python libraries (best decompilation quality).
2. **radare2** – uses r2pipe with the r2ghidra decompiler.
3. **angr** – a pure-Python fallback with no external tooling, so ToCode still runs when neither IDA nor radare2 is available. It is an optional extra (it is large: ~450 MB of native dependencies), so it is not installed by default. Get it in any of these ways:

   ```bash
   bash ./install.sh --all                        # recommended: installs every backend
   pip install tocode-cli[angr]                   # or, with pip directly
   uv tool install --force --editable '.[angr]'   # or, from a local checkout
   ```

   The angr export is structurally identical to the others (same files and metadata); its pseudo-C is lower quality than Hex-Rays or r2ghidra.

 4. **Binary Ninja**, is opt-in (`--backend binja`) and never chosen by `auto`, because it drives a running Binary Ninja instead of reading a file. See [Binary Ninja](#binary-ninja) below.

Other disassemblers may be added in the future.

### .NET assemblies

`tocode App.dll` (also `.exe`, an apphost launcher next to its `.dll`, single-file bundles, and `.nupkg` packages) uses a built-in .NET backend: [dnlib](https://github.com/0xd4d/dnlib) for metadata and [ICSharpCode.Decompiler](https://github.com/icsharpcode/ILSpy) (ILSpy's engine) for C#, loaded through [pythonnet](https://pypi.org/project/pythonnet/). No dnSpy/ILSpy install is needed, only a **.NET 9+ runtime** (e.g. `sudo apt install dotnet-runtime-10.0`, or the SDK; `DOTNET_ROOT` is honoured).

ToCode does not ship these two libraries (both MIT). The first .NET export asks once whether to download them from nuget.org and remembers the answer. Non-interactive runs (agents, CI) are never prompted: run `tocode --setup-dotnet` once instead, which downloads without asking, or re-verifies and repairs an existing install. Each download is checked against SHA-256 hashes pinned in `src/tocode/backends/dotnet_libs.py`, for both the `.nupkg` and the extracted DLL, and the files are re-hashed after being written. They are stored per user in `~/.local/share/tocode/dotnet` (macOS: `~/Library/Application Support/tocode/dotnet`, Windows: `%LOCALAPPDATA%\tocode\dotnet`, override: `TOCODE_DOTNET_LIB_DIR`). Delete that folder to undo the install or reset the remembered answer.

- `src/raw/<Assembly>/<Namespace>/.../<Type>.cs`: C# per top-level type, folders follow assemblies and namespaces like a dnSpy/ILSpy project export; `<Type>.il` next to it keeps the bytecode (IL with RVA, raw bytes, and metadata tokens per instruction).
- Per-method C# and IL line ranges in `functions.json`/`function-index.json` (address `<Assembly>!0x<token>`), with lambdas and async/iterator state machines linked to the method that owns them.
- `assemblies.json`, `types.json`, `strings.json` (user strings with `ldstr` xrefs), `imports.json` (cross-assembly members and P/Invoke), `exports.json`, `reachable.json`, `namespace-graph.json`, `resources.json`, `container.json`, `triage.json` (P/Invoke, suspicious API families, obfuscation hints, strings of interest).
- Native code goes through the regular native backends on a background thread, like APK `.so` files: mixed-mode (C++/CLI) assemblies, native libraries inside bundles/packages, and P/Invoke targets shipped next to the input. `--no-native` skips it.
- Single-file bundles and packages carry the .NET runtime/framework; those assemblies and runtime native libraries are listed but only decompiled with `--include-framework`. NuGet packages decompile each assembly once, from its newest target framework.
- `--as-native` exports a managed PE with the native backend instead (e.g. to look at a ReadyToRun or mixed-mode image in IDA).

```bash
tocode App.dll                      # assembly (+ P/Invoke libraries next to it)
tocode publish/App                  # single-file bundle or apphost launcher
tocode Vendor.Lib.1.0.0.nupkg       # NuGet package
```

### Android APKs

`tocode app.apk` (also `.apks`/`.xapk` bundles) uses [ASC](https://github.com/MG1937/ASC) (`droidasc`, a core dependency) for the DEX side and the regular native backends for every shared object in the package:

- `src/raw/<package>/<Class>.java`: one decompiled Java file per class, folders follow Java packages (no clustering, no summaries).
- `AndroidManifest.xml` + `manifest.json`: decoded and parsed manifest (permissions, components with intent filters and exported state, application attributes, split manifests).
- `classes.json`, `functions.json`, `function-index.json`, `strings.json`, `imports.json`, `exports.json` (exported components + JNI methods), `reachable.json` (from manifest components), `package-graph.json`, `sections.json`, `triage.json`.
- `lib/<abi>/*.so`: every native library extracted; `native/<abi>/<lib>/`: a complete nested ToCode export per library (all ABIs), produced on a background thread while the DEX side decompiles. `native-libs.json` records the status of each (each library runs in its own process; one failing or being OOM-killed never fails the APK export, and the native thread waits for `TOCODE_NATIVE_MIN_FREE_MB`, default 1024 MB, of free memory before each library). Pass `--no-native` to skip the native decompilation (libraries are still extracted). `--backend` picks the native backend (`auto`/`ida`/`r2`/`angr`; `binja` is not supported for APKs).
- `data/apk/**`: every other APK entry verbatim; `data/res/**/*.xml` and `data/resources.json`: decoded binary XML and `resources.arsc`.

`base.apk` automatically merges sibling `split_*.apk` files (config and ABI splits) into the same project; `--no-splits` exports it alone. The default output directory is `<manifest package>_decompiler`.

```bash
tocode base.apk                     # DEX + all splits + native libs (IDA/r2/angr)
tocode app.apks --no-native -j 4    # bundle, DEX/Android side only
```


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

The Binary Ninja backend exports the binary you already have **open** in Binary Ninja, emitting its Pseudo C. It does **not** need a Binary Ninja *headless* license: ToCode connects to the running GUI over a small RPC bridge.

Since I don't have access to Binary Ninja headless, run this script once in Binary Ninja's Python console to open an RPC server ToCode can connect to:

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

Then drive it from ToCode:

```bash
tocode --backend binja --list-binja              # list open views with an index
tocode --backend binja -o out/                   # export the focused view
tocode --backend binja --binja-view 1 -o out/    # export a specific view by index
tocode --backend binja --all-views -o out/       # export every open view, one folder each
```

Use `--binja-host` / `--binja-port` (or `TOCODE_BINJA_HOST` / `TOCODE_BINJA_PORT`; default `127.0.0.1:18812`) to reach Binary Ninja on another machine.

Already scripting inside Binary Ninja? Skip the server and export the live view directly:

```python
import sys; sys.path.insert(0, "/path/to/ToCode/src")
from tocode import export_from_binaryview
export_from_binaryview(bv, "out/")
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for setup, tests, the local quality gate, and release steps.
