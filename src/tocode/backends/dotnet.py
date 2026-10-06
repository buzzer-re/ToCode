""".NET backend: dnlib inventory plus ICSharpCode.Decompiler C#/IL output.

Neither library ships with ToCode: ``dotnet_libs`` downloads them on first use
(with consent, hash-pinned) into a per-user folder, and they are loaded in-process
through pythonnet, so exporting a .NET binary needs a .NET 9+ runtime and no
other tool. The parent process inventories every assembly with dnlib (types,
members, P/Invoke, resources, references) and scans IL bytes in pure Python for
call/string/field cross-references; spawned workers decompile types to C# and
disassemble them to IL (with raw bytecode), returning per-method line ranges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any
import zipfile

from ..errors import ToCodeError
from . import dotnet_libs
from .dotnet_pe import (
    PE_MACHINES,
    BundleManifest,
    PeInfo,
    extract_bundle_entry,
    is_apphost_launcher,
    iter_user_strings,
    method_body,
    read_bundle,
    read_pe_info,
    scan_il_tokens,
)

MIN_RUNTIME_MAJOR = 9
NUPKG_SUFFIXES = frozenset({".nupkg", ".snupkg"})
MAX_STRING_XREFS = 64
MAX_FIELD_REFS = 32

# Assemblies and native libraries of the .NET runtime itself. A self-contained
# app or bundle carries a couple of hundred of them; they are inventoried and
# extracted but only decompiled with --include-framework.
_FRAMEWORK_ASSEMBLY_RX = re.compile(
    r"^(System(\..+)?|mscorlib|netstandard|WindowsBase|PresentationCore|"
    r"PresentationFramework|Microsoft\.(CSharp|VisualBasic(\..+)?|Win32\..+|"
    r"NETCore\..+|Extensions\.DependencyModel))\.dll$",
    re.IGNORECASE,
)
_FRAMEWORK_NATIVE_RX = re.compile(
    r"^(lib)?(coreclr|clrjit|clrgc(exp)?|hostfxr|hostpolicy|mscordaccore|mscordbi|"
    r"mscorrc|createdump|coreclrtraceptprovider|System(\.[A-Za-z]+)*\.Native|"
    r"Microsoft\.DiaSymReader\.Native\.[a-z0-9]+|D3DCompiler_47_cor3|"
    r"PenImc_cor3|PresentationNative_cor3|vcruntime140_cor3|wpfgfx_cor3)"
    r"(\.so|\.dylib|\.dll)?$",
    re.IGNORECASE,
)
_ELF_MACHINES = {
    0x03: "x86",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
    0xF3: "riscv64",
}


# --------------------------------------------------------------------------
# Input classification
# --------------------------------------------------------------------------


def is_nupkg(path: Path) -> bool:
    return path.suffix.lower() in NUPKG_SUFFIXES


def is_dotnet_input(path: Path) -> bool:
    """Managed PE, single-file bundle, apphost launcher, or NuGet package."""
    if is_nupkg(path):
        return zipfile.is_zipfile(path)
    info = read_pe_info(path)
    if info is not None and info.is_managed:
        return True
    if read_bundle(path) is not None:
        return True
    return _apphost_assembly(path) is not None


def _apphost_assembly(path: Path) -> Path | None:
    if not is_apphost_launcher(path):
        return None
    stem = path.name[:-4] if path.name.lower().endswith(".exe") else path.name
    candidate = path.with_name(f"{stem}.dll")
    info = read_pe_info(candidate) if candidate.is_file() else None
    return candidate if info is not None and info.is_managed else None


def native_arch(path: Path) -> str:
    try:
        head = path.read_bytes()[:0x400] if path.stat().st_size < 0x400 else None
        if head is None:
            with path.open("rb") as handle:
                head = handle.read(0x400)
    except OSError:
        return "unknown"
    if head[:4] == b"\x7fELF" and len(head) >= 20:
        return _ELF_MACHINES.get(int.from_bytes(head[18:20], "little"), "unknown")
    info = read_pe_info(path)
    if info is not None:
        return info.machine
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        cpu = int.from_bytes(head[4:8], "little")
        return {0x01000007: "x86_64", 0x0100000C: "arm64", 7: "x86", 12: "arm"}.get(
            cpu, "unknown"
        )
    return "unknown"


def is_native_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    if head[:4] == b"\x7fELF" or head[:4] in (
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ):
        return True
    if head[:2] == b"MZ":
        info = read_pe_info(path)
        return info is not None and not info.is_managed
    return False


def is_framework_assembly(name: str) -> bool:
    return bool(_FRAMEWORK_ASSEMBLY_RX.match(Path(name).name))


def is_framework_native(name: str) -> bool:
    return bool(_FRAMEWORK_NATIVE_RX.match(Path(name).name))


# --------------------------------------------------------------------------
# Input discovery
# --------------------------------------------------------------------------


@dataclass(slots=True)
class AssemblyFile:
    path: Path
    entry: str  # path inside the container (or the file name)
    source: str  # container the assembly came from
    framework: bool = False
    include: bool = True
    reason: str | None = None
    tfm: str | None = None


@dataclass(slots=True)
class NativeFile:
    name: str
    path: Path
    entry: str
    source: str
    arch: str
    framework: bool = False
    reason: str | None = None


@dataclass(slots=True)
class ExtraFile:
    entry: str
    path: Path
    kind: str


@dataclass(slots=True)
class DotnetInput:
    kind: str  # assembly | apphost | bundle | nupkg
    input: Path
    assemblies: list[AssemblyFile]
    natives: list[NativeFile] = field(default_factory=list)
    extras: list[ExtraFile] = field(default_factory=list)
    search_dirs: list[Path] = field(default_factory=list)
    bundle: BundleManifest | None = None
    workdir: Path | None = None

    @property
    def included(self) -> list[AssemblyFile]:
        return [item for item in self.assemblies if item.include]


def discover_dotnet_input(
    path: Path, *, workdir: Path, include_framework: bool = False
) -> DotnetInput:
    path = Path(path).resolve()
    if is_nupkg(path):
        return _discover_nupkg(path, workdir, include_framework)
    info = read_pe_info(path)
    if info is not None and info.is_managed:
        assembly = AssemblyFile(path=path, entry=path.name, source=path.name)
        found = DotnetInput("assembly", path, [assembly], search_dirs=[path.parent])
        if info.mixed_mode:
            found.natives.append(
                NativeFile(
                    name=path.name,
                    path=path,
                    entry="(native code of the mixed-mode assembly)",
                    source=path.name,
                    arch=info.machine,
                )
            )
        return found
    bundle = read_bundle(path)
    if bundle is not None:
        return _discover_bundle(path, bundle, workdir, include_framework)
    sibling = _apphost_assembly(path)
    if sibling is not None:
        assembly = AssemblyFile(
            path=sibling, entry=sibling.name, source=f"{path.name} (apphost launcher)"
        )
        return DotnetInput("apphost", path, [assembly], search_dirs=[path.parent])
    raise ToCodeError(f"not a .NET assembly, bundle, or NuGet package: {path}")


def _framework_names_from_deps(deps_path: Path) -> set[str]:
    try:
        deps = json.loads(deps_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    names: set[str] = set()
    libraries = deps.get("libraries", {})
    for target in deps.get("targets", {}).values():
        for key, value in target.items():
            library = libraries.get(key, {})
            if library.get("type") != "runtimepack" and not key.lower().startswith(
                "runtimepack."
            ):
                continue
            for group in ("runtime", "native"):
                for asset in value.get(group, {}):
                    names.add(Path(asset).name.lower())
    return names


def _discover_bundle(
    path: Path, bundle: BundleManifest, workdir: Path, include_framework: bool
) -> DotnetInput:
    root = workdir / "bundle"
    found = DotnetInput("bundle", path, [], bundle=bundle, workdir=workdir)
    found.search_dirs.append(root)
    extracted: list[tuple[Any, Path]] = []
    for entry in bundle.entries:
        target = _safe_join(root, entry.path)
        if target is None:
            continue
        extract_bundle_entry(path, entry, target)
        extracted.append((entry, target))
    deps = next(
        (target for entry, target in extracted if entry.kind == "deps-json"), None
    )
    framework_names = _framework_names_from_deps(deps) if deps else set()
    for entry, target in extracted:
        lower = Path(entry.path).name.lower()
        info = read_pe_info(target) if entry.kind in {"assembly", "unknown"} else None
        if info is not None and info.is_managed:
            framework = lower in framework_names or is_framework_assembly(lower)
            found.assemblies.append(
                AssemblyFile(
                    path=target,
                    entry=entry.path,
                    source=path.name,
                    framework=framework,
                    include=include_framework or not framework,
                    reason=None
                    if include_framework or not framework
                    else "framework assembly (use --include-framework)",
                )
            )
        elif entry.kind == "native" or is_native_binary(target):
            framework = lower in framework_names or is_framework_native(lower)
            found.natives.append(
                NativeFile(
                    name=Path(entry.path).name,
                    path=target,
                    entry=entry.path,
                    source=path.name,
                    arch=native_arch(target),
                    framework=framework,
                    reason="framework native library (use --include-framework)"
                    if framework and not include_framework
                    else None,
                )
            )
        else:
            found.extras.append(ExtraFile(entry.path, target, entry.kind))
    if not found.assemblies:
        raise ToCodeError(f"single-file bundle contains no managed assemblies: {path}")
    return found


def _tfm_rank(tfm: str) -> tuple[int, int, int]:
    """Order target frameworks: net5.0+ > netcoreapp > netstandard > .NET Framework.

    Modern TFMs carry a dot (``net6.0``, ``net10.0-windows``); .NET Framework
    ones do not (``net35``, ``net472``).
    """
    text = tfm.lower()
    for family, rank in (("net", 3), ("netcoreapp", 2), ("netstandard", 1)):
        match = re.match(rf"^{family}(\d+)\.(\d+)", text)
        if match:
            return (rank, int(match.group(1)), int(match.group(2)))
    match = re.match(r"^net(\d)(\d)(\d)?$", text)
    if match:
        return (
            0,
            int(match.group(1)),
            int(match.group(2)) * 10 + int(match.group(3) or 0),
        )
    return (-1, 0, 0)


def _discover_nupkg(path: Path, workdir: Path, include_framework: bool) -> DotnetInput:
    root = workdir / "nupkg"
    found = DotnetInput("nupkg", path, [], workdir=workdir)
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            target = _safe_join(root, info.filename)
            if target is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as sink:
                shutil.copyfileobj(source, sink, 1 << 20)
            parts = info.filename.split("/")
            pe = read_pe_info(target)
            if pe is not None and pe.is_managed:
                tfm = _nupkg_tfm(parts)
                found.assemblies.append(
                    AssemblyFile(
                        path=target,
                        entry=info.filename,
                        source=path.name,
                        framework=is_framework_assembly(parts[-1]),
                        tfm=tfm,
                    )
                )
            elif is_native_binary(target):
                found.natives.append(
                    NativeFile(
                        name=parts[-1],
                        path=target,
                        entry=info.filename,
                        source=path.name,
                        arch=_nupkg_rid(parts) or native_arch(target),
                    )
                )
            else:
                found.extras.append(ExtraFile(info.filename, target, "package-file"))
    if not found.assemblies:
        raise ToCodeError(f"NuGet package contains no managed assemblies: {path}")
    # One copy per assembly name: the newest target framework wins; reference
    # assemblies (ref/) only when nothing else exists.
    best: dict[str, AssemblyFile] = {}
    for item in found.assemblies:
        key = Path(item.entry).name.lower()
        current = best.get(key)
        if current is None or _nupkg_preference(item) > _nupkg_preference(current):
            best[key] = item
    for item in found.assemblies:
        chosen = best[Path(item.entry).name.lower()]
        if item is not chosen:
            item.include = False
            item.reason = f"duplicate of {chosen.entry} (newer target framework)"
        elif item.framework and not include_framework:
            item.include = False
            item.reason = "framework assembly (use --include-framework)"
    found.search_dirs.extend(sorted({item.path.parent for item in found.included}))
    return found


def _nupkg_tfm(parts: list[str]) -> str | None:
    for marker in ("lib", "ref", "tools"):
        if marker in parts:
            index = parts.index(marker)
            if index + 1 < len(parts) - 1:
                return parts[index + 1]
    return None


def _nupkg_rid(parts: list[str]) -> str | None:
    if len(parts) > 2 and parts[0] == "runtimes":
        return parts[1]
    return None


def _nupkg_preference(item: AssemblyFile) -> tuple[int, tuple[int, int, int]]:
    top = item.entry.split("/", 1)[0]
    kind = {"lib": 3, "runtimes": 2, "tools": 2, "ref": 0}.get(top, 1)
    return (kind, _tfm_rank(item.tfm or ""))


def _safe_join(root: Path, name: str) -> Path | None:
    parts = [
        part
        for part in name.replace("\\", "/").split("/")
        if part not in {"", ".", ".."}
    ]
    if not parts:
        return None
    return root.joinpath(*parts)


def pinvoke_neighbours(
    input_dir: Path, module_names: set[str]
) -> list[tuple[str, Path]]:
    """Native libraries next to the input that P/Invoke declarations name."""
    found: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for module in sorted(module_names):
        base = Path(module).name
        stem = base
        for suffix in (".so", ".dll", ".dylib"):
            if stem.lower().endswith(suffix):
                stem = stem[: -len(suffix)]
        candidates = {
            base,
            f"{stem}.so",
            f"lib{stem}.so",
            f"{stem}.dll",
            f"{stem}.dylib",
            f"lib{stem}.dylib",
        }
        for name in sorted(candidates):
            path = (input_dir / name).resolve()
            if path in seen or not path.is_file():
                continue
            if is_native_binary(path):
                seen.add(path)
                found.append((module, path))
    return found


# --------------------------------------------------------------------------
# .NET runtime (pythonnet)
# --------------------------------------------------------------------------

_runtime: dict[str, Any] | None = None


def _version_tuple(text: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", text.split("-", 1)[0])
    return tuple(int(item) for item in numbers[:3])


def dotnet_root_candidates() -> list[Path]:
    candidates: list[Path] = []
    for name in ("DOTNET_ROOT", "DOTNET_ROOT_ARM64", "DOTNET_ROOT_X64"):
        value = os.environ.get(name, "").strip()
        if value:
            candidates.append(Path(value).expanduser())
    exe = shutil.which("dotnet")
    if exe:
        candidates.append(Path(exe).resolve().parent)
    candidates.extend(
        Path(item)
        for item in (
            "/usr/lib/dotnet",
            "/usr/share/dotnet",
            "/usr/local/share/dotnet",
            "/opt/dotnet",
            str(Path.home() / ".dotnet"),
            "C:/Program Files/dotnet",
        )
    )
    return candidates


def find_runtime() -> tuple[Path, str] | None:
    """Newest installed Microsoft.NETCore.App >= 9 as ``(dotnet root, version)``."""
    best: tuple[tuple[int, ...], Path, str] | None = None
    for root in dotnet_root_candidates():
        shared = root / "shared" / "Microsoft.NETCore.App"
        if not shared.is_dir():
            continue
        for item in shared.iterdir():
            version = _version_tuple(item.name)
            if not version or version[0] < MIN_RUNTIME_MAJOR:
                continue
            if not (item / "System.Private.CoreLib.dll").is_file():
                continue
            if best is None or version > best[0]:
                best = (version, root, item.name)
    if best is None:
        return None
    return best[1], best[2]


def probe_dotnet() -> tuple[bool, str]:
    if importlib.util.find_spec("pythonnet") is None:
        return False, "pythonnet is not installed (pip install pythonnet)"
    found = find_runtime()
    if found is None:
        return (
            False,
            f"no .NET runtime >= {MIN_RUNTIME_MAJOR} found (install e.g. "
            "dotnet-runtime-10.0, or set DOTNET_ROOT)",
        )
    return True, f".NET {found[1]} at {found[0]}"


def load_runtime() -> dict[str, Any]:
    """Load CoreCLR and the downloaded libraries once per process."""
    global _runtime
    if _runtime is not None:
        return _runtime
    ok, reason = probe_dotnet()
    if not ok:
        raise ToCodeError(f".NET input requires the .NET backend: {reason}")
    library_dir = dotnet_libs.require_installed()
    found = find_runtime()
    assert found is not None
    root, version = found
    os.environ.setdefault("DOTNET_ROOT", str(root))
    # Keep the runtime quiet and lean inside a Python host.
    os.environ.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    os.environ.setdefault("DOTNET_gcServer", "0")
    import pythonnet

    try:
        pythonnet.load("coreclr", dotnet_root=str(root))
    except RuntimeError as exc:
        if "already" not in str(exc).lower():
            raise ToCodeError(f"cannot load the .NET runtime: {exc}") from exc
    import clr  # type: ignore[import-not-found]

    import System  # type: ignore[import-not-found]

    # Reference by name from a sys.path folder: pythonnet 3.0 (Python 3.10)
    # rejects full paths in AddReference; 3.1+ accepts both.
    if str(library_dir) not in sys.path:
        sys.path.append(str(library_dir))
    for spec in dotnet_libs.LIBRARIES:
        try:
            clr.AddReference(spec.file_name.removesuffix(".dll"))
        except Exception:
            System.Reflection.Assembly.LoadFrom(str(library_dir / spec.file_name))

    actual = str(System.Environment.Version)
    if _version_tuple(actual)[:1] < (MIN_RUNTIME_MAJOR,):
        raise ToCodeError(
            f".NET runtime {actual} was loaded; ToCode needs {MIN_RUNTIME_MAJOR}+"
        )
    _runtime = {
        "clr": clr,
        "System": System,
        "root": root,
        "version": actual,
        "framework_dir": root / "shared" / "Microsoft.NETCore.App" / version,
    }
    return _runtime


# --------------------------------------------------------------------------
# Inventory records
# --------------------------------------------------------------------------


@dataclass(slots=True)
class FieldInfo:
    token: int
    name: str
    type: str
    flags: list[str]
    constant: str | None = None


@dataclass(slots=True)
class PropertyInfo:
    token: int
    name: str
    type: str
    getter: int | None
    setter: int | None


@dataclass(slots=True)
class EventInfo:
    token: int
    name: str
    type: str
    add: int | None
    remove: int | None


@dataclass(slots=True)
class MethodInfo:
    id: int
    assembly: int
    token: int
    name: str
    type_token: int
    type_name: str
    full_name: str
    return_type: str
    params: list[tuple[str, str]]
    flags: list[str]
    impl_flags: list[str]
    rva: int
    il_size: int
    is_static: bool
    is_virtual: bool
    is_abstract: bool
    is_constructor: bool
    compiler_generated: bool
    pinvoke_module: str | None = None
    pinvoke_entry: str | None = None
    unmanaged_entry: str | None = None
    state_machine_type: int | None = None
    owner_method: int | None = None  # state machine / closure owner (method id)
    attributes: list[str] = field(default_factory=list)
    callees: list[int] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    callers: list[int] = field(default_factory=list)
    string_ref_count: int = 0
    field_refs: list[str] = field(default_factory=list)
    cs_start: int | None = None
    cs_end: int | None = None
    il_start: int | None = None
    il_end: int | None = None

    @property
    def address(self) -> str:
        return f"{self.assembly_name}!0x{self.token:08x}"

    # Set by the session after inventory (kept out of __init__ for brevity).
    assembly_name: str = ""

    @property
    def prototype(self) -> str:
        params = ", ".join(f"{kind} {name}" for name, kind in self.params)
        return f"{self.return_type} {self.name}({params})"


@dataclass(slots=True)
class TypeInfo:
    assembly: int
    token: int
    full_name: str  # dnlib style, nested with '/'
    reflection_name: str  # nested with '+'
    namespace: str
    name: str
    kind: str
    flags: list[str]
    visibility: str
    base_type: str | None
    interfaces: list[str]
    generic_params: list[str]
    declaring_type: int | None
    top_level: int  # token of the top-level type that owns the file
    attributes: list[str]
    fields: list[FieldInfo]
    properties: list[PropertyInfo]
    events: list[EventInfo]
    methods: list[int]  # method ids
    compiler_generated: bool = False
    cs_path: Path | None = None
    il_path: Path | None = None
    cs_lines: int = 0
    il_lines: int = 0
    error: str | None = None
    il_error: str | None = None


@dataclass(slots=True)
class ResourceInfo:
    name: str
    kind: str  # embedded | linked | assembly-linked
    size: int | None
    public: bool
    file: str | None = None
    path: Path | None = None
    entries: list[dict[str, Any]] | None = None
    error: str | None = None


@dataclass(slots=True)
class AssemblyInfo:
    index: int
    file: AssemblyFile
    pe: PeInfo
    name: str
    full_name: str
    version: str
    culture: str
    public_key_token: str | None
    module_name: str
    mvid: str
    kind: str
    target_framework: str | None
    entry_point: int | None
    assembly_refs: list[dict[str, Any]]
    module_refs: list[str]
    attributes: list[str]
    resources: list[ResourceInfo]
    folder: str = ""
    types: list[int] = field(default_factory=list)  # tokens
    user_strings: list[tuple[int, str]] = field(default_factory=list)
    obfuscation_hints: list[str] = field(default_factory=list)
    error: str | None = None


def _str(value: Any) -> str:
    return "" if value is None else str(value)


def _flag_list(value: Any) -> list[str]:
    text = _str(value)
    return [
        item.strip() for item in text.split(",") if item.strip() and item.strip() != "0"
    ]


def _attribute_text(attribute: Any) -> str:
    try:
        name = _str(attribute.TypeFullName)
        args = []
        for arg in attribute.ConstructorArguments:
            args.append(_short_value(arg.Value))
        for named in attribute.NamedArguments:
            args.append(f"{_str(named.Name)}={_short_value(named.Argument.Value)}")
        return f"{name}({', '.join(args)})" if args else name
    except Exception:  # pragma: no cover - malformed blobs
        return "<unreadable attribute>"


def _short_value(value: Any) -> str:
    text = _str(value)
    return text if len(text) <= 200 else text[:197] + "..."


def _type_sig_token(signature: Any) -> int | None:
    """TypeDef token behind a ``typeof(X)`` attribute argument (a TypeSig)."""
    target = getattr(signature, "TypeDefOrRef", None)
    if target is None:
        return None
    token = int(target.MDToken.Raw)
    if token >> 24 == 0x02:
        return token
    try:
        resolved = target.ResolveTypeDef()
    except Exception:
        return None
    return int(resolved.MDToken.Raw) if resolved is not None else None


def type_kind(type_def: Any) -> str:
    if type_def.IsInterface:
        return "interface"
    if type_def.IsEnum:
        return "enum"
    if type_def.IsDelegate:
        return "delegate"
    if type_def.IsValueType:
        return "struct"
    if type_def.IsAbstract and type_def.IsSealed:
        return "static class"
    return "class"


_COMPILER_GENERATED = "System.Runtime.CompilerServices.CompilerGeneratedAttribute"
_GENERATED_MEMBER_RX = re.compile(r"^<([^>]+)>(?:[bg]__|$)")
_STATE_MACHINE_ATTRIBUTES = {
    "System.Runtime.CompilerServices.AsyncStateMachineAttribute",
    "System.Runtime.CompilerServices.IteratorStateMachineAttribute",
    "System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute",
}


class DotnetSession:
    """dnlib-backed inventory over every included assembly."""

    backend_name = "dotnet"
    backend_label = ".NET"
    decompiler_label = "ICSharpCode.Decompiler + dnlib"

    def __init__(self, found: DotnetInput) -> None:
        self.input = found
        self.assemblies: list[AssemblyInfo] = []
        self.types: dict[tuple[int, int], TypeInfo] = {}
        self.methods: list[MethodInfo] = []
        self._method_by_token: dict[tuple[int, int], MethodInfo] = {}
        self._method_by_name: dict[str, MethodInfo] = {}
        # (assembly index, #US offset) -> ids of the methods that load it
        self.string_xrefs: dict[tuple[int, int], list[int]] = {}
        self.external_refs: dict[str, dict[str, list[int]]] = {}
        self.pinvoke_modules: set[str] = set()

    # -- loading -----------------------------------------------------------

    def load(self, progress: Any = None) -> None:
        runtime = load_runtime()
        from dnlib.DotNet import ModuleDefMD  # type: ignore[import-not-found]

        modules: list[Any] = []
        for index, item in enumerate(self.input.included):
            pe = read_pe_info(item.path)
            if pe is None:
                continue
            try:
                module = ModuleDefMD.Load(str(item.path))
            except Exception as exc:
                raise ToCodeError(f"dnlib cannot load {item.entry}: {exc}") from exc
            info = self._assembly_info(len(self.assemblies), item, pe, module)
            self.assemblies.append(info)
            modules.append(module)
            self._types_and_methods(info, module)
        del runtime
        for info, module in zip(self.assemblies, modules):
            self._link_owners(info)
            self._scan_references(info, module)
        self._modules = modules

    def _assembly_info(
        self, index: int, item: AssemblyFile, pe: PeInfo, module: Any
    ) -> AssemblyInfo:
        assembly = module.Assembly
        target_framework = None
        attributes: list[str] = []
        if assembly is not None:
            for attribute in assembly.CustomAttributes:
                text = _attribute_text(attribute)
                attributes.append(text)
                if _str(attribute.TypeFullName).endswith("TargetFrameworkAttribute"):
                    args = list(attribute.ConstructorArguments)
                    if args:
                        target_framework = _str(args[0].Value)
        for attribute in module.CustomAttributes:
            attributes.append(f"module: {_attribute_text(attribute)}")
        refs = []
        for ref in module.GetAssemblyRefs():
            refs.append(
                {
                    "name": _str(ref.Name),
                    "version": _str(ref.Version),
                    "culture": _str(ref.Culture) or None,
                    "public_key_token": _str(ref.PublicKeyOrToken.Token)
                    if ref.PublicKeyOrToken is not None
                    else None,
                    "full_name": _str(ref.FullName),
                }
            )
        module_refs = sorted({_str(ref.Name) for ref in module.GetModuleRefs()})
        entry = module.ManagedEntryPoint
        entry_token = int(entry.MDToken.Raw) if entry is not None else None
        name = _str(assembly.Name) if assembly is not None else _str(module.Name)
        info = AssemblyInfo(
            index=index,
            file=item,
            pe=pe,
            name=name or item.path.stem,
            full_name=_str(assembly.FullName)
            if assembly is not None
            else _str(module.Name),
            version=_str(assembly.Version) if assembly is not None else "",
            culture=_str(assembly.Culture) if assembly is not None else "",
            public_key_token=_str(assembly.PublicKeyToken)
            if assembly is not None and assembly.PublicKeyToken is not None
            else None,
            module_name=_str(module.Name),
            mvid=_str(module.Mvid),
            kind=_str(module.Kind),
            target_framework=target_framework,
            entry_point=entry_token,
            assembly_refs=refs,
            module_refs=module_refs,
            attributes=attributes,
            resources=[],
        )
        for resource in module.Resources:
            kind = _str(resource.ResourceType).lower()
            size = None
            file_name = None
            if "embedded" in kind:
                try:
                    size = int(resource.Length)
                except Exception:
                    size = None
            elif "linked" in kind and "assembly" not in kind:
                file_name = _str(getattr(resource, "FileName", None)) or None
            info.resources.append(
                ResourceInfo(
                    name=_str(resource.Name),
                    kind="embedded"
                    if "embedded" in kind
                    else ("assembly-linked" if "assembly" in kind else "linked"),
                    size=size,
                    public=bool(resource.IsPublic),
                    file=file_name,
                )
            )
        heap = pe.stream("#US")
        if heap is not None:
            data = item.path.read_bytes()[heap.offset : heap.offset + heap.size]
            info.user_strings = iter_user_strings(data)
        return info

    def _types_and_methods(self, info: AssemblyInfo, module: Any) -> None:
        odd_names = 0
        total = 0
        for type_def in module.GetTypes():
            token = int(type_def.MDToken.Raw)
            top = type_def
            while top.DeclaringType is not None:
                top = top.DeclaringType
            name = _str(type_def.Name)
            total += 1
            if name and not re.match(r"^[A-Za-z_<][\w`<>.$-]*$", name):
                odd_names += 1
            attributes = [_attribute_text(item) for item in type_def.CustomAttributes]
            compiler_generated = name.startswith("<") or any(
                item.startswith(_COMPILER_GENERATED) for item in attributes
            )
            record = TypeInfo(
                assembly=info.index,
                token=token,
                full_name=_str(type_def.FullName),
                reflection_name=_str(type_def.ReflectionFullName),
                namespace=_str(top.Namespace),
                name=name,
                kind=type_kind(type_def),
                flags=_flag_list(type_def.Attributes),
                visibility=_str(type_def.Visibility),
                base_type=_str(type_def.BaseType.FullName)
                if type_def.BaseType is not None
                else None,
                interfaces=[
                    _str(item.Interface.FullName)
                    for item in type_def.Interfaces
                    if item.Interface is not None
                ],
                generic_params=[_str(item.Name) for item in type_def.GenericParameters],
                declaring_type=int(type_def.DeclaringType.MDToken.Raw)
                if type_def.DeclaringType is not None
                else None,
                top_level=int(top.MDToken.Raw),
                attributes=attributes,
                fields=[self._field(item) for item in type_def.Fields],
                properties=[self._property(item) for item in type_def.Properties],
                events=[self._event(item) for item in type_def.Events],
                methods=[],
                compiler_generated=compiler_generated,
            )
            self.types[(info.index, token)] = record
            info.types.append(token)
            for method in type_def.Methods:
                self._method(info, record, method)
        if total and odd_names / total > 0.2:
            info.obfuscation_hints.append(
                f"{odd_names}/{total} type names are not valid C# identifiers"
            )
        for attribute in info.attributes:
            lowered = attribute.lower()
            if any(
                marker in lowered
                for marker in (
                    "confusedby",
                    "dotfuscator",
                    "obfuscat",
                    "suppressildasm",
                )
            ):
                info.obfuscation_hints.append(f"attribute: {attribute}")

    def _field(self, item: Any) -> FieldInfo:
        constant = None
        if item.HasConstant and item.Constant is not None:
            constant = _short_value(item.Constant.Value)
        return FieldInfo(
            token=int(item.MDToken.Raw),
            name=_str(item.Name),
            type=_str(item.FieldType.FullName) if item.FieldType is not None else "?",
            flags=_flag_list(item.Attributes),
            constant=constant,
        )

    def _property(self, item: Any) -> PropertyInfo:
        getter = item.GetMethod
        setter = item.SetMethod
        signature = item.PropertySig
        return PropertyInfo(
            token=int(item.MDToken.Raw),
            name=_str(item.Name),
            type=_str(signature.RetType.FullName)
            if signature is not None and signature.RetType is not None
            else "?",
            getter=int(getter.MDToken.Raw) if getter is not None else None,
            setter=int(setter.MDToken.Raw) if setter is not None else None,
        )

    def _event(self, item: Any) -> EventInfo:
        add = item.AddMethod
        remove = item.RemoveMethod
        return EventInfo(
            token=int(item.MDToken.Raw),
            name=_str(item.Name),
            type=_str(item.EventType.FullName) if item.EventType is not None else "?",
            add=int(add.MDToken.Raw) if add is not None else None,
            remove=int(remove.MDToken.Raw) if remove is not None else None,
        )

    def _method(self, info: AssemblyInfo, owner: TypeInfo, method: Any) -> None:
        signature = method.MethodSig
        params: list[tuple[str, str]] = []
        if signature is not None:
            names = [
                _str(item.Name)
                for item in method.Parameters
                if not item.IsHiddenThisParameter
            ]
            for position, kind in enumerate(signature.Params):
                label = (
                    names[position]
                    if position < len(names) and names[position]
                    else f"p{position}"
                )
                params.append((label, _str(kind.FullName)))
        attributes = [_attribute_text(item) for item in method.CustomAttributes]
        state_machine = None
        unmanaged_entry = None
        for attribute in method.CustomAttributes:
            type_name = _str(attribute.TypeFullName)
            if type_name in _STATE_MACHINE_ATTRIBUTES:
                args = list(attribute.ConstructorArguments)
                if args and args[0].Value is not None:
                    state_machine = _type_sig_token(args[0].Value)
            elif type_name.endswith("UnmanagedCallersOnlyAttribute"):
                for named in attribute.NamedArguments:
                    if _str(named.Name) == "EntryPoint":
                        unmanaged_entry = _str(named.Argument.Value) or None
        impl_map = method.ImplMap
        pinvoke_module = None
        pinvoke_entry = None
        if impl_map is not None:
            pinvoke_module = (
                _str(impl_map.Module.Name) if impl_map.Module is not None else None
            )
            pinvoke_entry = _str(impl_map.Name) or _str(method.Name)
            if pinvoke_module:
                self.pinvoke_modules.add(pinvoke_module)
        body_size = 0
        rva = int(method.RVA)
        name = _str(method.Name)
        record = MethodInfo(
            id=len(self.methods),
            assembly=info.index,
            token=int(method.MDToken.Raw),
            name=name,
            type_token=owner.token,
            type_name=owner.full_name,
            full_name=_str(method.FullName),
            return_type=_str(signature.RetType.FullName)
            if signature is not None and signature.RetType is not None
            else "System.Void",
            params=params,
            flags=_flag_list(method.Attributes),
            impl_flags=_flag_list(method.ImplAttributes),
            rva=rva,
            il_size=body_size,
            is_static=bool(method.IsStatic),
            is_virtual=bool(method.IsVirtual),
            is_abstract=bool(method.IsAbstract),
            is_constructor=bool(method.IsConstructor),
            compiler_generated=owner.compiler_generated
            or name.startswith("<")
            or any(item.startswith(_COMPILER_GENERATED) for item in attributes),
            pinvoke_module=pinvoke_module,
            pinvoke_entry=pinvoke_entry,
            unmanaged_entry=unmanaged_entry,
            state_machine_type=state_machine,
            attributes=attributes,
        )
        record.assembly_name = info.name
        self.methods.append(record)
        owner.methods.append(record.id)
        self._method_by_token[(info.index, record.token)] = record
        self._method_by_name.setdefault(f"{info.name}|{record.full_name}", record)

    def _link_owners(self, info: AssemblyInfo) -> None:
        """Point compiler-generated methods back to the method that owns them.

        State machines come from [AsyncStateMachine]/[IteratorStateMachine];
        lambdas (``<Owner>b__N``) and local functions (``<Owner>g__Name|N``)
        are matched by the C# compiler's naming scheme against the enclosing
        type and, for closure classes (``<>c``, ``<>c__DisplayClass``), its
        declaring type.
        """
        for method in self.methods:
            if method.assembly != info.index or method.state_machine_type is None:
                continue
            machine = self.types.get((info.index, method.state_machine_type))
            if machine is None:
                continue
            for member in machine.methods:
                self.methods[member].owner_method = method.id
        for method in self.methods:
            if method.assembly != info.index or method.owner_method is not None:
                continue
            match = _GENERATED_MEMBER_RX.match(method.name)
            if match is None:
                continue
            owner_name = match.group(1)
            record = self.types.get((info.index, method.type_token))
            while record is not None:
                candidates = [
                    self.methods[item]
                    for item in record.methods
                    if self.methods[item].name == owner_name and item != method.id
                ]
                if candidates:
                    method.owner_method = candidates[0].id
                    break
                parent = record.declaring_type
                record = self.types.get((info.index, parent)) if parent else None

    # -- references ---------------------------------------------------------

    def _scan_references(self, info: AssemblyInfo, module: Any) -> None:
        data = info.file.path.read_bytes()
        member_refs = self._member_refs(info, module)
        method_specs = self._method_specs(module)
        field_names = {
            field_info.token: f"{record.full_name}::{field_info.name}"
            for (assembly, _), record in self.types.items()
            if assembly == info.index
            for field_info in record.fields
        }
        for method in self.methods:
            if method.assembly != info.index or method.rva == 0:
                continue
            offset = info.pe.rva_to_offset(method.rva)
            if offset is None:
                continue
            code = method_body(data, offset)
            if code is None:
                continue
            method.il_size = len(code)
            callees: list[int] = []
            external: list[str] = []
            fields: list[str] = []
            seen: set[int] = set()
            strings = 0
            for kind, token in scan_il_tokens(code):
                if kind == "string":
                    strings += 1
                    bucket = self.string_xrefs.setdefault(
                        (info.index, token & 0xFFFFFF), []
                    )
                    if len(bucket) < MAX_STRING_XREFS and method.id not in bucket:
                        bucket.append(method.id)
                    continue
                if token in seen:
                    continue
                seen.add(token)
                if kind == "method":
                    table = token >> 24
                    if table == 0x2B:
                        token = method_specs.get(token & 0xFFFFFF, token)
                        table = token >> 24
                    if table == 0x06:
                        target = self._method_by_token.get((info.index, token))
                        if target is not None:
                            callees.append(target.id)
                            target.callers.append(method.id)
                        continue
                    if table == 0x0A:
                        ref = member_refs.get(token)
                        if ref is None:
                            continue
                        full_name, scope, internal = ref
                        target = internal
                        if target is None:
                            target = self._method_by_name.get(f"{scope}|{full_name}")
                        if target is not None:
                            callees.append(target.id)
                            target.callers.append(method.id)
                        else:
                            external.append(f"[{scope}]{full_name}")
                            refs = self.external_refs.setdefault(scope, {}).setdefault(
                                full_name, []
                            )
                            if len(refs) < 32:
                                refs.append(method.id)
                elif kind == "field" and len(fields) < MAX_FIELD_REFS:
                    table = token >> 24
                    if table == 0x04:
                        name = field_names.get(token)
                        if name:
                            fields.append(name)
                    elif table == 0x0A:
                        ref = member_refs.get(token)
                        if ref is not None:
                            fields.append(f"[{ref[1]}]{ref[0]}")
            method.callees = callees
            method.external_calls = external
            method.string_ref_count = strings
            method.field_refs = fields

    def _member_refs(
        self, info: AssemblyInfo, module: Any
    ) -> dict[int, tuple[str, str, MethodInfo | None]]:
        result: dict[int, tuple[str, str, MethodInfo | None]] = {}
        rows = int(module.Metadata.TablesStream.MemberRefTable.Rows)
        for rid in range(1, rows + 1):
            try:
                ref = module.ResolveMemberRef(rid)
            except Exception:
                continue
            if ref is None:
                continue
            scope = info.name
            internal: MethodInfo | None = None
            declaring = ref.DeclaringType
            try:
                if declaring is not None and declaring.DefinitionAssembly is not None:
                    scope = _str(declaring.DefinitionAssembly.Name)
                elif (
                    ref.Class is not None
                    and _str(ref.Class.GetType().Name) == "ModuleRefUser"
                ):
                    scope = _str(ref.Class.Name)
            except Exception:
                pass
            if scope == info.name and ref.IsMethodRef:
                try:
                    resolved = ref.ResolveMethod()
                except Exception:
                    resolved = None
                if (
                    resolved is not None
                    and resolved.Module is not None
                    and _str(resolved.Module.Name) == info.module_name
                ):
                    internal = self._method_by_token.get(
                        (info.index, int(resolved.MDToken.Raw))
                    )
            result[0x0A000000 | rid] = (_str(ref.FullName), scope, internal)
        return result

    def _method_specs(self, module: Any) -> dict[int, int]:
        result: dict[int, int] = {}
        rows = int(module.Metadata.TablesStream.MethodSpecTable.Rows)
        for rid in range(1, rows + 1):
            try:
                spec = module.ResolveMethodSpec(rid)
            except Exception:
                continue
            if spec is not None and spec.Method is not None:
                result[rid] = int(spec.Method.MDToken.Raw)
        return result

    # -- resources ----------------------------------------------------------

    def save_resource(self, info: AssemblyInfo, name: str, target: Path) -> int | None:
        """Write an embedded resource's bytes to ``target``; its size or None."""
        import System  # type: ignore[import-not-found]

        module = self._modules[info.index]
        for resource in module.Resources:
            if _str(resource.Name) != name:
                continue
            try:
                raw = resource.CreateReader().ToArray()
            except Exception:
                return None
            target.parent.mkdir(parents=True, exist_ok=True)
            System.IO.File.WriteAllBytes(str(target), raw)
            return int(raw.Length)
        return None

    def decode_resources_file(
        self, info: AssemblyInfo, name: str
    ) -> list[dict[str, Any]]:
        """Entries of a ``.resources`` blob via dnlib's ResourceReader."""
        from dnlib.DotNet.Resources import ResourceReader  # type: ignore[import-not-found]

        module = self._modules[info.index]
        resource = next(item for item in module.Resources if _str(item.Name) == name)
        elements = ResourceReader.Read(module, resource.CreateReader())
        rows: list[dict[str, Any]] = []
        for element in elements.ResourceElements:
            data = element.ResourceData
            code = _str(data.Code)
            value: Any
            built_in = getattr(data, "Data", None)
            if built_in is not None and not hasattr(built_in, "Length"):
                value = _short_value(built_in)
            else:
                raw = getattr(data, "Data", None)
                try:
                    value = (
                        f"<{len(bytes(raw))} bytes>" if raw is not None else _str(data)
                    )
                except Exception:
                    value = _str(data)
            rows.append({"name": _str(element.Name), "type": code, "value": value})
        return rows

    def close(self) -> None:
        for module in getattr(self, "_modules", []):
            try:
                module.Dispose()
            except Exception:
                pass
        self._modules = []

    # -- lookups ------------------------------------------------------------

    def method(self, assembly: int, token: int) -> MethodInfo | None:
        return self._method_by_token.get((assembly, token))

    def _type_index(
        self,
    ) -> tuple[dict[int, list[TypeInfo]], dict[tuple[int, int], list[TypeInfo]]]:
        cached = getattr(self, "_index_cache", None)
        if cached is not None and cached[0] == len(self.types):
            return cached[1], cached[2]
        tops: dict[int, list[TypeInfo]] = {}
        groups: dict[tuple[int, int], list[TypeInfo]] = {}
        for (index, _), record in self.types.items():
            if record.declaring_type is None:
                tops.setdefault(index, []).append(record)
            groups.setdefault((index, record.top_level), []).append(record)
        self._index_cache = (len(self.types), tops, groups)
        return tops, groups

    def top_level_types(self, assembly: int) -> list[TypeInfo]:
        return self._type_index()[0].get(assembly, [])

    def nested_types(self, assembly: int, top: int) -> list[TypeInfo]:
        """The top-level type ``top`` and every type nested in it."""
        return self._type_index()[1].get((assembly, top), [])


# --------------------------------------------------------------------------
# Worker-side decompilation
# --------------------------------------------------------------------------

_METHOD_IL_RX = re.compile(r"^\s*\.method /\* (06[0-9A-Fa-f]{6}) \*/")
_END_METHOD_RX = re.compile(r"^\s*\} // end of method ")
_DECLARATION_NODES = {
    "MethodDeclaration",
    "ConstructorDeclaration",
    "DestructorDeclaration",
    "OperatorDeclaration",
    "PropertyDeclaration",
    "IndexerDeclaration",
    "EventDeclaration",
    "CustomEventDeclaration",
    "Accessor",
    "LambdaExpression",
    "AnonymousMethodExpression",
    "LocalFunctionDeclarationStatement",
}


@dataclass(slots=True)
class DecompiledType:
    assembly: int
    token: int
    cs: str | None
    cs_error: str | None
    il: str | None
    il_error: str | None
    # metadata token -> (first line, last line) in the respective text
    cs_ranges: dict[int, tuple[int, int]]
    il_ranges: dict[int, tuple[int, int]]


@dataclass(slots=True)
class WorkItem:
    assembly: int
    path: str
    token: int  # 0 = assembly/module attributes + manifest


_worker: dict[str, Any] = {}


def init_dotnet_worker(search_dirs: list[str]) -> None:
    load_runtime()
    _worker["search_dirs"] = search_dirs
    _worker["decompilers"] = {}
    _worker["files"] = {}


def _decompiler_for(path: str) -> tuple[Any, Any, Any]:
    cached = _worker["decompilers"].get(path)
    if cached is not None:
        return cached
    from ICSharpCode.Decompiler import DecompilerSettings  # type: ignore[import-not-found]
    from ICSharpCode.Decompiler.CSharp import CSharpDecompiler  # type: ignore[import-not-found]
    from ICSharpCode.Decompiler.Metadata import (  # type: ignore[import-not-found]
        DotNetCorePathFinderExtensions,
        PEFile,
        UniversalAssemblyResolver,
    )

    settings = DecompilerSettings()
    settings.ThrowOnAssemblyResolveErrors = False
    settings.ShowXmlDocumentation = False
    pe = PEFile(path)
    try:
        target = DotNetCorePathFinderExtensions.DetectTargetFrameworkId(pe)
    except Exception:
        target = ""
    resolver = UniversalAssemblyResolver(path, False, target)
    for directory in _worker.get("search_dirs", []):
        resolver.AddSearchDirectory(directory)
    framework_dir = (_runtime or {}).get("framework_dir")
    if framework_dir is not None:
        resolver.AddSearchDirectory(str(framework_dir))
    decompiler = CSharpDecompiler(pe, resolver, settings)
    cached = (decompiler, pe, settings)
    _worker["decompilers"][path] = cached
    return cached


def decompile_batch_in_worker(items: list[WorkItem]) -> list[DecompiledType]:
    return [decompile_item(item) for item in items]


def decompile_item(item: WorkItem) -> DecompiledType:
    result = DecompiledType(item.assembly, item.token, None, None, None, None, {}, {})
    try:
        decompiler, pe, settings = _decompiler_for(item.path)
    except Exception as exc:
        result.cs_error = result.il_error = f"cannot open assembly: {_exc_text(exc)}"
        return result
    if item.token == 0:
        try:
            result.cs = str(decompiler.DecompileModuleAndAssemblyAttributesToString())
        except Exception as exc:
            result.cs_error = _exc_text(exc)
        try:
            result.il = _manifest_il(pe)
        except Exception as exc:
            result.il_error = _exc_text(exc)
        return result
    try:
        result.cs, result.cs_ranges = _decompile_type(decompiler, settings, item.token)
    except Exception as exc:
        result.cs_error = _exc_text(exc)
    try:
        result.il, result.il_ranges = _disassemble_type(pe, item.token)
    except Exception as exc:
        result.il_error = _exc_text(exc)
    return result


def _exc_text(exc: BaseException) -> str:
    text = str(exc).strip().splitlines()
    first = text[0] if text else type(exc).__name__
    return first[:500]


def _decompile_type(
    decompiler: Any, settings: Any, token: int
) -> tuple[str, dict[int, tuple[int, int]]]:
    from System.IO import StringWriter  # type: ignore[import-not-found]
    from System.Reflection.Metadata.Ecma335 import MetadataTokens  # type: ignore[import-not-found]
    from ICSharpCode.Decompiler.CSharp import AnnotationExtensions  # type: ignore[import-not-found]
    from ICSharpCode.Decompiler.CSharp.OutputVisitor import (  # type: ignore[import-not-found]
        CSharpOutputVisitor,
        TokenWriter,
    )
    from ICSharpCode.Decompiler.TypeSystem import IEntity, IEvent, IProperty  # type: ignore[import-not-found]

    # DecompileTypes (unlike Decompile(EntityHandle)) wraps the type in its
    # namespace declaration, as a project export would.
    from System.Collections.Generic import List  # type: ignore[import-not-found]
    from System.Reflection.Metadata import TypeDefinitionHandle  # type: ignore[import-not-found]

    handles = List[TypeDefinitionHandle]()
    handles.Add(MetadataTokens.TypeDefinitionHandle(token & 0xFFFFFF))
    tree = decompiler.DecompileTypes(handles)
    writer = StringWriter()
    tree.AcceptVisitor(
        CSharpOutputVisitor(
            TokenWriter.CreateWriterThatSetsLocationsInAST(writer, "    "),
            settings.CSharpFormattingOptions,
        )
    )
    ranges: dict[int, tuple[int, int]] = {}

    def record(entity: Any, start: int, end: int) -> None:
        try:
            value = int(MetadataTokens.GetToken(IEntity(entity).MetadataToken))
        except Exception:
            return
        if value and value not in ranges:
            ranges[value] = (start, end)

    for node in tree.Descendants:
        kind = type(node).__name__
        if kind not in _DECLARATION_NODES:
            continue
        start = int(node.StartLocation.Line)
        end = int(node.EndLocation.Line)
        if start <= 0:
            continue
        symbol = AnnotationExtensions.GetSymbol(node)
        if symbol is None:
            for annotation in node.Annotations:
                if type(annotation).__name__ == "ILFunction":
                    method = getattr(annotation, "Method", None)
                    if method is not None:
                        record(method, start, end)
            continue
        record(symbol, start, end)
        # Properties/events: map their accessor methods to the same span when
        # the accessors have no separate Accessor node (expression bodies).
        try:
            prop = IProperty(symbol)
            for accessor in (prop.Getter, prop.Setter):
                if accessor is not None:
                    record(accessor, start, end)
        except Exception:
            pass
        try:
            event = IEvent(symbol)
            for accessor in (
                event.AddAccessor,
                event.RemoveAccessor,
                event.InvokeAccessor,
            ):
                if accessor is not None:
                    record(accessor, start, end)
        except Exception:
            pass
    text = str(writer.ToString()).replace("\r\n", "\n")
    return text, ranges


def _new_disassembler(output: Any) -> Any:
    from System.Threading import CancellationToken  # type: ignore[import-not-found]
    from ICSharpCode.Decompiler.Disassembler import ReflectionDisassembler  # type: ignore[import-not-found]

    disassembler = ReflectionDisassembler(output, getattr(CancellationToken, "None"))
    disassembler.ShowMetadataTokens = True
    disassembler.ShowRawRVAOffsetAndBytes = True
    disassembler.DetectControlStructure = True
    disassembler.ExpandMemberDefinitions = True
    return disassembler


def _disassemble_type(pe: Any, token: int) -> tuple[str, dict[int, tuple[int, int]]]:
    from System.Reflection.Metadata.Ecma335 import MetadataTokens  # type: ignore[import-not-found]
    from ICSharpCode.Decompiler import PlainTextOutput  # type: ignore[import-not-found]

    output = PlainTextOutput()
    output.IndentationString = "    "
    _new_disassembler(output).DisassembleType(
        pe, MetadataTokens.TypeDefinitionHandle(token & 0xFFFFFF)
    )
    text = str(output.ToString()).replace("\r\n", "\n")
    return text, il_method_ranges(text)


def _manifest_il(pe: Any) -> str:
    from ICSharpCode.Decompiler import PlainTextOutput  # type: ignore[import-not-found]

    output = PlainTextOutput()
    output.IndentationString = "    "
    disassembler = _new_disassembler(output)
    disassembler.WriteAssemblyReferences(pe.Metadata)
    if pe.Metadata.IsAssembly:
        disassembler.WriteAssemblyHeader(pe)
    output.WriteLine()
    disassembler.WriteModuleHeader(pe)
    return str(output.ToString()).replace("\r\n", "\n")


def il_method_ranges(text: str) -> dict[int, tuple[int, int]]:
    """Line ranges of every ``.method`` block in ReflectionDisassembler output."""
    ranges: dict[int, tuple[int, int]] = {}
    current: tuple[int, int] | None = None
    for number, line in enumerate(text.split("\n"), start=1):
        match = _METHOD_IL_RX.match(line)
        if match:
            current = (int(match.group(1), 16), number)
            continue
        if current is not None and _END_METHOD_RX.match(line):
            ranges[current[0]] = (current[1], number)
            current = None
    return ranges


def runtime_description() -> str:
    runtime = _runtime or {}
    return f".NET {runtime.get('version', '?')} ({sys.platform})"


__all__ = [
    "PE_MACHINES",
    "AssemblyFile",
    "AssemblyInfo",
    "DecompiledType",
    "DotnetInput",
    "DotnetSession",
    "MethodInfo",
    "NativeFile",
    "TypeInfo",
    "WorkItem",
    "decompile_batch_in_worker",
    "discover_dotnet_input",
    "init_dotnet_worker",
    "is_dotnet_input",
    "load_runtime",
    "pinvoke_neighbours",
    "probe_dotnet",
]
