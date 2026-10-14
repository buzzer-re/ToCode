"""Facts parsed from one binary, and the links resolved between binaries."""

from __future__ import annotations

from dataclasses import MISSING, asdict, dataclass, field, fields
from typing import Any

# Library reference kinds (what the importer asked the loader for).
LIB_NEEDED = "needed"  # ELF DT_NEEDED, Mach-O LC_LOAD_DYLIB, PE import descriptor
LIB_WEAK = "weak"  # Mach-O LC_LOAD_WEAK_DYLIB (missing at runtime is fine)
LIB_REEXPORT = "reexport"  # Mach-O LC_REEXPORT_DYLIB
LIB_UPWARD = "upward"  # Mach-O LC_LOAD_UPWARD_DYLIB
LIB_LAZY = "lazy"  # Mach-O LC_LAZY_LOAD_DYLIB
LIB_DELAY = "delay"  # PE delay-load import descriptor
LIB_ASSEMBLY = "assembly"  # .NET AssemblyRef
LIB_PINVOKE = "pinvoke"  # .NET ModuleRef used by P/Invoke (ImplMap)

# Mach-O special library ordinals (two-level namespace lookups).
SPECIAL_SELF = "self"
SPECIAL_MAIN = "main_executable"
SPECIAL_FLAT = "flat_lookup"
SPECIAL_WEAK = "weak_lookup"


@dataclass(slots=True)
class LibraryRef:
    """One library the binary names, in the order the loader sees them."""

    name: str  # as written: "@rpath/core.dylib", "libfoo.so.1", "KERNEL32.dll"
    kind: str = LIB_NEEDED
    # Mach-O: compatibility/current version; .NET: assembly version.
    version: str | None = None


@dataclass(slots=True)
class ImportSym:
    name: str  # as the linker wrote it (Mach-O keeps the leading "_")
    # Index into ``FileFacts.libraries``; None for flat/global lookup (ELF
    # without version info, Mach-O flat namespace, special ordinals).
    library: int | None = None
    special: str | None = None  # SPECIAL_* for Mach-O special ordinals
    ordinal: int | None = None  # PE import by ordinal
    version: str | None = None  # ELF symbol version ("GLIBC_2.17")
    weak: bool = False
    slot: int | None = None  # link-time VA of the pointer the loader fills
    kind: str | None = None  # "function" | "data" | "tls" | None (unknown)
    # .NET: declaring type of a member reference (or the managed method that
    # declares a P/Invoke), its canonical signature, and the MethodDef tokens of
    # the importer's methods whose IL references it.
    owner: str | None = None
    signature: str | None = None
    callers: list[int] | None = None


@dataclass(slots=True)
class ExportSym:
    name: str
    address: int | None = None  # link-time VA; None for re-exports/forwarders
    ordinal: int | None = None  # PE export ordinal
    # PE forwarder ("OTHER.Func" / "OTHER.#12") or Mach-O re-export.
    forwarder: str | None = None
    reexport_library: int | None = None  # index into ``FileFacts.libraries``
    reexport_name: str | None = None
    version: str | None = None  # ELF symbol version
    default_version: bool = True  # ELF "@@" (default) vs "@" (hidden)
    weak: bool = False
    kind: str | None = None  # "function" | "data" | "tls" | "absolute" | "resolver"
    signature: str | None = None  # .NET canonical method signature
    token: int | None = None  # .NET MethodDef token


@dataclass(slots=True)
class FileFacts:
    """Everything the link resolver needs from one binary (or one fat slice)."""

    path: str  # POSIX path relative to the input folder
    format: str  # "elf" | "pe" | "macho" | "dotnet"
    arch: str
    bits: int
    kind: str  # "executable" | "library" | "bundle" | "object" | "other"
    image_base: int = 0  # link-time base the addresses below are relative to
    identity: str | None = None  # SONAME / install name / PE export name / assembly
    libraries: list[LibraryRef] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)  # ELF DT_RPATH, Mach-O LC_RPATH
    runpaths: list[str] = field(default_factory=list)  # ELF DT_RUNPATH
    imports: list[ImportSym] = field(default_factory=list)
    exports: list[ExportSym] = field(default_factory=list)
    flat_namespace: bool = False  # Mach-O without MH_TWOLEVEL
    uuid: str | None = None  # Mach-O LC_UUID, ELF build-id, PE RSDS GUID+age
    slice_offset: int = 0  # fat slice offset inside the file (0 for thin files)
    slice_size: int | None = None
    entry: int | None = None
    notes: list[str] = field(default_factory=list)  # parse warnings
    # Managed only: the assembly name/version and the files .NET would probe.
    managed: dict[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        # Compact: drop defaulted keys from every import/export row.
        payload["imports"] = [_compact(item) for item in self.imports]
        payload["exports"] = [_compact(item) for item in self.exports]
        payload["libraries"] = [_compact(item) for item in self.libraries]
        return payload

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "FileFacts":
        data = dict(payload)
        data["libraries"] = [LibraryRef(**item) for item in data.get("libraries", [])]
        data["imports"] = [ImportSym(**item) for item in data.get("imports", [])]
        data["exports"] = [ExportSym(**item) for item in data.get("exports", [])]
        known = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})


def _compact(item: Any) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for entry in fields(item):
        value = getattr(item, entry.name)
        if entry.default is not MISSING and entry.default == value:
            continue
        row[entry.name] = value
    return row


# FileEdge.status values
EDGE_IN_FOLDER = "in_folder"
EDGE_SYSTEM = "system"
EDGE_APISET = "apiset"
EDGE_MISSING = "missing"
EDGE_WEAK_MISSING = "weak_missing"
EDGE_ARCH_MISMATCH = "arch_mismatch"
EDGE_SONAME_UNREACHABLE = "soname_match_unreachable"
EDGE_FRAMEWORK = "framework"  # .NET framework assembly not in the folder


@dataclass(slots=True)
class FileEdge:
    """``source`` loads ``target`` (or tries to): one resolved library reference."""

    source: str  # importer relpath
    library: int  # index into the importer's ``libraries``
    name: str  # the reference as written
    kind: str
    status: str
    target: str | None = None  # relpath inside the folder when resolved
    via: list[str] = field(default_factory=list)  # how the loader got there
    chain_root: str | None = None  # executable whose load chain produced this

    def to_json(self) -> dict[str, Any]:
        return {
            "from": self.source,
            "library": self.name,
            "kind": self.kind,
            "status": self.status,
            "to": self.target,
            "via": self.via,
            "chain_root": self.chain_root,
        }
