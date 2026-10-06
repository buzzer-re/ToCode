"""Walk a folder and collect the binaries and their link facts."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import plistlib
import posixpath
from typing import Any, Callable

from .extract import read_facts
from .model import FileFacts
from .resolve import Folder
from .runtime_libs import is_runtime_library
from .sniff import CODE_KINDS, MACHO_FAT, PE, ZIP, classify

# Job types
JOB_NATIVE = "native"
JOB_DOTNET = "dotnet"  # one managed assembly (or a single-file bundle, or a nupkg)
JOB_APK = "apk"


@dataclass(slots=True)
class Entry:
    relpath: str
    size: int
    kind: str  # sniff kind: elf | pe | macho | macho_fat | zip | java_class | data
    detail: str = ""
    sha256: str | None = None
    archs: list[str] = field(default_factory=list)
    arch: str | None = None  # slice linked and decompiled
    format: str | None = None  # elf | pe | macho | dotnet
    role: str | None = None  # executable | library | bundle | ...
    job: str | None = None  # JOB_* when the file has code to decompile
    runtime: bool = False  # bundled runtime/framework library
    alias_of: str | None = None  # symlink to another file of the folder
    duplicate_of: str | None = None  # byte-identical to an earlier file
    main: bool = False  # the bundle's/app's main executable
    apphost_for: str | None = None  # .NET apphost launcher -> its App.dll
    bundle: bool = False  # .NET single-file bundle
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "path": self.relpath,
            "size": self.size,
            "kind": self.kind,
        }
        for key in (
            "detail", "sha256", "archs", "arch", "format", "role", "job", "alias_of",
            "duplicate_of", "apphost_for", "notes",
        ):  # fmt: skip
            value = getattr(self, key)
            if value:
                row[key] = value
        for key in ("runtime", "main", "bundle"):
            if getattr(self, key):
                row[key] = True
        return row


@dataclass
class Inventory:
    root: Path
    entries: list[Entry]
    folder: Folder
    roots: list[str]  # chain roots: main executables first, then other executables
    arch: str | None
    skipped_dirs: list[str] = field(default_factory=list)

    def entry(self, relpath: str) -> Entry | None:
        return self._by_path.get(relpath)

    def __post_init__(self) -> None:
        self._by_path = {item.relpath: item for item in self.entries}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def walk(
    root: Path, *, exclude_dirs: Callable[[str], bool] | None = None
) -> tuple[list[tuple[str, Path]], dict[str, str], list[str]]:
    """Regular files (relpath, path), file symlinks (relpath -> target relpath)."""
    files: list[tuple[str, Path]] = []
    aliases: dict[str, str] = {}
    skipped: list[str] = []
    real_root = os.path.realpath(root)
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        rel_dir = Path(directory).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        if exclude_dirs is not None:
            kept = []
            for name in dirnames:
                relpath = posixpath.join(rel_dir, name)
                if exclude_dirs(relpath):
                    skipped.append(relpath)
                else:
                    kept.append(name)
            dirnames[:] = kept
        for name in sorted(filenames):
            path = Path(directory) / name
            relpath = posixpath.join(rel_dir, name)
            if path.is_symlink():
                real = os.path.realpath(path)
                if real.startswith(real_root + os.sep) and os.path.isfile(real):
                    aliases[relpath] = Path(real).relative_to(real_root).as_posix()
                continue
            if path.is_file():
                files.append((relpath, path))
    return files, aliases, skipped


def scan(
    root: Path,
    *,
    arch: str | None = None,
    log: Callable[[str], None] = lambda _message: None,
    hash_files: bool = True,
) -> Inventory:
    root = root.resolve()
    files, aliases, skipped = walk(root, exclude_dirs=_is_noise_dir)
    entries: list[Entry] = []
    images: dict[str, dict[str, FileFacts]] = {}
    seen_hashes: dict[str, str] = {}
    log(f"Scanning {len(files)} files under {root}")
    for relpath, path in files:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        sniff = classify(path) if size >= 4 else None
        kind = sniff.kind if sniff else "data"
        entry = Entry(
            relpath=relpath, size=size, kind=kind, detail=sniff.detail if sniff else ""
        )
        entries.append(entry)
        if kind == ZIP:
            flavour = entry.detail
            if flavour == "apk":
                entry.job = JOB_APK
            elif flavour in ("nupkg", "snupkg"):
                entry.job = JOB_DOTNET
            continue
        if kind not in CODE_KINDS:
            continue
        if hash_files:
            entry.sha256 = _sha256(path)
            first = seen_hashes.setdefault(entry.sha256, relpath)
            if first != relpath:
                entry.duplicate_of = first
        slices = read_facts(path, relpath, kind)
        by_arch: dict[str, FileFacts] = {}
        for facts in slices:
            by_arch.setdefault(facts.arch, facts)
            entry.notes.extend(facts.notes)
        entry.archs = list(by_arch)
        first_facts = slices[0]
        entry.format = first_facts.format
        entry.role = first_facts.kind
        if first_facts.format == "dotnet":
            entry.job = JOB_DOTNET
            managed = first_facts.managed or {}
            if managed.get("entry_point_token"):
                entry.role = "executable"
                for facts in by_arch.values():
                    facts.kind = "executable"
        elif first_facts.arch != "unknown":
            entry.job = JOB_NATIVE
        if kind == PE or kind in ("elf", "macho"):
            _dotnet_host(path, entry)
        entry.runtime = entry.runtime or is_runtime_library(
            posixpath.basename(relpath), managed=first_facts.format == "dotnet"
        )
        if entry.job is not None:
            images[relpath] = by_arch
    _mark_main(root, entries, aliases)
    chosen = arch or _main_arch(entries, images)
    selected: dict[str, str] = {}
    for entry in entries:
        if entry.relpath not in images:
            continue
        archs = entry.archs
        if len(archs) == 1:
            entry.arch = archs[0]
        elif chosen in archs:
            entry.arch = chosen
        else:
            entry.arch = archs[0]
            entry.notes.append(f"no {chosen} slice; using {archs[0]}")
        selected[entry.relpath] = entry.arch
    for entry in entries:
        if entry.kind == MACHO_FAT and entry.arch is not None and len(entry.archs) > 1:
            entry.detail = f"fat ({', '.join(entry.archs)}); using {entry.arch}"
    folder = Folder(root=root, images=images, selected=selected, aliases=aliases)
    roots = _chain_roots(entries)
    alias_entries = [
        Entry(relpath=alias, size=0, kind="symlink", alias_of=target)
        for alias, target in sorted(aliases.items())
    ]
    return Inventory(
        root=root,
        entries=entries + alias_entries,
        folder=folder,
        roots=roots,
        arch=chosen,
        skipped_dirs=skipped,
    )


def _is_noise_dir(relpath: str) -> bool:
    name = posixpath.basename(relpath)
    # Our own outputs and VCS metadata are never part of the application.
    return (
        name in {".git", ".hg", ".svn", "__pycache__", ".tocode-folder"}
        or name.endswith("_decompiled")
        or name.endswith("_decompiler")
    )


def _dotnet_host(path: Path, entry: Entry) -> None:
    from ..backends.dotnet import _apphost_assembly
    from ..backends.dotnet_pe import read_bundle

    if read_bundle(path) is not None:
        entry.bundle = True
        entry.job = JOB_DOTNET
        return
    assembly = _apphost_assembly(path)
    if assembly is not None:
        entry.apphost_for = posixpath.join(
            posixpath.dirname(entry.relpath), assembly.name
        )
        entry.runtime = True  # the generic Microsoft launcher


def _mark_main(root: Path, entries: list[Entry], aliases: dict[str, str]) -> None:
    by_path = {item.relpath: item for item in entries}
    found = False
    for entry in entries:
        if posixpath.basename(entry.relpath) != "Info.plist":
            continue
        contents = posixpath.dirname(entry.relpath)
        if posixpath.basename(contents) != "Contents":
            continue
        try:
            with (root / entry.relpath).open("rb") as handle:
                plist = plistlib.load(handle)
        except Exception:  # noqa: BLE001 - malformed plist: no main executable
            continue
        executable = (
            plist.get("CFBundleExecutable") if isinstance(plist, dict) else None
        )
        if not isinstance(executable, str):
            continue
        target = posixpath.join(contents, "MacOS", executable)
        target = aliases.get(target, target)
        main = by_path.get(target)
        if main is not None and main.job is not None:
            main.main = True
            found = True
    if found:
        return
    executables = [
        item for item in entries
        if item.role == "executable" and item.job is not None and not item.runtime
    ]  # fmt: skip
    if executables:
        depth = min(item.relpath.count("/") for item in executables)
        for item in executables:
            if item.relpath.count("/") == depth:
                item.main = True


def _main_arch(
    entries: list[Entry], images: dict[str, dict[str, FileFacts]]
) -> str | None:
    for wanted_main in (True, False):
        for entry in entries:
            if entry.main != wanted_main or entry.role != "executable":
                continue
            archs = [item for item in entry.archs if item != "msil"]
            if len(archs) == 1:
                return archs[0]
    for entry in entries:
        archs = [item for item in entry.archs if item != "msil"]
        if len(archs) == 1:
            return archs[0]
    return None


def _chain_roots(entries: list[Entry]) -> list[str]:
    executables = [
        item for item in entries
        if item.job is not None and item.role == "executable" and item.duplicate_of is None
    ]  # fmt: skip
    executables.sort(
        key=lambda item: (
            not item.main,
            item.relpath.count("/"),
            -item.size,
            item.relpath,
        )
    )
    return [item.relpath for item in executables]
