"""Loader rules: which file each library reference loads.

Each executable starts a load chain, walked breadth-first the way the
platform loader would, so context-dependent rules (``@executable_path``,
``@rpath`` stacks inherited from the loading images, ELF ``DT_RPATH``
inheritance, already-loaded SONAMEs, the process directory for Windows DLLs)
get the context of a real process. Libraries no executable here loads become
their own chain roots. Every edge records how it was resolved in ``via``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import os
from pathlib import Path
import posixpath

from .model import (
    EDGE_APISET,
    EDGE_ARCH_MISMATCH,
    EDGE_FRAMEWORK,
    EDGE_IN_FOLDER,
    EDGE_MISSING,
    EDGE_SYSTEM,
    EDGE_WEAK_MISSING,
    LIB_ASSEMBLY,
    LIB_PINVOKE,
    LIB_WEAK,
    FileEdge,
    FileFacts,
)

# Not in the folder, and the loader would look in system locations next
# (ld.so cache, the Windows search order, the GAC): could be an OS library or
# a missing one; ToCode cannot tell without the target system.
EDGE_EXTERNAL = "external"
# A file with that name exists in the folder, but no loader rule reaches it
# from this importer (typically loaded through LD_LIBRARY_PATH set by a launch
# script, or SetDllDirectory). Recorded with ``target`` and flagged.
EDGE_NAME_UNREACHABLE = "name_match_unreachable"

# HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs (Windows 10/11),
# plus ntdll/kernelbase which every process maps first.
KNOWN_DLLS = frozenset(
    name.lower()
    for name in (
        "advapi32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll", "coml2.dll",
        "difxapi.dll", "gdi32.dll", "gdiplus.dll", "imagehlp.dll", "imm32.dll",
        "kernel32.dll", "msctf.dll", "msvcrt.dll", "normaliz.dll", "nsi.dll",
        "ole32.dll", "oleaut32.dll", "psapi.dll", "rpcrt4.dll", "sechost.dll",
        "setupapi.dll", "shcore.dll", "shell32.dll", "shlwapi.dll", "user32.dll",
        "wldap32.dll", "wow64.dll", "wow64cpu.dll", "wow64win.dll", "ws2_32.dll",
        "ntdll.dll", "kernelbase.dll",
    )
)  # fmt: skip
MACHO_SYSTEM_PREFIXES = ("/System/", "/usr/lib/", "/Library/Apple/")


@dataclass
class Folder:
    """The binaries of one input folder, as the resolver sees them."""

    root: Path
    # relpath -> arch -> facts (one entry per fat slice; "msil" for IL images)
    images: dict[str, dict[str, FileFacts]]
    # Arch each image is linked/decompiled as (the chosen fat slice).
    selected: dict[str, str]
    aliases: dict[str, str] = field(default_factory=dict)  # symlink -> canonical
    _exact: dict[str, str] = field(default_factory=dict, init=False)
    _folded: dict[str, str] = field(default_factory=dict, init=False)
    _by_name: dict[str, list[str]] = field(default_factory=dict, init=False)
    _by_soname: dict[str, list[str]] = field(default_factory=dict, init=False)
    _by_assembly: dict[str, list[str]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for relpath in self.images:
            self._index(relpath, relpath)
        for alias, target in self.aliases.items():
            if target in self.images:
                self._index(alias, target)
        for relpath in self.images:
            facts = self.facts(relpath)
            if facts is None or not facts.identity:
                continue
            if facts.format == "elf":
                self._by_soname.setdefault(facts.identity, []).append(relpath)
            elif facts.format == "dotnet":
                self._by_assembly.setdefault(facts.identity.lower(), []).append(relpath)

    def _index(self, path: str, target: str) -> None:
        self._exact.setdefault(path, target)
        self._folded.setdefault(path.lower(), target)
        self._by_name.setdefault(posixpath.basename(path).lower(), []).append(target)

    def facts(self, relpath: str, arch: str | None = None) -> FileFacts | None:
        slices = self.images.get(relpath)
        if not slices:
            return None
        wanted = arch or self.selected.get(relpath)
        if wanted in slices:
            return slices[wanted]
        if "msil" in slices:
            return slices["msil"]
        return None if arch else next(iter(slices.values()))

    def lookup(self, candidate: str, *, fold_case: bool) -> str | None:
        """Folder file at ``candidate`` (relative POSIX path), via symlinks too."""
        path = posixpath.normpath(candidate)
        if path.startswith("../") or path == ".." or path.startswith("/"):
            return None
        found = self._exact.get(path)
        if found is None and fold_case:
            found = self._folded.get(path.lower())
        if found is not None:
            return found
        # Directory symlinks (Foo.framework/Versions/Current -> A) are not
        # walked; let the filesystem resolve them, but stay inside the folder.
        try:
            real = os.path.realpath(self.root / path)
            root = os.path.realpath(self.root)
        except OSError:
            return None
        if not real.startswith(root + os.sep):
            return None
        relative = Path(real).relative_to(root).as_posix()
        return self._exact.get(relative) or (
            self._folded.get(relative.lower()) if fold_case else None
        )

    def by_name(self, name: str) -> list[str]:
        return self._by_name.get(name.lower(), [])

    def by_soname(self, soname: str) -> list[str]:
        return self._by_soname.get(soname, [])

    def by_assembly(self, name: str) -> list[str]:
        return self._by_assembly.get(name.lower(), [])


@dataclass(slots=True)
class _Node:
    relpath: str
    parent: "_Node | None"

    def lineage(self) -> list[str]:
        items: list[str] = []
        node: _Node | None = self
        while node is not None:
            items.append(node.relpath)
            node = node.parent
        return items  # self first, chain root last


@dataclass
class Resolution:
    edges: list[FileEdge] = field(default_factory=list)
    # chain root -> images in load order (the root first)
    chains: dict[str, list[str]] = field(default_factory=dict)
    # image -> first chain root that loaded it
    loaded_by: dict[str, str] = field(default_factory=dict)
    cycles: list[list[str]] = field(default_factory=list)

    def edges_from(self, relpath: str) -> list[FileEdge]:
        return [edge for edge in self.edges if edge.source == relpath]


def resolve_folder(folder: Folder, roots: list[str]) -> Resolution:
    result = Resolution()
    edge_index: dict[tuple[str, int, str | None], int] = {}
    best: dict[tuple[str, int], int] = {}
    pending = [item for item in roots if item in folder.images]
    seen_roots: set[str] = set()
    main_exe = pending[0] if pending else None

    def add_edge(edge: FileEdge) -> None:
        if edge.kind == LIB_PINVOKE:
            key3 = (edge.source, edge.library, edge.target)
            if key3 not in edge_index:
                edge_index[key3] = len(result.edges)
                result.edges.append(edge)
            return
        key = (edge.source, edge.library)
        index = best.get(key)
        if index is None:
            best[key] = len(result.edges)
            result.edges.append(edge)
        elif (
            result.edges[index].status != EDGE_IN_FOLDER
            and edge.status == EDGE_IN_FOLDER
        ):
            result.edges[index] = edge

    def run_chain(root: str, standalone: bool) -> None:
        order: list[str] = []
        loaded: dict[str, _Node] = {}
        root_facts = folder.facts(root)
        if root_facts is None:
            return
        context = _Context(folder, root, main_exe if standalone else root, standalone)
        queue: deque[_Node] = deque([_Node(root, None)])
        loaded[root] = queue[0]
        while queue:
            node = queue.popleft()
            order.append(node.relpath)
            result.loaded_by.setdefault(node.relpath, root)
            facts = folder.facts(node.relpath)
            if facts is None:
                continue
            for index, lib in enumerate(facts.libraries):
                for edge in context.resolve(
                    node, facts, index, lib.name, lib.kind, loaded
                ):
                    edge.chain_root = root
                    add_edge(edge)
                    target = edge.target
                    # A name-only match is followed too (flagged on the edge):
                    # it is what loads once LD_LIBRARY_PATH/SetDllDirectory or a
                    # launcher makes the directory searchable.
                    if (
                        edge.status not in (EDGE_IN_FOLDER, EDGE_NAME_UNREACHABLE)
                        or target is None
                    ):
                        continue
                    if target in loaded:
                        continue
                    child = _Node(target, node)
                    loaded[target] = child
                    queue.append(child)
        result.chains[root] = order

    for root in pending:
        if root not in seen_roots:
            seen_roots.add(root)
            run_chain(root, standalone=False)
    # Libraries no executable here loads: resolve their own references.
    for relpath in sorted(folder.images):
        if relpath not in result.loaded_by and relpath not in seen_roots:
            seen_roots.add(relpath)
            run_chain(relpath, standalone=True)
    result.cycles = dependency_cycles(result.edges)
    return result


def dependency_cycles(edges: list[FileEdge]) -> list[list[str]]:
    """Strongly connected groups of files that load each other (Tarjan)."""
    graph: dict[str, set[str]] = {}
    for edge in edges:
        if edge.status == EDGE_IN_FOLDER and edge.target and edge.target != edge.source:
            graph.setdefault(edge.source, set()).add(edge.target)
            graph.setdefault(edge.target, set())
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    groups: list[list[str]] = []
    counter = 0
    for start in sorted(graph):
        if start in index:
            continue
        work: list[tuple[str, list[str]]] = [(start, sorted(graph[start]))]
        index[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        while work:
            node, children = work[-1]
            if children:
                child = children.pop()
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, sorted(graph[child])))
                elif child in on_stack:
                    low[node] = min(low[node], index[child])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                group: list[str] = []
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    group.append(item)
                    if item == node:
                        break
                if len(group) > 1:
                    groups.append(sorted(group))
    return sorted(groups)


class _Context:
    def __init__(
        self, folder: Folder, root: str, executable: str | None, standalone: bool
    ) -> None:
        self.folder = folder
        self.root = root
        self.executable = executable or root
        self.standalone = standalone

    def resolve(self, node, facts, index, name, kind, loaded) -> list[FileEdge]:
        if facts.format == "macho":
            edges = [self._macho(node, facts, index, name, kind)]
        elif facts.format == "elf":
            edges = [self._elf(node, facts, index, name, kind, loaded)]
        elif facts.format == "pe" or (
            facts.format == "dotnet" and kind not in (LIB_ASSEMBLY, LIB_PINVOKE)
        ):
            edges = [self._pe(node, facts, index, name, kind, loaded)]
        elif kind == LIB_PINVOKE:
            edges = self._pinvoke(node, facts, index, name, kind)
        else:
            edges = [self._assembly(node, facts, index, name, kind)]
        return edges

    # -- shared -----------------------------------------------------------
    def _edge(self, node, index, name, kind, status, target=None, via=None) -> FileEdge:
        return FileEdge(
            source=node.relpath,
            library=index,
            name=name,
            kind=kind,
            status=status,
            target=target,
            via=via or [],
        )

    def _arch_checked(self, node, facts, index, name, kind, target, via) -> FileEdge:
        if self.folder.facts(target, facts.arch) is None and facts.arch != "msil":
            have = sorted(self.folder.images.get(target, {}))
            return self._edge(
                node, index, name, kind, EDGE_ARCH_MISMATCH, target,
                via + [f"{target} has {', '.join(have) or 'no'} code, importer is {facts.arch}"],
            )  # fmt: skip
        return self._edge(node, index, name, kind, EDGE_IN_FOLDER, target, via)

    # -- Mach-O (dyld) ----------------------------------------------------
    def _macho(self, node, facts, index, name, kind) -> FileEdge:
        here = posixpath.dirname(node.relpath)
        exe_dir = posixpath.dirname(self.executable)
        via: list[str] = []
        candidates: list[tuple[str, str]] = []
        if name.startswith("@executable_path/"):
            note = "@executable_path"
            if self.standalone:
                note += f" assumed {exe_dir or '.'} (not loaded by an executable here)"
            candidates.append((posixpath.join(exe_dir, name[17:]), note))
        elif name.startswith("@loader_path/"):
            candidates.append(
                (posixpath.join(here, name[13:]), f"@loader_path={here or '.'}")
            )
        elif name.startswith("@rpath/"):
            tail = name[7:]
            for owner in node.lineage():
                owner_facts = self.folder.facts(owner)
                if owner_facts is None:
                    continue
                owner_dir = posixpath.dirname(owner)
                for rpath in owner_facts.rpaths:
                    expanded = _expand_macho_path(rpath, owner_dir, exe_dir)
                    if expanded is None:
                        via.append(f"LC_RPATH {rpath} of {owner}: outside the folder")
                        continue
                    candidates.append(
                        (posixpath.join(expanded, tail), f"LC_RPATH {rpath} of {owner}")
                    )
        elif name.startswith("/"):
            status = (
                EDGE_SYSTEM if name.startswith(MACHO_SYSTEM_PREFIXES) else EDGE_EXTERNAL
            )
            if kind == LIB_WEAK and status == EDGE_EXTERNAL:
                status = EDGE_WEAK_MISSING
            return self._edge(
                node, index, name, kind, status, via=["absolute install name"]
            )
        else:
            candidates.append((posixpath.join(here, name), "relative name"))
        for candidate, note in candidates:
            target = self.folder.lookup(candidate, fold_case=True)
            if target is not None:
                return self._arch_checked(
                    node, facts, index, name, kind, target, via + [note]
                )
            via.append(f"{note}: no {candidate}")
        status = EDGE_WEAK_MISSING if kind == LIB_WEAK else EDGE_MISSING
        return self._unreachable(
            node, index, name, kind, status, via, posixpath.basename(name)
        )

    def _unreachable(self, node, index, name, kind, status, via, leaf) -> FileEdge:
        others = [item for item in self.folder.by_name(leaf) if item != node.relpath]
        if others:
            return self._edge(
                node, index, name, kind, EDGE_NAME_UNREACHABLE, others[0],
                via + [f"{others[0]} has this name but no loader rule reaches it"],
            )  # fmt: skip
        return self._edge(node, index, name, kind, status, via=via)

    # -- ELF (glibc ld.so) ------------------------------------------------
    def _elf(self, node, facts, index, name, kind, loaded) -> FileEdge:
        here = posixpath.dirname(node.relpath)
        if "/" in name:
            if name.startswith("/"):
                return self._edge(
                    node, index, name, kind, EDGE_EXTERNAL, via=["absolute path"]
                )
            target = self.folder.lookup(posixpath.join(here, name), fold_case=False)
            if target is not None:
                return self._arch_checked(
                    node, facts, index, name, kind, target, ["relative path (cwd)"]
                )
            return self._edge(
                node, index, name, kind, EDGE_MISSING, via=["relative path (cwd)"]
            )
        for relpath in loaded:
            other = self.folder.facts(relpath)
            if other is not None and other.format == "elf" and other.identity == name:
                return self._arch_checked(
                    node,
                    facts,
                    index,
                    name,
                    kind,
                    relpath,
                    [f"SONAME already loaded ({relpath})"],
                )
        via: list[str] = []
        search: list[tuple[str, str, str]] = []  # (path entry, owner relpath, label)
        if not facts.runpaths:
            for owner in node.lineage():
                owner_facts = self.folder.facts(owner)
                if owner_facts is None or (
                    owner != node.relpath and owner_facts.runpaths
                ):
                    continue
                for entry in owner_facts.rpaths:
                    search.append((entry, owner, f"DT_RPATH {entry} of {owner}"))
        for entry in facts.runpaths:
            search.append((entry, node.relpath, f"DT_RUNPATH {entry}"))
        for entry, owner, label in search:
            expanded = _expand_origin(entry, posixpath.dirname(owner))
            if expanded is None:
                via.append(f"{label}: outside the folder")
                continue
            target = self.folder.lookup(posixpath.join(expanded, name), fold_case=False)
            if target is not None:
                return self._arch_checked(
                    node, facts, index, name, kind, target, via + [label]
                )
            via.append(f"{label}: not found")
        via.append("then the system library path")
        matches = [item for item in self.folder.by_soname(name) if item != node.relpath]
        if matches:
            return self._edge(
                node, index, name, kind, EDGE_NAME_UNREACHABLE, matches[0],
                via + [f"{matches[0]} has SONAME {name} but no search path reaches it"],
            )  # fmt: skip
        return self._unreachable(node, index, name, kind, EDGE_EXTERNAL, via, name)

    # -- PE (Windows loader) ----------------------------------------------
    def _pe(self, node, facts, index, name, kind, loaded) -> FileEdge:
        lower = name.lower()
        if lower.startswith(("api-ms-win-", "ext-ms-win-")):
            return self._edge(
                node, index, name, kind, EDGE_APISET, via=["API set contract"]
            )
        if lower in KNOWN_DLLS:
            return self._edge(node, index, name, kind, EDGE_SYSTEM, via=["KnownDLLs"])
        for relpath in loaded:
            if posixpath.basename(relpath).lower() == lower:
                return self._arch_checked(
                    node,
                    facts,
                    index,
                    name,
                    kind,
                    relpath,
                    [f"module already loaded ({relpath})"],
                )
        app_dir = posixpath.dirname(self.executable)
        label = "application directory"
        if self.standalone:
            app_dir = posixpath.dirname(node.relpath)
            label = "DLL directory (not loaded by an executable here)"
        target = self.folder.lookup(posixpath.join(app_dir, name), fold_case=True)
        if target is not None:
            return self._arch_checked(
                node, facts, index, name, kind, target, [f"{label} {app_dir or '.'}"]
            )
        via = [
            f"{label} {app_dir or '.'}: not found",
            "then the system directories and PATH",
        ]
        return self._unreachable(node, index, name, kind, EDGE_EXTERNAL, via, name)

    # -- .NET ---------------------------------------------------------------
    def _assembly(self, node, facts, index, name, kind) -> FileEdge:
        here = posixpath.dirname(node.relpath)
        app_dir = here if self.standalone else posixpath.dirname(self.executable)
        for directory, label in (
            (app_dir, "application base"),
            (here, "assembly directory"),
        ):
            for suffix in (".dll", ".exe"):
                target = self.folder.lookup(
                    posixpath.join(directory, name + suffix), fold_case=True
                )
                if target is not None:
                    return self._edge(
                        node, index, name, kind, EDGE_IN_FOLDER, target, [label]
                    )
        from ..backends.dotnet import is_framework_assembly

        if is_framework_assembly(f"{name}.dll"):
            return self._edge(
                node, index, name, kind, EDGE_FRAMEWORK, via=["shared framework"]
            )
        matches = [
            item for item in self.folder.by_assembly(name) if item != node.relpath
        ]
        if matches:
            return self._edge(
                node, index, name, kind, EDGE_NAME_UNREACHABLE, matches[0],
                [f"{matches[0]} is assembly {name} but outside the probing paths"],
            )  # fmt: skip
        return self._edge(
            node, index, name, kind, EDGE_MISSING, via=["not in the application base"]
        )

    def _pinvoke(self, node, facts, index, name, kind) -> list[FileEdge]:
        here = posixpath.dirname(node.relpath)
        stem = name
        for suffix in (".dll", ".so", ".dylib"):
            if stem.lower().endswith(suffix):
                stem = stem[: -len(suffix)]
        names = [
            name,
            f"{stem}.dll",
            f"{stem}.so",
            f"lib{stem}.so",
            f"{stem}.dylib",
            f"lib{stem}.dylib",
        ]
        dirs = [here]
        # deps.json native assets of portable apps: runtimes/<rid>/native/
        runtimes = posixpath.join(here, "runtimes")
        for relpath in self.folder.images:
            if relpath.startswith(runtimes + "/") and "/native/" in relpath:
                directory = posixpath.dirname(relpath)
                if directory not in dirs:
                    dirs.append(directory)
        edges: list[FileEdge] = []
        for directory in dirs:
            for candidate in dict.fromkeys(names):
                target = self.folder.lookup(
                    posixpath.join(directory, candidate), fold_case=True
                )
                if target is None or any(edge.target == target for edge in edges):
                    continue
                label = (
                    "NATIVE_DLL_SEARCH_DIRECTORIES"
                    if directory == here
                    else "runtimes/<rid>/native"
                )
                edges.append(
                    self._edge(node, index, name, kind, EDGE_IN_FOLDER, target, [label])
                )
        if edges:
            return edges
        from ..backends.dotnet import is_framework_native

        status = EDGE_FRAMEWORK if is_framework_native(name) else EDGE_EXTERNAL
        return [
            self._edge(
                node, index, name, kind, status, via=["not next to the assembly"]
            )
        ]


def _expand_macho_path(path: str, owner_dir: str, exe_dir: str) -> str | None:
    for token, base in (("@loader_path", owner_dir), ("@executable_path", exe_dir)):
        if path == token or path.startswith(token + "/"):
            return posixpath.normpath(
                posixpath.join(base or ".", path[len(token) :].lstrip("/"))
            )
    return None  # absolute rpaths point outside the folder


def _expand_origin(entry: str, owner_dir: str) -> str | None:
    for token in ("${ORIGIN}", "$ORIGIN"):
        if entry.startswith(token):
            rest = entry[len(token) :].lstrip("/")
            return posixpath.join(owner_dir, rest) if rest else (owner_dir or ".")
    return None
