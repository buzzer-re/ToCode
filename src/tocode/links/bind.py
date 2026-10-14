"""Symbol binding: which export of which file each import binds to."""

from __future__ import annotations

from dataclasses import dataclass, field
import posixpath
from typing import Any

from .model import (
    EDGE_APISET,
    EDGE_IN_FOLDER,
    EDGE_SYSTEM,
    LIB_REEXPORT,
    SPECIAL_FLAT,
    SPECIAL_MAIN,
    SPECIAL_SELF,
    SPECIAL_WEAK,
    ExportSym,
    FileEdge,
    FileFacts,
    ImportSym,
)
from .resolve import (
    EDGE_EXTERNAL,
    EDGE_NAME_UNREACHABLE,
    KNOWN_DLLS,
    Folder,
    Resolution,
)

# SymbolLink.status values beyond the FileEdge statuses
LINK_BOUND = "bound"  # bound to an export of a file in the folder
LINK_UNRESOLVED = "unresolved_symbol"  # the library is here, the symbol is not
LINK_NO_LIBRARY = "no_definer_in_folder"  # flat/weak/global lookup found none here
MAX_FOLLOW = 16


@dataclass(slots=True)
class SymbolLink:
    importer: str
    symbol: str
    status: str
    library: str | None = None  # the library reference as written
    kind: str | None = None
    resolution: str | None = None  # how it bound (two_level, versioned, ...)
    target: str | None = None  # file relpath of the defining binary
    export: str | None = None  # export name in the target
    address: int | None = None  # link-time VA in the target
    token: int | None = None  # .NET MethodDef token in the target
    version: str | None = None
    ordinal: int | None = None
    via: list[str] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)
    callers: list[int] | None = None  # .NET MethodDef tokens in the importer
    owner: str | None = None  # .NET declaring type / managed P/Invoke method
    slot: int | None = None  # importer's pointer slot (PE IAT, Mach-O bind)

    def to_json(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "importer": self.importer,
            "symbol": self.symbol,
            "status": self.status,
            "library": self.library,
        }
        for key in (
            "kind",
            "resolution",
            "target",
            "export",
            "version",
            "ordinal",
            "owner",
        ):
            value = getattr(self, key)
            if value is not None:
                row[key] = value
        if self.address is not None:
            row["target_va"] = f"0x{self.address:x}"
        if self.token is not None:
            row["target_token"] = f"0x{self.token:08x}"
        if self.via:
            row["via"] = self.via
        if self.candidates:
            row["candidates"] = self.candidates
        return row


class _Exports:
    def __init__(self, facts: FileFacts) -> None:
        self.facts = facts
        self.by_name: dict[str, list[ExportSym]] = {}
        self.by_ordinal: dict[int, ExportSym] = {}
        self.by_signature: dict[tuple[str, str | None], ExportSym] = {}
        for item in facts.exports:
            self.by_name.setdefault(item.name, []).append(item)
            if item.ordinal is not None:
                self.by_ordinal.setdefault(item.ordinal, item)
            if item.signature is not None:
                self.by_signature.setdefault((item.name, item.signature), item)

    def named(self, name: str, version: str | None = None) -> ExportSym | None:
        rows = self.by_name.get(name)
        if not rows:
            return None
        if version is not None:
            for item in rows:
                if item.version == version:
                    return item
            unversioned = [item for item in rows if item.version is None]
            return unversioned[0] if unversioned else None
        defaults = [item for item in rows if item.default_version]
        return (defaults or rows)[0]


class Binder:
    def __init__(self, folder: Folder, resolution: Resolution) -> None:
        self.folder = folder
        self.resolution = resolution
        self._exports: dict[tuple[str, str], _Exports] = {}
        self.edges: dict[tuple[str, int], list[FileEdge]] = {}
        for edge in resolution.edges:
            self.edges.setdefault((edge.source, edge.library), []).append(edge)

    def exports(self, relpath: str, arch: str | None = None) -> _Exports | None:
        facts = self.folder.facts(relpath, arch)
        if facts is None:
            return None
        key = (relpath, facts.arch)
        cached = self._exports.get(key)
        if cached is None:
            cached = self._exports[key] = _Exports(facts)
        return cached

    def chain_order(self, relpath: str) -> list[str]:
        root = self.resolution.loaded_by.get(relpath, relpath)
        return self.resolution.chains.get(root, [relpath])

    def bind_all(self) -> list[SymbolLink]:
        links: list[SymbolLink] = []
        for relpath in sorted(self.folder.images):
            facts = self.folder.facts(relpath)
            if facts is not None:
                links.extend(self.bind_file(relpath, facts))
        return links

    def bind_file(self, relpath: str, facts: FileFacts) -> list[SymbolLink]:
        rows: list[SymbolLink] = []
        for item in facts.imports:
            library = (
                facts.libraries[item.library].name
                if item.library is not None and item.library < len(facts.libraries)
                else None
            )
            if item.kind == "pinvoke":
                rows.extend(self._pinvoke(relpath, facts, item, library))
                continue
            link = SymbolLink(
                importer=relpath,
                symbol=item.name,
                status=LINK_NO_LIBRARY,
                library=library,
                kind=item.kind,
                version=item.version,
                ordinal=item.ordinal,
                callers=item.callers,
                owner=item.owner,
                slot=item.slot,
            )
            if facts.format == "macho":
                self._macho(link, relpath, facts, item)
            elif facts.format == "elf":
                self._elf(link, relpath, facts, item)
            elif facts.format == "dotnet" and item.signature is not None:
                self._member(link, relpath, facts, item)
            else:
                self._pe(link, relpath, facts, item)
            rows.append(link)
        return rows

    # -- helpers ------------------------------------------------------------
    def _edge(self, relpath: str, library: int | None) -> FileEdge | None:
        if library is None:
            return None
        edges = self.edges.get((relpath, library))
        return edges[0] if edges else None

    def _apply_edge(self, link: SymbolLink, edge: FileEdge | None) -> str | None:
        """Copy a non-folder edge status onto the link; return the target relpath."""
        if edge is None:
            link.status = EDGE_EXTERNAL
            return None
        if edge.status == EDGE_NAME_UNREACHABLE and edge.target is not None:
            link.via.append(
                f"{edge.target} is reached by name only (not by a loader search path)"
            )
            return edge.target
        if edge.status != EDGE_IN_FOLDER or edge.target is None:
            link.status = edge.status
            if edge.target is not None:
                link.via.append(f"{edge.status}: {edge.target}")
            return None
        return edge.target

    def _bound(
        self, link: SymbolLink, target: str, export: ExportSym, resolution: str
    ) -> None:
        link.status = LINK_BOUND
        link.resolution = link.resolution or resolution
        link.target = target
        link.export = export.name
        link.address = export.address
        link.token = export.token

    # -- Mach-O -------------------------------------------------------------
    def _macho(
        self, link: SymbolLink, relpath: str, facts: FileFacts, item: ImportSym
    ) -> None:
        if item.special in (SPECIAL_FLAT, SPECIAL_WEAK) or (
            item.library is None and item.special is None
        ):
            self._scope_lookup(
                link, relpath, facts, item.name, item.special or SPECIAL_FLAT
            )
            return
        if item.special == SPECIAL_SELF:
            self._macho_find(link, relpath, facts.arch, item.name, "self", 0)
            return
        if item.special == SPECIAL_MAIN:
            root = self.resolution.loaded_by.get(relpath, relpath)
            self._macho_find(link, root, facts.arch, item.name, "main_executable", 0)
            return
        target = self._apply_edge(link, self._edge(relpath, item.library))
        if target is None:
            return
        if not self._macho_find(link, target, facts.arch, item.name, "two_level", 0):
            link.status = LINK_UNRESOLVED
            link.target = target

    def _macho_find(self, link, target, arch, name, resolution, depth) -> bool:
        if depth > MAX_FOLLOW:
            return False
        table = self.exports(target, arch)
        if table is None:
            return False
        export = table.named(name)
        if export is not None:
            if export.reexport_library is not None:
                edge = self._edge(target, export.reexport_library)
                if edge is None or edge.status != EDGE_IN_FOLDER or edge.target is None:
                    link.status = edge.status if edge else EDGE_EXTERNAL
                    link.via.append(
                        f"re-exported by {target} from {edge.name if edge else '?'}"
                    )
                    link.target = None
                    return True
                link.via.append(f"re-exported by {target}")
                return self._macho_find(
                    link,
                    edge.target,
                    arch,
                    export.reexport_name or name,
                    "reexport",
                    depth + 1,
                )
            self._bound(link, target, export, resolution)
            return True
        # Symbols of LC_REEXPORT_DYLIB libraries are visible through this one.
        facts = table.facts
        for index, lib in enumerate(facts.libraries):
            if lib.kind != LIB_REEXPORT:
                continue
            edge = self._edge(target, index)
            if edge is None or edge.status != EDGE_IN_FOLDER or edge.target is None:
                continue
            mark = len(link.via)
            link.via.append(f"re-exported library of {target}")
            if self._macho_find(link, edge.target, arch, name, "reexport", depth + 1):
                return True
            del link.via[mark:]
        return False

    def _scope_lookup(self, link, relpath, facts, name, mode) -> None:
        """dyld flat/weak lookup and ELF global scope: first definer in load order."""
        definers: list[tuple[str, ExportSym]] = []
        for image in self.chain_order(relpath):
            if image == relpath and mode not in (SPECIAL_WEAK,):
                continue
            table = self.exports(image, facts.arch)
            if table is None:
                continue
            export = table.named(name)
            if export is not None and export.reexport_library is None:
                definers.append((image, export))
        link.resolution = mode
        if not definers:
            link.status = LINK_NO_LIBRARY
            return
        if mode == SPECIAL_WEAK:
            strong = [entry for entry in definers if not entry[1].weak]
            chosen = (strong or definers)[0]
        else:
            chosen = definers[0]
        self._bound(link, chosen[0], chosen[1], mode)
        link.candidates = [image for image, _export in definers if image != chosen[0]]

    # -- ELF ----------------------------------------------------------------
    def _elf(
        self, link: SymbolLink, relpath: str, facts: FileFacts, item: ImportSym
    ) -> None:
        if item.library is not None:
            # Versioned reference: only the file named by the version need binds it.
            target = self._apply_edge(link, self._edge(relpath, item.library))
            if target is None:
                return
            table = self.exports(target, facts.arch)
            export = table.named(item.name, item.version) if table else None
            if export is None:
                link.status = LINK_UNRESOLVED
                link.target = target
                return
            self._bound(link, target, export, "versioned")
            return
        self._scope_lookup(link, relpath, facts, item.name, "global_scope")
        if link.status == LINK_BOUND:
            outside = [
                edge.name
                for edge in self.resolution.edges
                if edge.source in self.chain_order(relpath)
                and edge.status not in (EDGE_IN_FOLDER, EDGE_NAME_UNREACHABLE)
            ]
            if outside:
                link.via.append(
                    f"{len(set(outside))} libraries outside the folder are also in the "
                    "lookup scope and were not inspected"
                )

    # -- PE -----------------------------------------------------------------
    def _pe(
        self, link: SymbolLink, relpath: str, facts: FileFacts, item: ImportSym
    ) -> None:
        target = self._apply_edge(link, self._edge(relpath, item.library))
        if target is None:
            return
        self._pe_find(
            link,
            relpath,
            target,
            facts.arch,
            item.name,
            item.ordinal,
            "name" if item.ordinal is None else "ordinal",
            0,
        )

    def _pe_find(
        self, link, importer, target, arch, name, ordinal, resolution, depth
    ) -> None:
        table = self.exports(target, arch)
        export = None
        if table is not None:
            export = (
                table.by_ordinal.get(ordinal)
                if ordinal is not None
                else table.named(name)
            )
        if export is None:
            link.status = LINK_UNRESOLVED
            link.target = target
            return
        if export.forwarder is None:
            self._bound(link, target, export, resolution)
            return
        if depth >= MAX_FOLLOW:
            link.status = LINK_UNRESOLVED
            link.via.append("forwarder chain too long")
            return
        module, _, symbol = export.forwarder.rpartition(".")
        link.via.append(f"forwarded by {target} to {export.forwarder}")
        link.resolution = "forwarder"
        dll = module if module.lower().endswith(".dll") else f"{module}.dll"
        lower = dll.lower()
        if lower.startswith(("api-ms-win-", "ext-ms-win-")):
            link.status, link.target = EDGE_APISET, None
            return
        if lower in KNOWN_DLLS:
            link.status, link.target = EDGE_SYSTEM, None
            return
        next_target = self._pe_module(importer, dll)
        if next_target is None:
            link.status, link.target = EDGE_EXTERNAL, None
            return
        if symbol.startswith("#") and symbol[1:].isdigit():
            self._pe_find(
                link,
                importer,
                next_target,
                arch,
                symbol,
                int(symbol[1:]),
                "forwarder",
                depth + 1,
            )
        else:
            self._pe_find(
                link, importer, next_target, arch, symbol, None, "forwarder", depth + 1
            )

    def _pe_module(self, importer: str, dll: str) -> str | None:
        lower = dll.lower()
        for image in self.chain_order(importer):
            if posixpath.basename(image).lower() == lower:
                return image
        root = self.resolution.loaded_by.get(importer, importer)
        return self.folder.lookup(
            posixpath.join(posixpath.dirname(root), dll), fold_case=True
        )

    # -- .NET -----------------------------------------------------------------
    def _member(
        self, link: SymbolLink, relpath: str, facts: FileFacts, item: ImportSym
    ) -> None:
        target = self._apply_edge(link, self._edge(relpath, item.library))
        if target is None:
            return
        owner = item.owner or ""
        for _ in range(MAX_FOLLOW):
            table = self.exports(target)
            if table is None:
                link.status, link.target = LINK_UNRESOLVED, target
                return
            if item.kind == "data":
                link.status, link.target = LINK_BOUND, target
                link.resolution = "field"
                return
            export = table.by_signature.get((item.name, item.signature))
            if export is not None:
                self._bound(link, target, export, link.resolution or "member_ref")
                return
            forwarded = (table.facts.managed or {}).get("forwarders", {}).get(owner)
            if not forwarded:
                break
            matches = self.folder.by_assembly(forwarded)
            link.via.append(f"type forwarded by {target} to {forwarded}")
            link.resolution = "type_forwarder"
            if not matches:
                link.status, link.target = EDGE_EXTERNAL, None
                return
            target = matches[0]
        link.status, link.target = LINK_UNRESOLVED, target

    def _pinvoke(self, relpath, facts, item, library) -> list[SymbolLink]:
        edges: list[FileEdge | None] = list(
            self.edges.get((relpath, item.library), [])
            if item.library is not None
            else []
        )
        rows: list[SymbolLink] = []
        for edge in edges or [None]:
            link = SymbolLink(
                importer=relpath,
                symbol=item.name,
                status=LINK_NO_LIBRARY,
                library=library,
                kind="pinvoke",
                callers=item.callers,
                owner=item.owner,
            )
            target = self._apply_edge(link, edge)
            if target is not None:
                table = self.exports(target)
                export = None
                if table is not None:
                    for name in _pinvoke_names(
                        item.name, item.signature, table.facts.format
                    ):
                        if name.startswith("#") and name[1:].isdigit():
                            export = table.by_ordinal.get(int(name[1:]))
                        else:
                            export = table.named(name)
                        if export is not None:
                            break
                if export is None:
                    link.status, link.target = LINK_UNRESOLVED, target
                else:
                    self._bound(link, target, export, "pinvoke")
            rows.append(link)
        return rows


def _pinvoke_names(name: str, charset: str | None, target_format: str) -> list[str]:
    """Entry point names the runtime tries, in order (ExactSpelling/CharSet)."""
    if target_format == "macho":
        return [f"_{name}"]
    if target_format != "pe" or charset == "exact":
        return [name]
    if charset in ("unicode", "auto"):
        return [f"{name}W", name]
    return [name, f"{name}A"]
