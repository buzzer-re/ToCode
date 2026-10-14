"""Resolve and bind a scanned folder: the full set of link facts."""

from __future__ import annotations

from dataclasses import dataclass
import posixpath

from .bind import Binder, SymbolLink
from .inventory import Inventory
from .model import EDGE_IN_FOLDER, FileEdge
from .resolve import Resolution, resolve_folder

LIB_APPHOST = "apphost"


@dataclass
class FolderLinks:
    resolution: Resolution
    links: list[SymbolLink]


def link_folder(inventory: Inventory) -> FolderLinks:
    resolution = resolve_folder(inventory.folder, inventory.roots)
    for entry in inventory.entries:
        target = entry.apphost_for
        if target is None or target not in inventory.folder.images:
            continue
        # The .NET apphost carries the path of the app assembly it starts.
        resolution.edges.append(
            FileEdge(
                source=entry.relpath,
                library=-1,
                name=posixpath.basename(target),
                kind=LIB_APPHOST,
                status=EDGE_IN_FOLDER,
                target=target,
                via=["apphost launcher"],
                chain_root=entry.relpath,
            )
        )
    links = Binder(inventory.folder, resolution).bind_all()
    return FolderLinks(resolution=resolution, links=links)
