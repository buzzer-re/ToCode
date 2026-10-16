"""What an export keeps so ``sync`` can update it incrementally.

``.tocode/sync/manifest.json`` records how functions were placed into files
(clusters with their members, labels, folders) and the export's options;
``.tocode/sync/renders/<address>.json`` keeps each function's rendered C,
assembly, and summary, so a cluster file can be rebuilt without decompiling
its untouched members again.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .metadata import write_json, write_text_atomic
from .schema import Cluster, RenderedFunction

SYNC_SCHEMA = 1


def sync_dir(root: Path) -> Path:
    return root / ".tocode" / "sync"


def renders_dir(root: Path) -> Path:
    return sync_dir(root) / "renders"


def manifest_path(root: Path) -> Path:
    return sync_dir(root) / "manifest.json"


def write_manifest(
    root: Path,
    *,
    clusters: Iterable[Cluster],
    backend: str,
    decompiler: str,
    tree: bool,
    entropy: bool,
    origin: str | None,
) -> None:
    write_json(
        manifest_path(root),
        {
            "schema": SYNC_SCHEMA,
            "backend": backend,
            "decompiler": decompiler,
            "tree": tree,
            "entropy": entropy,
            "origin": origin,
            "clusters": [cluster_to_json(cluster) for cluster in clusters],
        },
    )


def read_manifest(root: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(manifest_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != SYNC_SCHEMA:
        return None
    return payload


def cluster_to_json(cluster: Cluster) -> dict[str, Any]:
    return {
        "root": f"0x{cluster.root:x}" if cluster.root >= 0 else cluster.root,
        "label": cluster.label,
        "summary": cluster.summary,
        "folder": cluster.folder,
        "file_base": cluster.file_base,
        "members": [f"0x{address:x}" for address in cluster.members],
    }


def cluster_from_json(payload: dict[str, Any]) -> Cluster:
    root = payload.get("root")
    return Cluster(
        root=int(root, 16) if isinstance(root, str) else int(root or 0),
        label=str(payload.get("label") or ""),
        summary=str(payload.get("summary") or ""),
        members=[int(str(item), 16) for item in payload.get("members", [])],
        folder=str(payload.get("folder") or "app"),
        file_base=payload.get("file_base"),
    )


def render_path(root: Path, address: int) -> Path:
    return renders_dir(root) / f"{address:016x}.json"


def load_render(root: Path, address: int) -> RenderedFunction | None:
    from .exporter import _rendered_from_json

    try:
        payload = json.loads(render_path(root, address).read_text(encoding="utf-8"))
        return _rendered_from_json(payload["rendered"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_render(root: Path, rendered: RenderedFunction) -> None:
    from .exporter import _rendered_to_json

    write_text_atomic(
        render_path(root, rendered.address),
        json.dumps({"rendered": _rendered_to_json(rendered)}, indent=1) + "\n",
    )


def drop_render(root: Path, address: int) -> None:
    render_path(root, address).unlink(missing_ok=True)
