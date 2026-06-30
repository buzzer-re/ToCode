"""ToCode binary exporter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

__all__ = ["__version__", "export_from_binaryview"]

__version__ = "0.1.0"


def export_from_binaryview(
    bv: Any,
    out_dir: str | Path,
    *,
    bn: Any = None,
    tree: bool = False,
    entropy: bool = False,
    jobs: int | None = None,
    quiet: bool = True,
) -> Any:
    """Export a project tree directly from a live Binary Ninja ``BinaryView``.

    Intended for the Binary Ninja UI scripting console, where ``bv`` already
    exists. A complete run is then a few pasted lines::

        import sys; sys.path.insert(0, "/path/to/ToCode/src")
        from tocode import export_from_binaryview
        export_from_binaryview(bv, "/tmp/out")

    ``bn`` is the ``binaryninja`` module; leave it ``None`` to import it locally
    (the in-UI case). Returns the :class:`~tocode.exporter.ExportSummary`.
    """
    # Imported lazily so importing the package never drags in the backend stack.
    from .analysis import create_analyzer
    from .exporter import export_binary
    from .progress import Progress

    progress = Progress(enabled=not quiet)
    view_file = getattr(bv, "file", None)
    filename = getattr(view_file, "filename", None) or getattr(
        view_file, "original_filename", None
    )
    input_path = Path(str(filename)) if filename else Path("binaryview")
    with create_analyzer(
        input_path,
        backend="binja",
        progress=progress,
        binja_bv=bv,
        binja_bn=bn,
    ) as analyzer:
        return export_binary(
            analyzer,
            out_dir=Path(out_dir),
            progress=progress,
            jobs=jobs,
            tree=tree,
            entropy=entropy,
        )
