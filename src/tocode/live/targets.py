"""What ``open(path, database?, backend?)`` refers to.

A path is one of:

- an export folder (``project.json``): the export's own database
  (``<binary>.i64``/``.idb``/``.bndb`` next to it) unless ``database`` names
  another; without a database, the original binary with the export's backend;
- a folder master (``.tocode-folder/``): every exported binary in it, each
  opened on demand as its own session;
- a binary or a database: opened directly; its default export folder
  (``<stem>_decompiler``) is attached when it exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from ..backends.base import IDA_DATABASE_SUFFIXES, is_binja_database, is_ida_database
from ..errors import ToCodeError
from ..naming import default_output_name

DATABASE_SUFFIXES = (*sorted(IDA_DATABASE_SUFFIXES), ".bndb")
FOLDER_STATE = Path(".tocode-folder") / "state.json"


@dataclass(slots=True)
class Target:
    """One session's worth: what the worker opens and where its export lives."""

    name: str
    open_path: Path  # what create_analyzer opens (a database or the binary)
    binary: Path  # the original binary (may no longer exist for a database)
    backend: str
    export_dir: Path | None = None
    database: Path | None = None  # the database edits are saved into, if any
    folder: str | None = None  # owning folder session, for folder binaries
    relpath: str | None = None

    def describe(self) -> dict[str, Any]:
        return {
            "session": self.name,
            "binary": str(self.binary),
            "opened": str(self.open_path),
            "database": str(self.database) if self.database else None,
            "backend": self.backend,
            "export_dir": str(self.export_dir) if self.export_dir else None,
            "folder": self.folder,
            "relpath": self.relpath,
        }


@dataclass(slots=True)
class FolderTarget:
    """A folder master: binaries by relative path, each with its export folder."""

    name: str
    master: Path
    input_dir: Path | None
    binaries: dict[str, Path] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        return {
            "session": self.name,
            "folder": str(self.master),
            "input_dir": str(self.input_dir) if self.input_dir else None,
            "binaries": [
                {"relpath": relpath, "status": self.statuses.get(relpath)}
                for relpath in self.binaries
            ],
        }


def is_database(path: Path) -> bool:
    return is_ida_database(path) or is_binja_database(path)


def is_export_dir(path: Path) -> bool:
    return (path / "project.json").is_file() and (path / "functions.json").is_file()


def is_folder_master(path: Path) -> bool:
    return (path / FOLDER_STATE).is_file()


def resolve(
    path: Path,
    *,
    database: Path | None = None,
    backend: str | None = None,
    name: str | None = None,
) -> Target | FolderTarget:
    path = path.expanduser().resolve()
    db = database.expanduser().resolve() if database is not None else None
    if db is not None and not db.is_file():
        raise ToCodeError(f"database not found: {db}")
    if path.is_dir():
        if is_folder_master(path):
            if db is not None:
                raise ToCodeError(
                    "a folder holds many binaries; pass `database` when opening "
                    "one of them (open its export folder, or `session` = its path)"
                )
            return folder_target(path, name=name)
        if is_export_dir(path):
            return export_target(path, database=db, backend=backend, name=name)
        raise ToCodeError(
            f"{path} is neither a ToCode export nor a folder export; export it "
            "first (`tocode <path>`), or open the binary itself"
        )
    if not path.is_file():
        raise ToCodeError(f"not found: {path}")
    return file_target(path, database=db, backend=backend, name=name)


def export_target(
    export_dir: Path,
    *,
    database: Path | None = None,
    backend: str | None = None,
    name: str | None = None,
    folder: str | None = None,
    relpath: str | None = None,
) -> Target:
    project = _read_json(export_dir / "project.json")
    binary = Path(str(project.get("binary") or export_dir.name))
    recorded = project.get("backend") or "auto"
    if recorded == "dotnet":
        # A .NET export: the database is its edit log, replayed onto the input.
        if not binary.is_file():
            raise ToCodeError(
                f"the .NET export at {export_dir} needs its input {binary}, which is gone"
            )
        return Target(
            name=name or relpath or _session_name(binary),
            open_path=binary,
            binary=binary,
            backend="dotnet",
            export_dir=export_dir,
            database=database or dotnet_edit_log(export_dir),
            folder=folder,
            relpath=relpath,
        )
    own = database or own_database(export_dir, binary, project)
    if own is not None:
        open_path = own
        chosen = _backend_for_database(own)
    else:
        if not binary.is_file():
            raise ToCodeError(
                f"the export at {export_dir} has no database and its binary "
                f"{binary} is gone; pass `database`"
            )
        open_path = binary
        chosen = backend or str(recorded)
    return Target(
        name=name or relpath or _session_name(binary),
        open_path=open_path,
        binary=binary,
        backend=chosen,
        export_dir=export_dir,
        database=own,
        folder=folder,
        relpath=relpath,
    )


def file_target(
    path: Path,
    *,
    database: Path | None = None,
    backend: str | None = None,
    name: str | None = None,
) -> Target:
    if (
        not is_database(path)
        and (backend in (None, "auto", "dotnet"))
        and _is_dotnet(path)
    ):
        export_dir = path.parent / default_output_name(path)
        attached = None
        if is_export_dir(export_dir):
            recorded = Path(
                str(_read_json(export_dir / "project.json").get("binary") or "")
            )
            if recorded.resolve() == path.resolve():
                attached = export_dir
        return Target(
            name=name or _session_name(path),
            open_path=path,
            binary=path,
            backend="dotnet",
            export_dir=attached,
            database=database or (dotnet_edit_log(attached) if attached else None),
        )
    if is_database(path):
        database = database or path
    export_dir = path.parent / default_output_name(path)
    if is_export_dir(export_dir):
        project = _read_json(export_dir / "project.json")
        recorded = Path(str(project.get("binary") or ""))
        # Only attach the export made from this very file.
        if recorded.resolve() != path.resolve() and not is_database(path):
            export_dir = None  # type: ignore[assignment]
    else:
        export_dir = None  # type: ignore[assignment]
    open_path = database or path
    return Target(
        name=name or _session_name(path),
        open_path=open_path,
        binary=path,
        backend=_backend_for_database(open_path)
        if is_database(open_path)
        else (backend or "auto"),
        export_dir=export_dir,
        database=database,
    )


def folder_target(master: Path, *, name: str | None = None) -> FolderTarget:
    from ..folder import DONE, export_dir_for

    state = _read_json(master / FOLDER_STATE)
    project = _read_json(master / "project.json")
    input_dir = project.get("input")
    target = FolderTarget(
        name=name or master.name.removesuffix("_decompiled") or master.name,
        master=master,
        input_dir=Path(str(input_dir)) if input_dir else None,
    )
    jobs = state.get("jobs") or {}
    for relpath in sorted(jobs):
        record = jobs[relpath] if isinstance(jobs[relpath], dict) else {}
        status = str(record.get("status") or "")
        export_dir = export_dir_for(master, relpath)
        target.statuses[relpath] = status
        if status == DONE and is_export_dir(export_dir):
            target.binaries[relpath] = export_dir
    return target


def own_database(
    export_dir: Path, binary: Path, project: dict[str, Any]
) -> Path | None:
    """The database an export ships (``<binary>.i64`` / ``.idb`` / ``.bndb``)."""
    recorded = project.get("ida_database")
    candidates: list[Path] = []
    if recorded:
        candidates.append(export_dir / Path(str(recorded)).name)
    stems = {binary.stem, binary.name}
    for stem in stems:
        candidates.extend(
            export_dir / f"{stem}{suffix}" for suffix in DATABASE_SUFFIXES
        )
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate.resolve()
    return None


def dotnet_edit_log(export_dir: Path) -> Path:
    return export_dir / ".tocode" / "dotnet" / "edits.json"


def _is_dotnet(path: Path) -> bool:
    try:
        from ..backends.dotnet import is_dotnet_input

        return bool(is_dotnet_input(path))
    except Exception:  # noqa: BLE001 - not readable as .NET
        return False


def _backend_for_database(path: Path) -> str:
    return "ida" if is_ida_database(path) else "binja"


def _session_name(path: Path) -> str:
    stem = path.name
    for suffix in DATABASE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
    return stem or path.name


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}
