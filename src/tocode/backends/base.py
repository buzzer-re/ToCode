from __future__ import annotations

from dataclasses import dataclass
import importlib
import importlib.util
import os
from pathlib import Path
import sys
from typing import Any, Literal, Protocol

from ..errors import ToCodeError


BackendRequest = Literal["auto", "ida", "r2"]
BackendName = Literal["ida", "r2"]
IDA_DATABASE_SUFFIXES = frozenset({".i64", ".idb"})


class DecompilerSession(Protocol):
    backend_name: BackendName
    backend_label: str
    decompiler_label: str
    analysis_command: str | None
    parallel_safe: bool

    def analyze(self) -> None: ...

    def close(self) -> None: ...

    def info(self) -> dict[str, Any]: ...

    def entries(self) -> list[dict[str, Any]]: ...

    def sections(self) -> list[dict[str, Any]]: ...

    def imports(self) -> list[dict[str, Any]]: ...

    def exports(self) -> list[dict[str, Any]]: ...

    def symbols(self) -> list[dict[str, Any]]: ...

    def relocations(self) -> list[dict[str, Any]]: ...

    def strings(self) -> list[dict[str, Any]]: ...

    def flags(self) -> list[dict[str, Any]]: ...

    def functions(self) -> list[dict[str, Any]]: ...

    def disasm(self, address: int) -> str: ...

    def decompile(self, address: int) -> str: ...

    def function_summary(self, address: int) -> str: ...

    def ensure_decompiler(self) -> None: ...

    def calls_from(
        self, address: int, imports: dict[int, Any], functions: dict[int, Any]
    ) -> tuple[list[int], list[str]]: ...


@dataclass(slots=True)
class IdaProbe:
    available: bool
    reason: str
    idadir: Path | None = None
    ida_domain_path: Path | None = None


@dataclass(slots=True)
class BackendChoice:
    requested: BackendRequest
    selected: BackendName
    reason: str


def choose_backend(
    requested: BackendRequest,
    *,
    input_path: Path | None = None,
    idadir: Path | None = None,
    ida_domain_path: Path | None = None,
) -> BackendChoice:
    if input_path is not None and is_ida_database(input_path):
        if requested == "r2":
            raise ToCodeError("IDA database input requires the IDA backend")
        requested = "ida"

    if requested == "r2":
        return BackendChoice(requested, "r2", "selected by CLI")

    probe = probe_ida(idadir=idadir, ida_domain_path=ida_domain_path)
    if requested == "ida":
        if not probe.available:
            raise ToCodeError(f"IDA backend requested but unavailable: {probe.reason}")
        return BackendChoice(requested, "ida", probe.reason)

    if probe.available:
        return BackendChoice(requested, "ida", probe.reason)
    return BackendChoice(requested, "r2", f"IDA unavailable ({probe.reason}); using r2")


def is_ida_database(path: Path) -> bool:
    return path.suffix.lower() in IDA_DATABASE_SUFFIXES


@dataclass(slots=True)
class IdaRuntime:
    idapro: Any
    ida_domain: Any
    idadir: Path | None
    ida_domain_path: Path | None


def probe_ida(
    *, idadir: Path | None = None, ida_domain_path: Path | None = None
) -> IdaProbe:
    try:
        runtime = bootstrap_ida(idadir=idadir, ida_domain_path=ida_domain_path)
    except ToCodeError as exc:
        return IdaProbe(False, str(exc))
    if runtime.idadir is not None:
        return IdaProbe(
            True,
            f"ida-domain available via IDADIR={runtime.idadir}",
            runtime.idadir,
            runtime.ida_domain_path,
        )
    return IdaProbe(
        True, "ida-domain importable", runtime.idadir, runtime.ida_domain_path
    )


def bootstrap_ida(
    *, idadir: Path | None = None, ida_domain_path: Path | None = None
) -> IdaRuntime:
    resolved_idadir = discover_idadir(idadir)
    if resolved_idadir is not None:
        os.environ.setdefault("IDADIR", str(resolved_idadir))

    _add_idapro_wheel(resolved_idadir)
    resolved_domain = discover_ida_domain(ida_domain_path)
    _add_python_root(resolved_domain)

    try:
        idapro = importlib.import_module("idapro")
    except ImportError as exc:
        raise ToCodeError(
            "unable to import idapro; pass --idadir or install IDA Python support"
        ) from exc

    try:
        ida_domain = importlib.import_module("ida_domain")
    except ImportError as exc:
        raise ToCodeError(
            "unable to import ida_domain; pass --ida-domain-path or install ida-domain"
        ) from exc

    return IdaRuntime(
        idapro=idapro,
        ida_domain=ida_domain,
        idadir=resolved_idadir,
        ida_domain_path=resolved_domain,
    )


def discover_idadir(explicit: Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser())
    env_value = os.environ.get("IDADIR")
    if env_value:
        candidates.append(Path(env_value).expanduser())

    home = Path.home()
    candidates.extend(sorted(home.glob("ida-pro-*"), reverse=True))
    candidates.extend(sorted(home.glob("IDA*"), reverse=True))

    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        install_root = os.environ.get(env_name)
        if not install_root:
            continue
        root = Path(install_root)
        if root.is_dir():
            candidates.extend(sorted(root.glob("IDA*"), reverse=True))

    applications = Path("/Applications")
    if applications.is_dir():
        candidates.extend(
            sorted(applications.glob("IDA*.app/Contents/MacOS"), reverse=True)
        )

    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if _looks_like_ida(resolved):
            return resolved
    return None


def discover_ida_domain(explicit: Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser())
    env_value = os.environ.get("TOCODE_IDA_DOMAIN_PATH")
    if env_value:
        candidates.append(Path(env_value).expanduser())

    home = Path.home()
    candidates.extend(
        [
            home / "ida-domain",
            home / "ida_domain",
            home / "src" / "ida-domain",
            home / "src" / "ida_domain",
        ]
    )
    for candidate in candidates:
        if not candidate.exists():
            continue
        resolved = candidate.resolve()
        if (resolved / "ida_domain" / "__init__.py").is_file():
            return resolved
        if resolved.name == "ida_domain" and (resolved / "__init__.py").is_file():
            return resolved.parent
    return None


def _looks_like_ida(path: Path) -> bool:
    return (
        (path / "idalib").exists()
        or (path / "idalib" / "python").exists()
        or (path / "idat64").exists()
        or (path / "idat").exists()
    )


def _add_idapro_wheel(idadir: Path | None) -> None:
    if importlib.util.find_spec("idapro") is not None or idadir is None:
        return
    wheel_dir = idadir / "idalib" / "python"
    if not wheel_dir.is_dir():
        return
    for wheel in sorted(wheel_dir.glob("idapro-*.whl"), reverse=True):
        _prepend(wheel)
        if importlib.util.find_spec("idapro") is not None:
            return


def _add_python_root(path: Path | None) -> None:
    if importlib.util.find_spec("ida_domain") is not None or path is None:
        return
    _prepend(path)


def _prepend(path: Path) -> None:
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)
