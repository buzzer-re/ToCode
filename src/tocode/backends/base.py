from __future__ import annotations

from dataclasses import dataclass
import importlib
import importlib.util
import os
from pathlib import Path
import shutil
import sys
from typing import Any, Literal, Protocol

from ..errors import ToCodeError


BackendRequest = Literal["auto", "ida", "r2", "angr", "binja"]
BackendName = Literal["ida", "r2", "angr", "binja"]
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

    # functions() rows may carry these optional keys (read with .get, defaulting
    # to None/[]), enriching the export when the backend recovered them:
    #   source_file, source_dir, source_line  -> original DWARF/debug location
    #   return_type: str | None               -> recovered return type
    #   params:  list[{"name": str, "type": str}]
    #   locals:  list[{"name": str, "type": str}]
    #   calltype: str | None                  -> calling convention

    def types(self) -> list[dict[str, Any]]:
        """Aggregate type catalog the backend identified.

        Optional: consumers call it defensively. Each row:
        ``{"name", "kind", "size"|None, "c_decl", "members"?, "ordinal"?}``.
        """
        ...

    def disasm(self, address: int) -> str: ...

    def decompile(self, address: int) -> str: ...

    def function_summary(self, address: int) -> str: ...

    def ensure_decompiler(self) -> None: ...

    def calls_from(
        self, address: int, imports: dict[int, Any], functions: dict[int, Any]
    ) -> tuple[list[int], list[str]]: ...

    def data_xrefs(self, addresses: Any) -> dict[int, list[tuple[int, bool]]]: ...


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
    binja_dir: Path | None = None,
    skip: frozenset[str] = frozenset(),
) -> BackendChoice:
    if input_path is not None and is_ida_database(input_path):
        if requested in {"r2", "angr", "binja"}:
            raise ToCodeError("IDA database input requires the IDA backend")
        requested = "ida"
    if input_path is not None and is_binja_database(input_path):
        if requested in {"r2", "angr", "ida"}:
            raise ToCodeError(
                "Binary Ninja database (.bndb) input requires the binja backend"
            )
        requested = "binja"

    if requested == "binja":
        # Satisfied by the local Binary Ninja API (headless, chosen in
        # create_analyzer when a file is given), by a view injected from the
        # Binary Ninja UI, or by the MCP/RPyc routes the CLI drives itself.
        return BackendChoice(requested, "binja", "selected by CLI")

    if requested == "r2":
        if not probe_r2():
            raise ToCodeError(
                "r2 backend requested but unavailable: r2pipe or the r2 "
                "executable is missing"
            )
        return BackendChoice(requested, "r2", "selected by CLI")

    if requested == "angr":
        if not probe_angr():
            raise ToCodeError(
                "angr backend requested but unavailable: install with "
                "`pip install tocode-cli[angr]`"
            )
        return BackendChoice(requested, "angr", "selected by CLI")

    probe = probe_ida(idadir=idadir, ida_domain_path=ida_domain_path)
    if requested == "ida":
        if not probe.available:
            raise ToCodeError(f"IDA backend requested but unavailable: {probe.reason}")
        return BackendChoice(requested, "ida", probe.reason)

    # auto: prefer IDA, then the Binary Ninja API, then radare2, then angr as a
    # last resort. A Binary Ninja license that does not allow headless use is
    # only detected when the file is opened; create_analyzer then retries with
    # binja in ``skip``.
    if probe.available:
        return BackendChoice(requested, "ida", probe.reason)
    if "binja" not in skip and probe_binja_headless(binja_dir):
        return BackendChoice(
            requested,
            "binja",
            f"IDA unavailable ({probe.reason}); using the Binary Ninja Python API",
        )
    if probe_r2():
        return BackendChoice(
            requested, "r2", f"IDA unavailable ({probe.reason}); using r2"
        )
    if probe_angr():
        return BackendChoice(
            requested,
            "angr",
            f"IDA and r2 unavailable ({probe.reason}); using angr",
        )
    raise ToCodeError(
        "no decompiler backend available: IDA not found "
        f"({probe.reason}), radare2 not found, and angr is not installed "
        "(`pip install tocode-cli[angr]`)"
    )


def probe_r2() -> bool:
    if importlib.util.find_spec("r2pipe") is None:
        return False
    return shutil.which("r2") is not None


def probe_angr() -> bool:
    return importlib.util.find_spec("angr") is not None


def probe_binja() -> bool:
    # Advisory only: true when running inside (or alongside) a Binary Ninja that
    # exposes the ``binaryninja`` module locally.
    return importlib.util.find_spec("binaryninja") is not None


def discover_binja_dir(explicit: Path | None = None) -> Path | None:
    """Binary Ninja's ``python`` folder (holding the ``binaryninja`` package)."""
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser())
    for env_name in ("TOCODE_BINJA_DIR", "BN_INSTALL_DIR", "BINJA_DIR"):
        value = os.environ.get(env_name, "").strip()
        if value:
            candidates.append(Path(value).expanduser())
    # Binary Ninja's own install_api.py writes the path into a .pth file in the
    # user site-packages of the Python it was run with; reuse it from any Python.
    candidates.extend(_binaryninja_pth_paths())
    home = Path.home()
    candidates.extend(
        [
            home / "binaryninja",
            home / "Applications" / "Binary Ninja.app" / "Contents" / "Resources",
            Path("/Applications/Binary Ninja.app/Contents/Resources"),
            Path("/opt/binaryninja"),
        ]
    )
    for env_name in ("ProgramFiles", "LOCALAPPDATA"):
        root = os.environ.get(env_name)
        if root:
            candidates.append(Path(root) / "Vector35" / "BinaryNinja")
    for candidate in candidates:
        for python_dir in (candidate, candidate / "python"):
            if (python_dir / "binaryninja" / "__init__.py").is_file():
                return python_dir.resolve()
    return None


def _binaryninja_pth_paths() -> list[Path]:
    found: list[Path] = []
    roots: list[Path] = []
    for pattern in (
        ".local/lib/python3*/site-packages",
        "Library/Python/3*/lib/python/site-packages",
    ):
        roots.extend(Path.home().glob(pattern))
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.extend(Path(appdata).glob("Python/Python3*/site-packages"))
    for root in roots:
        pth = root / "binaryninja.pth"
        try:
            lines = pth.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        found.extend(Path(line.strip()) for line in lines if line.strip())
    return found


def bootstrap_binja(explicit: Path | None = None) -> Path | None:
    """Make ``import binaryninja`` work; returns the python folder used."""
    if importlib.util.find_spec("binaryninja") is not None:
        return None
    python_dir = discover_binja_dir(explicit)
    if python_dir is not None:
        _prepend(python_dir)
    return python_dir


def probe_binja_headless(explicit: Path | None = None) -> bool:
    """True when the Binary Ninja Python API can be imported (cheap: no import).

    Whether the license allows headless use is only known when a file is
    opened; ``auto`` then falls back to the next backend.
    """
    if os.environ.get("TOCODE_DISABLE_BINJA_HEADLESS", "").strip() in (
        "1",
        "true",
        "yes",
    ):
        return False
    bootstrap_binja(explicit)
    return importlib.util.find_spec("binaryninja") is not None


def is_ida_database(path: Path) -> bool:
    return path.suffix.lower() in IDA_DATABASE_SUFFIXES


def is_binja_database(path: Path) -> bool:
    return path.suffix.lower() == ".bndb"


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
