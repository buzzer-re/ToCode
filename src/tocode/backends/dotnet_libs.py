"""On-demand installer for the third-party .NET libraries the .NET backend uses.

ToCode does not ship any DLL. The first time a .NET input is exported, the user
is asked (once) whether to download dnlib and ICSharpCode.Decompiler from
nuget.org; the answer is remembered. Each download is checked against hashes
pinned in this file (the ``.nupkg`` and each extracted DLL) and the files are
re-hashed after being written to disk. Normal runs only check that the files
are present; ``tocode --setup-dotnet`` re-verifies and repairs an install.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Callable
import urllib.error
import urllib.request
import zipfile

from ..errors import ToCodeError

NUGET_FLAT_CONTAINER = "https://api.nuget.org/v3-flatcontainer"
CONSENT_FILE = "consent.json"
INSTALLED_FILE = "installed.json"
DOWNLOAD_TIMEOUT_SECONDS = 60


@dataclass(frozen=True, slots=True)
class LibrarySpec:
    package: str  # NuGet package id
    version: str
    nupkg_sha256: str  # pinned hash of the whole .nupkg
    member: str  # path of the DLL inside the package
    dll_sha256: str  # pinned hash of the extracted DLL
    license: str  # SPDX identifier, shown when asking
    license_member: str | None = None  # license file to keep next to the DLL

    @property
    def file_name(self) -> str:
        return self.member.rsplit("/", 1)[-1]

    @property
    def url(self) -> str:
        lower = self.package.lower()
        return f"{NUGET_FLAT_CONTAINER}/{lower}/{self.version}/{lower}.{self.version}.nupkg"


# Changing a version means updating both hashes; download the .nupkg from
# nuget.org, hash it, extract ``member``, and hash that too.
LIBRARIES: tuple[LibrarySpec, ...] = (
    LibrarySpec(
        package="dnlib",
        version="4.5.0",
        nupkg_sha256="63bc2f9579568204cc8b30fa9f6700a231bcf868a8032e09118887af3eafee58",
        member="lib/netstandard2.0/dnlib.dll",
        dll_sha256="566fdab59c91a3c2eab14a22b67f01cb3c0cdb48fa9b9b6677e2b32998636efb",
        license="MIT",
        license_member="LICENSE.txt",
    ),
    LibrarySpec(
        package="ICSharpCode.Decompiler",
        version="11.1.0.9782",
        nupkg_sha256="1f76df4d35193ba4eeb50ffcd84eae381a2c48c67f95c1104dc406759448a811",
        member="lib/netstandard2.0/ICSharpCode.Decompiler.dll",
        dll_sha256="38e6abf7497845d79d9d01d56351a3203991356de1d3496b8c51142f495e9f9c",
        license="MIT",
    ),
)


def library_dir() -> Path:
    """Per-user location of the downloaded libraries (outside any repository)."""
    explicit = os.environ.get("TOCODE_DOTNET_LIB_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        xdg = os.environ.get("XDG_DATA_HOME", "").strip()
        base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "tocode" / "dotnet"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify_installed(directory: Path | None = None) -> list[str]:
    """Problems with the installed DLLs (empty list = present and intact)."""
    directory = directory or library_dir()
    problems: list[str] = []
    for spec in LIBRARIES:
        path = directory / spec.file_name
        if not path.is_file():
            problems.append(f"{spec.file_name} is not installed")
            continue
        actual = sha256_file(path)
        if actual != spec.dll_sha256:
            problems.append(
                f"{path} has SHA-256 {actual}, expected {spec.dll_sha256} "
                "(modified or from another version)"
            )
    return problems


def is_installed(directory: Path | None = None) -> bool:
    """Cheap presence check used on every run (hashes are checked at download)."""
    directory = directory or library_dir()
    return all((directory / spec.file_name).is_file() for spec in LIBRARIES)


def require_installed(directory: Path | None = None) -> Path:
    directory = directory or library_dir()
    if not is_installed(directory):
        raise ToCodeError(
            "the .NET decompiler libraries are not installed; run "
            "`tocode --setup-dotnet` to download and verify them"
        )
    return directory


# --------------------------------------------------------------------------
# Download and install
# --------------------------------------------------------------------------

Fetcher = Callable[[str], bytes]


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "tocode-dotnet-setup"})
    try:
        with urllib.request.urlopen(
            request, timeout=DOWNLOAD_TIMEOUT_SECONDS
        ) as response:
            return bytes(response.read())
    except (urllib.error.URLError, OSError) as exc:
        raise ToCodeError(f"cannot download {url}: {exc}") from exc


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    ) as handle:
        handle.write(data)
        temp = Path(handle.name)
    try:
        temp.replace(path)
    except OSError:
        temp.unlink(missing_ok=True)
        raise


def install(
    *,
    directory: Path | None = None,
    fetch: Fetcher = _fetch,
    log: Callable[[str], None] = lambda _message: None,
) -> Path:
    """Download, verify (package and DLL hashes), and install every library."""
    directory = directory or library_dir()
    directory.mkdir(parents=True, exist_ok=True)
    record: dict[str, object] = {
        "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "libraries": [],
    }
    for spec in LIBRARIES:
        log(f"Downloading {spec.package} {spec.version} from nuget.org")
        package = fetch(spec.url)
        actual = sha256_bytes(package)
        if actual != spec.nupkg_sha256:
            raise ToCodeError(
                f"{spec.package} {spec.version}: package SHA-256 {actual} does not "
                f"match the pinned {spec.nupkg_sha256}; nothing was installed"
            )
        try:
            with zipfile.ZipFile(io.BytesIO(package)) as archive:
                dll = archive.read(spec.member)
                license_text = (
                    archive.read(spec.license_member) if spec.license_member else None
                )
        except (zipfile.BadZipFile, KeyError) as exc:
            raise ToCodeError(
                f"{spec.package}: unexpected package layout: {exc}"
            ) from exc
        dll_hash = sha256_bytes(dll)
        if dll_hash != spec.dll_sha256:
            raise ToCodeError(
                f"{spec.package} {spec.version}: {spec.member} SHA-256 {dll_hash} does "
                f"not match the pinned {spec.dll_sha256}; nothing was installed"
            )
        _write_atomic(directory / spec.file_name, dll)
        if license_text is not None:
            _write_atomic(directory / f"LICENSE-{spec.package}.txt", license_text)
        # Checksum what is now on disk, not only what was downloaded.
        on_disk = sha256_file(directory / spec.file_name)
        if on_disk != spec.dll_sha256:
            (directory / spec.file_name).unlink(missing_ok=True)
            raise ToCodeError(
                f"{spec.file_name}: SHA-256 changed while writing to disk"
            )
        log(f"Verified {spec.file_name} (SHA-256 {on_disk[:16]}…)")
        libraries = record["libraries"]
        assert isinstance(libraries, list)
        libraries.append(
            {
                "package": spec.package,
                "version": spec.version,
                "license": spec.license,
                "url": spec.url,
                "nupkg_sha256": spec.nupkg_sha256,
                "file": spec.file_name,
                "sha256": spec.dll_sha256,
            }
        )
    _write_atomic(
        directory / INSTALLED_FILE, (json.dumps(record, indent=2) + "\n").encode()
    )
    record_decision(True, directory=directory)
    return directory


# --------------------------------------------------------------------------
# Consent ("ask once")
# --------------------------------------------------------------------------


def read_decision(directory: Path | None = None) -> bool | None:
    """True/False once the user answered; None when never asked."""
    path = (directory or library_dir()) / CONSENT_FILE
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    decision = payload.get("download") if isinstance(payload, dict) else None
    return decision if isinstance(decision, bool) else None


def record_decision(accepted: bool, *, directory: Path | None = None) -> None:
    directory = directory or library_dir()
    payload = {
        "download": accepted,
        "decided_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _write_atomic(
        directory / CONSENT_FILE, (json.dumps(payload, indent=2) + "\n").encode()
    )


def consent_prompt() -> str:
    lines = [
        ".NET support needs two open-source libraries that ToCode does not ship:",
    ]
    for spec in LIBRARIES:
        lines.append(
            f"  - {spec.package} {spec.version} ({spec.license}) from nuget.org"
        )
    lines.extend(
        [
            f"They are verified against pinned SHA-256 hashes and stored in {library_dir()}.",
            "Download them now? This is asked only once. [Y/n] ",
        ]
    )
    return "\n".join(lines)


Asker = Callable[[str], str]


def ensure_libraries(
    *,
    interactive: bool,
    ask: Asker = input,
    fetch: Fetcher = _fetch,
    log: Callable[[str], None] = lambda _message: None,
    directory: Path | None = None,
) -> Path:
    """Make the libraries available, asking once; raises when the user declined."""
    directory = directory or library_dir()
    if is_installed(directory):
        return directory
    decision = read_decision(directory)
    if decision is False:
        raise ToCodeError(
            "the .NET backend is disabled because the library download was "
            "declined; run `tocode --setup-dotnet` to enable it, or pass "
            "--as-native to export the file with the native backend"
        )
    if decision is None:
        if not interactive:
            raise ToCodeError(
                "the .NET backend needs dnlib and ICSharpCode.Decompiler, which "
                "are downloaded on first use; run `tocode --setup-dotnet` once "
                "(non-interactive sessions are never prompted), or pass "
                "--as-native to export the file with the native backend"
            )
        try:
            answer = ask(consent_prompt()).strip().lower()
        except EOFError:
            answer = "n"
        accepted = answer in {"", "y", "yes"}
        record_decision(accepted, directory=directory)
        if not accepted:
            raise ToCodeError(
                "download declined (remembered); run `tocode --setup-dotnet` to "
                "enable .NET support later, or pass --as-native"
            )
    return install(directory=directory, fetch=fetch, log=log)


def setup(
    *,
    force: bool = False,
    fetch: Fetcher = _fetch,
    log: Callable[[str], None] = print,
    directory: Path | None = None,
) -> Path:
    """`tocode --setup-dotnet`: verify an existing install, or (re)download it."""
    directory = directory or library_dir()
    if not force:
        problems = verify_installed(directory)
        if not problems:
            record_decision(True, directory=directory)
            log(f".NET libraries already installed and verified in {directory}")
            return directory
        for problem in problems:
            log(problem)
    install(directory=directory, fetch=fetch, log=log)
    log(f".NET libraries installed in {directory}")
    return directory
