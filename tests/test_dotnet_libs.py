from __future__ import annotations

import hashlib
import io
from pathlib import Path
import zipfile

import pytest

from tocode.backends import dotnet_libs
from tocode.backends.dotnet_libs import LibrarySpec
from tocode.errors import ToCodeError


def _package(member: str, payload: bytes, license_text: bytes | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member, payload)
        if license_text is not None:
            archive.writestr("LICENSE.txt", license_text)
    return buffer.getvalue()


class FakeNuGet:
    """Serves fake packages and records requests (no network in tests)."""

    def __init__(self, packages: dict[str, bytes]) -> None:
        self.packages = packages
        self.requests: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.requests.append(url)
        return self.packages[url]


@pytest.fixture
def libraries(monkeypatch: pytest.MonkeyPatch) -> FakeNuGet:
    """Two fake libraries whose pinned hashes match the fake packages."""
    specs = []
    packages = {}
    for package, payload, license_text in (
        ("Fake.Metadata", b"metadata-dll", b"MIT license text"),
        ("Fake.Decompiler", b"decompiler-dll", None),
    ):
        member = f"lib/netstandard2.0/{package}.dll"
        nupkg = _package(member, payload, license_text)
        spec = LibrarySpec(
            package=package,
            version="1.0.0",
            nupkg_sha256=hashlib.sha256(nupkg).hexdigest(),
            member=member,
            dll_sha256=hashlib.sha256(payload).hexdigest(),
            license="MIT",
            license_member="LICENSE.txt" if license_text else None,
        )
        specs.append(spec)
        packages[spec.url] = nupkg
    monkeypatch.setattr(dotnet_libs, "LIBRARIES", tuple(specs))
    return FakeNuGet(packages)


def test_library_dir_honours_override_and_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOCODE_DOTNET_LIB_DIR", str(tmp_path / "custom"))
    assert dotnet_libs.library_dir() == tmp_path / "custom"
    monkeypatch.delenv("TOCODE_DOTNET_LIB_DIR")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(dotnet_libs.sys, "platform", "linux")
    assert dotnet_libs.library_dir() == tmp_path / "xdg" / "tocode" / "dotnet"


def test_pinned_specs_point_at_nuget() -> None:
    for spec in dotnet_libs.LIBRARIES:
        assert spec.url.startswith("https://api.nuget.org/v3-flatcontainer/")
        assert len(spec.nupkg_sha256) == 64 and len(spec.dll_sha256) == 64
        assert spec.member.endswith(".dll")


def test_install_verifies_and_writes_files(
    tmp_path: Path, libraries: FakeNuGet
) -> None:
    messages: list[str] = []

    dotnet_libs.install(directory=tmp_path, fetch=libraries, log=messages.append)

    assert (tmp_path / "Fake.Metadata.dll").read_bytes() == b"metadata-dll"
    assert (tmp_path / "Fake.Decompiler.dll").read_bytes() == b"decompiler-dll"
    assert (tmp_path / "LICENSE-Fake.Metadata.txt").read_bytes() == b"MIT license text"
    assert (tmp_path / "installed.json").is_file()
    assert dotnet_libs.read_decision(tmp_path) is True
    assert dotnet_libs.verify_installed(tmp_path) == []
    assert any(message.startswith("Verified Fake.Metadata.dll") for message in messages)


def test_install_rejects_a_package_with_the_wrong_hash(
    tmp_path: Path, libraries: FakeNuGet
) -> None:
    url = dotnet_libs.LIBRARIES[0].url
    libraries.packages[url] = _package(dotnet_libs.LIBRARIES[0].member, b"tampered")

    with pytest.raises(
        ToCodeError, match="package SHA-256 .* does not match the pinned"
    ):
        dotnet_libs.install(directory=tmp_path, fetch=libraries)

    assert not (tmp_path / "Fake.Metadata.dll").exists()


def test_install_rejects_a_dll_with_the_wrong_hash(
    tmp_path: Path, libraries: FakeNuGet, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = dotnet_libs.LIBRARIES[0]
    # A package that matches its pinned hash but carries an unexpected DLL.
    bad = LibrarySpec(
        package=good.package,
        version=good.version,
        nupkg_sha256=good.nupkg_sha256,
        member=good.member,
        dll_sha256="0" * 64,
        license="MIT",
    )
    monkeypatch.setattr(dotnet_libs, "LIBRARIES", (bad,))

    with pytest.raises(ToCodeError, match="does not match the pinned"):
        dotnet_libs.install(directory=tmp_path, fetch=libraries)

    assert not (tmp_path / "Fake.Metadata.dll").exists()


def test_ensure_asks_once_and_installs_on_yes(
    tmp_path: Path, libraries: FakeNuGet
) -> None:
    prompts: list[str] = []

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return ""  # Enter = default yes

    dotnet_libs.ensure_libraries(
        interactive=True, ask=ask, fetch=libraries, directory=tmp_path
    )
    dotnet_libs.ensure_libraries(
        interactive=True, ask=ask, fetch=libraries, directory=tmp_path
    )

    assert len(prompts) == 1 and "Fake.Metadata 1.0.0 (MIT)" in prompts[0]
    assert len(libraries.requests) == 2  # one download per library, once
    assert dotnet_libs.is_installed(tmp_path)


def test_ensure_remembers_a_no(tmp_path: Path, libraries: FakeNuGet) -> None:
    prompts: list[str] = []

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return "n"

    with pytest.raises(ToCodeError, match="declined"):
        dotnet_libs.ensure_libraries(
            interactive=True, ask=ask, fetch=libraries, directory=tmp_path
        )
    with pytest.raises(ToCodeError, match="--setup-dotnet"):
        dotnet_libs.ensure_libraries(
            interactive=True, ask=ask, fetch=libraries, directory=tmp_path
        )

    assert len(prompts) == 1
    assert libraries.requests == []
    assert dotnet_libs.read_decision(tmp_path) is False


def test_ensure_treats_end_of_input_as_no(tmp_path: Path, libraries: FakeNuGet) -> None:
    def ask(prompt: str) -> str:
        raise EOFError

    with pytest.raises(ToCodeError, match="declined"):
        dotnet_libs.ensure_libraries(
            interactive=True, ask=ask, fetch=libraries, directory=tmp_path
        )
    assert libraries.requests == []


def test_ensure_never_prompts_when_not_interactive(
    tmp_path: Path, libraries: FakeNuGet
) -> None:
    def ask(prompt: str) -> str:
        raise AssertionError("must not prompt")

    with pytest.raises(ToCodeError, match="tocode --setup-dotnet"):
        dotnet_libs.ensure_libraries(
            interactive=False, ask=ask, fetch=libraries, directory=tmp_path
        )
    assert libraries.requests == []
    assert dotnet_libs.read_decision(tmp_path) is None  # still undecided


def test_ensure_reinstalls_silently_after_a_previous_yes(
    tmp_path: Path, libraries: FakeNuGet
) -> None:
    dotnet_libs.install(directory=tmp_path, fetch=libraries)
    (tmp_path / "Fake.Decompiler.dll").unlink()

    def ask(prompt: str) -> str:
        raise AssertionError("already accepted")

    dotnet_libs.ensure_libraries(
        interactive=False, ask=ask, fetch=libraries, directory=tmp_path
    )
    assert dotnet_libs.is_installed(tmp_path)


def test_setup_verifies_and_repairs_a_modified_install(
    tmp_path: Path, libraries: FakeNuGet
) -> None:
    dotnet_libs.install(directory=tmp_path, fetch=libraries)
    libraries.requests.clear()
    messages: list[str] = []

    dotnet_libs.setup(directory=tmp_path, fetch=libraries, log=messages.append)
    assert libraries.requests == []  # intact: nothing downloaded
    assert "already installed and verified" in messages[-1]

    (tmp_path / "Fake.Metadata.dll").write_bytes(b"patched")
    assert dotnet_libs.is_installed(tmp_path)  # normal runs only check presence
    assert dotnet_libs.verify_installed(tmp_path)  # setup re-hashes

    dotnet_libs.setup(directory=tmp_path, fetch=libraries, log=messages.append)
    assert (tmp_path / "Fake.Metadata.dll").read_bytes() == b"metadata-dll"
    assert len(libraries.requests) == 2


def test_setup_after_a_no_enables_dotnet(tmp_path: Path, libraries: FakeNuGet) -> None:
    dotnet_libs.record_decision(False, directory=tmp_path)

    dotnet_libs.setup(directory=tmp_path, fetch=libraries, log=lambda _message: None)

    assert dotnet_libs.read_decision(tmp_path) is True
    assert dotnet_libs.is_installed(tmp_path)


def test_require_installed_explains_how_to_install(
    tmp_path: Path, libraries: FakeNuGet
) -> None:
    with pytest.raises(ToCodeError, match="tocode --setup-dotnet"):
        dotnet_libs.require_installed(tmp_path)
