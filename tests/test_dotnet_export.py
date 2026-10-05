from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from dotnet_fixtures import managed_pe, native_elf, single_file_bundle, write
from tocode import dotnet as pipeline
from tocode import dotnet_metadata as meta
from tocode.apk_native import NativeLib
from tocode.backends.dotnet import (
    AssemblyInfo,
    DecompiledType,
    DotnetSession,
    MethodInfo,
    ResourceInfo,
    TypeInfo,
    WorkItem,
)
from tocode.backends.dotnet_pe import parse_pe
from tocode.dotnet import (
    DotnetExportOptions,
    build_csproj,
    export_dotnet,
    namespace_parts,
    safe_file_name,
    target_framework_moniker,
    type_file_stem,
)
from tocode.errors import ToCodeError
from tocode.progress import Progress

PROGRAM = 0x02000002
CLOSURE = 0x02000003
CLIENT = 0x02000004
BROKEN = 0x02000005
BOX = 0x02000006
MODULE = 0x02000001

PROGRAM_CS = """using System;

namespace Contoso.App;

public static class Program
{
    public static void Main(string[] args)
    {
        var client = new Client();
        Action a = () => client.Send();
        a();
    }
}
"""


def _type(
    token: int,
    name: str,
    namespace: str,
    *,
    declaring: int | None = None,
    top: int | None = None,
    kind: str = "class",
    visibility: str = "Public",
    parent_name: str | None = None,
) -> TypeInfo:
    full = f"{namespace}.{name}" if namespace else name
    if parent_name is not None:
        full = f"{parent_name}/{name}"  # dnlib's nested-type naming
    return TypeInfo(
        assembly=0,
        token=token,
        full_name=full,
        reflection_name=full,
        namespace=namespace,
        name=name,
        kind=kind,
        flags=["Public"],
        visibility=visibility,
        base_type="System.Object",
        interfaces=[],
        generic_params=["T"] if "`" in name else [],
        declaring_type=declaring,
        top_level=top if top is not None else token,
        attributes=[],
        fields=[],
        properties=[],
        events=[],
        methods=[],
        compiler_generated=name.startswith("<"),
    )


class FakeSession(DotnetSession):
    """Inventory built by hand: no .NET runtime involved."""

    def load(self, progress: Any = None) -> None:
        item = self.input.included[0]
        pe = parse_pe(item.path.read_bytes())
        assert pe is not None
        info = AssemblyInfo(
            index=0,
            file=item,
            pe=pe,
            name="Contoso.App",
            full_name="Contoso.App, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
            version="1.0.0.0",
            culture="",
            public_key_token=None,
            module_name="Contoso.App.dll",
            mvid="00000000-0000-0000-0000-000000000001",
            kind="Console",
            target_framework=".NETCoreApp,Version=v10.0",
            entry_point=0x06000001,
            assembly_refs=[
                {"name": "System.Runtime", "version": "10.0.0.0"},
                {"name": "Vendor.Lib", "version": "2.0.0.0"},
            ],
            module_refs=["native_helper"],
            attributes=[
                "System.Runtime.Versioning.TargetFrameworkAttribute(.NETCoreApp,Version=v10.0)"
            ],
            resources=[
                ResourceInfo("Contoso.App.Strings.resources", "embedded", 10, True),
                ResourceInfo("config.json", "embedded", 2, False),
                ResourceInfo("Other.dll", "linked", None, True, file="Other.dll"),
            ],
            user_strings=[(1, "https://api.example.invalid/v1"), (64, "hello world")],
        )
        self.assemblies = [info]
        types = [
            _type(MODULE, "<Module>", ""),
            _type(PROGRAM, "Program", "Contoso.App", kind="static class"),
            _type(
                CLOSURE,
                "<>c",
                "Contoso.App",
                declaring=PROGRAM,
                top=PROGRAM,
                visibility="NestedPrivate",
                parent_name="Contoso.App.Program",
            ),
            _type(CLIENT, "Client", "Contoso.App.Net"),
            _type(BROKEN, "Broken", "Contoso.App"),
            _type(BOX, "Box`1", "Contoso.App"),
        ]
        for record in types:
            self.types[(0, record.token)] = record
            info.types.append(record.token)

        def method(token: int, owner: int, name: str, **extra: Any) -> MethodInfo:
            record = self.types[(0, owner)]
            item = MethodInfo(
                id=len(self.methods),
                assembly=0,
                token=token,
                name=name,
                type_token=owner,
                type_name=record.full_name,
                full_name=f"System.Void {record.full_name}::{name}()",
                return_type="System.Void",
                params=[],
                flags=["Public"] if not name.startswith("<") else ["Private"],
                impl_flags=[],
                rva=0x2050 + token % 0x100,
                il_size=12,
                is_static=True,
                is_virtual=False,
                is_abstract=False,
                is_constructor=name in {".ctor", ".cctor"},
                compiler_generated=name.startswith("<") or record.compiler_generated,
                **extra,
            )
            item.assembly_name = "Contoso.App"
            self.methods.append(item)
            record.methods.append(item.id)
            self._method_by_token[(0, token)] = item
            return item

        main = method(0x06000001, PROGRAM, "Main")
        lambda_ = method(0x06000002, CLOSURE, "<Main>b__0_0")
        send = method(0x06000003, CLIENT, "Send")
        native = method(
            0x06000004,
            CLIENT,
            "compute",
            pinvoke_module="native_helper",
            pinvoke_entry="helper_compute",
        )
        method(0x06000005, BROKEN, "Explode")
        cctor = method(0x06000006, MODULE, ".cctor")
        method(0x06000007, BOX, "Get")
        lambda_.owner_method = main.id
        main.callees = [send.id]
        send.callers = [main.id]
        lambda_.callees = [send.id]
        send.callers.append(lambda_.id)
        send.callees = [native.id]
        native.callers = [send.id]
        send.external_calls = [
            "[System.Net.Http]System.Net.Http.HttpResponseMessage System.Net.Http.HttpClient::Send(System.Net.Http.HttpRequestMessage)"
        ]
        self.external_refs = {
            "System.Net.Http": {
                send.external_calls[0][len("[System.Net.Http]") :]: [send.id]
            }
        }
        main.string_ref_count = 1
        self.string_xrefs = {(0, 1): [main.id]}
        self.pinvoke_modules = {"native_helper"}
        del cctor

    def save_resource(self, info: AssemblyInfo, name: str, target: Path) -> int | None:
        payload = b"{}" if name == "config.json" else b"\x00resources"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return len(payload)

    def decode_resources_file(
        self, info: AssemblyInfo, name: str
    ) -> list[dict[str, Any]]:
        return [{"name": "Greeting", "type": "String", "value": "hi"}]

    def close(self) -> None:
        return


class FakeDecompiler:
    def __init__(self, session: DotnetSession) -> None:
        self.session = session
        self.items: list[WorkItem] = []

    def decompile(self, item: WorkItem) -> DecompiledType:
        self.items.append(item)
        if item.token == 0:
            return DecompiledType(
                0,
                0,
                "[assembly: Fake]\n",
                None,
                ".assembly Contoso.App\n",
                None,
                {},
                {},
            )
        if item.token == BROKEN:
            return DecompiledType(
                0, BROKEN, None, "boom", ".class Broken\n", None, {}, {}
            )
        if item.token == PROGRAM:
            il = "\n".join(
                [
                    ".class Program",
                    "{",
                    "    .method /* 06000001 */ public static void Main",
                    "    {",
                    "    } // end of method Program::Main",
                    "}",
                ]
            )
            return DecompiledType(
                0,
                PROGRAM,
                PROGRAM_CS,
                None,
                il,
                None,
                {0x06000001: (7, 12), 0x06000002: (10, 10)},
                {0x06000001: (3, 5)},
            )
        return DecompiledType(
            0,
            item.token,
            f"// type {item.token:#x}\n",
            None,
            f"// il {item.token:#x}\n",
            None,
            {},
            {},
        )


def _fake_native_exporter(calls: list[str]) -> Any:
    def run(
        lib: NativeLib, out_dir: Path, progress: Progress
    ) -> tuple[str, str, int, int]:
        calls.append(lib.name)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AGENTS.md").write_text(lib.origin or "", encoding="utf-8")
        return ("ida", "Hex-Rays", 3, 0)

    return run


def _export(tmp_path: Path, **options: Any) -> Any:
    calls: list[str] = []
    summary = export_dotnet(
        tmp_path / "Contoso.App.dll",
        options=DotnetExportOptions(out_dir=tmp_path / "export", **options),
        progress=Progress(enabled=False),
        native_exporter=_fake_native_exporter(calls),
        decompiler_factory=FakeDecompiler,
        session_factory=FakeSession,
    )
    return summary, calls


@pytest.fixture
def assembly(tmp_path: Path) -> Path:
    write(tmp_path / "libnative_helper.so", native_elf())
    return write(tmp_path / "Contoso.App.dll", managed_pe(strings=["x"]))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def test_file_naming_helpers() -> None:
    assert (
        safe_file_name("<PrivateImplementationDetails>")
        == "_PrivateImplementationDetails_"
    )
    assert safe_file_name("..hidden") == "hidden"
    assert namespace_parts("Contoso.App.Net") == ["Contoso", "App", "Net"]
    assert namespace_parts("") == []
    assert type_file_stem(_type(1, "Dictionary`2", "System")) == "Dictionary-2"
    assert type_file_stem(_type(1, "\u0001\u0002", "")) == "__"


def test_target_framework_monikers() -> None:
    assert target_framework_moniker(".NETCoreApp,Version=v10.0") == "net10.0"
    assert target_framework_moniker(".NETCoreApp,Version=v3.1") == "netcoreapp3.1"
    assert target_framework_moniker(".NETStandard,Version=v2.0") == "netstandard2.0"
    assert target_framework_moniker(".NETFramework,Version=v4.7.2") == "net472"
    assert target_framework_moniker(".NETFramework,Version=v4.8") == "net48"
    assert target_framework_moniker(None) is None
    assert target_framework_moniker("Unity") is None


# --------------------------------------------------------------------------
# end-to-end with fakes
# --------------------------------------------------------------------------


def test_export_dotnet_writes_a_project_tree(tmp_path: Path, assembly: Path) -> None:
    summary, calls = _export(tmp_path, jobs=1)

    root = summary.root_dir
    assert root == tmp_path / "export"
    assert summary.kind == "assembly" and summary.assemblies == ["Contoso.App"]
    assert summary.failed_types == [("Contoso.App.Broken", "boom")]
    assert summary.native_total == 1 and summary.native_done == 1
    assert calls == ["libnative_helper.so"]

    raw = root / "src" / "raw" / "Contoso.App"
    for name in (
        "Contoso/App/Program.cs",
        "Contoso/App/Program.il",
        "Contoso/App/Net/Client.cs",
        "Contoso/App/Net/Client.il",
        "Contoso/App/Broken.cs",
        "Contoso/App/Box-1.cs",
        "_Module_.cs",
        "Properties/AssemblyInfo.cs",
        "Properties/Manifest.il",
        "Contoso.App.csproj",
    ):
        assert (raw / name).is_file(), name
    program = (raw / "Contoso/App/Program.cs").read_text(encoding="utf-8")
    assert program.startswith(
        "// ToCode: Contoso.App.Program (0x02000002) from Contoso.App 1.0.0.0\n"
    )
    assert "namespace Contoso.App;" in program
    broken = (raw / "Contoso/App/Broken.cs").read_text(encoding="utf-8")
    assert "decompilation failed: boom" in broken and "Broken::System.Void" in broken
    csproj = (raw / "Contoso.App.csproj").read_text(encoding="utf-8")
    assert "<OutputType>Exe</OutputType>" in csproj
    assert "<TargetFramework>net10.0</TargetFramework>" in csproj
    assert '<Reference Include="Vendor.Lib" />' in csproj
    assert "System.Runtime" not in csproj

    for name in (
        "AGENTS.md",
        "CLAUDE.md",
        "assemblies.json",
        "types.json",
        "functions.json",
        "function-index.json",
        "strings.json",
        "imports.json",
        "exports.json",
        "sections.json",
        "reachable.json",
        "namespace-graph.json",
        "resources.json",
        "container.json",
        "triage.json",
        "native-libs.json",
        "project.json",
        "export-manifest.json",
        "tocode.log",
    ):
        assert (root / name).is_file(), name

    functions = {
        row["c_name"]: row
        for row in json.loads((root / "functions.json").read_text())["functions"]
    }
    main = functions["Contoso.App.Program.Main"]
    # +1 for the ToCode header line written above the decompiler output.
    assert (main["source_line_start"], main["source_line_end"]) == (8, 13)
    assert (main["asm_line_start"], main["asm_line_end"]) == (4, 6)
    assert main["source_file"] == "src/raw/Contoso.App/Contoso/App/Program.cs"
    assert main["asm_file"] == "src/raw/Contoso.App/Contoso/App/Program.il"
    assert main["callees"] == ["Contoso.App!0x06000003"]
    assert main["dead_code"] is False
    lambda_ = functions["Contoso.App.Program.<>c.<Main>b__0_0"]
    assert lambda_["source_line_start"] == 11
    assert lambda_["owner"] == "Contoso.App!0x06000001"
    native = functions["Contoso.App.Net.Client.compute"]
    assert native["pinvoke"] == {"module": "native_helper", "entry": "helper_compute"}
    explode = functions["Contoso.App.Broken.Explode"]
    assert explode["source_line_start"] == 1  # failure stub spans the file

    index = json.loads((root / "function-index.json").read_text())
    assert index["language"] == "csharp" and index["asm_language"] == "il"
    entry = next(
        row for row in index["functions"] if row["address"] == "Contoso.App!0x06000001"
    )
    assert entry["c"]["line_start"] == 8 and entry["asm"]["line_start"] == 4

    imports = json.loads((root / "imports.json").read_text())["imports"]
    assert [(group["dll"], group["kind"]) for group in imports] == [
        ("System.Net.Http", "assembly"),
        ("native_helper", "pinvoke"),
    ]
    assert imports[1]["functions"][0]["name"] == "helper_compute"

    exports = json.loads((root / "exports.json").read_text())["exports"]
    assert [(row["kind"], row["address"]) for row in exports] == [
        ("entrypoint", "Contoso.App!0x06000001"),
        ("module-initializer", "Contoso.App!0x06000006"),
    ]

    reachable = json.loads((root / "reachable.json").read_text())
    depths = {row["address"]: row["depth"] for row in reachable["reachable"]}
    assert depths["Contoso.App!0x06000003"] == 1
    assert depths["Contoso.App!0x06000002"] == 1  # lambda via its owner
    assert depths["Contoso.App!0x06000004"] == 2

    strings = json.loads((root / "strings.json").read_text())["strings"]
    assert strings[0]["value"] == "https://api.example.invalid/v1"
    assert strings[0]["vaddr"] == "Contoso.App!0x70000001"
    assert strings[0]["xrefs"][0]["address"] == "Contoso.App!0x06000001"

    types = {
        row["name"]: row
        for row in json.loads((root / "types.json").read_text())["types"]
    }
    assert (
        types["Contoso.App.Program+<>c"]["cs_file"]
        == "src/raw/Contoso.App/Contoso/App/Program.cs"
    )
    assert types["Contoso.App.Broken"]["decompile_error"] == "boom"

    assemblies = json.loads((root / "assemblies.json").read_text())["assemblies"]
    assert assemblies[0]["entry_point"]["address"] == "Contoso.App!0x06000001"
    assert assemblies[0]["project"] == "Contoso.App/Contoso.App.csproj"

    resources = json.loads((root / "resources.json").read_text())["resources"]
    by_name = {row["name"]: row for row in resources}
    assert by_name["config.json"]["path"] == "data/resources/Contoso.App/config.json"
    assert by_name["Contoso.App.Strings.resources"]["entries"][0]["value"] == "hi"
    assert by_name["Other.dll"]["kind"] == "linked"
    assert (
        root / "data/resources/Contoso.App/Contoso.App.Strings.resources.json"
    ).is_file()

    triage = json.loads((root / "triage.json").read_text())
    assert triage["binary_type"] == "dotnet-assembly"
    assert triage["pinvoke"] == [
        {"module": "native_helper", "functions": ["helper_compute"]}
    ]
    assert triage["suspicious_apis"][0]["category"] == "network"
    assert triage["strings_of_interest"][0]["value"] == "https://api.example.invalid/v1"

    libs = json.loads((root / "native-libs.json").read_text())["libs"]
    assert libs[0]["status"] == "done" and libs[0]["path"].startswith("lib/arm64/")
    origin = (root / libs[0]["export_dir"] / "AGENTS.md").read_text(encoding="utf-8")
    assert "`Contoso.App` .NET assembly" in origin
    assert "P/Invoke declarations name (`native_helper`)" in origin

    graph = json.loads((root / "namespace-graph.json").read_text())["namespaces"]
    app = next(row for row in graph if row["namespace"] == "Contoso.App")
    assert app["calls_namespaces"] == [
        {"namespace": "Contoso.App:Contoso.App.Net", "calls": 2}
    ]

    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
    assert "Contoso.App" in agents and "native/<arch>/<lib>/" in agents
    assert (root / "CLAUDE.md").read_text(encoding="utf-8") == "@./AGENTS.md\n"
    manifest = json.loads((root / "export-manifest.json").read_text())
    assert manifest["format"] == "dotnet-assembly"
    assert manifest["failures"] == [
        {"address": None, "name": "Contoso.App.Broken", "error": "boom"}
    ]
    log = (root / "tocode.log").read_text(encoding="utf-8")
    assert "export Contoso.App!Contoso.App.Broken failed: boom" in log


def test_export_dotnet_no_native_and_stale_cleanup(
    tmp_path: Path, assembly: Path
) -> None:
    stale = tmp_path / "export" / "src" / "raw" / "Old" / "Gone.cs"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale", encoding="utf-8")

    summary, calls = _export(tmp_path, native=False)

    assert calls == []
    assert not stale.exists()
    libs = json.loads((summary.root_dir / "native-libs.json").read_text())["libs"]
    assert libs[0]["status"] == "skipped: --no-native"
    assert (summary.root_dir / "lib" / "arm64" / "libnative_helper.so").is_file()
    assert not (summary.root_dir / "native").exists()


def test_export_dotnet_default_out_dir(
    tmp_path: Path, assembly: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TOCODE_DEFAULT_OUT_ROOT", raising=False)
    summary = export_dotnet(
        assembly,
        options=DotnetExportOptions(native=False),
        progress=Progress(enabled=False),
        decompiler_factory=FakeDecompiler,
        session_factory=FakeSession,
    )
    assert summary.root_dir == tmp_path / "Contoso_App_decompiler"


def test_export_dotnet_bundle_skips_runtime_natives(tmp_path: Path) -> None:
    bundle = write(
        tmp_path / "App",
        single_file_bundle(
            [
                ("Contoso.App.dll", 1, managed_pe(strings=["x"]), True),
                ("libcoreclr.so", 2, native_elf(), False),
                ("libcustom.so", 2, native_elf(), False),
            ]
        ),
    )
    calls: list[str] = []
    summary = export_dotnet(
        bundle,
        options=DotnetExportOptions(out_dir=tmp_path / "export"),
        progress=Progress(enabled=False),
        native_exporter=_fake_native_exporter(calls),
        decompiler_factory=FakeDecompiler,
        session_factory=FakeSession,
    )

    assert summary.kind == "bundle"
    assert calls == ["libcustom.so"]
    libs = {
        row["name"]: row["status"]
        for row in json.loads((summary.root_dir / "native-libs.json").read_text())[
            "libs"
        ]
    }
    assert libs == {
        "libcoreclr.so": "skipped: .NET runtime library (use --include-framework)",
        "libcustom.so": "done",
    }
    container = json.loads((summary.root_dir / "container.json").read_text())
    assert (
        container["kind"] == "bundle"
        and container["bundle"]["bundle_id"] == "testbundle01"
    )
    assert [entry["path"] for entry in container["entries"]] == [
        "Contoso.App.dll",
        "libcoreclr.so",
        "libcustom.so",
    ]
    assert (summary.root_dir / "data" / "assemblies" / "Contoso.App.dll").is_file()


def test_export_dotnet_rejects_missing_input(tmp_path: Path) -> None:
    with pytest.raises(ToCodeError):
        export_dotnet(tmp_path / "missing.dll", progress=Progress(enabled=False))


def test_decompile_pool_isolates_crashing_types(
    tmp_path: Path, assembly: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch that kills its worker is re-run type by type; only the culprit fails."""
    rounds: list[list[list[int]]] = []

    def fake_round(
        context: Any,
        batches: list[tuple[list[WorkItem], bool]],
        workers: int,
        search_dirs: list[str],
        timeout: int,
        bar: Any,
    ) -> list[tuple[list[WorkItem], bool, str]]:
        rounds.append([[item.token for item in batch] for batch, _ in batches])
        failed = []
        fake = FakeDecompiler(context.session)
        for batch, isolated in batches:
            if any(item.token == CLIENT for item in batch):
                failed.append((batch, isolated, "decompiler process crashed"))
                continue
            for item in batch:
                pipeline._store_result(context, fake.decompile(item))
        return failed

    monkeypatch.setattr(pipeline, "_run_round", fake_round)
    summary = export_dotnet(
        assembly,
        options=DotnetExportOptions(out_dir=tmp_path / "export", native=False),
        progress=Progress(enabled=False),
        session_factory=FakeSession,
    )

    assert (
        "Contoso.App.Net.Client",
        "decompiler process crashed",
    ) in summary.failed_types
    assert ("Contoso.App.Program", "boom") not in summary.failed_types
    # first round: one batch; then each item alone; then the culprit once more alone.
    assert len(rounds[0]) == 1 and all(len(batch) == 1 for batch in rounds[1])
    client = (
        summary.root_dir / "src/raw/Contoso.App/Contoso/App/Net/Client.il"
    ).read_text()
    assert "IL disassembly failed: decompiler process crashed" in client


# --------------------------------------------------------------------------
# metadata helpers
# --------------------------------------------------------------------------


def test_build_csproj_for_library_with_internal_refs(tmp_path: Path) -> None:
    pe = parse_pe(managed_pe())
    assert pe is not None
    from tocode.backends.dotnet import AssemblyFile

    info = AssemblyInfo(
        index=0,
        file=AssemblyFile(tmp_path / "A.dll", "A.dll", "A.dll"),
        pe=pe,
        name="A",
        full_name="A",
        version="1.0.0.0",
        culture="",
        public_key_token=None,
        module_name="A.dll",
        mvid="",
        kind="Dll",
        target_framework=".NETStandard,Version=v2.0",
        entry_point=None,
        assembly_refs=[
            {"name": "B"},
            {"name": "netstandard"},
            {"name": "Newtonsoft.Json"},
        ],
        module_refs=[],
        attributes=[],
        resources=[],
    )
    text = build_csproj(info, internal_refs={"B"})
    assert "<OutputType>Library</OutputType>" in text
    assert "<TargetFramework>netstandard2.0</TargetFramework>" in text
    assert '<ProjectReference Include="../B/B.csproj" />' in text
    assert '<Reference Include="Newtonsoft.Json" />' in text
    assert 'netstandard"' not in text


def test_interesting_strings_rank_secrets_first() -> None:
    rows = meta.interesting_strings(
        [
            ("a", "AES/CBC/PKCS7Padding"),
            ("b", "connect to https://c2.example.invalid/x"),
            ("c", "short"),
            ("d", "/proc/self/maps"),
        ]
    )
    assert [row["address"] for row in rows] == ["b", "d", "a"]


def _real_runtime() -> bool:
    from tocode.backends import dotnet_libs
    from tocode.backends.dotnet import probe_dotnet

    return probe_dotnet()[0] and dotnet_libs.is_installed()


@pytest.mark.skipif(
    not __import__("os").environ.get("TOCODE_TEST_DOTNET") or not _real_runtime(),
    reason="set TOCODE_TEST_DOTNET to a managed assembly (needs .NET 9+ and pythonnet)",
)
def test_export_real_assembly(tmp_path: Path) -> None:
    import os

    source = Path(os.environ["TOCODE_TEST_DOTNET"])
    summary = export_dotnet(
        source,
        options=DotnetExportOptions(out_dir=tmp_path / "export", native=False, jobs=1),
        progress=Progress(enabled=False),
    )

    assert summary.type_count > 0 and not summary.failed_types
    index = json.loads((summary.root_dir / "function-index.json").read_text())
    with_body = [row for row in index["functions"] if row["asm"]]
    assert with_body and all(row["asm"]["line_start"] > 1 for row in with_body)
    cs_files = list((summary.root_dir / "src" / "raw").rglob("*.cs"))
    il_files = list((summary.root_dir / "src" / "raw").rglob("*.il"))
    assert cs_files and len(il_files) == len(cs_files)


def test_suspicious_apis_ignore_compiler_generated_calls(
    tmp_path: Path, assembly: Path
) -> None:
    from tocode.backends.dotnet import discover_dotnet_input

    session = FakeSession(discover_dotnet_input(assembly, workdir=tmp_path / "work"))
    session.load()
    session.methods[0].external_calls = [
        "[System.Runtime]!!0 System.Activator::CreateInstance<!!0>()",
        "[System.Runtime]System.Int32 System.Environment::get_CurrentManagedThreadId()",
        "[System.Runtime]System.Object System.Activator::CreateInstance(System.Type)",
        "[System.Runtime]System.String System.Environment::GetEnvironmentVariable(System.String)",
    ]
    session.methods[2].external_calls = []

    found = {
        row["category"]: [api["name"] for api in row["apis"]]
        for row in meta.suspicious_apis(session)
    }

    assert found == {
        "dynamic code loading / reflection": [
            "[System.Runtime]System.Object System.Activator::CreateInstance(System.Type)"
        ],
        "environment / host info": [
            "[System.Runtime]System.String System.Environment::GetEnvironmentVariable(System.String)"
        ],
    }
