# Bundled .NET libraries

ToCode's .NET backend loads these assemblies in-process through pythonnet, so
exporting a .NET binary needs only a .NET 9+ runtime -- no dnSpy/ILSpy install.
They are the unmodified `lib/netstandard2.0/` assemblies of the NuGet packages
below (both MIT licensed; license texts are next to them).

| File | NuGet package | Version | nupkg sha256 | dll sha256 |
| --- | --- | --- | --- | --- |
| `dnlib.dll` | [dnlib](https://www.nuget.org/packages/dnlib) | 4.5.0 | `63bc2f9579568204cc8b30fa9f6700a231bcf868a8032e09118887af3eafee58` | `566fdab59c91a3c2eab14a22b67f01cb3c0cdb48fa9b9b6677e2b32998636efb` |
| `ICSharpCode.Decompiler.dll` | [ICSharpCode.Decompiler](https://www.nuget.org/packages/ICSharpCode.Decompiler) | 11.1.0.9782 | `1f76df4d35193ba4eeb50ffcd84eae381a2c48c67f95c1104dc406759448a811` | `38e6abf7497845d79d9d01d56351a3203991356de1d3496b8c51142f495e9f9c` |

ICSharpCode.Decompiler 11.x references System.Reflection.Metadata and
System.Collections.Immutable 9.0, which ship inbox with the .NET 9+ runtime;
that is why the backend requires .NET 9 or newer.

To update: download the `.nupkg` from nuget.org, extract
`lib/netstandard2.0/<name>.dll`, and update the hashes above and in
`tests/test_dotnet_backend.py`.
