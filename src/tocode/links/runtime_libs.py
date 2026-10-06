"""Recognise bundled runtime/framework libraries by file name.

These are linked like any other file but only decompiled with
``--include-framework``: a VC++ runtime, the .NET shared framework, or a copy
of libstdc++ is the same code in every application that ships it.
"""

from __future__ import annotations

import re

from ..backends.dotnet import is_framework_assembly, is_framework_native

_NATIVE_RUNTIME_RX = re.compile(
    r"^("
    # Microsoft C/C++ runtimes and API set forwarders
    r"msvc[pr]\d+[a-z]*|vcruntime\d+(_\d+)?|ucrtbased?|concrt\d+|vccorlib\d+|"
    r"vcomp\d+|mfc\d+[a-z]*|atl\d+|api-ms-win-.*|ext-ms-win-.*|"
    # MinGW runtimes
    r"libgcc_s_[a-z0-9_]+-\d+|libstdc\+\+-\d+|libwinpthread-\d+|libgomp-\d+|"
    # glibc / GCC / LLVM runtime copies on Linux and macOS
    r"libc|libm|libdl|librt|libpthread|libresolv|libutil|ld-linux(-[a-z0-9_-]+)?|"
    r"libstdc\+\+|libgcc_s|libatomic|libgomp|libc\+\+(abi)?|libunwind"
    r")(\.dll|\.so(\.[0-9.]+)?|\.dylib|\.[0-9.]+\.dylib)?$",
    re.IGNORECASE,
)


def is_runtime_library(name: str, *, managed: bool) -> bool:
    if managed:
        return is_framework_assembly(name)
    return bool(_NATIVE_RUNTIME_RX.match(name)) or is_framework_native(name)
