"""Link facts between the binaries of a folder.

Everything here is pure Python and reads the files directly: the import and
export tables the linker wrote, and the loader rules that consume them. No
decompiler backend is involved, so a whole application folder can be mapped
in seconds and the result does not depend on how a backend names symbols.
"""
