"""ToCode live: an MCP server over live decompiler sessions.

``tocode mcp`` keeps IDA / Binary Ninja / r2 / angr sessions open in worker
processes (one per binary or database) and exposes them as MCP tools over
stdio: queries (decompile, disassemble, xrefs, ...), edits (rename, types,
comments), ``eval`` inside the database, and ``sync``, which updates an
exported project from the database incrementally.

Modules: ``jsonrpc`` (stdio transport), ``targets`` (what ``open`` resolves
to), ``worker`` (the per-session process and its operations), ``sessions``
(worker lifecycle), ``tools`` (the MCP tool table), ``server`` (entry point).
"""
