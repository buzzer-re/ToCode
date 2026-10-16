# ToCode MCP tools

Every tool except `open` and `sessions` takes `session`: the id `open` returned, a folder
binary's relative path (`bin/app`, or `<folder>:bin/app`), or nothing when one session is open.
Targets and addresses accept `0x...` addresses or names (auto names like `sub_401000` too).
List tools page with `offset`/`limit` and return `total` and `next_offset`.

## Sessions

### `open`

Open a binary or database and keep it alive for the other tools. `path` is an export folder (made by `tocode <binary>`), a folder export, a binary, or a database (.i64/.idb/.bndb). By default an export's own database is used; pass `database` to edit another one. Returns the session id (a folder returns its binaries; address them as `session`=<relative path>).

- `path` (required): string. Export folder, folder export, binary, or database
- `database`: string. Database to open instead of the export's own copy
- `backend`: `auto` | `ida` | `binja` | `r2` | `angr`. Backend for a plain binary (databases pick their own)

### `sessions`

List open sessions and folders.

### `close`

Close a session (saving its database unless `save` is false).

- `save`: boolean

## Query

### `info`

Binary facts, backend, counts, database and export folder.

### `functions`

List functions (address, name, size, signature, kind, caller/callee counts).

- `filter`: string. Case-insensitive regular expression (or substring) to match
- `kind`: `all` | `app` | `library` | `import` | `thunk` | `runtime`
- `offset`: integer. First row to return
- `limit`: integer. Rows per page

### `function`

One function: prototype, params, locals, callers, callees, imports it calls, and where it is in the export (file:lines).

- `target` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`

### `decompile`

Decompile a function now, from the live database (reflects edits).

- `target` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`

### `disassemble`

Disassemble a function from the live database.

- `target` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `max_lines`: integer

### `xrefs`

Cross-references: `to` (callers and data reads/writes of the target) or `from` (what a function calls).

- `target` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `direction`: `to` | `from`

### `strings`

Strings with the functions that use them.

- `filter`: string. Case-insensitive regular expression (or substring) to match
- `offset`: integer. First row to return
- `limit`: integer. Rows per page

### `imports`

Imported symbols and their libraries.

- `filter`: string. Case-insensitive regular expression (or substring) to match
- `offset`: integer. First row to return
- `limit`: integer. Rows per page

### `exports`

Exported symbols.

- `filter`: string. Case-insensitive regular expression (or substring) to match
- `offset`: integer. First row to return
- `limit`: integer. Rows per page

### `sections`

Sections/segments with addresses, sizes and permissions.

### `types`

Types in the database (structs, unions, enums, typedefs).

- `filter`: string. Case-insensitive regular expression (or substring) to match
- `kind`: `struct` | `union` | `enum` | `typedef` | `func`
- `offset`: integer. First row to return
- `limit`: integer. Rows per page

### `type`

One type's C declaration and members.

- `name` (required): string

### `read_bytes`

Read bytes at an address (hex and ASCII, at most 64 KiB).

- `address` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `size`: integer

### `search`

Search the binary's sections for text, hex bytes (`de ad be ef`), or a byte regex; returns addresses and the functions containing them.

- `pattern` (required): string
- `kind`: `text` | `hex` | `regex`
- `limit`: integer

### `lookup`

Find functions and symbols whose name contains `name`.

- `name` (required): string
- `limit`: integer

### `status`

What the next `sync` will update (functions changed in this session).

## Edit

### `save`

Save the session's database so edits survive the session.

### `rename`

Rename a function or a global. Callers pick up the new name on the next `sync`.

- `target` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `name` (required): string. New name (a C identifier)

### `rename_many`

Rename many functions, types, members, or globals in one call (deobfuscation passes). Each entry is {target, name}; failures are reported per entry and do not stop the rest.

- `renames` (required): array

### `set_type`

Set a function's prototype (`int parse(char *buf, size_t len)`) or a global's type (`struct config *g_config`).

- `target` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `c_decl` (required): string

### `set_comment`

Comment an instruction (`line`) or a whole function (`function`).

- `address` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `text` (required): string
- `kind`: `line` | `function`

### `declare_types`

Add or replace C types (structs, unions, enums, typedefs) in the database, e.g. `struct packet { uint16_t len; uint8_t type; uint8_t payload[]; };`.

- `c_source` (required): string

### `rename_local`

Rename a local variable or parameter of a function (as the decompiler names it).

- `function` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `old` (required): string
- `new` (required): string

### `set_local_type`

Set the type of a function's local variable or parameter.

- `function` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`
- `name` (required): string
- `c_type` (required): string

### `define_function`

Create a function at an address the analysis missed.

- `address` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`

### `undefine`

Delete the function (or undefine the data) at an address.

- `address` (required): string. Function or symbol: an address (`0x401000`) or a name. For .NET: `Assembly!0x06000012`, `Namespace.Type`, or `Namespace.Type::Member`

## Project

### `sync`

Update the export on disk from the database: new functions are added next to their callers, renamed/retyped functions and their callers and every function using a changed type are re-rendered, and only files whose content changed are rewritten (plus the JSON and headers). `mode`=`full` re-renders everything (after changes made outside this server, e.g. in the IDA UI); `addresses` forces some functions. Saves the database when it changed.

- `mode`: `auto` | `full`
- `addresses`: array

### `export`

Write a ToCode export for a session opened on a plain binary (default folder: <binary>_decompiler next to it).

- `out_dir`: string

## Script

### `eval`

Run a script inside the database. Python by default: the last expression (or `result`) is returned and stdout is captured. Names: IDA `db` (ida-domain) plus idaapi/idc/ida_* modules; Binary Ninja `bv`, `bn`; r2 `r2` (`r2.cmd(...)`); angr `project`; everywhere `session`, `analysis`, `resolve(name)`, and `touch(addr, ...)` to mark functions your script changed for the next `sync`. Names you define persist between calls (`reset` clears them). `language`=`r2` runs an r2 command.

- `code` (required): string
- `language`: `python` | `r2`
- `reset`: boolean
- `timeout`: number. Seconds (default 300)
