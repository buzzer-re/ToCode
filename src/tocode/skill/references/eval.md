# `eval` recipes

`eval` runs Python inside the session's analysis process. The last expression
(or a variable named `result`) is returned as JSON; `print` output comes back
in `stdout`. Names you define persist between calls (`reset=true` clears them).

Always available: `session`, `analysis` (ToCode's inventory), `resolve(name)`
(name or `0x...` to an address), and `touch(addr, ...)` (mark functions your
script changed so the next `sync` re-renders them).

Renames and prototype changes made in a script are found by `sync` on its
own (it diffs the database against the export). Changes inside a function
body (local variable names, comments) are not: `touch` those functions, or
run `sync` with `mode="full"`.

Keep scripts bounded. A call that outlives its `timeout` (default 300 s) stops
the session's worker; unsaved edits since the last `save`/`sync` are lost.

## IDA (`db` is the ida-domain database; `idaapi`, `idc`, `idautils`, `ida_*` are imported)

Functions that call a function (for imports, use the `xrefs` tool: it follows
the PLT/thunk stub to the real callers):

```python
import idautils, ida_funcs
target = resolve("parse_config")
sorted({hex(ida_funcs.get_func(x.frm).start_ea) for x in idautils.XrefsTo(target)
        if ida_funcs.get_func(x.frm)})
```

Find an immediate constant (crypto constants, magic values):

```python
import idautils, idc
hits = []
for f in idautils.Functions():
    for ea in idautils.FuncItems(f):
        for n in range(3):
            if idc.get_operand_type(ea, n) == idc.o_imm and idc.get_operand_value(ea, n) == 0x67452301:
                hits.append((hex(f), hex(ea)))
hits
```

Pseudocode of a function as text, and its local variables:

```python
import ida_hexrays
cfunc = ida_hexrays.decompile(resolve("parse_config"))
[(v.name, str(v.type())) for v in cfunc.get_lvars()], str(cfunc)[:2000]
```

Bulk renames (each also reported by the next `sync`):

```python
import idc
for ea, name in [(0x401200, "read_header"), (0x401340, "check_crc")]:
    assert idc.set_name(ea, name, idc.SN_CHECK), name
"ok"
```

Rename a local variable through Hex-Rays (then `touch` the function):

```python
import ida_hexrays
f = resolve("parse_config")
ida_hexrays.rename_lvar(f, "v3", "cursor")
touch(f)
```

Read memory and strings:

```python
import ida_bytes, idc
ida_bytes.get_bytes(0x403000, 32).hex(), idc.get_strlit_contents(0x403020, -1, idc.STRTYPE_C)
```

Segments and entry points:

```python
import idautils, idc
[(idc.get_segm_name(s), hex(s), hex(idc.get_segm_end(s))) for s in idautils.Segments()]
```

## Binary Ninja (`bv` is the BinaryView, `bn` the module)

High-level IL of a function:

```python
f = bv.get_function_at(resolve("main"))
[str(line) for line in f.hlil.instructions][:40]
```

Code references to an address, and the functions they are in:

```python
[(hex(r.address), r.function.name) for r in bv.get_code_refs(resolve("strcpy"))]
```

Define a type and apply it to a global:

```python
t = bv.parse_type_string("struct packet { uint16_t len; uint8_t kind; uint8_t data[]; }")[0]
bv.define_user_type("packet", t)
bv.define_user_data_var(0x404010, bv.parse_type_string("struct packet *")[0])
```

Rename a variable (then `touch` the function):

```python
f = bv.get_function_at(resolve("handle_packet"))
var = next(v for v in f.vars if v.name == "var_18")
f.create_user_var(var, var.type, "pkt")
touch(f.start)
```

Strings referenced from a function:

```python
f = bv.get_function_at(resolve("main"))
[s.value for s in bv.get_strings() if any(r.function == f for r in bv.get_code_refs(s.start))]
```

## radare2 (`language="r2"` runs a command; in Python, `r2.cmd(...)` / `r2.cmdj(...)`)

| Command | Purpose |
| --- | --- |
| `afl~crypt` | functions whose name contains crypt |
| `pdf @ main` | disassemble a function |
| `pdg @ main` | decompile (r2ghidra) |
| `axt @ sym.imp.strcpy` | references to an import |
| `/x deadbeef` | search bytes |
| `izz~http` | strings containing http |
| `afvn new old @ fcn` | rename a local variable |

```python
[f["name"] for f in r2.cmdj("aflj") if f["size"] > 1000]
```

## angr (`project` is the angr Project; query-only)

```python
cfg = project.analyses.CFGFast(normalize=True)
[hex(a) for a in cfg.kb.functions.callgraph.predecessors(resolve("encrypt"))]
```
