"""Changes to the database: the edit tools and saving.

Every edit goes through this module so the session knows which functions it
made stale: the function itself, and for renames and prototype changes its
callers (their decompiled text names it). ``sync`` re-renders exactly those,
plus whatever its own diff of the database finds.

One small adapter per backend; angr is query-only.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from .worker import LiveSession

from .worker import OpError

_IDENT_RX = re.compile(r"^[A-Za-z_$?@.][\w$?@.:<>~]*$")
_TYPE_NAMES_RX = re.compile(
    r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{|typedef\b[^;]*?\b([A-Za-z_]\w*)\s*;",
    re.S,
)


# --------------------------------------------------------------------------
# Saving
# --------------------------------------------------------------------------


def database_path(live: "LiveSession") -> Path | None:
    """The database this session writes to."""
    if live.target.database is not None:
        return live.target.database
    value = getattr(live.session, "_cache_db", None)
    return Path(value) if value else None


def save_database(live: "LiveSession") -> dict[str, Any]:
    backend = live.backend
    path = database_path(live)
    if backend == "ida":
        import ida_loader  # type: ignore[import-not-found]

        if path is None:
            return {"saved": False, "reason": "no database path for this session"}
        ok = bool(ida_loader.save_database(str(path), 0))
        if ok:
            live._edited = False
        return {"saved": ok, "database": str(path)}
    if backend == "binja":
        from ..backends.binja_headless import can_create_databases

        bv = getattr(live.session, "_bv", None)
        bn = getattr(live.session, "_bn", None)
        if bv is None or bn is None:
            return {"saved": False, "reason": "no Binary Ninja view"}
        if not can_create_databases(bn, getattr(live.session, "binja_dir", None)):
            return {
                "saved": False,
                "reason": "this Binary Ninja cannot save databases headless; "
                "edits last for this session only",
            }
        if path is not None and path.suffix.lower() == ".bndb" and path.is_file():
            ok = bool(bv.file.save_auto_snapshot())
        else:
            path = path or _default_bndb(live)
            ok = bool(bv.create_database(str(path)))
        if ok:
            live._edited = False
        return {"saved": ok, "database": str(path) if path else None}
    return {
        "saved": False,
        "reason": f"the {backend} backend keeps edits for this session only",
    }


def _default_bndb(live: "LiveSession") -> Path:
    base = live.target.export_dir or live.target.binary.parent
    return base / f"{live.target.binary.stem}.bndb"


# --------------------------------------------------------------------------
# Edit operations
# --------------------------------------------------------------------------


def register(live: "LiveSession") -> None:
    ops: dict[str, Callable[[dict[str, Any]], Any]] = {
        "rename": lambda args: _rename(live, args),
        "rename_many": lambda args: _rename_many(live, args),
        "set_type": lambda args: _set_type(live, args),
        "set_comment": lambda args: _set_comment(live, args),
        "declare_types": lambda args: _declare_types(live, args),
        "rename_local": lambda args: _rename_local(live, args),
        "set_local_type": lambda args: _set_local_type(live, args),
        "define_function": lambda args: _define_function(live, args),
        "undefine": lambda args: _undefine(live, args),
    }
    live.ops.update(ops)
    live.edit_ops = set(ops)


def _adapter(live: "LiveSession") -> "_Backend":
    if not live.allow_edits:
        raise OpError("edits are disabled for this server (--read-only)")
    backend = live.backend
    if backend == "ida":
        return _Ida(live)
    if backend == "binja":
        return _Binja(live)
    if backend == "r2":
        return _R2(live)
    raise OpError(
        f"the {backend} backend is query-only; use IDA, Binary Ninja, or r2 to edit"
    )


def _edited(live: "LiveSession", *addresses: int) -> list[str]:
    live._edited = True
    for address in addresses:
        live.dirty.add(address)
    return sorted(hex(item) for item in addresses)


def _callers(live: "LiveSession", address: int) -> list[int]:
    return list(live.analysis.callers.get(address, []))


def _users(live: "LiveSession", address: int) -> list[int]:
    """Functions that read or write a data address."""
    users = set()
    refs = live.analysis.data_xrefs.get(address)
    if refs is None:
        try:
            refs = live.session.data_xrefs([address]).get(address, [])
        except Exception:  # noqa: BLE001
            refs = []
    for source, _write in refs or []:
        owner = live.routine_at(source)
        if owner is not None:
            users.add(owner.address)
    return sorted(users)


def _rename(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    address = live.resolve(args.get("target"))
    name = str(args.get("name") or "").strip()
    if not name or not _IDENT_RX.match(name):
        raise OpError(f"{name!r} is not a valid name")
    backend = _adapter(live)
    routine = live.analysis.routines.get(address)
    if routine is not None:
        old = routine.name
        backend.rename_function(address, name)
        routine.name = name
        live.reindex()
        touched = _edited(live, address, *_callers(live, address))
        return {
            "address": hex(address),
            "old": old,
            "name": name,
            "kind": "function",
            "pending_sync": touched,
        }
    backend.rename_data(address, name)
    for symbol in live.analysis.symbols:
        if symbol.vaddr == address:
            symbol.name = name
    live.assigned_names[name] = address
    live.reindex()
    touched = _edited(live, *_users(live, address))
    live.globals_changed = True
    return {
        "address": hex(address),
        "name": name,
        "kind": "data",
        "pending_sync": touched,
    }


def _rename_many(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    renames = args.get("renames") or []
    if not isinstance(renames, list) or not renames:
        raise OpError("rename_many needs `renames`: a list of {target, name}")
    done, errors, pending = 0, [], set()
    # Resolve every target first: names refer to the state before the batch.
    resolved = []
    for item in renames:
        try:
            resolved.append((item, live.resolve(item.get("target"))))
        except OpError as exc:
            errors.append({"target": item.get("target"), "error": str(exc)})
    for item, address in resolved:
        try:
            result = _rename(live, {"target": address, "name": item.get("name")})
        except OpError as exc:
            errors.append({"target": item.get("target"), "error": str(exc)})
            continue
        done += 1
        pending.update(result["pending_sync"])
    return {"renamed": done, "errors": errors, "pending_sync": sorted(pending)}


def _set_type(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    address = live.resolve(args.get("target"))
    decl = str(args.get("c_decl") or "").strip().rstrip(";")
    if not decl:
        raise OpError(
            "set_type needs a C declaration, e.g. `int parse(char *buf, int len)`"
        )
    backend = _adapter(live)
    routine = live.analysis.routines.get(address)
    if routine is not None:
        backend.set_function_type(address, decl)
        routine.signature = decl
        live.stale = True  # params/locals change: collect them again lazily
        touched = _edited(live, address, *_callers(live, address))
        return {
            "address": hex(address),
            "c_decl": decl,
            "kind": "function",
            "pending_sync": touched,
        }
    backend.set_data_type(address, decl)
    live.globals_changed = True
    touched = _edited(live, *_users(live, address))
    return {
        "address": hex(address),
        "c_decl": decl,
        "kind": "data",
        "pending_sync": touched,
    }


def _set_comment(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    address = live.resolve(args.get("address"), what="address")
    text = str(args.get("text") or "")
    kind = args.get("kind") or "line"
    owner = live.routine_at(address)
    if kind == "function" and owner is None:
        raise OpError(f"no function at {hex(address)} for a function comment")
    backend = _adapter(live)
    if kind == "function":
        assert owner is not None
        backend.function_comment(owner.address, text)
    elif kind == "line":
        backend.line_comment(address, text)
    else:
        raise OpError("kind must be line or function")
    touched = _edited(live, *([owner.address] if owner else []))
    return {"address": hex(address), "kind": kind, "pending_sync": touched}


def _declare_types(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    source = str(args.get("c_source") or "").strip()
    if not source:
        raise OpError(
            "declare_types needs C declarations (structs, unions, enums, typedefs)"
        )
    backend = _adapter(live)
    backend.declare_types(source)
    names = sorted(
        {
            first or second
            for first, second in _TYPE_NAMES_RX.findall(source)
            if first or second
        }
    )
    live.types_changed = True
    live._edited = True
    live.refresh_types()
    return {"declared": names, "pending_sync": "functions using these types"}


def _function(live: "LiveSession", args: dict[str, Any]) -> int:
    return live.function_for(args.get("function")).address


def _rename_local(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    address = _function(live, args)
    old = str(args.get("old") or "")
    new = str(args.get("new") or "").strip()
    if not old or not new or not _IDENT_RX.match(new):
        raise OpError("rename_local needs `old` and a valid `new` name")
    _adapter(live).rename_local(address, old, new)
    live.stale = True
    return {
        "function": hex(address),
        "old": old,
        "new": new,
        "pending_sync": _edited(live, address),
    }


def _set_local_type(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    address = _function(live, args)
    name = str(args.get("name") or "")
    c_type = str(args.get("c_type") or "").strip().rstrip(";")
    if not name or not c_type:
        raise OpError("set_local_type needs `name` and `c_type`")
    _adapter(live).set_local_type(address, name, c_type)
    live.stale = True
    return {
        "function": hex(address),
        "name": name,
        "c_type": c_type,
        "pending_sync": _edited(live, address),
    }


def _define_function(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    address = live.resolve(args.get("address"), what="address")
    _adapter(live).define_function(address)
    live.stale = True
    live.functions_changed = True
    return {"address": hex(address), "pending_sync": _edited(live, address)}


def _undefine(live: "LiveSession", args: dict[str, Any]) -> dict[str, Any]:
    address = live.resolve(args.get("address"), what="address")
    routine = live.analysis.routines.get(address)
    callers = _callers(live, address) if routine is not None else []
    _adapter(live).undefine(address, routine is not None)
    live.stale = True
    live.functions_changed = True
    return {"address": hex(address), "pending_sync": _edited(live, *callers)}


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------


class _Backend:
    def __init__(self, live: "LiveSession") -> None:
        self.live = live
        self.session: Any = live.session

    def _fail(self, what: str) -> OpError:
        return OpError(f"{self.live.backend} could not {what}")

    def rename_function(self, address: int, name: str) -> None:
        raise self._fail("rename functions")

    def rename_data(self, address: int, name: str) -> None:
        raise self._fail("rename data")

    def set_function_type(self, address: int, decl: str) -> None:
        raise self._fail("set function types")

    def set_data_type(self, address: int, decl: str) -> None:
        raise self._fail("set data types")

    def function_comment(self, address: int, text: str) -> None:
        raise self._fail("set function comments")

    def line_comment(self, address: int, text: str) -> None:
        raise self._fail("set comments")

    def declare_types(self, source: str) -> None:
        raise self._fail("declare types")

    def rename_local(self, function: int, old: str, new: str) -> None:
        raise self._fail("rename local variables")

    def set_local_type(self, function: int, name: str, c_type: str) -> None:
        raise self._fail("set local variable types")

    def define_function(self, address: int) -> None:
        raise self._fail("define functions")

    def undefine(self, address: int, is_function: bool) -> None:
        raise self._fail("undefine")


class _Ida(_Backend):
    def _modules(self) -> Any:
        import ida_bytes  # type: ignore[import-not-found]
        import ida_funcs  # type: ignore[import-not-found]
        import ida_name  # type: ignore[import-not-found]
        import idc  # type: ignore[import-not-found]

        return ida_bytes, ida_funcs, ida_name, idc

    def _set_name(self, address: int, name: str) -> None:
        _, _, ida_name, _ = self._modules()
        flags = ida_name.SN_CHECK | getattr(ida_name, "SN_NOWARN", 0)
        if not ida_name.set_name(address, name, flags):
            raise OpError(
                f"IDA refused the name {name!r} at {hex(address)} (already used, or invalid)"
            )
        self._forget(address)

    def _forget(self, address: int) -> None:
        """Drop cached decompilations so the next render sees the edit."""
        try:
            import ida_hexrays  # type: ignore[import-not-found]

            ida_hexrays.mark_cfunc_dirty(address, False)
        except Exception:  # noqa: BLE001 - no decompiler, nothing cached
            pass
        cache = getattr(self.session, "_locals_cache", None)
        if isinstance(cache, dict):
            cache.clear()

    def rename_function(self, address: int, name: str) -> None:
        self._set_name(address, name)

    def rename_data(self, address: int, name: str) -> None:
        self._set_name(address, name)

    def _apply(self, address: int, decl: str) -> None:
        _, _, _, idc = self._modules()
        if not idc.SetType(address, decl + ";"):
            raise OpError(f"IDA could not parse or apply the type {decl!r}")
        self._forget(address)

    def set_function_type(self, address: int, decl: str) -> None:
        self._apply(address, decl)

    def set_data_type(self, address: int, decl: str) -> None:
        self._apply(address, decl)

    def function_comment(self, address: int, text: str) -> None:
        _, ida_funcs, _, _ = self._modules()
        func = ida_funcs.get_func(address)
        if func is None or not ida_funcs.set_func_cmt(func, text, False):
            raise self._fail("set the function comment")
        self._forget(address)

    def line_comment(self, address: int, text: str) -> None:
        ida_bytes, _, _, _ = self._modules()
        if not ida_bytes.set_cmt(address, text, False):
            raise self._fail("set the comment")
        self._forget(address)

    def declare_types(self, source: str) -> None:
        _, _, _, idc = self._modules()
        errors = idc.parse_decls(source, getattr(idc, "PT_SILENT", 0))
        if errors is None or errors < 0 or errors > 0:
            raise OpError(f"IDA could not parse the declarations ({errors} errors)")
        try:
            import ida_hexrays  # type: ignore[import-not-found]

            ida_hexrays.clear_cached_cfuncs()
        except Exception:  # noqa: BLE001
            pass

    def _hexrays(self) -> Any:
        try:
            import ida_hexrays  # type: ignore[import-not-found]
        except ImportError as exc:
            raise OpError("local variables need the Hex-Rays decompiler") from exc
        return ida_hexrays

    def rename_local(self, function: int, old: str, new: str) -> None:
        ida_hexrays = self._hexrays()
        if not ida_hexrays.rename_lvar(function, old, new):
            raise OpError(
                f"no local variable {old!r} in {hex(function)} (or {new!r} is taken)"
            )
        self._forget(function)

    def set_local_type(self, function: int, name: str, c_type: str) -> None:
        ida_hexrays = self._hexrays()
        import ida_typeinf  # type: ignore[import-not-found]

        cfunc = ida_hexrays.decompile(function)
        if cfunc is None:
            raise OpError(f"Hex-Rays could not decompile {hex(function)}")
        lvar = next((item for item in cfunc.get_lvars() if item.name == name), None)
        if lvar is None:
            raise OpError(f"no local variable {name!r} in {hex(function)}")
        tif = ida_typeinf.tinfo_t()
        if (
            ida_typeinf.parse_decl(
                tif, None, f"{c_type} __tocode_v;", ida_typeinf.PT_SIL
            )
            is None
        ):
            raise OpError(f"IDA could not parse the type {c_type!r}")
        info = ida_hexrays.lvar_saved_info_t()
        info.ll = lvar
        info.type = tif
        if not ida_hexrays.modify_user_lvar_info(function, ida_hexrays.MLI_TYPE, info):
            raise OpError(f"IDA could not retype {name!r}")
        self._forget(function)

    def define_function(self, address: int) -> None:
        _, ida_funcs, _, _ = self._modules()
        if not ida_funcs.add_func(address):
            raise OpError(f"IDA could not create a function at {hex(address)}")
        try:
            import ida_auto  # type: ignore[import-not-found]

            ida_auto.auto_wait()
        except Exception:  # noqa: BLE001
            pass

    def undefine(self, address: int, is_function: bool) -> None:
        ida_bytes, ida_funcs, _, _ = self._modules()
        if is_function:
            if not ida_funcs.del_func(address):
                raise OpError(f"IDA could not delete the function at {hex(address)}")
        elif not ida_bytes.del_items(address, 0, 1):
            raise OpError(f"IDA could not undefine {hex(address)}")


class _Binja(_Backend):
    @property
    def bv(self) -> Any:
        return self.session._bv

    @property
    def bn(self) -> Any:
        return self.session._bn

    def _func(self, address: int) -> Any:
        func = self.bv.get_function_at(address)
        if func is None:
            raise OpError(f"no Binary Ninja function at {hex(address)}")
        return func

    def _forget(self) -> None:
        for cache in ("_decompile_cache", "_disasm_cache"):
            value = getattr(self.session, cache, None)
            if isinstance(value, dict):
                value.clear()

    def _parse(self, decl: str) -> Any:
        try:
            parsed = self.bv.parse_type_string(decl)
        except Exception as exc:  # noqa: BLE001
            raise OpError(f"Binary Ninja could not parse {decl!r}: {exc}") from exc
        return parsed[0] if isinstance(parsed, tuple) else parsed

    def rename_function(self, address: int, name: str) -> None:
        self._func(address).name = name
        self._forget()

    def rename_data(self, address: int, name: str) -> None:
        bn = self.bn
        self.bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, address, name))
        self._forget()

    def set_function_type(self, address: int, decl: str) -> None:
        func = self._func(address)
        setter = getattr(func, "set_user_type", None)
        parsed = self._parse(decl)
        if callable(setter):
            setter(parsed)
        else:
            func.type = parsed
        self._forget()

    def set_data_type(self, address: int, decl: str) -> None:
        self.bv.define_user_data_var(address, self._parse(decl))
        self._forget()

    def function_comment(self, address: int, text: str) -> None:
        self._func(address).comment = text
        self._forget()

    def line_comment(self, address: int, text: str) -> None:
        owner = self.live.routine_at(address)
        if owner is not None:
            self._func(owner.address).set_comment_at(address, text)
        else:
            self.bv.set_comment_at(address, text)
        self._forget()

    def declare_types(self, source: str) -> None:
        try:
            result = self.bv.parse_types_from_string(source)
        except Exception as exc:  # noqa: BLE001
            raise OpError(
                f"Binary Ninja could not parse the declarations: {exc}"
            ) from exc
        for kind in ("types", "variables", "functions"):
            for name, type_obj in dict(getattr(result, kind, {}) or {}).items():
                if kind == "types":
                    self.bv.define_user_type(name, type_obj)
        self._forget()

    def _var(self, function: int, name: str) -> tuple[Any, Any]:
        func = self._func(function)
        for var in list(getattr(func, "vars", [])):
            if getattr(var, "name", None) == name:
                return func, var
        raise OpError(f"no local variable {name!r} in {hex(function)}")

    def rename_local(self, function: int, old: str, new: str) -> None:
        func, var = self._var(function, old)
        func.create_user_var(var, var.type, new)
        self._forget()

    def set_local_type(self, function: int, name: str, c_type: str) -> None:
        func, var = self._var(function, name)
        func.create_user_var(var, self._parse(c_type), name)
        self._forget()

    def define_function(self, address: int) -> None:
        self.bv.add_user_function(address)
        self.bv.update_analysis_and_wait()

    def undefine(self, address: int, is_function: bool) -> None:
        if is_function:
            self.bv.remove_user_function(self._func(address))
        else:
            self.bv.undefine_user_data_var(address)


class _R2(_Backend):
    def _cmd(self, command: str) -> str:
        output = str(self.session.cmd(command) or "")
        if "ERROR" in output or "Cannot" in output:
            raise OpError(f"r2: {output.strip()[:300]}")
        return output

    def rename_function(self, address: int, name: str) -> None:
        self._cmd(f"afn {name} @ {address:#x}")

    def rename_data(self, address: int, name: str) -> None:
        self._cmd(f"f {name} @ {address:#x}")

    def set_function_type(self, address: int, decl: str) -> None:
        self._cmd(f"afs {decl} @ {address:#x}")

    def function_comment(self, address: int, text: str) -> None:
        self.line_comment(address, text)

    def line_comment(self, address: int, text: str) -> None:
        self._cmd(f"CCu base64:{_b64(text)} @ {address:#x}")

    def declare_types(self, source: str) -> None:
        self._cmd(f'td "{source}"'.replace("\n", " "))

    def rename_local(self, function: int, old: str, new: str) -> None:
        self._cmd(f"afvn {new} {old} @ {function:#x}")

    def set_local_type(self, function: int, name: str, c_type: str) -> None:
        self._cmd(f"afvt {name} {c_type} @ {function:#x}")

    def define_function(self, address: int) -> None:
        self._cmd(f"af @ {address:#x}")

    def undefine(self, address: int, is_function: bool) -> None:
        self._cmd(f"af- @ {address:#x}" if is_function else f"Cd- @ {address:#x}")


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")
