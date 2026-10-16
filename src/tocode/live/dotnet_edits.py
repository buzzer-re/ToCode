"""Edits to .NET assemblies: the edit log and the edit tools.

The log (``.tocode/dotnet/edits.json``) is the session's database: an ordered
list of edits addressed by assembly and metadata token, replayed onto the
original assemblies whenever a session opens. Renames of types, members, and
parameters change the dnlib modules (and so the patched copies); local
variable renames and comments are text edits applied when C# is rendered,
because neither lives in an assembly's metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any, Callable

from ..metadata import write_text_atomic
from .worker import OpError

if TYPE_CHECKING:
    from .dotnet_live import DotnetLiveSession, Entity

LOG_SCHEMA = 1
_IDENT_RX = re.compile(r"^[A-Za-z_][\w`]*$")
_NAMESPACE_RX = re.compile(r"^[A-Za-z_][\w.]*$")
_UNSUPPORTED = {
    "set_type": "types in .NET come from metadata; rename the type or member instead",
    "declare_types": "types in .NET come from metadata; rename the type or member instead",
    "set_local_type": "local variable types come from metadata; rename the local instead",
    "define_function": "every .NET method is already defined in metadata",
    "undefine": "removing .NET methods would break the assembly",
}


@dataclass
class EditLog:
    path: Path
    entries: list[dict[str, Any]] = field(default_factory=list)
    synced: int = 0  # entries already reflected in the export

    @classmethod
    def open(cls, path: Path) -> "EditLog":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls(path=path)
        if not isinstance(payload, dict) or payload.get("schema") != LOG_SCHEMA:
            return cls(path=path)
        entries = [
            entry for entry in payload.get("edits", []) if isinstance(entry, dict)
        ]
        return cls(
            path=path,
            entries=entries,
            synced=min(int(payload.get("synced") or 0), len(entries)),
        )

    def save(self) -> None:
        write_text_atomic(
            self.path,
            json.dumps(
                {"schema": LOG_SCHEMA, "synced": self.synced, "edits": self.entries},
                indent=1,
            )
            + "\n",
        )

    def local_renames(self, assembly: str) -> dict[int, list[tuple[str, str]]]:
        renames: dict[int, list[tuple[str, str]]] = {}
        for entry in self.entries:
            if entry.get("op") == "rename_local" and entry.get("assembly") == assembly:
                renames.setdefault(int(entry["token"], 16), []).append(
                    (entry["old"], entry["name"])
                )
        return renames

    def comments(self, assembly: str) -> dict[int, str]:
        comments: dict[int, str] = {}
        for entry in self.entries:
            if entry.get("op") == "comment" and entry.get("assembly") == assembly:
                token = int(entry["token"], 16)
                if entry.get("text"):
                    comments[token] = str(entry["text"])
                else:
                    comments.pop(token, None)
        return comments


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------


def register(live: "DotnetLiveSession") -> None:
    ops = {
        "rename": lambda args: _rename_tool(live, args),
        "rename_many": lambda args: _rename_many(live, args),
        "rename_local": lambda args: _rename_local_tool(live, args),
        "set_comment": lambda args: _comment_tool(live, args),
    }
    for name, reason in _UNSUPPORTED.items():
        ops[name] = _refuser(name, reason)
    live.ops.update(ops)
    live.edit_ops = set(ops)


def _refuser(name: str, reason: str) -> Callable[[dict[str, Any]], Any]:
    def refuse(_args: dict[str, Any]) -> Any:
        raise OpError(f"{name} is not available for .NET: {reason}")

    return refuse


def _allowed(live: "DotnetLiveSession") -> None:
    if not live.allow_edits:
        raise OpError("edits are disabled for this server (--read-only)")


def _record(live: "DotnetLiveSession", entry: dict[str, Any]) -> list[str]:
    """Apply an edit, append it to the log, and save the log."""
    dirty = apply(live, entry)
    entry["time"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    live.edits.entries.append(entry)
    live.edits.save()
    live.dirty.update(dirty)
    live._edited = True
    return sorted(live.type_name(key) for key in dirty)


def _rename_tool(live: "DotnetLiveSession", args: dict[str, Any]) -> dict[str, Any]:
    _allowed(live)
    entity = live.resolve(args.get("target"))
    name = str(args.get("name") or "").strip()
    old = live.entity_name(entity)
    pending = _record(live, _rename_entry(live, entity, name))
    return {
        "address": entity.address(live.session),
        "kind": entity.kind,
        "old": old,
        "name": name,
        "pending_sync": pending,
    }


def _rename_entry(
    live: "DotnetLiveSession", entity: "Entity", name: str
) -> dict[str, Any]:
    if entity.kind == "type":
        if not _NAMESPACE_RX.match(name):
            raise OpError(
                f"{name!r} is not a valid type name (`Name` or `Namespace.Name`)"
            )
    elif not _IDENT_RX.match(name):
        raise OpError(f"{name!r} is not a valid identifier")
    return {
        "op": "rename",
        "kind": entity.kind,
        "assembly": live.session.assemblies[entity.assembly].name,
        "token": f"0x{entity.token:08x}",
        "old": live.entity_name(entity),
        "name": name,
    }


def _rename_many(live: "DotnetLiveSession", args: dict[str, Any]) -> dict[str, Any]:
    _allowed(live)
    renames = args.get("renames") or []
    if not isinstance(renames, list) or not renames:
        raise OpError("rename_many needs `renames`: a list of {target, name}")
    done: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    pending: set[str] = set()
    # Resolve every target first: names in the batch refer to the state
    # before it (renaming a type must not break its members' targets).
    resolved: list[tuple[dict[str, Any], Any]] = []
    for item in renames:
        try:
            resolved.append((item, live.resolve(item.get("target"))))
        except OpError as exc:
            errors.append({"target": item.get("target"), "error": str(exc)})
    for item, entity in resolved:
        try:
            name = str(item.get("name") or "").strip()
            pending.update(_record(live, _rename_entry(live, entity, name)))
            done.append(
                {
                    "target": item.get("target"),
                    "address": entity.address(live.session),
                    "name": name,
                }
            )
        except OpError as exc:
            errors.append({"target": item.get("target"), "error": str(exc)})
    return {"renamed": len(done), "errors": errors, "pending_sync": sorted(pending)}


def _rename_local_tool(
    live: "DotnetLiveSession", args: dict[str, Any]
) -> dict[str, Any]:
    _allowed(live)
    entity = live.resolve(args.get("function"), kinds=("method",))
    method = live.method_of(entity)
    old = str(args.get("old") or "")
    new = str(args.get("new") or "").strip()
    if not old or not _IDENT_RX.match(new):
        raise OpError("rename_local needs `old` and a valid `new` name")
    assembly = live.session.assemblies[entity.assembly].name
    params = [name for name, _ in method.params]
    if old in params:
        # Parameter names live in metadata: rename them in the assembly.
        entry = {
            "op": "rename_param",
            "assembly": assembly,
            "token": f"0x{entity.token:08x}",
            "index": params.index(old),
            "old": old,
            "name": new,
        }
    else:
        if not re.search(rf"\b{re.escape(old)}\b", live.csharp(entity)):
            raise OpError(
                f"no local variable {old!r} in {live.entity_name(entity)} (names as the decompiled C# shows them)"
            )
        entry = {
            "op": "rename_local",
            "assembly": assembly,
            "token": f"0x{entity.token:08x}",
            "old": old,
            "name": new,
        }
    pending = _record(live, entry)
    return {
        "function": live.entity_name(entity),
        "old": old,
        "new": new,
        "pending_sync": pending,
    }


def _comment_tool(live: "DotnetLiveSession", args: dict[str, Any]) -> dict[str, Any]:
    _allowed(live)
    entity = live.resolve(args.get("address"))
    text = str(args.get("text") or "")
    entry = {
        "op": "comment",
        "assembly": live.session.assemblies[entity.assembly].name,
        "token": f"0x{entity.token:08x}",
        "text": text,
    }
    pending = _record(live, entry)
    return {"target": live.entity_name(entity), "pending_sync": pending}


# --------------------------------------------------------------------------
# Applying edits
# --------------------------------------------------------------------------


def replay(live: "DotnetLiveSession") -> None:
    """Apply the whole log to freshly loaded assemblies."""
    for index, entry in enumerate(live.edits.entries):
        try:
            dirty = apply(live, entry)
        except OpError as exc:
            live.log(f"live: skipping edit {index} ({entry.get('op')}): {exc}")
            continue
        if index >= live.edits.synced:
            live.dirty.update(dirty)


def apply(live: "DotnetLiveSession", entry: dict[str, Any]) -> set[tuple[int, int]]:
    """Apply one edit to the loaded assemblies; return the types it makes stale."""
    from .dotnet_live import TOKEN_KINDS, Entity

    op = entry.get("op")
    assembly = live._assembly_index(str(entry.get("assembly")))
    token = int(str(entry.get("token")), 16)
    kind = TOKEN_KINDS.get(token >> 24, "")
    entity = Entity(kind, assembly, token)
    if op in ("comment", "rename_local"):
        return {live.top_level(entity)}
    module = live.session._modules[assembly]
    rid = token & 0xFFFFFF
    name = str(entry.get("name") or "")
    if op == "rename_param":
        method = module.ResolveMethod(rid)
        params = [p for p in method.Parameters if not p.IsHiddenThisParameter]
        index = int(entry.get("index") or 0)
        if index >= len(params):
            raise OpError(f"no parameter {index} in {method.FullName}")
        params[index].Name = name
        record = live.session.method(assembly, token)
        if record is not None and index < len(record.params):
            record.params[index] = (name, record.params[index][1])
        dirty = {live.top_level(entity)}
    elif op == "rename":
        dirty = _affected(live, entity)
        from dnlib.DotNet import UTF8String  # type: ignore[import-not-found]

        if kind == "type":
            definition = module.ResolveTypeDef(rid)
            if "." in name and definition.DeclaringType is None:
                namespace, _, short = name.rpartition(".")
                definition.Namespace = UTF8String(namespace)
                definition.Name = UTF8String(short)
            else:
                definition.Name = UTF8String(name)
        else:
            resolver = {
                "method": module.ResolveMethod,
                "field": module.ResolveField,
                "property": module.ResolveProperty,
                "event": module.ResolveEvent,
            }.get(kind)
            if resolver is None:
                raise OpError(f"cannot rename a {kind or 'token 0x%08x' % token}")
            definition = resolver(rid)
            if definition is None:
                raise OpError(
                    f"no {kind} 0x{token:08x} in {live.session.assemblies[assembly].name}"
                )
            definition.Name = UTF8String(name)
        _rename_in_inventory(live, entity, module)
    else:
        raise OpError(f"unknown edit {op}")
    live.unwritten.add(assembly)
    live.reload_needed = True
    return dirty


def _rename_in_inventory(
    live: "DotnetLiveSession", entity: "Entity", module: Any
) -> None:
    """Bring the inventory records and the name index up to date with a
    rename, touching only the renamed entity (and, for a type, its nested
    types and their members)."""
    from .dotnet_live import Entity

    session = live.session
    asm = entity.assembly
    if entity.kind == "type":
        top = live.top_level(entity)
        records = list(session.nested_types(top[0], top[1]))
        entities = [Entity("type", asm, r.token) for r in records]
        for record in records:
            entities += [
                Entity("method", asm, session.methods[i].token) for i in record.methods
            ]
            entities += [Entity("field", asm, m.token) for m in record.fields]
            entities += [Entity("property", asm, m.token) for m in record.properties]
            entities += [Entity("event", asm, m.token) for m in record.events]
        for item in entities:
            live.index_entity(item, remove=True)
        for record in records:
            definition = module.ResolveTypeDef(record.token & 0xFFFFFF)
            record.name = str(definition.Name)
            record.namespace = str(definition.Namespace)
            record.full_name = str(definition.FullName)
            record.reflection_name = str(definition.ReflectionFullName)
            for method_id in record.methods:
                method = session.methods[method_id]
                method_def = module.ResolveMethod(method.token & 0xFFFFFF)
                method.type_name = record.full_name
                method.full_name = str(method_def.FullName)
        for item in entities:
            live.index_entity(item)
        return
    live.index_entity(entity, remove=True)
    if entity.kind == "method":
        method = live.method_of(entity)
        method_def = module.ResolveMethod(entity.token & 0xFFFFFF)
        method.name = str(method_def.Name)
        method.full_name = str(method_def.FullName)
    else:
        record = live.type_of(entity)
        for member in record.fields + record.properties + record.events:
            if member.token == entity.token:
                resolver = {
                    "field": module.ResolveField,
                    "property": module.ResolveProperty,
                    "event": module.ResolveEvent,
                }[entity.kind]
                member.name = str(resolver(entity.token & 0xFFFFFF).Name)
    live.index_entity(entity)


def _affected(live: "DotnetLiveSession", entity: "Entity") -> set[tuple[int, int]]:
    """Types whose C# changes when ``entity`` is renamed (computed before),
    from the session's reverse indexes: no scan over all methods."""
    session = live.session
    asm = entity.assembly
    dirty = {live.top_level(entity)}
    callers: list[int] = []
    accessors: tuple[Any, ...] = ()
    if entity.kind == "method":
        callers = list(live.method_of(entity).callers)
    elif entity.kind in ("field", "property", "event"):
        record = live.type_of(entity)
        users = set(live.field_users.get((asm, entity.token), ()))
        for prop in record.properties:
            if prop.token == entity.token:
                backing = next(
                    (
                        f
                        for f in record.fields
                        if f.name == f"<{prop.name}>k__BackingField"
                    ),
                    None,
                )
                if backing is not None:
                    users |= live.field_users.get((asm, backing.token), set())
                accessors = (prop.getter, prop.setter)
                break
        else:
            accessors = next(
                ((e.add, e.remove) for e in record.events if e.token == entity.token),
                (),
            )
        for token in accessors:
            method = session.method(asm, token) if token else None
            if method is not None:
                callers += method.callers
        callers += list(users)
    else:
        # A type: every exported file that mentions its name (word index).
        return dirty | words(live).get(live.type_of(entity).name.split("`")[0], set())
    for method_id in callers:
        method = session.methods[method_id]
        owner = session.types.get((method.assembly, method.type_token))
        if owner is not None:
            dirty.add((method.assembly, owner.top_level or owner.token))
    return dirty


_WORD_RX = re.compile(r"[A-Za-z_]\w*")


def words(live: "DotnetLiveSession") -> dict[str, set[tuple[int, int]]]:
    """Identifier -> exported types whose C# file contains it.

    Built once from the export's files and kept until the next sync rewrites
    them, so a type rename finds its users with one lookup.
    """
    cached = live._words
    if cached is not None:
        return cached
    from .dotnet_sync import disk_layout

    index: dict[str, set[tuple[int, int]]] = {}
    for key, row in disk_layout(live).types.items():
        record = live.session.types.get(key)
        if record is None or record.declaring_type is not None:
            continue  # nested types share their top-level type's file
        try:
            text = Path(row["cs_path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for word in set(_WORD_RX.findall(text)):
            index.setdefault(word, set()).add(key)
    live._words = index
    return index


def apply_text_edits(
    live: "DotnetLiveSession",
    assembly: int,
    text: str,
    ranges: dict[int, tuple[int, int]],
    offset: int,
) -> tuple[str, dict[int, tuple[int, int]]]:
    """Local renames and comments, applied to decompiled C#.

    ``ranges`` maps member tokens to their (first, last) lines in ``text``
    minus ``offset``; the returned ranges follow the inserted comment lines.
    """
    name = live.session.assemblies[assembly].name
    renames = live.edits.local_renames(name)
    comments = live.edits.comments(name)
    if not renames and not comments:
        return text, ranges
    lines = text.split("\n")
    for token, pairs in renames.items():
        span = ranges.get(token)
        if span is None:
            continue
        start, end = span[0] + offset - 1, span[1] + offset
        for index in range(max(0, start), min(end, len(lines))):
            for old, new in pairs:
                lines[index] = re.sub(rf"\b{re.escape(old)}\b", new, lines[index])
    inserts = sorted(
        (
            (ranges[token][0] + offset, comment)
            for token, comment in comments.items()
            if token in ranges
        ),
        reverse=True,
    )
    for line_number, comment in inserts:
        position = max(0, line_number - 1)
        anchor = lines[position] if position < len(lines) else ""
        indent = anchor[: len(anchor) - len(anchor.lstrip())]
        lines[position:position] = [
            f"{indent}// {part}" for part in comment.splitlines() or [""]
        ]
    points = sorted(
        (line, len(comment.splitlines() or [""])) for line, comment in inserts
    )

    def before(line: int, inclusive: bool) -> int:
        return sum(
            size
            for point, size in points
            if point < line or (inclusive and point <= line)
        )

    moved = {
        token: (start + before(start + offset, False), end + before(end + offset, True))
        for token, (start, end) in ranges.items()
    }
    return "\n".join(lines), moved
