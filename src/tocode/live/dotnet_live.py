"""The live session for .NET: assemblies through dnlib and ICSharpCode.

The "database" of a .NET session is an edit log (renames and comments,
addressed by metadata token) plus renamed copies of the assemblies written
from it (``<export>/patched/``). Opening loads the original input, replays the
log, and decompiles from the patched copies; the originals are never touched.

Cost model: an edit changes the dnlib objects and updates only the affected
inventory records and name-index entries. A patched copy is written only when
a query needs decompiled code from an edited assembly; the inventory is
reloaded once per ``sync`` (which rewrites the JSON documents anyway).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Callable

from ..progress import Progress
from .targets import Target
from .worker import (
    MAX_READ,
    OpError,
    _clip,
    _jsonable,
    _matcher,
    _page,
    run_python,
)

TOKEN_KINDS = {
    0x02: "type",
    0x04: "field",
    0x06: "method",
    0x14: "event",
    0x17: "property",
}
_ADDRESS_RX = re.compile(r"^(?:(?P<asm>[^!]+)!)?0x(?P<token>[0-9a-fA-F]{8})$")


@dataclass(frozen=True, slots=True)
class Entity:
    kind: str  # type, method, field, property, event
    assembly: int
    token: int

    def address(self, session: Any) -> str:
        return f"{session.assemblies[self.assembly].name}!0x{self.token:08x}"


class DotnetLiveSession:
    backend = "dotnet"

    def __init__(
        self,
        target: Target,
        *,
        log_path: Path,
        allow_eval: bool = True,
        allow_edits: bool = True,
    ) -> None:
        from ..backends.dotnet import (
            DotnetSession,
            discover_dotnet_input,
            init_dotnet_worker,
            load_runtime,
        )
        from . import dotnet_edits

        self.target = target
        self.allow_eval = allow_eval
        self.allow_edits = allow_edits
        self.progress = Progress(enabled=False, log_path=log_path)
        self.log(f"live: opening .NET input {target.open_path}")
        load_runtime()
        self.workdir = Path(tempfile.mkdtemp(prefix="tocode-live-dotnet-"))
        include_framework = bool(self._project().get("include_framework"))
        self.found = discover_dotnet_input(
            target.open_path, workdir=self.workdir, include_framework=include_framework
        )
        self.original_paths = [item.path for item in self.found.included]
        self.session: Any = DotnetSession(self.found, in_memory=True)
        self.session.load()
        init_dotnet_worker([str(path) for path in self.found.search_dirs])
        self.eval_namespace: dict[str, Any] | None = None
        # Top-level types, as (assembly index, type token), the next sync must
        # write again; assemblies whose patched copy is behind the edits; and
        # whether the inventory's derived strings (references) are behind.
        self.dirty: set[tuple[int, int]] = set()
        self.unwritten: set[int] = set()
        self.reload_needed = False
        self._edited = False
        # Caches of the export on disk, dropped when a sync rewrites it.
        self._locations: dict[str, dict[str, Any]] | None = None
        self._layout: Any = None
        self._words: dict[str, set[tuple[int, int]]] | None = None
        self.edits = dotnet_edits.EditLog.open(self.edit_log_path())
        self.ops: dict[str, Callable[[dict[str, Any]], Any]] = {
            "info": lambda _args: self.info(),
            "functions": self.op_functions,
            "function": self.op_function,
            "decompile": self.op_decompile,
            "disassemble": self.op_disassemble,
            "xrefs": self.op_xrefs,
            "strings": self.op_strings,
            "imports": self.op_imports,
            "exports": self.op_exports,
            "sections": self.op_sections,
            "types": self.op_types,
            "type": self.op_type,
            "read_bytes": self.op_read_bytes,
            "search": self.op_search,
            "lookup": self.op_lookup,
            "eval": self.op_eval,
            "save": lambda _args: self.save(),
            "status": lambda _args: self.status(),
        }
        self.edit_ops: set[str] = set()
        self._index()
        dotnet_edits.register(self)
        from . import dotnet_sync

        dotnet_sync.register(self)
        dotnet_edits.replay(self)
        self.log("live: .NET session ready")

    # -- plumbing ---------------------------------------------------------------

    def log(self, message: str) -> None:
        self.progress.file_log(message)

    def dispatch(self, op: str, args: dict[str, Any]) -> Any:
        handler = self.ops.get(op)
        if handler is None:
            raise OpError(f"unknown operation {op}")
        return handler(args)

    def _project(self) -> dict[str, Any]:
        if self.target.export_dir is None:
            return {}
        try:
            return json.loads(
                (self.target.export_dir / "project.json").read_text("utf-8")
            )
        except (OSError, ValueError):
            return {}

    def edit_log_path(self) -> Path:
        if self.target.database is not None:
            return self.target.database
        if self.target.export_dir is not None:
            return self.target.export_dir / ".tocode" / "dotnet" / "edits.json"
        base = Path.home() / ".cache" / "tocode" / "live" / "dotnet"
        return base / f"{self.target.binary.name}.edits.json"

    def patched_path(self, assembly: int) -> Path:
        base = self.target.export_dir or self.edit_log_path().parent
        info = self.session.assemblies[assembly]
        return base / "patched" / (info.folder or info.name) / Path(info.file.path).name

    def assembly_path(self, assembly: int) -> str:
        """The file the decompiler reads: the patched copy once there is one."""
        patched = self.patched_path(assembly)
        if self.edits.entries and patched.is_file():
            return str(patched)
        return str(self.original_paths[assembly])

    def info(self) -> dict[str, Any]:
        session = self.session
        return {
            **self.target.describe(),
            "backend": "dotnet",
            "backend_label": ".NET",
            "decompiler": session.decompiler_label,
            "kind": self.found.kind,
            "assemblies": [
                {
                    "name": item.name,
                    "version": item.version,
                    "framework": item.target_framework,
                }
                for item in session.assemblies
            ],
            "functions": len(session.methods),
            "types": len(session.types),
            "strings": sum(len(item.user_strings) for item in session.assemblies),
            "edits": len(self.edits.entries),
            "eval": self.allow_eval,
            "edits_allowed": self.allow_edits,
            "edit_log": str(self.edit_log_path()),
        }

    def status(self) -> dict[str, Any]:
        return {
            "pending_types": sorted(self.type_name(key) for key in self.dirty),
            "pending_edits": len(self.edits.entries) - self.edits.synced,
        }

    def save(self) -> dict[str, Any]:
        """Write the edit log and the patched assemblies."""
        self.edits.save()
        written = self.write_patched()
        self._edited = False
        return {"saved": True, "edit_log": str(self.edits.path), "patched": written}

    def close(self, *, save: bool) -> dict[str, Any]:
        result: dict[str, Any] = {"saved": False}
        if save and (self._edited or self.unwritten):
            result = self.save()
        try:
            self.session.close()
        finally:
            shutil.rmtree(self.workdir, ignore_errors=True)
        return result

    # -- patched assemblies ---------------------------------------------------------

    def write_patched(self) -> list[str]:
        """Write the patched copies of edited assemblies (only those)."""
        from ..backends.dotnet import _worker

        written: list[str] = []
        for index in sorted(self.unwritten):
            target = self.patched_path(index)
            target.parent.mkdir(parents=True, exist_ok=True)
            cached = _worker.get("decompilers", {}).pop(str(target), None)
            if cached is not None:
                try:
                    cached[1].Dispose()
                except Exception:  # noqa: BLE001
                    pass
            write_module(self.session._modules[index], target)
            written.append(str(target))
        self.unwritten.clear()
        return written

    def reload(self) -> list[str]:
        """Write pending copies and load the inventory from them (for sync).

        Renames are already reflected in names; what a reload adds is the
        derived strings (reference lists, signatures) the JSON documents
        print, so it runs once per sync rather than after every edit.
        """
        from ..backends.dotnet import DotnetSession

        written = self.write_patched()
        if not self.reload_needed:
            return written
        for index in range(len(self.found.included)):
            patched = self.patched_path(index)
            if patched.is_file():
                self.found.included[index].path = patched
        session = DotnetSession(self.found, in_memory=True)
        session.load()
        old = self.session
        self.session = session
        old.close()
        self.reload_needed = False
        self.eval_namespace = None
        self._index()
        return written

    # -- names ----------------------------------------------------------------------

    def _index(self) -> None:
        """Name lookups and reverse references, built once per inventory."""
        from ..dotnet import _assembly_folders

        session = self.session
        _assembly_folders(session)
        self.names: dict[str, list[Entity]] = {}
        self.lower: dict[str, list[Entity]] = {}
        # (assembly, member token) -> (assembly, declaring type token)
        self.member_owner: dict[tuple[int, int], tuple[int, int]] = {}
        # (assembly, field token) -> methods (ids) that read or write it
        self.field_users: dict[tuple[int, int], set[int]] = {}
        field_by_name: dict[tuple[int, str], int] = {}
        for (assembly, token), record in session.types.items():
            self.index_entity(Entity("type", assembly, token))
            for kind, members in (
                ("field", record.fields),
                ("property", record.properties),
                ("event", record.events),
            ):
                for member in members:
                    self.member_owner[(assembly, member.token)] = (assembly, token)
                    self.index_entity(Entity(kind, assembly, member.token))
            for item in record.fields:
                field_by_name[(assembly, f"{record.full_name}::{item.name}")] = (
                    item.token
                )
        for method in session.methods:
            self.index_entity(Entity("method", method.assembly, method.token))
            for ref in method.field_refs:
                token = field_by_name.get((method.assembly, ref))
                if token is not None:
                    self.field_users.setdefault((method.assembly, token), set()).add(
                        method.id
                    )

    def entity_keys(self, entity: Entity) -> list[str]:
        """The names an entity can be looked up by."""
        if entity.kind == "type":
            record = self.session.types.get((entity.assembly, entity.token))
            return (
                [record.full_name, record.reflection_name, record.name]
                if record
                else []
            )
        if entity.kind == "method":
            method = self.session.method(entity.assembly, entity.token)
            if method is None:
                return []
            owner = method.type_name.replace("/", "+")
            return [
                f"{owner}::{method.name}",
                f"{owner}.{method.name}",
                method.name,
                method.full_name,
            ]
        owner_key = self.member_owner.get((entity.assembly, entity.token))
        record = self.session.types.get(owner_key) if owner_key else None
        if record is None:
            return []
        member = next(
            (
                m
                for m in record.fields + record.properties + record.events
                if m.token == entity.token
            ),
            None,
        )
        if member is None:
            return []
        owner = record.reflection_name
        return [f"{owner}::{member.name}", f"{owner}.{member.name}", member.name]

    def index_entity(self, entity: Entity, *, remove: bool = False) -> None:
        for name in self.entity_keys(entity):
            for table, key in ((self.names, name), (self.lower, name.lower())):
                bucket = table.setdefault(key, [])
                if remove:
                    if entity in bucket:
                        bucket.remove(entity)
                    if not bucket:
                        del table[key]
                elif entity not in bucket:
                    bucket.append(entity)

    def resolve(self, value: Any, *, kinds: tuple[str, ...] | None = None) -> Entity:
        if not isinstance(value, str) or not value.strip():
            raise OpError(
                "target must be `Assembly!0x06000012`, `Namespace.Type`, `Type::Member`, or a name"
            )
        text = value.strip()
        match = _ADDRESS_RX.match(text)
        if match is not None:
            token = int(match.group("token"), 16)
            kind = TOKEN_KINDS.get(token >> 24)
            if kind is None:
                raise OpError(
                    f"0x{token:08x} is not a type, method, field, property, or event token"
                )
            assembly = self._assembly_index(match.group("asm"))
            return self._check(Entity(kind, assembly, token), kinds)
        found = list(self.names.get(text) or self.lower.get(text.lower()) or [])
        if kinds is not None:
            found = [entity for entity in found if entity.kind in kinds]
        if not found:
            raise OpError(f"no type or member named {text!r}; try `lookup`")
        if len(found) > 1:
            choices = ", ".join(
                f"{e.kind} {e.address(self.session)} ({self.entity_name(e)})"
                for e in found[:12]
            )
            raise OpError(f"{text!r} is ambiguous; use an address: {choices}")
        return found[0]

    def _check(self, entity: Entity, kinds: tuple[str, ...] | None) -> Entity:
        if kinds is not None and entity.kind not in kinds:
            raise OpError(
                f"{entity.address(self.session)} is a {entity.kind}, expected {' or '.join(kinds)}"
            )
        return entity

    def _assembly_index(self, name: str | None) -> int:
        assemblies = self.session.assemblies
        if name is None:
            if len(assemblies) == 1:
                return 0
            raise OpError(
                "several assemblies are loaded; prefix the token with `Assembly!`"
            )
        for info in assemblies:
            if info.name == name or info.name.lower() == name.lower():
                return int(info.index)
        raise OpError(
            f"no assembly named {name!r} (loaded: {', '.join(a.name for a in assemblies)})"
        )

    def method_of(self, entity: Entity) -> Any:
        method = self.session.method(entity.assembly, entity.token)
        if method is None:
            raise OpError(f"no method {entity.address(self.session)}")
        return method

    def type_of(self, entity: Entity) -> Any:
        """The type record that declares an entity (the type itself for a type)."""
        session = self.session
        if entity.kind == "type":
            record = session.types.get((entity.assembly, entity.token))
        elif entity.kind == "method":
            method = self.method_of(entity)
            record = session.types.get((entity.assembly, method.type_token))
        else:
            owner = self.member_owner.get((entity.assembly, entity.token))
            record = session.types.get(owner) if owner else None
        if record is None:
            raise OpError(f"no declaring type for {entity.address(session)}")
        return record

    def top_level(self, entity: Entity) -> tuple[int, int]:
        record = self.type_of(entity)
        return (entity.assembly, record.top_level or record.token)

    def entity_name(self, entity: Entity) -> str:
        if entity.kind == "type":
            return str(self.type_of(entity).reflection_name)
        if entity.kind == "method":
            method = self.method_of(entity)
            return f"{method.type_name.replace('/', '+')}::{method.name}"
        record = self.type_of(entity)
        for member in record.fields + record.properties + record.events:
            if member.token == entity.token:
                return f"{record.reflection_name}::{member.name}"
        return entity.address(self.session)

    def type_name(self, key: tuple[int, int]) -> str:
        record = self.session.types.get(key)
        return str(record.reflection_name) if record is not None else f"0x{key[1]:08x}"

    def touch(self, *targets: Any) -> None:
        for value in targets:
            self.dirty.add(self.top_level(self.resolve(value)))

    # -- decompiling ------------------------------------------------------------------

    def decompiler(self, assembly: int) -> tuple[Any, Any, Any]:
        from ..backends.dotnet import _decompiler_for

        if assembly in self.unwritten:
            self.write_patched()
        return _decompiler_for(self.assembly_path(assembly))

    def csharp(self, entity: Entity) -> str:
        """C# for one type or member, with this session's text edits applied."""
        from ..backends.dotnet import _decompile_type
        from System.Reflection.Metadata.Ecma335 import MetadataTokens  # type: ignore[import-not-found]

        from . import dotnet_edits

        decompiler, _pe, settings = self.decompiler(entity.assembly)
        if entity.kind == "type":
            text, ranges = _decompile_type(decompiler, settings, entity.token)
        else:
            handle = MetadataTokens.EntityHandle(int(entity.token))
            text = str(decompiler.DecompileAsString(handle)).replace("\r\n", "\n")
            ranges = {entity.token: (1, text.count("\n") + 1)}
        text, _ = dotnet_edits.apply_text_edits(self, entity.assembly, text, ranges, 0)
        return text

    def il(self, entity: Entity) -> str:
        from ..backends.dotnet import _disassemble_type, _new_disassembler
        from ICSharpCode.Decompiler import PlainTextOutput  # type: ignore[import-not-found]
        from System.Reflection.Metadata.Ecma335 import MetadataTokens  # type: ignore[import-not-found]

        _decompiler, pe, _settings = self.decompiler(entity.assembly)
        if entity.kind == "type":
            return _disassemble_type(pe, entity.token)[0]
        if entity.kind != "method":
            raise OpError("disassemble works on a method or a type")
        output = PlainTextOutput()
        output.IndentationString = "    "
        _new_disassembler(output).DisassembleMethod(
            pe, MetadataTokens.MethodDefinitionHandle(entity.token & 0xFFFFFF)
        )
        return str(output.ToString()).replace("\r\n", "\n")

    # -- queries ----------------------------------------------------------------------

    def _location(self, method: Any) -> dict[str, Any] | None:
        locations = self._locations
        if locations is None:
            locations = self._locations = _load_dotnet_locations(self.target.export_dir)
        return locations.get(method.address)

    def _method_row(self, method: Any) -> dict[str, Any]:
        return {
            "address": method.address,
            "name": f"{method.type_name.replace('/', '+')}::{method.name}",
            "prototype": method.prototype,
            "size": method.il_size,
            "kind": "generated"
            if method.compiler_generated
            else "pinvoke"
            if method.pinvoke_module
            else "constructor"
            if method.is_constructor
            else "method",
            "callers": len(method.callers),
            "callees": len(method.callees) + len(method.external_calls),
        }

    def op_functions(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        kind = args.get("kind") or "all"
        rows = []
        for method in self.session.methods:
            row = self._method_row(method)
            if kind == "app" and row["kind"] == "generated":
                continue
            if kind not in ("all", "app") and row["kind"] != kind:
                continue
            if pattern is not None and not pattern(row["name"]):
                continue
            rows.append(row)
        return _page(rows, args)

    def op_function(self, args: dict[str, Any]) -> dict[str, Any]:
        method = self.method_of(self.resolve(args.get("target"), kinds=("method",)))
        methods = self.session.methods
        row = self._method_row(method)
        row.update(
            {
                "return_type": method.return_type,
                "params": [
                    {"name": name, "type": kind} for name, kind in method.params
                ],
                "flags": method.flags,
                "static": method.is_static,
                "virtual": method.is_virtual,
                "callers": [
                    self._method_row(methods[i])["name"] for i in method.callers
                ],
                "callees": [
                    self._method_row(methods[i])["name"] for i in method.callees
                ],
                "external_calls": method.external_calls,
                "fields": method.field_refs,
                "strings": method.string_ref_count,
                "pinvoke": f"{method.pinvoke_module}!{method.pinvoke_entry}"
                if method.pinvoke_module
                else None,
                "owner": self._method_row(methods[method.owner_method])["name"]
                if method.owner_method is not None
                else None,
                "export": self._location(method),
            }
        )
        return row

    def op_decompile(self, args: dict[str, Any]) -> dict[str, Any]:
        entity = self.resolve(args.get("target"), kinds=("type", "method"))
        return {
            "address": entity.address(self.session),
            "name": self.entity_name(entity),
            "code": _clip(self.csharp(entity)),
        }

    def op_disassemble(self, args: dict[str, Any]) -> dict[str, Any]:
        entity = self.resolve(args.get("target"), kinds=("type", "method"))
        text = self.il(entity)
        limit = int(args.get("max_lines") or 0)
        if limit > 0:
            lines = text.splitlines()
            text = "\n".join(lines[:limit]) + (
                f"\n... {len(lines) - limit} more lines" if len(lines) > limit else ""
            )
        return {
            "address": entity.address(self.session),
            "name": self.entity_name(entity),
            "disassembly": _clip(text),
        }

    def op_xrefs(self, args: dict[str, Any]) -> dict[str, Any]:
        entity = self.resolve(args.get("target"))
        direction = args.get("direction") or "to"
        methods = self.session.methods
        rows: list[dict[str, Any]] = []
        if entity.kind == "method":
            method = self.method_of(entity)
            if direction == "from":
                rows += [
                    {
                        "to": methods[i].address,
                        "name": self._method_row(methods[i])["name"],
                        "kind": "call",
                    }
                    for i in method.callees
                ]
                rows += [
                    {"to": None, "name": name, "kind": "external call"}
                    for name in method.external_calls
                ]
                rows += [
                    {"to": None, "name": name, "kind": "field"}
                    for name in method.field_refs
                ]
            else:
                rows += [
                    {
                        "from": methods[i].address,
                        "function": self._method_row(methods[i])["name"],
                        "kind": "call",
                    }
                    for i in method.callers
                ]
        else:
            if direction == "from":
                raise OpError("xrefs from works on a method")
            name = self.entity_name(entity)
            short = name.split("::")[-1]
            record = self.type_of(entity)
            for method in methods:
                if method.assembly != entity.assembly:
                    continue
                if entity.kind == "type":
                    uses = method.type_token != entity.token and (
                        record.reflection_name in method.prototype.replace("/", "+")
                        or any(record.full_name in ref for ref in method.field_refs)
                        or any(
                            methods[i].type_token == entity.token
                            for i in method.callees
                        )
                    )
                else:
                    uses = any(
                        ref.endswith(f"::{short}") and record.full_name in ref
                        for ref in method.field_refs
                    )
                if uses:
                    rows.append(
                        {
                            "from": method.address,
                            "function": self._method_row(method)["name"],
                            "kind": "use",
                        }
                    )
        return {
            "target": entity.address(self.session),
            "direction": direction,
            "refs": rows,
        }

    def op_strings(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        methods = self.session.methods
        rows = []
        for info in self.session.assemblies:
            for offset, value in info.user_strings:
                if pattern is not None and not pattern(value):
                    continue
                users = [
                    self._method_row(methods[i])["name"]
                    for i in self.session.string_xrefs.get((info.index, offset), ())
                ]
                rows.append(
                    {
                        "address": f"{info.name}!0x{0x70000000 | offset:08x}",
                        "value": value,
                        "used_by": users,
                    }
                )
        return _page(rows, args)

    def op_imports(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        rows = []
        for scope, members in sorted(self.session.external_refs.items()):
            for member, users in sorted(members.items()):
                if pattern is not None and not pattern(f"{scope} {member}"):
                    continue
                rows.append({"library": scope, "name": member, "used_by": len(users)})
        for method in self.session.methods:
            if method.pinvoke_module and (
                pattern is None or pattern(str(method.pinvoke_entry))
            ):
                rows.append(
                    {
                        "library": method.pinvoke_module,
                        "name": method.pinvoke_entry,
                        "pinvoke": method.address,
                    }
                )
        return _page(rows, args)

    def op_exports(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        rows = [
            {
                "address": f"{self.session.assemblies[asm].name}!0x{token:08x}",
                "name": record.reflection_name,
                "kind": record.kind,
            }
            for (asm, token), record in self.session.types.items()
            if record.visibility.startswith("Public")
            or record.visibility.startswith("NestedPublic")
            if pattern is None or pattern(record.reflection_name)
        ]
        return _page(rows, args)

    def op_sections(self, _args: dict[str, Any]) -> dict[str, Any]:
        return {
            "assemblies": [
                {
                    "name": info.name,
                    "version": info.version,
                    "framework": info.target_framework,
                    "kind": info.kind,
                    "path": str(info.file.path),
                    "types": len(info.types),
                    "obfuscation_hints": info.obfuscation_hints,
                }
                for info in self.session.assemblies
            ]
        }

    def op_types(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = _matcher(args.get("filter"))
        kind = args.get("kind")
        rows = [
            {
                "address": f"{self.session.assemblies[asm].name}!0x{token:08x}",
                "name": record.reflection_name,
                "kind": record.kind,
                "members": len(record.fields)
                + len(record.properties)
                + len(record.events)
                + len(record.methods),
            }
            for (asm, token), record in self.session.types.items()
            if (pattern is None or pattern(record.reflection_name))
            and (not kind or record.kind == kind)
        ]
        return _page(rows, args)

    def op_type(self, args: dict[str, Any]) -> dict[str, Any]:
        entity = self.resolve(args.get("name"), kinds=("type",))
        record = self.type_of(entity)
        methods = self.session.methods
        return {
            "address": entity.address(self.session),
            "name": record.reflection_name,
            "kind": record.kind,
            "base_type": record.base_type,
            "interfaces": record.interfaces,
            "fields": [
                {"name": f.name, "type": f.type, "token": f"0x{f.token:08x}"}
                for f in record.fields
            ],
            "properties": [
                {"name": p.name, "type": p.type, "token": f"0x{p.token:08x}"}
                for p in record.properties
            ],
            "methods": [
                {
                    "name": methods[i].name,
                    "prototype": methods[i].prototype,
                    "address": methods[i].address,
                }
                for i in record.methods
            ],
            "c_decl": _clip(self.csharp(entity)),
        }

    def op_read_bytes(self, args: dict[str, Any]) -> dict[str, Any]:
        """Raw bytes of an assembly: at a file offset, or a method's body."""
        target = args.get("address")
        size = max(1, min(int(args.get("size") or 64), MAX_READ))
        if (
            isinstance(target, str)
            and "!" in target
            or (isinstance(target, str) and target.startswith("0x0"))
        ):
            entity = self.resolve(target, kinds=("method",))
            method = self.method_of(entity)
            info = self.session.assemblies[entity.assembly]
            offset = info.pe.rva_to_offset(method.rva) if method.rva else None
            if offset is None:
                raise OpError("the method has no body")
            path, size = (
                Path(self.original_paths[entity.assembly]),
                min(size, max(1, method.il_size + 12)),
            )
        else:
            offset = int(str(target), 0)
            path = Path(self.original_paths[0])
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(size)
        return {
            "file": path.name,
            "offset": hex(offset),
            "size": len(data),
            "hex": data.hex(),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
        }

    def op_search(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = str(args.get("pattern") or "")
        kind = args.get("kind") or "text"
        limit = max(1, min(int(args.get("limit") or 50), 1000))
        if not pattern:
            raise OpError("search needs a pattern")
        hits: list[dict[str, Any]] = []
        if kind == "hex":
            needle = bytes.fromhex(pattern.replace(" ", ""))
            for index, path in enumerate(self.original_paths):
                data = Path(path).read_bytes()
                start = data.find(needle)
                while start >= 0 and len(hits) < limit:
                    hits.append(
                        {
                            "assembly": self.session.assemblies[index].name,
                            "offset": hex(start),
                        }
                    )
                    start = data.find(needle, start + 1)
            return {"pattern": pattern, "kind": kind, "hits": hits}
        matcher = re.compile(pattern) if kind == "regex" else None
        for row in self.op_strings({"limit": 100000})["items"]:
            value = row["value"]
            if matcher.search(value) if matcher else pattern in value:
                hits.append(row)
                if len(hits) >= limit:
                    break
        return {"pattern": pattern, "kind": kind, "hits": hits}

    def op_lookup(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("name") or "").strip().lower()
        if not query:
            raise OpError("lookup needs a name")
        limit = max(1, min(int(args.get("limit") or 50), 500))
        rows: list[dict[str, Any]] = []
        seen: set[Entity] = set()
        for name in sorted(self.names):
            if query not in name.lower():
                continue
            for entity in self.names[name]:
                if entity in seen:
                    continue
                seen.add(entity)
                rows.append(
                    {
                        "name": self.entity_name(entity),
                        "kind": entity.kind,
                        "address": entity.address(self.session),
                    }
                )
            if len(rows) >= limit:
                break
        return {"query": query, "matches": rows[:limit]}

    # -- eval -------------------------------------------------------------------------

    def _namespace(self) -> dict[str, Any]:
        if self.eval_namespace is None:
            self.eval_namespace = {
                "__name__": "__tocode_eval__",
                "session": self.session,
                "modules": list(self.session._modules),
                "module": self.session._modules[0] if self.session._modules else None,
                "resolve": self.resolve,
                "decompile": lambda target: self.csharp(self.resolve(target)),
                "touch": self.touch,
                "result": None,
            }
        return self.eval_namespace

    def op_eval(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.allow_eval:
            raise OpError("eval is disabled for this server (--no-eval / --read-only)")
        if (args.get("language") or "python") != "python":
            raise OpError("eval on .NET runs Python (dnlib objects are in `modules`)")
        if args.get("reset"):
            self.eval_namespace = None
        before = set(self.dirty)
        value, output, error = run_python(
            self._namespace(), str(args.get("code") or "")
        )
        return {
            "result": _jsonable(value),
            "stdout": _clip(output),
            "error": error,
            "touched": sorted(self.type_name(key) for key in self.dirty - before),
        }


def write_module(module: Any, target: Path) -> None:
    """Write a dnlib module with its metadata tokens preserved, atomically.

    Only row ids are preserved: keeping the old string heap would carry the
    previous names along in the file.
    """
    from dnlib.DotNet.Writer import (  # type: ignore[import-not-found]
        MetadataFlags,
        ModuleWriterOptions,
        NativeModuleWriterOptions,
    )

    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    if module.IsILOnly:
        options = ModuleWriterOptions(module)
        options.MetadataOptions.Flags = (
            options.MetadataOptions.Flags | MetadataFlags.PreserveRids
        )
        module.Write(str(temporary), options)
    else:  # mixed-mode (C++/CLI): keep the native code
        native = NativeModuleWriterOptions(module, False)
        native.MetadataOptions.Flags = (
            native.MetadataOptions.Flags | MetadataFlags.PreserveRids
        )
        module.NativeWrite(str(temporary), native)
    os.replace(temporary, target)


def _load_dotnet_locations(export_dir: Path | None) -> dict[str, dict[str, Any]]:
    """`Assembly!0xTOKEN` -> where the method is in the export."""
    if export_dir is None:
        return {}
    try:
        rows = json.loads((export_dir / "function-index.json").read_text("utf-8")).get(
            "functions", []
        )
    except (OSError, ValueError):
        return {}
    locations = {}
    for row in rows:
        c = row.get("c") or {}
        asm = row.get("asm") or {}
        locations[str(row.get("address"))] = {
            "c": f"{c.get('path')}:{c.get('line_start')}-{c.get('line_end')}",
            "il": f"{asm.get('path')}:{asm.get('line_start')}-{asm.get('line_end')}",
        }
    return locations
