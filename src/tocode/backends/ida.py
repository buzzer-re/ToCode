from __future__ import annotations

from collections import Counter
import hashlib
import os
from pathlib import Path
from typing import Any

from .base import BackendName, bootstrap_ida, is_ida_database
from ..errors import BackendError


_MAX_THUNK_HOPS = 5


def _cache_root() -> Path:
    explicit = os.environ.get("TOCODE_IDA_CACHE_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "tocode" / "ida"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _database_path(binary: Path) -> tuple[Path, bool]:
    if is_ida_database(binary):
        return binary, False
    root = _cache_root()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{_sha256(binary)}.i64"
    return path, not path.exists()


class IdaSession:
    backend_name: BackendName = "ida"
    backend_label = "IDA Domain"
    decompiler_label = "Hex-Rays"
    analysis_command: str | None = None
    parallel_safe = True

    def __init__(
        self,
        binary: Path,
        *,
        idadir: Path | None = None,
        ida_domain_path: Path | None = None,
        db_path: Path | None = None,
        needs_analysis: bool | None = None,
    ) -> None:
        self.binary = Path(binary).resolve()
        self.idadir = idadir.resolve() if idadir is not None else None
        self.ida_domain_path = (
            ida_domain_path.resolve() if ida_domain_path is not None else None
        )
        runtime = bootstrap_ida(
            idadir=self.idadir, ida_domain_path=self.ida_domain_path
        )
        self._Database = runtime.ida_domain.Database
        self._Options = runtime.ida_domain.database.IdaCommandOptions

        self._ida_hexrays = self._optional_import("ida_hexrays")
        self._ida_loader = __import__("ida_loader")
        self._ida_segment = __import__("ida_segment")
        self._ida_bytes = __import__("ida_bytes")
        self._ida_entry = self._optional_import("ida_entry")
        self._ida_fixup = self._optional_import("ida_fixup")
        self._ida_auto = self._optional_import("ida_auto")
        self._ida_nalt = self._optional_import("ida_nalt")
        self._db: Any = None

        if db_path is None:
            resolved_db, first_open = _database_path(self.binary)
            needs_analysis = first_open
        else:
            resolved_db = db_path
            needs_analysis = bool(needs_analysis)
        self.analysis_command = (
            "IDA Domain auto-analysis" if needs_analysis else "IDA database inventory"
        )

        self._cache_db = None if is_ida_database(self.binary) else resolved_db
        if needs_analysis:
            self._opened_for_analysis = True
            options = self._Options(
                auto_analysis=True,
                new_database=True,
                output_database=str(resolved_db),
                plugin_options="lumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0",
            )
            try:
                self._db = self._Database.open(
                    str(self.binary), args=options, save_on_close=True
                )
            except Exception as exc:  # noqa: BLE001
                raise BackendError(
                    f"failed to open IDA database for {self.binary}"
                ) from exc
            self._wait_for_auto_analysis()
        else:
            self._opened_for_analysis = False
            options = self._Options(auto_analysis=False, new_database=False)
            try:
                self._db = self._Database.open(
                    str(resolved_db), args=options, save_on_close=False
                )
            except Exception as exc:  # noqa: BLE001
                raise BackendError(
                    f"failed to open IDA database at {resolved_db}"
                ) from exc

        self._strings_ready = False
        self._decompiler_ready = False
        self._disasm_cache: dict[int, str] = {}
        self._decompile_cache: dict[int, str] = {}
        self._summary_cache: dict[int, str] = {}
        self._locals_cache: dict[int, list[Any]] = {}
        self._imports_cache: list[dict[str, Any]] | None = None
        self._relocs_cache: list[dict[str, Any]] | None = None
        self._primed: set[int] = set()

    def _optional_import(self, module: str):
        try:
            return __import__(module)
        except ImportError:
            return None

    def _wait_for_auto_analysis(self) -> None:
        if self._ida_auto is None:
            return
        wait = getattr(self._ida_auto, "auto_wait", None)
        if callable(wait):
            try:
                wait()
            except Exception:  # noqa: BLE001
                pass

    def analyze(self) -> None:
        if self._strings_ready:
            return
        try:
            from ida_domain.strings import StringListConfig, StringType

            self._db.strings.rebuild(
                StringListConfig(
                    string_types=[StringType.C, StringType.C_16],
                    min_len=4,
                    only_ascii_7bit=False,
                )
            )
        except Exception:  # noqa: BLE001
            try:
                self._db.strings.rebuild()
            except Exception:  # noqa: BLE001
                pass
        self._strings_ready = True

    def close(self) -> None:
        if self._db is None:
            return
        try:
            self._db.close(save=self._opened_for_analysis)
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._opened_for_analysis = False
            self._db = None

    def database_path(self) -> Path | None:
        if self._cache_db is None:
            return self.binary if is_ida_database(self.binary) else None
        if not self._cache_db.exists() or self._opened_for_analysis:
            self._save_and_reopen_database()
        return self._cache_db if self._cache_db.exists() else None

    def prepare_parallel_workers(self) -> None:
        if self._cache_db is None:
            return
        if self._cache_db.exists() and not self._opened_for_analysis:
            return
        self._save_and_reopen_database()

    def release_parallel_resources(self) -> None:
        if self._cache_db is not None:
            self.prepare_parallel_workers()
        self._clear_caches()
        if self._db is None:
            return
        try:
            self._db.close(save=False)
        except Exception as exc:  # noqa: BLE001
            raise BackendError("failed to close parent IDA database") from exc
        self._db = None
        self._opened_for_analysis = False
        self._decompiler_ready = False

    def restore_parallel_resources(self) -> None:
        if self._db is not None:
            return
        resolved_db = self._cache_db
        if resolved_db is None and is_ida_database(self.binary):
            resolved_db = self.binary
        if resolved_db is None:
            return
        self._open_existing_database(resolved_db)

    def release_render_memory(self) -> None:
        self._disasm_cache.clear()
        self._decompile_cache.clear()
        self._summary_cache.clear()
        self._locals_cache.clear()
        if self._ida_hexrays is None:
            return
        clear_cached = getattr(self._ida_hexrays, "clear_cached_cfuncs", None)
        if callable(clear_cached):
            try:
                clear_cached()
            except Exception:  # noqa: BLE001
                pass

    def _save_and_reopen_database(self) -> None:
        if self._cache_db is None:
            return
        if self._db is None:
            self._open_existing_database(self._cache_db)
            return
        try:
            self._db.close(save=True)
        except Exception as exc:  # noqa: BLE001
            raise BackendError(
                f"failed to save IDA database at {self._cache_db}"
            ) from exc
        self._opened_for_analysis = False
        self._open_existing_database(self._cache_db)

    def _open_existing_database(self, resolved_db: Path) -> None:
        options = self._Options(auto_analysis=False, new_database=False)
        try:
            self._db = self._Database.open(
                str(resolved_db), args=options, save_on_close=False
            )
        except Exception as exc:  # noqa: BLE001
            raise BackendError(
                f"failed to reopen IDA database at {resolved_db}"
            ) from exc
        self._opened_for_analysis = False
        self._clear_caches()
        self.ensure_decompiler()

    def _clear_caches(self) -> None:
        self._decompiler_ready = False
        self._disasm_cache.clear()
        self._decompile_cache.clear()
        self._summary_cache.clear()
        self._locals_cache.clear()
        self._primed.clear()

    def worker(self) -> "IdaSession":
        if self._cache_db is not None and self._cache_db.exists():
            return IdaSession(
                self.binary,
                idadir=self.idadir,
                ida_domain_path=self.ida_domain_path,
                db_path=self._cache_db,
                needs_analysis=False,
            )
        return IdaSession(
            self.binary, idadir=self.idadir, ida_domain_path=self.ida_domain_path
        )

    def ensure_decompiler(self) -> None:
        if self._decompiler_ready:
            return
        if self._ida_hexrays is None:
            raise BackendError("Hex-Rays Python bindings are not available")
        try:
            available = bool(self._ida_hexrays.init_hexrays_plugin())
        except Exception as exc:  # noqa: BLE001
            raise BackendError("failed to initialize Hex-Rays") from exc
        if not available:
            raise BackendError("Hex-Rays is not available in this IDA installation")
        self._decompiler_ready = True

    def info(self) -> dict[str, Any]:
        return {
            "bin": {
                "arch": self._db.architecture or "unknown",
                "bits": int(self._db.bitness or 0),
                "baddr": int(self._db.base_address or 0),
                "os": "unknown",
                "format": self._db.format or "unknown",
                "class": self._db.format or "unknown",
                "type": self._db.format or "unknown",
            },
            "tocode": {
                "input_path": str(self._input_path()),
            },
        }

    def entries(self) -> list[dict[str, Any]]:
        return [
            {
                "ordinal": int(entry.ordinal),
                "name": entry.name,
                "vaddr": int(entry.address),
            }
            for entry in self._db.entries
        ]

    def sections(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for segment in self._db.segments:
            name = self._db.segments.get_name(segment) or f"seg_{segment.start_ea:x}"
            size = int(self._db.segments.get_size(segment))
            rows.append(
                {
                    "name": name,
                    "size": size,
                    "vsize": size,
                    "type": self._db.segments.get_class(segment) or "unknown",
                    "perm": self._segment_perms(segment),
                    "paddr": self._file_offset(segment.start_ea),
                    "vaddr": int(segment.start_ea),
                }
            )
        return rows

    def imports(self) -> list[dict[str, Any]]:
        if self._imports_cache is not None:
            return list(self._imports_cache)
        rows: list[dict[str, Any]] = []
        for item in self._db.imports.get_all_imports():
            name = item.name or f"{item.module_name}!#{item.ordinal}"
            rows.append(
                {
                    "plt": int(item.address),
                    "name": name,
                    "bind": item.module_name,
                    "dll": item.module_name,
                    "type": "import",
                    "delay": bool(getattr(item, "is_delay", False)),
                }
            )
        self._imports_cache = rows
        return list(rows)

    def exports(self) -> list[dict[str, Any]]:
        if self._ida_entry is None:
            return self._entry_rows()
        try:
            qty = int(self._ida_entry.get_entry_qty())
        except Exception:  # noqa: BLE001
            return self._entry_rows()
        rows: list[dict[str, Any]] = []
        for index in range(qty):
            try:
                ordinal = int(self._ida_entry.get_entry_ordinal(index))
                address = int(self._ida_entry.get_entry(ordinal))
                name = self._ida_entry.get_entry_name(ordinal) or self._db.names.get_at(
                    address
                )
                get_forwarder = getattr(self._ida_entry, "get_entry_forwarder", None)
                forwarder = (
                    get_forwarder(ordinal) if get_forwarder is not None else None
                )
            except Exception:  # noqa: BLE001
                continue
            rows.append(
                {
                    "ordinal": ordinal,
                    "name": name or f"export_{ordinal}",
                    "vaddr": address,
                    "bind": None,
                    "type": "export",
                    "is_forwarder": bool(forwarder),
                    "forwarder_target": str(forwarder) if forwarder else None,
                }
            )
        return rows or self._entry_rows()

    def _entry_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "ordinal": int(entry.ordinal),
                "name": entry.name,
                "vaddr": int(entry.address),
                "bind": None,
                "type": "entry",
                "is_forwarder": False,
                "forwarder_target": None,
            }
            for entry in self._db.entries
        ]

    def symbols(self) -> list[dict[str, Any]]:
        import_addrs = {int(item["plt"]) for item in self.imports()}
        return [
            {
                "name": name,
                "flagname": name,
                "realname": name,
                "size": 0,
                "type": "name",
                "vaddr": int(address),
                "paddr": self._file_offset(address),
                "is_imported": int(address) in import_addrs,
            }
            for address, name in self._db.names
        ]

    def relocations(self) -> list[dict[str, Any]]:
        if self._relocs_cache is not None:
            return list(self._relocs_cache)
        rows: list[dict[str, Any]] = []
        if self._ida_fixup is not None:
            try:
                ea = self._ida_fixup.get_first_fixup_ea()
                while ea != self._ida_bytes.BADADDR:
                    rows.append(
                        {
                            "name": self._db.names.get_at(ea) or f"fixup_{ea:x}",
                            "type": "fixup",
                            "vaddr": int(ea),
                            "paddr": self._file_offset(ea),
                            "is_ifunc": False,
                        }
                    )
                    ea = self._ida_fixup.get_next_fixup_ea(ea)
            except Exception:  # noqa: BLE001
                rows = []
        self._relocs_cache = rows
        return list(rows)

    def strings(self) -> list[dict[str, Any]]:
        self.analyze()
        rows: list[dict[str, Any]] = []
        for item in self._db.strings:
            rows.append(
                {
                    "vaddr": int(item.address),
                    "paddr": self._file_offset(item.address),
                    "size": len(item.contents),
                    "length": int(item.length),
                    "section": self._segment_name(item.address),
                    "type": getattr(item.type, "name", str(item.type)),
                    "string": self._string_value(item),
                }
            )
        return rows

    def flags(self) -> list[dict[str, Any]]:
        return [
            {"name": name, "offset": int(address), "size": 0, "realname": name}
            for address, name in self._db.names
        ]

    def functions(self) -> list[dict[str, Any]]:
        from ida_domain.functions import FunctionFlags

        rows: list[dict[str, Any]] = []
        for func in self._db.functions:
            name = self._db.functions.get_name(func) or f"sub_{func.start_ea:x}"
            segment_name = self._segment_name(func.start_ea)

            flags = self._db.functions.get_flags(func)
            is_library = bool(flags & FunctionFlags.LIB)
            is_thunk = bool(flags & FunctionFlags.THUNK)
            rows.append(
                {
                    "offset": int(func.start_ea),
                    "name": name,
                    "size": int(func.end_ea - func.start_ea),
                    "signature": self._db.functions.get_signature(func) or None,
                    "calltype": None,
                    "noreturn": not bool(self._db.functions.does_return(func)),
                    "stackframe": int(getattr(func, "frsize", 0) or 0),
                    "nlocals": 0,
                    "nargs": 0,
                    "outdegree": 0,
                    "indegree": 0,
                    "is_library": is_library,
                    "is_thunk": is_thunk,
                    "source_kind": self._classify(
                        name, segment_name, is_library=is_library, is_thunk=is_thunk
                    ),
                }
            )
        return rows

    def disasm(self, address: int) -> str:
        func = self._need_function(address)
        return "\n".join(self._function_disassembly(func))

    def decompile(self, address: int) -> str:
        self.ensure_decompiler()
        func = self._need_function(address)
        lines = self._function_pseudocode(func)
        return "\n".join(lines) if isinstance(lines, list) else str(lines)

    def function_summary(self, address: int) -> str:
        if address in self._summary_cache:
            return self._summary_cache[address]
        func = self._need_function(address)
        signature = self._db.functions.get_signature(
            func
        ) or self._db.functions.get_name(func)
        callers = self._db.functions.get_callers(func)
        callees = self._db.functions.get_callees(func)
        locals_count = Counter(
            "args" if bool(getattr(item, "is_argument", False)) else "locals"
            for item in self._locals(address)
            if not bool(getattr(item, "is_result", False))
        )
        callee_names = [
            self._db.functions.get_name(resolved) or f"sub_{resolved.start_ea:x}"
            for resolved in (self._resolve_thunk(item) for item in callees[:8])
        ]
        lines = [
            f"signature: {signature or f'sub_{address:x}'}",
            f"address: 0x{address:x}",
            f"size: {func.end_ea - func.start_ea} bytes",
            f"returns: {'no' if not self._db.functions.does_return(func) else 'yes'}",
            f"callers: {len(callers)}",
            f"callees: {len(callees)}",
            f"args: {locals_count['args']}",
            f"locals: {locals_count['locals']}",
        ]
        if callee_names:
            lines.append(f"callee_names: {', '.join(callee_names)}")
        return "\n".join(lines)

    def calls_from(
        self, address: int, imports, functions
    ) -> tuple[list[int], list[str]]:
        func = self._db.functions.get_at(address)
        if func is None:
            return [], []
        edges: set[int] = set()
        imported: set[str] = set()
        for callee in self._db.functions.get_callees(func):
            resolved = self._resolve_thunk(callee)
            target = int(resolved.start_ea)
            if target in imports:
                imported.add(imports[target].name)
            elif target in functions and target != address:
                edges.add(target)
            else:
                name = self._db.names.get_at(target)
                if name:
                    imported.add(name)
        return sorted(edges), sorted(name for name in imported if name)

    def _resolve_thunk(self, func):
        from ida_domain.functions import FunctionFlags

        current = func
        seen: set[int] = set()
        for _ in range(_MAX_THUNK_HOPS):
            if not (self._db.functions.get_flags(current) & FunctionFlags.THUNK):
                return current
            ea = int(current.start_ea)
            if ea in seen:
                return current
            seen.add(ea)
            callees = list(self._db.functions.get_callees(current))
            if len(callees) != 1:
                return current
            current = callees[0]
        return current

    def _need_function(self, address: int):
        func = self._db.functions.get_at(address)
        if func is None:
            raise BackendError(f"IDA could not resolve function at 0x{address:x}")
        return func

    def _prime(self, address: int) -> None:
        if address in self._primed:
            return
        if self._ida_hexrays is not None:
            try:
                self.ensure_decompiler()
                self._function_pseudocode(self._need_function(address))
            except Exception:  # noqa: BLE001
                pass
        self._locals_cache.pop(address, None)
        self._summary_cache.pop(address, None)
        self._primed.add(address)

    def _locals(self, address: int) -> list[Any]:
        if address not in self._locals_cache:
            try:
                self._locals_cache[address] = list(
                    self._db.functions.get_local_variables(self._need_function(address))
                )
            except Exception:  # noqa: BLE001
                self._locals_cache[address] = []
        return self._locals_cache[address]

    def _classify(
        self, name: str, segment_name: str | None, *, is_library: bool, is_thunk: bool
    ) -> str:
        if is_thunk:
            return "thunk"
        lowered_name = (name or "").lower()
        lowered_segment = (segment_name or "").lower()
        if lowered_segment in {
            ".init",
            ".fini",
            ".plt",
            ".plt.sec",
            ".init_array",
            ".fini_array",
        }:
            return "runtime"
        if lowered_name in {
            "_init",
            "_fini",
            "__libc_start_main",
            "__gmon_start__",
            "frame_dummy",
            "register_tm_clones",
            "deregister_tm_clones",
            "__do_global_dtors_aux",
        }:
            return "runtime"
        if lowered_name.startswith(
            ("__libc_csu_", "__scrt_", "_scrt_", "__crt", "_crt", "_global__sub_i_")
        ):
            return "runtime"
        if is_library:
            return "library"
        return "app"

    def _segment_perms(self, segment) -> str:
        perm = int(getattr(segment, "perm", 0) or 0)
        return "".join(
            [
                "r" if perm & int(self._ida_segment.SEGPERM_READ) else "-",
                "w" if perm & int(self._ida_segment.SEGPERM_WRITE) else "-",
                "x" if perm & int(self._ida_segment.SEGPERM_EXEC) else "-",
            ]
        )

    def _file_offset(self, ea: int) -> int:
        try:
            value = self._ida_loader.get_fileregion_offset(int(ea))
        except Exception:  # noqa: BLE001
            return 0
        return max(int(value), 0) if value is not None else 0

    def _segment_name(self, ea: int) -> str:
        try:
            segment = self._db.segments.get_at(int(ea))
        except Exception:  # noqa: BLE001
            return ""
        if segment is None:
            return ""
        return self._db.segments.get_name(segment) or ""

    def _string_value(self, item) -> str:
        try:
            return str(item)
        except Exception:  # noqa: BLE001
            contents = getattr(item, "contents", b"")
            if isinstance(contents, bytes):
                return contents.decode("utf-8", errors="replace")
            return str(contents)

    def _input_path(self) -> Path:
        if self._ida_nalt is None:
            return self.binary
        try:
            path = Path(str(self._ida_nalt.get_input_file_path())).expanduser()
        except Exception:  # noqa: BLE001
            return self.binary
        return path.resolve() if path.is_file() else self.binary

    def _function_disassembly(self, func):
        try:
            return self._db.functions.get_disassembly(func, remove_tags=True)
        except TypeError:
            return self._db.functions.get_disassembly(func)

    def _function_pseudocode(self, func):
        try:
            return self._db.functions.get_pseudocode(func, remove_tags=True)
        except TypeError:
            return self._db.functions.get_pseudocode(func)
