"""ASC (droidasc) backend: APK/DEX inventory and per-class Java decompilation.

ASC treats the APK as a read-only database, so this module keeps the same
shape: the parent process inflates every DEX once, walks the tinydex tables for
the inventory, and worker processes rebuild their own view of one DEX to
decompile classes. Nothing outside this module imports ``droidasc`` directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import importlib
import importlib.util
import mmap
from pathlib import Path
import struct
import sys
from typing import Any
import zipfile

from ..errors import ToCodeError


APK_SUFFIXES = frozenset({".apk"})
# Per-method/per-string reference caps. Both tables are unbounded in principle
# (a large APK has millions of edges), and the tail is not useful for triage.
MAX_STRING_XREFS = 64
MAX_FIELD_REFS = 32
APK_BUNDLE_SUFFIXES = frozenset({".apks", ".xapk"})
NO_INDEX = 0xFFFFFFFF

# Dalvik access flags (dex format spec).
ACC_PUBLIC = 0x1
ACC_PRIVATE = 0x2
ACC_PROTECTED = 0x4
ACC_STATIC = 0x8
ACC_FINAL = 0x10
ACC_SYNCHRONIZED = 0x20
ACC_VOLATILE = 0x40
ACC_BRIDGE = 0x40
ACC_TRANSIENT = 0x80
ACC_VARARGS = 0x80
ACC_NATIVE = 0x100
ACC_INTERFACE = 0x200
ACC_ABSTRACT = 0x400
ACC_STRICT = 0x800
ACC_SYNTHETIC = 0x1000
ACC_ANNOTATION = 0x2000
ACC_ENUM = 0x4000
ACC_CONSTRUCTOR = 0x10000
ACC_DECLARED_SYNCHRONIZED = 0x20000

_CLASS_FLAG_NAMES = (
    (ACC_PUBLIC, "public"),
    (ACC_PRIVATE, "private"),
    (ACC_PROTECTED, "protected"),
    (ACC_STATIC, "static"),
    (ACC_FINAL, "final"),
    (ACC_INTERFACE, "interface"),
    (ACC_ABSTRACT, "abstract"),
    (ACC_SYNTHETIC, "synthetic"),
    (ACC_ANNOTATION, "annotation"),
    (ACC_ENUM, "enum"),
)
_METHOD_FLAG_NAMES = (
    (ACC_PUBLIC, "public"),
    (ACC_PRIVATE, "private"),
    (ACC_PROTECTED, "protected"),
    (ACC_STATIC, "static"),
    (ACC_FINAL, "final"),
    (ACC_SYNCHRONIZED, "synchronized"),
    (ACC_BRIDGE, "bridge"),
    (ACC_VARARGS, "varargs"),
    (ACC_NATIVE, "native"),
    (ACC_ABSTRACT, "abstract"),
    (ACC_STRICT, "strictfp"),
    (ACC_SYNTHETIC, "synthetic"),
    (ACC_CONSTRUCTOR, "constructor"),
    (ACC_DECLARED_SYNCHRONIZED, "declared-synchronized"),
)
_FIELD_FLAG_NAMES = (
    (ACC_PUBLIC, "public"),
    (ACC_PRIVATE, "private"),
    (ACC_PROTECTED, "protected"),
    (ACC_STATIC, "static"),
    (ACC_FINAL, "final"),
    (ACC_VOLATILE, "volatile"),
    (ACC_TRANSIENT, "transient"),
    (ACC_SYNTHETIC, "synthetic"),
    (ACC_ENUM, "enum"),
)

# ``droidasc.asc_core.utils.decompiler`` replaces modules that are not yet
# imported with dummies (to make androguard import faster). Anything ToCode or
# androguard needs afterwards must therefore be loaded for real first.
_PRELOAD_MODULES = (
    "json",
    "math",
    "random",
    "tempfile",
    "shutil",
    "bisect",
    "weakref",
    "bz2",
    "lzma",
    "multiprocessing",
    "multiprocessing.connection",
    "xml.sax.saxutils",
    "xml.dom.minidom",
    "email",
    "email.parser",
    "urllib",
    "urllib.request",
    "http.client",
    "lxml",
    "lxml.etree",
    "asn1crypto",
    "asn1crypto.x509",
    "cryptography",
    "loguru",
    "click",
    "colorama",
    "dateutil",
    "urllib3",
    "requests",
    "idna",
    "chardet",
    "certifi",
    "androguard.core.axml",
)

_asc_cache: dict[str, Any] | None = None


def is_apk_bundle(path: Path) -> bool:
    return path.suffix.lower() in APK_BUNDLE_SUFFIXES


def is_apk_input(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in APK_SUFFIXES or suffix in APK_BUNDLE_SUFFIXES


def probe_asc() -> bool:
    return importlib.util.find_spec("droidasc") is not None


def preload_real_modules() -> None:
    for name in _PRELOAD_MODULES:
        if name in sys.modules:
            continue
        try:
            importlib.import_module(name)
        except Exception:  # pragma: no cover - optional third-party modules
            continue


def quiet_android_loggers() -> None:
    """androguard logs every instruction at DEBUG through loguru; silence it."""
    try:
        from loguru import logger

        logger.remove()
    except Exception:  # pragma: no cover - loguru always ships with androguard
        pass
    import logging

    for name in ("androguard", "asc", "droidasc"):
        logging.getLogger(name).disabled = True
        logging.getLogger(name).setLevel(logging.CRITICAL)


def asc_modules() -> dict[str, Any]:
    """Import droidasc lazily (it is slow and patches androguard at import)."""
    global _asc_cache
    if _asc_cache is not None:
        return _asc_cache
    if not probe_asc():
        raise ToCodeError(
            "APK input requires the ASC backend: install droidasc "
            "(`pip install droidasc`)"
        )
    preload_real_modules()
    quiet_android_loggers()
    apk_handler = importlib.import_module("droidasc.asc_client.apk_handler")
    dex_container = importlib.import_module("droidasc.asc_client.dex_container")
    manifest_handler = importlib.import_module("droidasc.asc_client.manifest_handler")
    tinydex = importlib.import_module("droidasc.asc_core.utils.tinydex")
    dvm_opcode = importlib.import_module("droidasc.asc_core.models.dvm_opcode")
    _asc_cache = {
        "apk_handler": apk_handler,
        "dex_container": dex_container,
        "manifest_handler": manifest_handler,
        "tinydex": tinydex,
        "dvm_opcode": dvm_opcode,
    }
    return _asc_cache


def _decompiler_modules() -> tuple[Any, Any]:
    mods = asc_modules()
    if "dex_manager" not in mods:
        preload_real_modules()
        quiet_android_loggers()
        mods["dex_manager"] = importlib.import_module(
            "droidasc.asc_core.core.dex.dex_manager"
        )
        mods["decompiler"] = importlib.import_module(
            "droidasc.asc_core.utils.decompiler"
        )
    return mods["dex_manager"], mods["decompiler"]


# --------------------------------------------------------------------------
# APK set discovery (bundles and split APKs)
# --------------------------------------------------------------------------


@dataclass(slots=True)
class ApkSet:
    primary: Path
    apks: list[Path]
    workdir: Path | None = None

    @property
    def is_split(self) -> bool:
        return len(self.apks) > 1


def discover_apk_set(path: Path, *, splits: bool = True, workdir: Path) -> ApkSet:
    """Resolve the APK(s) that make up one app.

    ``.apks``/``.xapk`` bundles are unpacked into ``workdir`` and every inner
    ``*.apk`` joins the set. A ``base.apk`` picks up sibling ``split_*.apk``
    files unless ``splits`` is off. Any other APK is exported on its own.
    """
    path = Path(path).resolve()
    if is_apk_bundle(path):
        return _unpack_bundle(path, workdir)
    if not zipfile.is_zipfile(path):
        raise ToCodeError(f"not a valid APK (zip) file: {path}")
    apks = [path]
    if splits and path.name.lower() == "base.apk":
        siblings = sorted(
            item
            for item in path.parent.glob("split_*.apk")
            if item.is_file() and zipfile.is_zipfile(item)
        )
        apks.extend(siblings)
    return ApkSet(primary=path, apks=apks)


def _unpack_bundle(path: Path, workdir: Path) -> ApkSet:
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ToCodeError(f"not a valid APK bundle (zip) file: {path}") from exc
    extracted: list[Path] = []
    with archive:
        for info in archive.infolist():
            name = Path(info.filename).name
            if "/" in info.filename.strip("/") or not name.lower().endswith(".apk"):
                continue
            target = workdir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as sink:
                while True:
                    chunk = source.read(1 << 20)
                    if not chunk:
                        break
                    sink.write(chunk)
            if zipfile.is_zipfile(target):
                extracted.append(target)
    if not extracted:
        raise ToCodeError(f"APK bundle contains no .apk entries: {path}")
    extracted.sort(key=_split_order)
    return ApkSet(primary=extracted[0], apks=extracted, workdir=workdir)


def _split_order(path: Path) -> tuple[int, str]:
    name = path.name.lower()
    if name == "base.apk":
        return (0, name)
    if name.startswith("split_config."):
        return (2, name)
    return (1, name)


# --------------------------------------------------------------------------
# DEX images and inventory records
# --------------------------------------------------------------------------


@dataclass(slots=True)
class DexImage:
    name: str
    source_apk: Path
    entry: str
    data: bytes
    dex: Any

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(slots=True)
class FieldRecord:
    dex: str
    index: int
    class_descriptor: str
    name: str
    type: str
    access_flags: int

    @property
    def is_static(self) -> bool:
        return bool(self.access_flags & ACC_STATIC)

    @property
    def flag_names(self) -> list[str]:
        return flag_names(self.access_flags, _FIELD_FLAG_NAMES)


@dataclass(slots=True)
class MethodRecord:
    id: int
    dex: str
    index: int
    class_descriptor: str
    name: str
    return_type: str
    params: list[str]
    access_flags: int
    is_direct: bool
    code_offset: int
    code_size: int
    registers: int = 0
    # Filled by the reference scan (worker side), resolved by the session.
    callees: list[int] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    # String references are kept once per string in ``AscSession.string_xrefs``
    # (a method-id list per string) rather than as a resolved list per method:
    # a large APK has millions of such edges and the per-method copy dominated
    # the exporter's memory.
    string_ref_count: int = 0
    field_refs: list[str] = field(default_factory=list)
    callers: list[int] = field(default_factory=list)
    line_start: int | None = None
    line_end: int | None = None

    @property
    def descriptor(self) -> str:
        return method_descriptor(
            self.class_descriptor, self.name, self.params, self.return_type
        )

    @property
    def is_native(self) -> bool:
        return bool(self.access_flags & ACC_NATIVE)

    @property
    def is_abstract(self) -> bool:
        return bool(self.access_flags & ACC_ABSTRACT)

    @property
    def is_static(self) -> bool:
        return bool(self.access_flags & ACC_STATIC)

    @property
    def flag_names(self) -> list[str]:
        return flag_names(self.access_flags, _METHOD_FLAG_NAMES)

    @property
    def address(self) -> str:
        return (
            f"{self.dex}:0x{self.code_offset:x}"
            if self.code_offset
            else (f"{self.dex}:method@{self.index}")
        )

    @property
    def prototype(self) -> str:
        params = ", ".join(java_type(item) for item in self.params)
        return f"{java_type(self.return_type)} {self.name}({params})"


@dataclass(slots=True)
class ClassRecord:
    descriptor: str
    dex: str
    index: int
    access_flags: int
    superclass: str | None
    interfaces: list[str]
    source_file: str | None
    methods: list[MethodRecord]
    fields: list[FieldRecord]
    java_path: Path | None = None
    line_count: int = 0
    error: str | None = None
    entry: bool = False

    @property
    def java_name(self) -> str:
        return java_type(self.descriptor)

    @property
    def package(self) -> str:
        name = self.java_name
        return name.rsplit(".", 1)[0] if "." in name else ""

    @property
    def simple_name(self) -> str:
        return self.java_name.rsplit(".", 1)[-1]

    @property
    def flag_names(self) -> list[str]:
        return flag_names(self.access_flags, _CLASS_FLAG_NAMES)

    @property
    def is_interface(self) -> bool:
        return bool(self.access_flags & ACC_INTERFACE)

    @property
    def has_native_methods(self) -> bool:
        return any(item.is_native for item in self.methods)


@dataclass(slots=True)
class StringRecord:
    dex: str
    index: int
    value: str
    offset: int


@dataclass(slots=True)
class DecompiledClass:
    descriptor: str
    source: str | None
    error: str | None
    # method index -> list of (ref kind, index) pairs from the bytecode scan.
    refs: dict[int, list[tuple[str, int]]]


def flag_names(flags: int, table: tuple[tuple[int, str], ...]) -> list[str]:
    return [name for bit, name in table if flags & bit]


def java_type(descriptor: str) -> str:
    """``Lcom/foo/Bar;`` -> ``com.foo.Bar``; ``[I`` -> ``int[]``."""
    dims = 0
    while descriptor.startswith("["):
        dims += 1
        descriptor = descriptor[1:]
    primitives = {
        "V": "void",
        "Z": "boolean",
        "B": "byte",
        "S": "short",
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
    }
    if descriptor in primitives:
        base = primitives[descriptor]
    elif descriptor.startswith("L") and descriptor.endswith(";"):
        base = descriptor[1:-1].replace("/", ".")
    else:
        base = descriptor
    return base + "[]" * dims


def method_descriptor(
    class_descriptor: str, name: str, params: list[str], return_type: str
) -> str:
    return f"{class_descriptor}->{name}({''.join(params)}){return_type}"


def class_java_relpath(descriptor: str) -> Path:
    """Package folders plus ``<Class>.java`` for a Dalvik class descriptor."""
    from ..naming import clean_path_component

    name = descriptor[1:-1] if descriptor.startswith("L") else descriptor
    parts = name.split("/")
    folders = [clean_path_component(item) for item in parts[:-1]]
    leaf = (
        "".join(
            ch if (ch.isascii() and (ch.isalnum() or ch in "_$")) else "_"
            for ch in parts[-1]
        ).strip("_")
        or "unnamed"
    )
    return Path(*folders, f"{leaf}.java") if folders else Path(f"{leaf}.java")


# --------------------------------------------------------------------------
# DEX loading
# --------------------------------------------------------------------------


def load_dex_images(apk: Path, *, prefix: str = "") -> list[DexImage]:
    """Inflate every ``classes*.dex`` (and v41 container members) of one APK."""
    mods = asc_modules()
    apk_handler = mods["apk_handler"]
    dex_container = mods["dex_container"]
    tinydex = mods["tinydex"]
    images: list[DexImage] = []
    with open(apk, "rb") as handle:
        try:
            view = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            return images  # empty file
        try:
            entries = apk_handler._parse_cd_dex_entries(view)
            for entry in entries:
                try:
                    data = bytes(apk_handler._inflate_dex(view, entry))
                except Exception as exc:
                    raise ToCodeError(f"cannot inflate {entry[0]} in {apk}: {exc}")
                for name, buf in dex_container.iter_logical_dex_buffers(entry[0], data):
                    payload = bytes(buf)
                    images.append(
                        DexImage(
                            name=f"{prefix}{name}",
                            source_apk=apk,
                            entry=entry[0],
                            data=payload,
                            dex=tinydex.DEX(payload, name),
                        )
                    )
        finally:
            view.close()
    return images


def load_apk_set_images(apk_set: ApkSet) -> list[DexImage]:
    """DEX images across the whole set; names stay unique across APKs."""
    images: list[DexImage] = []
    seen: set[str] = set()
    for apk in apk_set.apks:
        prefix = "" if apk == apk_set.primary else f"{apk.name}!"
        for image in load_dex_images(apk, prefix=prefix):
            if image.name in seen:
                image.name = f"{apk.name}!{image.name}"
            seen.add(image.name)
            images.append(image)
    return images


def manifest_xml(apk: Path) -> str:
    mods = asc_modules()
    try:
        return str(mods["manifest_handler"].get_manifest_xml(str(apk), pretty=True))
    except KeyError as exc:
        raise ToCodeError(f"{apk.name} has no AndroidManifest.xml") from exc
    except Exception as exc:
        raise ToCodeError(f"cannot decode AndroidManifest.xml in {apk.name}: {exc}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Bytecode reference scan
# --------------------------------------------------------------------------

REF_STRING = "string"
REF_TYPE = "type"
REF_FIELD = "field"
REF_METHOD = "method"

_U16 = struct.Struct("<H")
_I32 = struct.Struct("<i")
_U32 = struct.Struct("<I")


def scan_bytecode_refs(bytecode: Any, *, opcodes: Any = None) -> list[tuple[str, int]]:
    """Return every (kind, index) the instruction stream references.

    Mirrors ASC's ``IndexHandler``: walks the opcode table, stops at the first
    switch/array-data payload, and reads the constant-pool index of the
    string/type/field/method instruction formats.
    """
    if opcodes is None:
        opcodes = asc_modules()["dvm_opcode"]
    table = opcodes.opcodes
    index_flag = opcodes.IndexFlag
    verify_flag = opcodes.VerifyFlag
    fmt_k31c = opcodes.Format.k31c
    payload_mask = verify_flag.kVerifySwitchTargets | verify_flag.kVerifyArrayData
    kinds = {
        index_flag.kIndexStringRef: REF_STRING,
        index_flag.kIndexTypeRef: REF_TYPE,
        index_flag.kIndexFieldRef: REF_FIELD,
        index_flag.kIndexMethodRef: REF_METHOD,
        index_flag.kIndexMethodAndProtoRef: REF_METHOD,
    }
    data = bytes(bytecode)
    refs: list[tuple[str, int]] = []
    length = len(data)
    bound = length
    pc = 0
    while pc + 1 < length and pc < bound:
        op = table.get(data[pc])
        if op is None:
            break
        kind = kinds.get(op.idx)
        if kind is not None and pc + 4 <= length:
            if op.fmt == fmt_k31c:
                if pc + 6 <= length:
                    refs.append((kind, _U32.unpack_from(data, pc + 2)[0]))
            else:
                refs.append((kind, _U16.unpack_from(data, pc + 2)[0]))
        elif op.vflag & payload_mask and pc + 6 <= length:
            target = pc + _I32.unpack_from(data, pc + 2)[0] * 2
            if 0 < target < bound:
                bound = target
        pc += op.oplen * 2
    return refs


# --------------------------------------------------------------------------
# Session: inventory over loaded DEX images
# --------------------------------------------------------------------------


class AscSession:
    backend_name = "asc"
    backend_label = "ASC"
    decompiler_label = "ASC (droidasc) + androguard DAD"

    def __init__(self, apk_set: ApkSet) -> None:
        self.apk_set = apk_set
        self.images: list[DexImage] = []
        self.classes: list[ClassRecord] = []
        self.methods: list[MethodRecord] = []
        self.strings: list[StringRecord] = []
        self._by_descriptor: dict[str, ClassRecord] = {}
        self._method_by_descriptor: dict[str, MethodRecord] = {}
        self._images_by_name: dict[str, DexImage] = {}
        self._pool_cache: dict[tuple[str, str, int], str] = {}
        # (dex name, string index) -> ids of the methods that load it (capped).
        self.string_xrefs: dict[tuple[str, int], list[int]] = {}

    # -- loading -----------------------------------------------------------

    def load(self) -> None:
        self.images = load_apk_set_images(self.apk_set)
        self._images_by_name = {image.name: image for image in self.images}
        self.classes = []
        self.methods = []
        self.strings = []
        next_id = 0
        for image in self.images:
            dex = image.dex
            for class_index in range(len(dex.classes)):
                cls = dex.classes[class_index]
                record, next_id = self._class_record(image, cls, next_id)
                self.classes.append(record)
                self._by_descriptor[record.descriptor] = record
                for method in record.methods:
                    self.methods.append(method)
                    self._method_by_descriptor[method.descriptor] = method
            self.strings.extend(self._string_records(image))

    def _class_record(
        self, image: DexImage, cls: Any, next_id: int
    ) -> tuple[ClassRecord, int]:
        dex = image.dex
        (
            _class_idx,
            access_flags,
            superclass_idx,
            interfaces_off,
            source_file_idx,
            _annotations_off,
            _class_data_off,
            _static_values_off,
        ) = struct.unpack_from("<8I", dex.buf, cls._class_def_off)
        superclass = (
            self._type_name(image, superclass_idx)
            if superclass_idx != NO_INDEX
            else None
        )
        interfaces: list[str] = []
        if interfaces_off:
            count = _U32.unpack_from(dex.buf, interfaces_off)[0]
            for i in range(count):
                type_idx = _U16.unpack_from(dex.buf, interfaces_off + 4 + i * 2)[0]
                interfaces.append(self._type_name(image, type_idx))
        source_file = (
            self._string_value(image, source_file_idx)
            if source_file_idx != NO_INDEX
            else None
        )
        descriptor = cls.fullname
        methods: list[MethodRecord] = []
        for method in cls.methods:
            proto = method.prototype
            code_size = 0
            registers = 0
            code_off = method.code_offset
            if code_off:
                registers, _ins, _outs, _tries, _dbg, insns = struct.unpack_from(
                    "<HHHHII", dex.buf, code_off
                )
                code_size = insns * 2
            methods.append(
                MethodRecord(
                    id=next_id,
                    dex=image.name,
                    index=method.index,
                    class_descriptor=descriptor,
                    name=method.name,
                    return_type=self._type_name(image, proto.return_type_idx),
                    params=[item.descriptor for item in proto.parameters_type],
                    access_flags=method.access_flags,
                    is_direct=method.is_direct,
                    code_offset=code_off,
                    code_size=code_size,
                    registers=registers,
                )
            )
            next_id += 1
        fields = [
            FieldRecord(
                dex=image.name,
                index=item.index,
                class_descriptor=descriptor,
                name=item.name,
                type=str(item.type),
                access_flags=item.access_flags,
            )
            for item in cls.fields
        ]
        record = ClassRecord(
            descriptor=descriptor,
            dex=image.name,
            index=cls.index,
            access_flags=access_flags,
            superclass=superclass,
            interfaces=interfaces,
            source_file=source_file,
            methods=methods,
            fields=fields,
        )
        return record, next_id

    def _string_records(self, image: DexImage) -> list[StringRecord]:
        dex = image.dex
        count = len(dex.strings)
        base = dex.header.strings[0]
        records: list[StringRecord] = []
        for index in range(count):
            offset = _U32.unpack_from(dex.buf, base + index * 4)[0]
            try:
                value = dex.strings[index]
            except Exception:
                continue
            records.append(StringRecord(image.name, index, str(value), offset))
        return records

    # -- lookups -----------------------------------------------------------

    def image(self, name: str) -> DexImage:
        return self._images_by_name[name]

    def class_by_descriptor(self, descriptor: str) -> ClassRecord | None:
        return self._by_descriptor.get(descriptor)

    def method_by_descriptor(self, descriptor: str) -> MethodRecord | None:
        return self._method_by_descriptor.get(descriptor)

    def _type_name(self, image: DexImage, type_idx: int) -> str:
        key = (image.name, REF_TYPE, type_idx)
        cached = self._pool_cache.get(key)
        if cached is None:
            try:
                cached = str(image.dex.types[type_idx].descriptor)
            except Exception:
                cached = f"<type@{type_idx}>"
            self._pool_cache[key] = cached
        return cached

    def _string_value(self, image: DexImage, string_idx: int) -> str:
        key = (image.name, REF_STRING, string_idx)
        cached = self._pool_cache.get(key)
        if cached is None:
            try:
                cached = str(image.dex.strings[string_idx])
            except Exception:
                cached = f"<string@{string_idx}>"
            self._pool_cache[key] = cached
        return cached

    def _method_name(self, image: DexImage, method_idx: int) -> str:
        key = (image.name, REF_METHOD, method_idx)
        cached = self._pool_cache.get(key)
        if cached is None:
            try:
                method = image.dex.methods[method_idx]
                proto = method.prototype
                cached = method_descriptor(
                    method.cls.fullname,
                    method.name,
                    [item.descriptor for item in proto.parameters_type],
                    self._type_name(image, proto.return_type_idx),
                )
            except Exception:
                cached = f"<method@{method_idx}>"
            self._pool_cache[key] = cached
        return cached

    def _field_name(self, image: DexImage, field_idx: int) -> str:
        key = (image.name, REF_FIELD, field_idx)
        cached = self._pool_cache.get(key)
        if cached is None:
            try:
                item = image.dex.fields[field_idx]
                cached = f"{item.cls.fullname}->{item.name}:{item.type}"
            except Exception:
                cached = f"<field@{field_idx}>"
            self._pool_cache[key] = cached
        return cached

    # -- reference resolution ---------------------------------------------

    def apply_refs(
        self, record: ClassRecord, refs: dict[int, list[tuple[str, int]]]
    ) -> None:
        """Resolve a worker's raw (kind, index) pairs into method records."""
        image = self._images_by_name.get(record.dex)
        if image is None:
            return
        by_index = {method.index: method for method in record.methods}
        for method_index, pairs in refs.items():
            method = by_index.get(method_index)
            if method is None:
                continue
            callees: list[int] = []
            external: list[str] = []
            fields: list[str] = []
            string_count = 0
            seen: set[tuple[str, int]] = set()
            for kind, index in pairs:
                if (kind, index) in seen:
                    continue
                seen.add((kind, index))
                if kind == REF_METHOD:
                    descriptor = self._method_name(image, index)
                    target = self._method_by_descriptor.get(descriptor)
                    if target is None:
                        external.append(descriptor)
                    else:
                        callees.append(target.id)
                        target.callers.append(method.id)
                elif kind == REF_STRING:
                    string_count += 1
                    bucket = self.string_xrefs.setdefault((record.dex, index), [])
                    if len(bucket) < MAX_STRING_XREFS:
                        bucket.append(method.id)
                elif kind == REF_FIELD and len(fields) < MAX_FIELD_REFS:
                    fields.append(self._field_name(image, index))
            method.callees = callees
            method.external_calls = external
            method.string_ref_count = string_count
            method.field_refs = fields

    def scan_refs_inline(self, record: ClassRecord) -> dict[int, list[tuple[str, int]]]:
        """Reference scan in the parent (used when no worker pool runs)."""
        image = self._images_by_name[record.dex]
        cls = image.dex.classes[record.index]
        result: dict[int, list[tuple[str, int]]] = {}
        opcodes = asc_modules()["dvm_opcode"]
        for method in cls.methods:
            bytecode = method.bytecode
            if bytecode:
                result[method.index] = scan_bytecode_refs(bytecode, opcodes=opcodes)
        return result

    def close(self) -> None:
        self.images = []
        self._images_by_name = {}
        self._pool_cache = {}
        self.string_xrefs = {}


# --------------------------------------------------------------------------
# Worker-side decompilation (spawned processes)
# --------------------------------------------------------------------------

_worker_state: dict[str, Any] = {}


def init_decompile_worker(apk_set: ApkSet) -> None:
    """Load the DEX images of the set in this worker; managers are built lazily."""
    images = load_apk_set_images(apk_set)
    dex_manager_mod, decompiler_mod = _decompiler_modules()
    quiet_android_loggers()
    _worker_state["images"] = {image.name: image for image in images}
    _worker_state["managers"] = {}
    _worker_state["manager_factory"] = dex_manager_mod.DexManager
    _worker_state["decompile"] = decompiler_mod.decompile_dex_bytes
    _worker_state["opcodes"] = asc_modules()["dvm_opcode"]


def _worker_manager(dex_name: str) -> tuple[DexImage, Any]:
    image = _worker_state["images"][dex_name]
    managers = _worker_state["managers"]
    manager = managers.get(dex_name)
    if manager is None:
        manager = _worker_state["manager_factory"](memoryview(image.data))
        managers[dex_name] = manager
    return image, manager


def decompile_batch_in_worker(
    items: list[tuple[str, str, int]],
) -> list[DecompiledClass]:
    """Decompile ``(dex name, descriptor, class index)`` items in this worker."""
    results: list[DecompiledClass] = []
    for dex_name, descriptor, class_index in items:
        try:
            image, manager = _worker_manager(dex_name)
        except Exception as exc:
            results.append(
                DecompiledClass(descriptor, None, f"dex unavailable: {exc}", {})
            )
            continue
        results.append(
            decompile_class(
                image,
                descriptor,
                class_index,
                manager=manager,
                decompile=_worker_state["decompile"],
                opcodes=_worker_state["opcodes"],
            )
        )
    return results


def decompile_class(
    image: DexImage,
    descriptor: str,
    class_index: int,
    *,
    manager: Any,
    decompile: Any,
    opcodes: Any,
) -> DecompiledClass:
    refs: dict[int, list[tuple[str, int]]] = {}
    try:
        cls = image.dex.classes[class_index]
        for method in cls.methods:
            bytecode = method.bytecode
            if bytecode:
                refs[method.index] = scan_bytecode_refs(bytecode, opcodes=opcodes)
    except Exception as exc:  # pragma: no cover - defensive, tinydex is stable
        return DecompiledClass(descriptor, None, f"reference scan failed: {exc}", {})
    try:
        rebuilt = manager.extract_and_rebuild(descriptor)
        source = decompile(bytes(rebuilt), descriptor)
    except Exception as exc:
        return DecompiledClass(descriptor, None, f"{type(exc).__name__}: {exc}", refs)
    if not isinstance(source, str) or source.startswith("Error:"):
        return DecompiledClass(descriptor, None, str(source).strip() or "empty", refs)
    return DecompiledClass(descriptor, source, None, refs)


class InlineDecompiler:
    """In-process decompiler used for the serial path (and by tests)."""

    def __init__(self, session: AscSession) -> None:
        self.session = session
        self._managers: dict[str, Any] = {}
        self._factory: Any = None
        self._decompile: Any = None
        self._opcodes: Any = None

    def _ensure(self) -> None:
        if self._factory is None:
            dex_manager_mod, decompiler_mod = _decompiler_modules()
            self._factory = dex_manager_mod.DexManager
            self._decompile = decompiler_mod.decompile_dex_bytes
            self._opcodes = asc_modules()["dvm_opcode"]

    def decompile(self, record: ClassRecord) -> DecompiledClass:
        self._ensure()
        image = self.session.image(record.dex)
        manager = self._managers.get(record.dex)
        if manager is None:
            manager = self._factory(memoryview(image.data))
            self._managers[record.dex] = manager
        return decompile_class(
            image,
            record.descriptor,
            record.index,
            manager=manager,
            decompile=self._decompile,
            opcodes=self._opcodes,
        )
