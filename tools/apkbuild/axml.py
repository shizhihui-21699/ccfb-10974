"""Encoder for Android binary XML (AXML) and the compiled resource table.

Counterpart to :mod:`apksec.binxml` / :mod:`apksec.arsc`, used only to build
realistic test fixtures without aapt2.  The chunk layout mirrors what aapt2
emits for simple, single-configuration resources.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Union

from apksec import binxml

# Framework attribute resource ids, needed for the XML resource-map chunk.
ATTR_IDS = {
    "theme": 0x01010000,
    "label": 0x01010001,
    "icon": 0x01010002,
    "name": 0x01010003,
    "permission": 0x01010006,
    "readPermission": 0x01010007,
    "writePermission": 0x01010008,
    "protectionLevel": 0x01010009,
    "permissionGroup": 0x0101000A,
    "sharedUserId": 0x0101000B,
    "hasCode": 0x0101000C,
    "enabled": 0x0101000E,
    "debuggable": 0x0101000F,
    "exported": 0x01010010,
    "process": 0x01010011,
    "taskAffinity": 0x01010012,
    "multiprocess": 0x01010013,
    "authorities": 0x01010018,
    "scheme": 0x01010027,
    "host": 0x01010028,
    "port": 0x01010029,
    "path": 0x0101002A,
    "pathPrefix": 0x0101002B,
    "pathPattern": 0x0101002C,
    "action": 0x0101002D,
    "category": 0x0101002F,
    "priority": 0x01010030,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "targetSdkVersion": 0x01010270,
    "maxSdkVersion": 0x01010271,
    "allowBackup": 0x01010280,
    "fullBackupContent": 0x0101028B,
    "grantUriPermissions": 0x010102E7,
    "extractNativeLibs": 0x010104EA,
    "usesCleartextTraffic": 0x010104EC,
    "networkSecurityConfig": 0x01010527,
    "directBootAware": 0x01010529,
    "requestLegacyExternalStorage": 0x01010607,
    "autoVerify": 0x01010664,
    "dataExtractionRules": 0x010106D8,
    "compileSdkVersion": 0x01010572,
}

AttrValue = Union[bool, int, str, None, tuple]


@dataclass
class A:
    """One attribute.

    ``value`` may be a bool, an int, a str, ``None``, ``("ref", 0x7f000001)``,
    or ``("hex", 0x1f)``.
    """

    name: str
    value: AttrValue
    ns: Optional[str] = binxml.ANDROID_NS


class _StringPoolBuilder:
    def __init__(self, utf8: bool = True):
        self.utf8 = utf8
        self.strings: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s in self._index:
            return self._index[s]
        idx = len(self.strings)
        self.strings.append(s)
        self._index[s] = idx
        return idx

    def index(self, s: str) -> int:
        return self._index[s]

    def build(self) -> bytes:
        offsets: list[int] = []
        data = bytearray()
        for s in self.strings:
            offsets.append(len(data))
            if self.utf8:
                encoded = s.encode("utf-8")
                u16_len = len(s.encode("utf-16-le")) // 2
                data += _pack_pool_len(u16_len)
                data += _pack_pool_len(len(encoded))
                data += encoded + b"\x00"
            else:
                encoded = s.encode("utf-16-le")
                length = len(encoded) // 2
                if length > 0x7FFF:
                    raise ValueError("string too long for a UTF-16 pool")
                data += struct.pack("<H", length) + encoded + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        strings_start = 28 + 4 * len(self.strings)
        header = struct.pack(
            "<HHIIIIII",
            binxml.RES_STRING_POOL_TYPE,
            28,
            strings_start + len(data),
            len(self.strings),
            0,
            0x100 if self.utf8 else 0,
            strings_start,
            0,
        )
        return header + b"".join(struct.pack("<I", o) for o in offsets) + bytes(data)


def _pack_pool_len(n: int) -> bytes:
    if n > 0x7FFF:
        raise ValueError("string too long for a UTF-8 pool")
    if n > 0x7F:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    return bytes([n])


class AxmlBuilder:
    def __init__(self, utf8: bool = True):
        self.pool = _StringPoolBuilder(utf8=utf8)
        self.nodes: list[tuple] = []

    def start(self, name: str, attrs: Optional[list[A]] = None) -> None:
        self.nodes.append(("start", name, [self._encode_attr(a) for a in (attrs or [])]))

    def end(self, name: str) -> None:
        self.nodes.append(("end", name))

    def element(self, name: str, attrs: Optional[list[A]] = None) -> "_El":
        return _El(self, name, attrs or [])

    # -- encoding --------------------------------------------------------
    def _encode_attr(self, attr: A) -> tuple[str, Optional[str], Optional[str], int, int]:
        value = attr.value
        raw: Optional[str] = None
        if isinstance(value, bool):
            vtype = binxml.TYPE_INT_BOOLEAN
            data = 0xFFFFFFFF if value else 0
            raw = "true" if value else "false"
        elif isinstance(value, int):
            vtype, data = binxml.TYPE_INT_DEC, value & 0xFFFFFFFF
        elif isinstance(value, tuple) and value and value[0] == "ref":
            vtype, data = binxml.TYPE_REFERENCE, int(value[1])
            if len(value) > 2:
                raw = "@" + str(value[2])
        elif isinstance(value, tuple) and value and value[0] == "hex":
            vtype, data = binxml.TYPE_INT_HEX, int(value[1])
        elif value is None:
            vtype, data = binxml.TYPE_NULL, 0
        else:
            vtype, data, raw = binxml.TYPE_STRING, -1, str(value)
        return (attr.name, attr.ns, raw, vtype, data)

    def to_bytes(self) -> bytes:
        # Attribute names must occupy the first string-pool slots so the
        # resource map can be indexed by name index, exactly like aapt.
        attr_names: list[str] = []
        for node in self.nodes:
            if node[0] == "start":
                for enc in node[2]:
                    rid = ATTR_IDS.get(enc[0])
                    if rid is not None and enc[0] not in attr_names:
                        attr_names.append(enc[0])
        for name in attr_names:
            self.pool.add(name)

        body = bytearray()
        uses_android = any(
            (node[0] == "start" and any(enc[1] == binxml.ANDROID_NS for enc in node[2]))
            for node in self.nodes
        )
        line = 1
        if uses_android:
            body += self._namespace_chunk(True, line)
        for node in self.nodes:
            if node[0] == "start":
                body += self._start_element(line, node[1], node[2])
            elif node[0] == "end":
                body += self._end_element(line, node[1])
            line += 1
        if uses_android:
            body += self._namespace_chunk(False, line + 1)

        pool_chunk = self.pool.build()
        resmap = b""
        if attr_names:
            resmap = struct.pack(
                "<HHI", binxml.RES_XML_RESOURCE_MAP_TYPE, 8, 8 + 4 * len(attr_names)
            ) + b"".join(struct.pack("<I", ATTR_IDS[n]) for n in attr_names)

        total = 8 + len(pool_chunk) + len(resmap) + len(body)
        return struct.pack("<HHI", binxml.RES_XML_TYPE, 8, total) + pool_chunk + resmap + bytes(body)

    def _start_element(self, line: int, name: str, attrs) -> bytes:
        attrs = sorted(attrs, key=lambda a: ATTR_IDS.get(a[0], 0x7FFFFFFF))
        name_idx = self.pool.add(name)
        # Elements themselves are not namespaced; only attributes carry the
        # android namespace, exactly as aapt2 emits them.
        ns_idx = 0xFFFFFFFF
        encoded = bytearray()
        for (aname, ans, raw, vtype, data) in attrs:
            aname_idx = self.pool.add(aname)
            ans_idx = self.pool.add(ans) if ans else 0xFFFFFFFF
            raw_idx = self.pool.add(raw) if raw is not None else 0xFFFFFFFF
            if vtype == binxml.TYPE_STRING and data == -1:
                data = self.pool.add(raw or "")
            encoded += struct.pack(
                "<IIIHBBI",
                ans_idx,
                aname_idx,
                raw_idx,
                8,
                0,
                vtype,
                data & 0xFFFFFFFF,
            )
        node = struct.pack("<HHI", binxml.RES_XML_START_ELEMENT_TYPE, 16, 0) + struct.pack(
            "<II", line, 0xFFFFFFFF
        )
        ext = struct.pack(
            "<IIHHHHHH",
            ns_idx,
            name_idx,
            20,
            20,
            len(attrs),
            0,
            0,
            0,
        )
        size = len(node) + len(ext) + len(encoded)
        return struct.pack("<HHI", binxml.RES_XML_START_ELEMENT_TYPE, 16, size) + node[8:] + ext + bytes(encoded)

    def _end_element(self, line: int, name: str) -> bytes:
        name_idx = self.pool.add(name)
        size = 16 + 8
        return (
            struct.pack("<HHI", binxml.RES_XML_END_ELEMENT_TYPE, 16, size)
            + struct.pack("<II", line, 0xFFFFFFFF)
            + struct.pack("<II", 0xFFFFFFFF, name_idx)
        )

    def _namespace_chunk(self, start: bool, line: int) -> bytes:
        prefix_idx = self.pool.add("android")
        uri_idx = self.pool.add(binxml.ANDROID_NS)
        ctype = (
            binxml.RES_XML_START_NAMESPACE_TYPE
            if start
            else binxml.RES_XML_END_NAMESPACE_TYPE
        )
        size = 16 + 8
        return (
            struct.pack("<HHI", ctype, 16, size)
            + struct.pack("<II", line, 0xFFFFFFFF)
            + struct.pack("<II", prefix_idx, uri_idx)
        )


class _El:
    def __init__(self, builder: AxmlBuilder, name: str, attrs: list[A]):
        self.b = builder
        self.name = name
        builder.start(name, attrs)

    def __enter__(self) -> "_El":
        return self

    def __exit__(self, *exc) -> None:
        self.b.end(self.name)


# ---------------------------------------------------------------------------
# resources.arsc
# ---------------------------------------------------------------------------

RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

PACKAGE_HEADER_SIZE = 288
CONFIG_SIZE = 64


@dataclass
class ResSpec:
    type_name: str
    key: str
    value: Optional[str]  # string value; None means <null>


class ArscBuilder:
    """Compile a flat set of resources (single default config) to ARSC."""

    def __init__(self, package_name: str = "com.example.fixture", package_id: int = 0x7F):
        self.package_name = package_name
        self.package_id = package_id
        self.specs: list[ResSpec] = []

    def add(self, type_name: str, key: str, value: Optional[str]) -> int:
        for spec in self.specs:
            if spec.type_name == type_name and spec.key == key:
                spec.value = value
                return self.lookup_id(type_name, key)
        self.specs.append(ResSpec(type_name, key, value))
        return self.lookup_id(type_name, key)

    def _type_names(self) -> list[str]:
        names: list[str] = []
        for spec in self.specs:
            if spec.type_name not in names:
                names.append(spec.type_name)
        return names

    def lookup_id(self, type_name: str, key: str) -> Optional[int]:
        type_names = self._type_names()
        if type_name not in type_names:
            return None
        tid = type_names.index(type_name) + 1
        keys = [s.key for s in self.specs if s.type_name == type_name]
        if key not in keys:
            return None
        return (self.package_id << 24) | (tid << 16) | keys.index(key)

    def to_bytes(self) -> bytes:
        type_names = self._type_names()
        key_names: list[str] = []
        for spec in self.specs:
            if spec.key not in key_names:
                key_names.append(spec.key)
        strings: list[str] = []
        for spec in self.specs:
            if spec.value is not None and spec.value not in strings:
                strings.append(spec.value)

        global_pool = _StringPoolBuilder(utf8=True)
        for s in strings:
            global_pool.add(s)
        type_pool = _StringPoolBuilder(utf8=True)
        for n in type_names:
            type_pool.add(n)
        key_pool = _StringPoolBuilder(utf8=True)
        for n in key_names:
            key_pool.add(n)

        body = bytearray()
        for tid, type_name in enumerate(type_names, start=1):
            entries = [s for s in self.specs if s.type_name == type_name]
            # ResTable_typeSpec
            spec_size = 16 + 4 * len(entries)
            body += struct.pack(
                "<HHIBBHI",
                RES_TABLE_TYPE_SPEC_TYPE,
                16,
                spec_size,
                tid,
                0,
                0,
                len(entries),
            )
            body += b"".join(struct.pack("<I", 0) for _ in entries)
            # ResTable_type with one default configuration
            config = struct.pack("<I", CONFIG_SIZE) + b"\x00" * (CONFIG_SIZE - 4)
            header_size = 20 + len(config)
            offsets = bytearray()
            blobs = bytearray()
            for spec in entries:
                offsets += struct.pack("<I", len(blobs))
                key_idx = key_pool.index(spec.key)
                if spec.value is None:
                    vtype, vdata = binxml.TYPE_NULL, 0
                else:
                    vtype, vdata = binxml.TYPE_STRING, global_pool.index(spec.value)
                blobs += struct.pack("<HHI", 8, 0, key_idx)
                blobs += struct.pack("<HBBI", 8, 0, vtype, vdata)
            entries_start = header_size + len(offsets)
            chunk_size = entries_start + len(blobs)
            body += struct.pack(
                "<HHIBBHII",
                RES_TABLE_TYPE_TYPE,
                header_size,
                chunk_size,
                tid,
                0,
                0,
                len(entries),
                entries_start,
            )
            body += config + bytes(offsets) + bytes(blobs)

        type_strings_off = PACKAGE_HEADER_SIZE + len(body)
        key_strings_off = type_strings_off + len(type_pool.build())
        package_size = key_strings_off + len(key_pool.build())

        name_bytes = self.package_name.encode("utf-16-le")[:254]
        package_header = (
            struct.pack("<HHII", RES_TABLE_PACKAGE_TYPE, PACKAGE_HEADER_SIZE, package_size, self.package_id)
            + name_bytes.ljust(256, b"\x00")
            + struct.pack(
                "<IIIII",
                type_strings_off,
                len(type_names),
                key_strings_off,
                len(key_names),
                0,  # typeIdOffset
            )
        )
        package_chunk = package_header + bytes(body) + type_pool.build() + key_pool.build()

        global_chunk = global_pool.build()
        total = 12 + len(global_chunk) + len(package_chunk)
        return struct.pack("<HHII", RES_TABLE_TYPE, 12, total, 1) + global_chunk + package_chunk
