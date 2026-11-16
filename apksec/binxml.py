"""Parser for Android binary XML (AXML / compiled XML) files.

The format is a chunked binary format used for AndroidManifest.xml and for
compiled resource XML such as res/xml/network_security_config.xml.

Only parsing is implemented here; the test-fixture builder under ``tools/``
contains the encoder.  The parser is defensive: it validates every length and
offset and limits nesting / attribute counts so that a hostile APK cannot
exhaust memory or crash the auditor.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Chunk types (frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h)
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Res_value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F

MAX_STRING_COUNT = 500_000
MAX_STRING_BYTES = 2 * 1024 * 1024  # one string
MAX_XML_DEPTH = 256
MAX_ATTRIBUTES = 4096
MAX_CHUNKS = 200_000
MAX_RESOURCE_MAP = 65_536


class BinXmlError(ValueError):
    """Raised when a binary XML / resource chunk is malformed."""


# A small table mapping framework attribute resource IDs to names.  Attribute
# names are normally present in the string pool; this is only a fallback for
# obfuscated / stripped manifests.
ANDROID_ATTR_IDS: dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010004: "manageSpaceActivity",
    0x01010005: "allowClearUserData",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x01010009: "protectionLevel",
    0x0101000A: "permissionGroup",
    0x0101000B: "sharedUserId",
    0x0101000C: "hasCode",
    0x0101000D: "persistent",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010012: "taskAffinity",
    0x01010013: "multiprocess",
    0x01010018: "authorities",
    0x0101001B: "initialize",
    0x01010026: "mimeType",
    0x01010027: "scheme",
    0x01010028: "host",
    0x01010029: "port",
    0x0101002A: "path",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
    0x0101002D: "action",
    0x0101002E: "data",
    0x0101002F: "category",
    0x01010030: "priority",
    0x01010203: "alwaysRetainTaskState",
    0x01010204: "allowTaskReparenting",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010280: "allowBackup",
    0x01010281: "backupAgent",
    0x0101028B: "fullBackupContent",
    0x010102E7: "grantUriPermissions",
    0x010104EA: "extractNativeLibs",
    0x010104EC: "usesCleartextTraffic",
    0x01010527: "networkSecurityConfig",
    0x01010529: "directBootAware",
    0x01010607: "requestLegacyExternalStorage",
    0x01010664: "autoVerify",
    0x010106D8: "dataExtractionRules",
}


@dataclass
class Attribute:
    """One attribute of a binary XML element."""

    name: str
    ns: Optional[str]
    raw_value: Optional[str]  # original source text, when preserved
    value_type: int
    data: int
    res_id: Optional[int] = None
    _pool_value: Optional[str] = None

    @property
    def value(self) -> Optional[str]:
        """Best-effort textual representation of the typed value."""
        t = self.value_type
        if t == TYPE_STRING:
            return self._pool_value
        if t == TYPE_INT_BOOLEAN:
            return "true" if self.data else "false"
        if t == TYPE_INT_DEC:
            return str(struct.unpack("<i", struct.pack("<I", self.data))[0])
        if t == TYPE_INT_HEX:
            return f"0x{self.data:08x}"
        if t == TYPE_REFERENCE:
            return f"@0x{self.data:08x}"
        if t == TYPE_DYNAMIC_REFERENCE:
            return f"@dynamic/0x{self.data:08x}"
        if t == TYPE_ATTRIBUTE:
            return f"?0x{self.data:08x}"
        if t == TYPE_FLOAT:
            return repr(struct.unpack("<f", struct.pack("<I", self.data))[0])
        if t in (
            TYPE_INT_COLOR_ARGB8,
            TYPE_INT_COLOR_RGB8,
            TYPE_INT_COLOR_ARGB4,
            TYPE_INT_COLOR_RGB4,
        ):
            return f"#{self.data:08x}"
        if t in (TYPE_DIMENSION, TYPE_FRACTION):
            return f"0x{self.data:08x}"
        if t == TYPE_NULL:
            return None
        return self.raw_value

    @property
    def display(self) -> Optional[str]:
        if self.raw_value is not None and self.value_type in (
            TYPE_REFERENCE,
            TYPE_DYNAMIC_REFERENCE,
            TYPE_ATTRIBUTE,
        ):
            return self.raw_value
        return self.value if self.value is not None else self.raw_value

    def as_bool(self) -> Optional[bool]:
        if self.value_type == TYPE_INT_BOOLEAN:
            return bool(self.data)
        v = (self.value or "").strip().lower()
        if v in ("true", "1"):
            return True
        if v in ("false", "0"):
            return False
        return None

    def as_int(self) -> Optional[int]:
        if self.value_type in (TYPE_INT_DEC, TYPE_INT_HEX):
            return struct.unpack("<i", struct.pack("<I", self.data))[0]
        try:
            return int(self.value or "", 0)
        except ValueError:
            return None


@dataclass
class Element:
    """An element in the parsed XML tree."""

    name: str
    ns: Optional[str] = None
    line: int = 0
    attrs: list[Attribute] = field(default_factory=list)
    children: list["Element"] = field(default_factory=list)
    text: Optional[str] = None

    def attr(self, name: str, ns: Optional[str] = ANDROID_NS) -> Optional[Attribute]:
        """Return an attribute by local name.

        Android framework attributes live in the android namespace, but some
        (broken or hand-crafted) manifests omit the namespace, so fall back to
        a namespace-agnostic lookup.
        """
        fallback = None
        for a in self.attrs:
            if a.name != name:
                continue
            if ns is None or a.ns == ns:
                return a
            if fallback is None:
                fallback = a
        return fallback

    def value(self, name: str, ns: Optional[str] = ANDROID_NS) -> Optional[str]:
        a = self.attr(name, ns)
        return a.display if a is not None else None

    def flag(self, name: str) -> Optional[bool]:
        a = self.attr(name)
        return a.as_bool() if a is not None else None

    def int_value(self, name: str) -> Optional[int]:
        a = self.attr(name)
        return a.as_int() if a is not None else None

    def children_named(self, name: str) -> Iterator["Element"]:
        for c in self.children:
            if c.name == name:
                yield c

    def iter(self) -> Iterator["Element"]:
        yield self
        for c in self.children:
            yield from c.iter()


@dataclass
class Document:
    root: Optional[Element]
    strings: list[str]
    resource_ids: list[int]

    def dump(self, indent: int = 0) -> str:
        """Human readable dump, used by the ``dump`` CLI subcommand."""
        lines: list[str] = []

        def walk(el: Element, depth: int) -> None:
            pad = "  " * depth
            lines.append(f"{pad}<{el.name}>  (line {el.line})")
            if el.text:
                lines.append(f"{pad}  #text = {el.text!r}")
            for a in el.attrs:
                r = f"0x{a.res_id:08x} " if a.res_id is not None else ""
                lines.append(f"{pad}  @{r}{a.name} = {a.display!r}")
            for c in el.children:
                walk(c, depth + 1)

        if self.root is not None:
            walk(self.root, indent)
        return "\n".join(lines)


def _u16(data: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        raise BinXmlError("truncated 16-bit read")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise BinXmlError("truncated 32-bit read")
    return struct.unpack_from("<I", data, off)[0]


def _chunk_header(data: bytes, off: int) -> tuple[int, int, int]:
    if off + 8 > len(data):
        raise BinXmlError("truncated chunk header")
    typ, header_size, size = struct.unpack_from("<HHI", data, off)
    if header_size < 8:
        raise BinXmlError(f"invalid chunk header size {header_size}")
    if size < header_size or off + size > len(data):
        raise BinXmlError(f"chunk size {size} out of bounds")
    return typ, header_size, size


def parse_string_pool(data: bytes, off: int = 0) -> list[str]:
    """Parse a ResStringPool chunk at ``off`` and return its strings."""
    typ, header_size, size = _chunk_header(data, off)
    if typ != RES_STRING_POOL_TYPE:
        raise BinXmlError(f"expected string pool, got chunk 0x{typ:04x}")
    if header_size < 28:
        raise BinXmlError("string pool header too small")
    count = _u32(data, off + 8)
    style_count = _u32(data, off + 12)
    flags = _u32(data, off + 16)
    strings_start = _u32(data, off + 20)
    # styles_start = _u32(data, off + 24)
    if count > MAX_STRING_COUNT:
        raise BinXmlError(f"string count {count} exceeds limit")
    if style_count > MAX_STRING_COUNT:
        raise BinXmlError("style count exceeds limit")
    offsets_end = off + header_size + 4 * count
    if offsets_end > off + size:
        raise BinXmlError("string offsets exceed chunk")
    if count and not (header_size <= strings_start <= size):
        raise BinXmlError("invalid stringsStart")
    utf8 = bool(flags & 0x100)
    base = off + strings_start
    limit = off + size
    strings: list[str] = []
    for i in range(count):
        stroff = _u32(data, off + header_size + 4 * i)
        pos = base + stroff
        if pos >= limit:
            raise BinXmlError("string offset out of range")
        if utf8:
            # UTF-16 length, then UTF-8 byte length, each 1 or 2 bytes.
            b = data[pos]
            pos += 1
            if b & 0x80:
                if pos >= limit:
                    raise BinXmlError("truncated UTF-8 length")
                b = ((b & 0x7F) << 8) | data[pos]
                pos += 1
            blen = data[pos]
            pos += 1
            if blen & 0x80:
                if pos >= limit:
                    raise BinXmlError("truncated UTF-8 byte length")
                blen = ((blen & 0x7F) << 8) | data[pos]
                pos += 1
            if blen > MAX_STRING_BYTES or pos + blen > limit:
                raise BinXmlError("UTF-8 string exceeds bounds")
            raw = data[pos : pos + blen]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            length = _u16(data, pos)
            pos += 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | _u16(data, pos)
                pos += 2
            nbytes = length * 2
            if nbytes > MAX_STRING_BYTES * 2 or pos + nbytes > limit:
                raise BinXmlError("UTF-16 string exceeds bounds")
            strings.append(data[pos : pos + nbytes].decode("utf-16-le", errors="replace"))
    return strings


def _resolve_value(
    strings: list[str], data_type: int, data: int
) -> Optional[str]:
    if data_type == TYPE_STRING:
        if data >= len(strings):
            raise BinXmlError("string index out of range in value")
        return strings[data]
    return None


def parse_axml(data: bytes) -> Document:
    """Parse a binary XML document and return its element tree."""
    if len(data) < 8:
        raise BinXmlError("file too small for binary XML")
    typ, header_size, size = struct.unpack_from("<HHI", data, 0)
    if typ != RES_XML_TYPE:
        raise BinXmlError(f"not binary XML (chunk type 0x{typ:04x})")
    if size < header_size or size > len(data):
        raise BinXmlError("invalid XML chunk size")

    strings: list[str] = []
    resource_ids: list[int] = []
    root: Optional[Element] = None
    stack: list[Element] = []
    off = header_size
    chunks = 0
    while off + 8 <= size:
        chunks += 1
        if chunks > MAX_CHUNKS:
            raise BinXmlError("too many chunks")
        ctype, cheader, csize = _chunk_header(data, off)
        if csize < 8:
            raise BinXmlError("zero-size chunk")
        if ctype == RES_STRING_POOL_TYPE:
            strings = parse_string_pool(data, off)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            n = (csize - cheader) // 4
            if n > MAX_RESOURCE_MAP:
                raise BinXmlError("resource map too large")
            resource_ids = [
                _u32(data, off + cheader + 4 * i) for i in range(n)
            ]
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            if cheader < 16:
                raise BinXmlError("start element header too small")
            line = _u32(data, off + 8)
            ext = off + cheader
            if ext + 20 > off + csize:
                raise BinXmlError("truncated start element")
            ns_idx, name_idx, attr_start, attr_size, attr_count = struct.unpack_from(
                "<IIHHH", data, ext
            )
            # idIndex, classIndex, styleIndex follow but are unused here
            if attr_count > MAX_ATTRIBUTES:
                raise BinXmlError("too many attributes")
            if name_idx >= len(strings):
                raise BinXmlError("element name index out of range")
            if ns_idx != 0xFFFFFFFF and ns_idx >= len(strings):
                raise BinXmlError("element namespace index out of range")
            el = Element(
                name=strings[name_idx],
                ns=None if ns_idx == 0xFFFFFFFF else strings[ns_idx],
                line=line,
            )
            attr_base = ext + attr_start
            if attr_size < 20:
                raise BinXmlError("attribute size too small")
            if attr_base + attr_count * attr_size > off + csize:
                raise BinXmlError("attributes exceed chunk")
            for i in range(attr_count):
                aoff = attr_base + i * attr_size
                ans_idx, aname_idx, araw_idx = struct.unpack_from("<III", data, aoff)
                if aname_idx >= len(strings):
                    raise BinXmlError("attribute name index out of range")
                if ans_idx != 0xFFFFFFFF and ans_idx >= len(strings):
                    raise BinXmlError("attribute namespace index out of range")
                vtype = data[aoff + 15]
                vdata = _u32(data, aoff + 16)
                raw_value = None
                if araw_idx != 0xFFFFFFFF:
                    if araw_idx >= len(strings):
                        raise BinXmlError("attribute raw value index out of range")
                    raw_value = strings[araw_idx]
                res_id = (
                    resource_ids[aname_idx]
                    if aname_idx < len(resource_ids)
                    else None
                )
                a_name = strings[aname_idx]
                if not a_name and res_id is not None:
                    a_name = ANDROID_ATTR_IDS.get(res_id, f"0x{res_id:08x}")
                pool_value = _resolve_value(strings, vtype, vdata)
                el.attrs.append(
                    Attribute(
                        name=a_name,
                        ns=None if ans_idx == 0xFFFFFFFF else strings[ans_idx],
                        raw_value=raw_value,
                        value_type=vtype,
                        data=vdata,
                        res_id=res_id,
                        _pool_value=pool_value,
                    )
                )
            if stack:
                stack[-1].children.append(el)
            elif root is None:
                root = el
            else:
                raise BinXmlError("multiple root elements")
            if len(stack) >= MAX_XML_DEPTH:
                raise BinXmlError("XML nesting too deep")
            stack.append(el)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if not stack:
                raise BinXmlError("unbalanced end element")
            stack.pop()
        elif ctype == RES_XML_CDATA_TYPE:
            # ResXMLTree_cdataExt { ResStringPool_ref data; Res_value typedData; }
            if cheader < 16 or off + cheader + 12 > off + csize:
                raise BinXmlError("truncated CDATA chunk")
            data_idx = _u32(data, off + cheader)
            vtype = data[off + cheader + 7]
            vdata = _u32(data, off + cheader + 8)
            value = _resolve_value(strings, vtype, vdata)
            if value is None and data_idx != 0xFFFFFFFF:
                if data_idx >= len(strings):
                    raise BinXmlError("CDATA string index out of range")
                value = strings[data_idx]
            if stack and value is not None:
                stack[-1].text = (stack[-1].text or "") + value
        elif ctype in (
            RES_XML_START_NAMESPACE_TYPE,
            RES_XML_END_NAMESPACE_TYPE,
        ):
            pass
        # Unknown chunks are skipped; Android tooling also ignores them.
        off += csize

    if stack:
        raise BinXmlError("unclosed elements in binary XML")
    return Document(root=root, strings=strings, resource_ids=resource_ids)
