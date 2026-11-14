"""Parser for Android binary XML (AXML), the format used by AndroidManifest.xml
and compiled res/xml/* files inside an APK.

Implements the format documented at
https://source.android.com/docs/core/runtime/dex-format-adjacent/binary-xml
(and historically AOSP frameworks/base: ResourceTypes.h). No aapt/aapt2 needed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .binary import BinaryReader, decode_length8, decode_length16

# Chunk types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# String pool flags
UTF8_FLAG = 1 << 8

# Typed value data types (the low byte of Res_value.dataType)
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

# Well-known framework attribute resource IDs (frameworks/base attrs.xml).
# Only the subset relevant to manifest / network-security-config auditing.
ATTR_ID = {
    0x01010003: "name",
    0x01010010: "versionCode",
    0x0101020B: "minSdkVersion",
    0x0101020C: "targetSdkVersion",
    0x0101020D: "maxSdkVersion",
    0x0101021B: "debuggable",
    0x0101021C: "hasCode",
    0x01010263: "exported",
    0x01010273: "persistableMode",
    0x01010285: "taskAffinity",
    0x010102B7: "allowTaskReparenting",
    0x010102D7: "permission",
    0x010102DB: "process",
    0x010102E4: "taskAffinity",
    0x0101033A: "usesCleartextTraffic",
    0x0101033F: "networkSecurityConfig",
    0x0101035E: "allowBackup",
    0x01010374: "testOnly",
    0x01010375: "extractNativeLibs",
    0x01010392: "isSplitRequired",
    0x010103CE: "enableOnBackInvokedCallback",
    0x010103D5: "appCategory",
    0x010103DA: "requestLegacyExternalStorage",
    0x010103FC: "useEmbeddedDex",
    0x010104B3: "directBootAware",
    0x01010484: "appComponentFactory",
    0x01010526: "hasFragileUserData",
    0x01010527: "isGame",
    0x01010546: "allowClearUserData",
    0x01010547: "largeHeap",
    0x01010552: "supportsRtl",
    0x01010572: "fullBackupContent",
    0x01010573: "dataExtractionRules",
    0x01010581: "dataExtractionRules",
}


class AxmlError(ValueError):
    pass


@dataclass
class AxmlAttribute:
    namespace: Optional[str]
    name: str
    raw_name: str
    value: Any
    raw_value: Optional[str]
    type: int
    type_name: str
    resource_id: Optional[int] = None


@dataclass
class AxmlNode:
    name: str
    namespace: Optional[str]
    attributes: Dict[str, AxmlAttribute] = field(default_factory=dict)
    children: List["AxmlNode"] = field(default_factory=list)
    text: Optional[str] = None

    def get(self, attr: str, default: Any = None) -> Any:
        a = self.attributes.get(attr)
        return a.value if a is not None else default

    def get_raw(self, attr: str) -> Optional[str]:
        a = self.attributes.get(attr)
        return a.raw_value if a is not None else None

    def findall(self, tag: str) -> List["AxmlNode"]:
        return [c for c in self.children if c.name == tag]

    def find(self, tag: str) -> Optional["AxmlNode"]:
        for c in self.children:
            if c.name == tag:
                return c
        return None


_TYPE_NAMES = {
    TYPE_NULL: "null",
    TYPE_REFERENCE: "reference",
    TYPE_ATTRIBUTE: "attribute",
    TYPE_STRING: "string",
    TYPE_FLOAT: "float",
    TYPE_DIMENSION: "dimension",
    TYPE_FRACTION: "fraction",
    TYPE_INT_DEC: "int_dec",
    TYPE_INT_HEX: "int_hex",
    TYPE_INT_BOOLEAN: "boolean",
}


class AxmlParser:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.r = BinaryReader(data)
        self.strings: List[str] = []
        self.resource_map: List[int] = []
        # Per-parser namespace stack: prefix-uri -> uri
        self._ns_stack: List[tuple[Optional[str], str]] = []

    # ------------------------------------------------------------------ parse
    def parse(self) -> AxmlNode:
        if len(self.data) < 8:
            raise AxmlError("buffer too small for an AXML file")
        chunk_type, header_size, chunk_size = self._read_chunk_header()
        if chunk_type != RES_XML_TYPE:
            raise AxmlError(
                f"not an AXML file: root chunk type 0x{chunk_type:04x} "
                f"(expected 0x{RES_XML_TYPE:04x})"
            )
        if header_size != 8:
            raise AxmlError(f"unexpected XML chunk header size {header_size}")
        root: Optional[AxmlNode] = None
        # Stack of open elements; None entries mark namespace-only state.
        stack: List[AxmlNode] = []
        end = chunk_size if chunk_size else len(self.data)
        while self.r.pos < end:
            chunk_start = self.r.pos
            ctype, hsize, csize = self._read_chunk_header()
            body_start = self.r.pos
            if ctype == RES_STRING_POOL_TYPE:
                self._parse_string_pool(csize, hsize, chunk_start)
            elif ctype == RES_XML_RESOURCE_MAP_TYPE:
                count = (csize - hsize) // 4
                self.resource_map = [self.r.u32() for _ in range(count)]
            elif ctype == RES_XML_START_NAMESPACE_TYPE:
                self._parse_start_namespace()
            elif ctype == RES_XML_END_NAMESPACE_TYPE:
                self._parse_end_namespace()
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                node = self._parse_start_element()
                if stack:
                    stack[-1].children.append(node)
                else:
                    if root is not None:
                        raise AxmlError("multiple root elements")
                    root = node
                stack.append(node)
            elif ctype == RES_XML_END_ELEMENT_TYPE:
                self._parse_end_element()
                if not stack:
                    raise AxmlError("unbalanced END_ELEMENT chunk")
                stack.pop()
            elif ctype == RES_XML_CDATA_TYPE:
                self._parse_cdata(stack)
            else:
                # Unknown chunk: skip rather than fail, to stay tolerant of
                # newer platform additions.
                pass
            # Always consume the declared chunk size. body_start is right
            # after the common 8-byte ResChunk_header (type/headerSize/size),
            # so the chunk end is body_start - 8 + csize regardless of the
            # chunk-specific headerSize.
            self.r.pos = body_start - 8 + csize
        if root is None:
            raise AxmlError("AXML contains no root element")
        return root

    def _read_chunk_header(self) -> tuple[int, int, int]:
        ctype = self.r.u16()
        hsize = self.r.u16()
        csize = self.r.u32()
        return ctype, hsize, csize

    # ------------------------------------------------------------ string pool
    def _parse_string_pool(
        self, chunk_size: int, header_size: int, chunk_start: int
    ) -> None:
        string_count = self.r.u32()
        style_count = self.r.u32()
        flags = self.r.u32()
        strings_start = self.r.u32()
        styles_start = self.r.u32()
        is_utf8 = bool(flags & UTF8_FLAG)
        offsets = [self.r.u32() for _ in range(string_count)]
        # stringsStart is relative to the start of this chunk.
        pool_base = chunk_start
        string_data_base = pool_base + strings_start
        for off in offsets:
            p = string_data_base + off
            if is_utf8:
                # Two lengths: UTF-16 units then UTF-8 bytes. Skip the first.
                _, p = decode_length8(self.data, p)
                byte_len, p = decode_length8(self.data, p)
                raw = self.data[p : p + byte_len]
                self.strings.append(raw.decode("utf-8", errors="replace"))
            else:
                char_len, p = decode_length16(self.data, p)
                raw = self.data[p : p + char_len * 2]
                self.strings.append(
                    raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                )
        # The resource map is conventionally the chunk immediately following
        # the string pool; parse_xml() drives chunk iteration, so handle it there.

    # ------------------------------------------------------------- namespaces
    def _parse_start_namespace(self) -> None:
        # ResXMLTree_node header already consumed (lineNumber, comment).
        _line = self.r.u32()
        _comment = self.r.u32()
        prefix_idx = self.r.i32()
        uri_idx = self.r.i32()
        prefix = self._str(prefix_idx)
        uri = self._str(uri_idx) or ""
        self._ns_stack.append((prefix, uri))

    def _parse_end_namespace(self) -> None:
        _line = self.r.u32()
        _comment = self.r.i32()
        _prefix = self.r.i32()
        _uri = self.r.i32()
        if self._ns_stack:
            self._ns_stack.pop()

    def _resolve_namespace(self, uri_idx: int) -> Optional[str]:
        uri = self._str(uri_idx)
        return uri or None

    # --------------------------------------------------------------- elements
    def _parse_start_element(self) -> AxmlNode:
        _line = self.r.u32()
        comment_idx = self.r.i32()
        ns_idx = self.r.i32()
        name_idx = self.r.i32()
        attr_start = self.r.u16()
        attr_size = self.r.u16()
        attr_count = self.r.u16()
        _id_idx = self.r.u16()
        _class_idx = self.r.u16()
        _style_idx = self.r.u16()
        node = AxmlNode(
            name=self._str(name_idx) or f"idx:{name_idx}",
            namespace=self._resolve_namespace(ns_idx),
        )
        for i in range(attr_count):
            attr = self._parse_attribute(i)
            # Last-write-wins; framework attrs use unprefixed names which is
            # what manifest auditing looks up.
            node.attributes[attr.name] = attr
        return node

    def _parse_attribute(self, index: int) -> AxmlAttribute:
        ns_idx = self.r.i32()
        name_idx = self.r.i32()
        raw_value_idx = self.r.i32()
        size = self.r.u16()
        res0 = self.r.u8()
        data_type = self.r.u8()
        data = self.r.u32()

        namespace = self._resolve_namespace(ns_idx)
        raw_name = self._str(name_idx) or f"attr-{index}"
        resource_id = (
            self.resource_map[name_idx]
            if 0 <= name_idx < len(self.resource_map)
            else None
        )
        name = ATTR_ID.get(resource_id or -1, raw_name) if resource_id else raw_name
        raw_value = self._str(raw_value_idx)
        value = self._decode_typed_value(data_type, data, raw_value)
        return AxmlAttribute(
            namespace=namespace,
            name=name,
            raw_name=raw_name,
            value=value,
            raw_value=raw_value,
            type=data_type,
            type_name=_TYPE_NAMES.get(data_type, f"0x{data_type:02x}"),
            resource_id=resource_id,
        )

    def _decode_typed_value(
        self, data_type: int, data: int, raw_value: Optional[str]
    ) -> Any:
        if data_type == TYPE_STRING:
            return raw_value
        if data_type == TYPE_INT_BOOLEAN:
            return bool(data)
        if data_type in (TYPE_INT_DEC,):
            # Interpreted as signed int32; manifest version codes fit.
            return struct.unpack("<i", struct.pack("<I", data))[0]
        if data_type == TYPE_INT_HEX:
            return data
        if data_type == TYPE_REFERENCE or data_type == TYPE_ATTRIBUTE:
            return f"@0x{data:08x}"
        if data_type == TYPE_FLOAT:
            return struct.unpack("<f", struct.pack("<I", data))[0]
        if data_type == TYPE_NULL:
            return None
        # Dimension/fraction/unknown: keep the raw integer, plus raw string.
        return data

    def _parse_end_element(self) -> None:
        _line = self.r.u32()
        _comment = self.r.i32()
        _ns = self.r.i32()
        _name = self.r.i32()

    def _parse_cdata(self, stack: List[AxmlNode]) -> None:
        _line = self.r.u32()
        _comment = self.r.i32()
        text_idx = self.r.i32()
        # Res_value (8 bytes) follows.
        self.r.skip(8)
        if stack:
            stack[-1].text = self._str(text_idx)

    def _str(self, idx: int) -> Optional[str]:
        if idx < 0 or idx >= len(self.strings):
            return None
        return self.strings[idx]

    # --------------------------------------------------------- resource map
    def attach_resource_map(self, ids: List[int]) -> None:
        self.resource_map = ids


def parse_axml(data: bytes) -> AxmlNode:
    """Parse AXML bytes into an AxmlNode tree.

    The resource-map chunk (0x0180, sits between the string pool and the tree
    chunks and maps string indices onto framework attribute resource IDs) is
    consumed by the main parse loop.
    """
    return AxmlParser(data).parse()


def parse_axml_file(path: str) -> AxmlNode:
    with open(path, "rb") as fh:
        return parse_axml(fh.read())
