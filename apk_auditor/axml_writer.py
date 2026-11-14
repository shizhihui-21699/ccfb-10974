"""Encoder that turns an AxmlNode-style element tree back into binary AXML.

Used by the test-APK generator; also gives us a round-trip test for the parser.
Implements the subset of the format that aapt2 emits for manifest-like files:
string pool (UTF-8), optional resource map, namespaces, start/end elements with
typed attributes, CDATA.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

from .axml import (
    AxmlNode,
    RES_NULL_TYPE,
    RES_STRING_POOL_TYPE,
    RES_XML_TYPE,
    RES_XML_CDATA_TYPE,
    RES_XML_END_ELEMENT_TYPE,
    RES_XML_END_NAMESPACE_TYPE,
    RES_XML_RESOURCE_MAP_TYPE,
    RES_XML_START_ELEMENT_TYPE,
    RES_XML_START_NAMESPACE_TYPE,
    TYPE_INT_BOOLEAN,
    TYPE_INT_DEC,
    TYPE_INT_HEX,
    TYPE_REFERENCE,
    TYPE_STRING,
    UTF8_FLAG,
)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_PREFIX = "android"

# Inverse of axml.ATTR_ID for the names we emit ourselves.
_RES_ID_BY_NAME: Dict[str, int] = {}


def _build_attr_id_index() -> None:
    from . import axml as _axml

    for rid, name in _axml.ATTR_ID.items():
        _RES_ID_BY_NAME.setdefault(name, rid)


_build_attr_id_index()


def _u16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)


def _u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _i32(v: int) -> bytes:
    return struct.pack("<i", v)


def _chunk_header(chunk_type: int, header_size: int, payload_size: int) -> bytes:
    """Build a ResChunk_header.

    ``header_size`` is the chunk-specific header size *including* the common
    8-byte ResChunk_header (so tree nodes use 16, string pool 28). Callers
    pass every byte after the common header in ``payload_size`` — including
    the chunk-specific header fields. Total chunk size = 8 + payload_size;
    the declared headerSize is retained for tool compatibility.
    """
    return (
        _u16(chunk_type)
        + _u16(header_size)
        + _u32(8 + payload_size)
    )


def _utf8_len_enc(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    return bytes([0x80 | (n >> 8), n & 0xFF])


def _utf16_len_enc(n: int) -> bytes:
    if n < 0x8000:
        return _u16(n)
    return _u16(0x8000 | (n >> 16)) + _u16(n & 0xFFFF)


class AxmlWriter:
    def __init__(self, use_android_ns: bool = True) -> None:
        self.use_android_ns = use_android_ns
        self._strings: List[str] = []
        self._index: Dict[str, int] = {}
        # (string index, resource id or 0) once frozen.
        self._resource_ids: List[int] = []
        self._chunks: List[bytes] = []
        if use_android_ns:
            self.s(ANDROID_PREFIX)
            self.s(ANDROID_NS)

    # ------------------------------------------------------------- string pool
    def s(self, value: Optional[str]) -> int:
        if value is None:
            return -1
        idx = self._index.get(value)
        if idx is not None:
            return idx
        idx = len(self._strings)
        self._strings.append(value)
        self._index[value] = idx
        return idx

    def _encode_string_pool(self) -> bytes:
        # Resource IDs only cover the leading framework-attribute strings.
        offsets: List[int] = []
        blob = bytearray()
        for value in self._strings:
            offsets.append(len(blob))
            encoded = value.encode("utf-8")
            # UTF-8 pools store both the UTF-16 length and the byte length.
            utf16_len = len(value)
            blob += _utf8_len_enc(utf16_len)
            blob += _utf8_len_enc(len(encoded))
            blob += encoded
            blob += b"\x00"
        while len(blob) % 4:
            blob += b"\x00"
        header_size = 28
        offsets_blob = b"".join(_u32(o) for o in offsets)
        strings_start = header_size + len(offsets_blob)
        header = (
            _u16(RES_STRING_POOL_TYPE)
            + _u16(header_size)
            + _u32(0)  # total size, patched below
            + _u32(len(self._strings))
            + _u32(0)  # style count
            + _u32(UTF8_FLAG)
            + _u32(strings_start)
            + _u32(0)  # styles start
        )
        body = offsets_blob + bytes(blob)
        total = len(header) + len(body)
        header = header[:4] + _u32(total) + header[8:]
        return header + body

    def _encode_resource_map(self) -> bytes:
        if not self._resource_ids:
            return b""
        body = b"".join(_u32(rid) for rid in self._resource_ids)
        # Resource map has only the common 8-byte header; all of body is payload.
        return _chunk_header(RES_XML_RESOURCE_MAP_TYPE, 8, len(body)) + body

    def _node_header(self, line: int = 2, comment: int = -1) -> bytes:
        """ResXMLTree_node fields following the common ResChunk_header."""
        return _u32(line) + _i32(comment)

    # ------------------------------------------------------------------ nodes
    def _typed_value(self, value: Any) -> Tuple[int, int, Optional[str]]:
        """Return (data_type, raw_data, optional_raw_string)."""
        if isinstance(value, bool):
            return TYPE_INT_BOOLEAN, 0xFFFFFFFF if value else 0x00000000, None
        if isinstance(value, int):
            return TYPE_INT_DEC, value & 0xFFFFFFFF, None
        if isinstance(value, str) and value.startswith("@0x"):
            # aapt encodes resource references as TYPE_REFERENCE, no raw string.
            return TYPE_REFERENCE, int(value[3:], 16), None
        return TYPE_STRING, 0, str(value)

    def _attribute(
        self, namespace: Optional[str], name: str, value: Any
    ) -> bytes:
        ns_idx = self.s(namespace)
        name_idx = self.s(name)
        data_type, raw_data, raw_string = self._typed_value(value)
        raw_idx = self.s(raw_string) if data_type == TYPE_STRING else -1
        return (
            _i32(ns_idx)
            + _i32(name_idx)
            + _i32(raw_idx)
            + _u16(8)  # Res_value size
            + b"\x00"  # res0
            + bytes([data_type])
            + _u32(raw_data)
        )

    def _start_namespace(self) -> bytes:
        if not self.use_android_ns:
            return b""
        # headerSize 16 covers the common header + ResXMLTree_node (line,
        # comment); payload is only prefix + uri (two int32 indices).
        payload = _i32(self.s(ANDROID_PREFIX)) + _i32(self.s(ANDROID_NS))
        return (
            _chunk_header(RES_XML_START_NAMESPACE_TYPE, 16, 8 + len(payload))
            + self._node_header(line=1)
            + payload
        )

    def _end_namespace(self) -> bytes:
        if not self.use_android_ns:
            return b""
        payload = _i32(self.s(ANDROID_PREFIX)) + _i32(self.s(ANDROID_NS))
        return (
            _chunk_header(RES_XML_END_NAMESPACE_TYPE, 16, 8 + len(payload))
            + self._node_header(line=1)
            + payload
        )

    def _start_element(self, node: AxmlNode) -> bytes:
        ns_idx = self.s(node.namespace)
        name_idx = self.s(node.name)
        attr_blob = b""
        attr_size = 20
        for attr_name, attr in node.attributes.items():
            ns = attr.namespace
            if ns is None and self.use_android_ns and attr.resource_id:
                ns = ANDROID_NS
            attr_blob += self._attribute(ns, attr.raw_name or attr_name, attr.value)
        # Chunk layout (AOSP ResourceTypes.h):
        #   ResChunk_header(8) + ResXMLTree_node(8) [the 16-byte headerSize]
        #   ResXMLTree_attrExt fixed prefix (20) + N * ResXMLTree_attribute(20)
        # attributeStart=20 is the offset from the attrExt start to the attrs.
        attr_ext = (
            _i32(ns_idx)
            + _i32(name_idx)
            + _u16(20)
            + _u16(attr_size)
            + _u16(len(node.attributes))
            + _u16(0)           # id index
            + _u16(0)           # class index
            + _u16(0)           # style index
            + attr_blob
        )
        # Full payload after the common header: ResXMLTree_node (8) + attrExt.
        payload = self._node_header() + attr_ext
        return (
            _chunk_header(RES_XML_START_ELEMENT_TYPE, 16, len(payload)) + payload
        )

    def _end_element(self, node: AxmlNode) -> bytes:
        # Payload = ResXMLTree_node (8) + end-element ext (ns, name).
        payload = (
            self._node_header()
            + _i32(self.s(node.namespace))
            + _i32(self.s(node.name))
        )
        return _chunk_header(RES_XML_END_ELEMENT_TYPE, 16, len(payload)) + payload

    def _cdata(self, text: str) -> bytes:
        # Payload = ResXMLTree_node (8) + string index + Res_value (8).
        res_value = (
            _u16(8)
            + b"\x00"
            + bytes([RES_NULL_TYPE])
            + _u32(0)
        )
        payload = self._node_header() + _i32(self.s(text)) + res_value
        return _chunk_header(RES_XML_CDATA_TYPE, 16, len(payload)) + payload

    def _walk(self, node: AxmlNode) -> None:
        self._chunks.append(self._start_element(node))
        if node.text is not None:
            self._chunks.append(self._cdata(node.text))
        for child in node.children:
            self._walk(child)
        self._chunks.append(self._end_element(node))

    def write(self, root: AxmlNode) -> bytes:
        # Walk once to register every string; then assign framework resource
        # IDs to attribute-name strings in pool order.
        self._collect(root)
        self._assign_resource_ids()
        tree: List[bytes] = [self._start_namespace()]
        saved = self._chunks
        self._chunks = []
        self._walk(root)
        tree.extend(self._chunks)
        tree.append(self._end_namespace())
        self._chunks = saved
        tree_blob = b"".join(tree)
        pool = self._encode_string_pool()
        rmap = self._encode_resource_map()
        total = 8 + len(pool) + len(rmap) + len(tree_blob)
        header = _u16(RES_XML_TYPE) + _u16(8) + _u32(total)
        return header + pool + rmap + tree_blob

    def _collect(self, node: AxmlNode) -> None:
        self.s(node.namespace)
        self.s(node.name)
        if node.text is not None:
            self.s(node.text)
        for attr_name, attr in node.attributes.items():
            if attr.resource_id is None:
                rid = _RES_ID_BY_NAME.get(attr_name)
                if rid is not None:
                    attr.resource_id = rid
            if attr.resource_id and attr.namespace is None:
                attr.namespace = ANDROID_NS
            self.s(attr.namespace)
            self.s(attr.raw_name or attr_name)
            if attr.value is not None and not isinstance(attr.value, (bool, int)):
                self.s(str(attr.value))
        for child in node.children:
            self._collect(child)

    def _assign_resource_ids(self) -> None:
        # Resource map is parallel to the string pool but only needs entries up
        # to the highest attribute-name index; aapt emits exactly that prefix.
        ids: List[int] = []
        for idx, value in enumerate(self._strings):
            rid = _RES_ID_BY_NAME.get(value, 0)
            ids.append(rid)
        while ids and ids[-1] == 0:
            ids.pop()
        self._resource_ids = ids
