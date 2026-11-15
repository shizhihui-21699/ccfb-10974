"""二进制 AXML 编码器（测试夹具用）。

与 apk_audit/axml.py 的解析器互为逆操作：把内存里的元素树编码成
aapt 风格的二进制 Android XML。仅用于自造测试 APK，不参与审计本体。

实现遵循 ResourceTypes.h 的 chunk 布局：
  XML 文件头 -> StringPool -> (ResourceMap) -> 命名空间/元素节点流
"""

from __future__ import annotations

import struct

ANDROID_NS = "http://schemas.android.com/apk/res/android"

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
UTF8_FLAG = 1 << 8

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_DEC = 0x10


class Node:
    def __init__(self, tag: str, attrs: dict | set | None = None,
                 children: list["Node"] | None = None,
                 text: str | None = None):
        self.tag = tag
        # attrs: {(ns_uri 或 None, name): value}；也接受 (key, value) 元组可迭代
        if attrs is None:
            self.attrs: dict = {}
        elif isinstance(attrs, dict):
            self.attrs = attrs
        elif (
            isinstance(attrs, tuple)
            and len(attrs) == 2
            and isinstance(attrs[0], tuple)
        ):
            # 单个 ((ns, name), value)
            self.attrs = {attrs[0]: attrs[1]}
        else:
            self.attrs = dict(attrs)
        self.children = children or []
        self.text = text


class AXMLWriter:
    def __init__(self):
        self._strings: list[str] = []
        self._index: dict[str, int] = {}

    def _s(self, value: str | None) -> int:
        if value is None:
            return 0xFFFFFFFF
        if not isinstance(value, str):
            raise TypeError(f"字符串池只接受 str，收到 {type(value).__name__}: {value!r}")
        if value in self._index:
            return self._index[value]
        idx = len(self._strings)
        self._strings.append(value)
        self._index[value] = idx
        return idx

    # ------------------------------------------------------------------
    def _encode_utf8_length(self, n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        return bytes([0x80 | (n >> 8), n & 0xFF])

    def _string_pool(self) -> bytes:
        # 1) 先编码每个字符串（不含偏移），偏移相对字符串数据区起点
        encoded: list[bytes] = []
        for s in self._strings:
            raw = s.encode("utf-8")
            item = (
                self._encode_utf8_length(len(s))       # UTF-16 长度
                + self._encode_utf8_length(len(raw))   # UTF-8 字节长度
                + raw
                + b"\x00"                              # null 终止
            )
            encoded.append(item)

        # 2) 偏移表 + 字符串区都要 4 字节对齐
        header_size = 28
        count = len(self._strings)
        offsets_size = 4 * count
        strings_start = header_size + offsets_size
        # 字符串区起点相对 chunk 起点须 4 字节对齐
        pad = (-strings_start) % 4
        strings_start += pad

        offsets = []
        data = bytearray()
        for item in encoded:
            offsets.append(len(data))  # 首项为 0
            data += item
        while len(data) % 4:
            data.append(0)

        total = strings_start + len(data)
        out = bytearray()
        # ResStringPool_header 固定 28 字节：ResChunk_header(8) + 5*u32(20)
        out += struct.pack(
            "<HHIIIII",
            RES_STRING_POOL_TYPE, header_size, total,
            count, 0, UTF8_FLAG, strings_start,
        )
        assert len(out) == 24  # HHIIIII 占 24，补 4 字节到 headerSize=28
        out += b"\x00" * (header_size - 24)
        out += b"".join(struct.pack("<I", o) for o in offsets)
        out += b"\x00" * pad
        out += data
        return bytes(out)

    # ------------------------------------------------------------------
    def _typed(self, value) -> tuple[int, int, str | None]:
        """返回 (dataType, data, rawString 或 None)。"""
        if isinstance(value, bool):
            return TYPE_INT_BOOLEAN, (0xFFFFFFFF if value else 0), None
        if isinstance(value, int):
            return TYPE_INT_DEC, value, None
        if isinstance(value, str) and value.startswith("@") and value[1:].isalnum():
            # 仅纯十六进制资源 ID 才编码为 reference；符号引用（如 @xml/xxx）
            # 在没有 resources.arsc 的自造包里按字符串存储
            return TYPE_REFERENCE, int(value[1:], 16), None
        # 字符串类型：data 放字符串索引，rawValue 也放同一索引
        return TYPE_STRING, self._s(str(value)), str(value)

    def _collect_node_strings(self, node: Node):
        self._s(node.tag)
        if node.text is not None:
            self._s(node.text)
        for key, value in node.attrs.items():
            ns, name = key
            if ns:
                self._s(ns)
            self._s(name)
            if isinstance(value, str):
                self._s(value)
        for child in node.children:
            self._collect_node_strings(child)

    # ------------------------------------------------------------------
    def write(self, root: Node, with_android_ns: bool = True) -> bytes:
        # 先固定命名空间字符串的索引（uri、prefix），再收集节点字符串，
        # 保证字符串池索引顺序与偏移数组严格一致
        if with_android_ns:
            ns_idx = self._s(ANDROID_NS)
            prefix_idx = self._s("android")
        self._collect_node_strings(root)

        body = bytearray()
        if with_android_ns:
            body += self._namespace_chunk(
                RES_XML_START_NAMESPACE_TYPE, prefix_idx, ns_idx
            )
        self._write_node(body, root)
        if with_android_ns:
            body += self._namespace_chunk(
                RES_XML_END_NAMESPACE_TYPE, prefix_idx, ns_idx
            )

        pool = self._string_pool()
        total_size = 8 + len(pool) + len(body)
        header = struct.pack("<HHI", RES_XML_TYPE, 8, total_size)
        return header + pool + bytes(body)

    def _namespace_chunk(self, ctype: int, prefix: int, uri: int) -> bytes:
        # lineNumber(4) comment(4) prefix(4) uri(4)
        payload = struct.pack("<IIII", 1, 0xFFFFFFFF, prefix, uri)
        return struct.pack("<HHI", ctype, 16, 8 + len(payload)) + payload

    def _write_node(self, body: bytearray, node: Node):
        attr_items = []
        for key, value in node.attrs.items():
            ns, name = key
            ns_idx = self._s(ns) if ns else 0xFFFFFFFF
            name_idx = self._s(name)
            data_type, data, raw = self._typed(value)
            raw_idx = self._s(raw) if raw is not None else 0xFFFFFFFF
            attr_items.append((ns_idx, name_idx, raw_idx, data_type, data))

        # 节点体（chunk+8 起）：line/comment/ns/name 16 字节 + attrExt 12 字节
        # = 28 字节后才是属性区，故 attrStart 相对节点体起点为 28。
        # 标准 AAPT 此处历史值常为 20（其节点头布局略有差异），但只要
        # 解析器按 chunk+8+attrStart 定位即可正确往返；属性记录固定 20 字节。
        attr_start = 28
        attr_size = 20
        attr_count = len(attr_items)
        attr_ext = struct.pack(
            "<HHHHHH",
            attr_start, attr_size, attr_count,
            0, 0, 0,
        )
        payload = (
            struct.pack("<IIII", 1, 0xFFFFFFFF, 0xFFFFFFFF, self._s(node.tag))
            + attr_ext
        )
        for ns_idx, name_idx, raw_idx, data_type, data in attr_items:
            # ResXMLTree_attribute: ns(4) name(4) rawValue(4)
            # typedValue: size(2)=8 res0(1)=0 dataType(1) data(4)
            payload += struct.pack(
                "<IIIHBBI",
                ns_idx, name_idx, raw_idx,
                8, 0, data_type, data,
            )
        body += struct.pack(
            "<HHI", RES_XML_START_ELEMENT_TYPE, 16, 8 + len(payload)
        ) + payload

        if node.text is not None:
            # CDATA chunk（审计解析器会跳过，但保持结构完整）
            cdata_payload = struct.pack(
                "<IIIHBB", 1, 0xFFFFFFFF, self._s(node.text), 8, 0, TYPE_NULL
            )
            body += struct.pack("<HHI", 0x0104, 16, 8 + len(cdata_payload))
            body += cdata_payload

        for child in node.children:
            self._write_node(body, child)

        end_payload = struct.pack(
            "<IIII", 1, 0xFFFFFFFF, 0xFFFFFFFF, self._s(node.tag)
        )
        body += struct.pack(
            "<HHI", RES_XML_END_ELEMENT_TYPE, 16, 8 + len(end_payload)
        ) + end_payload