"""二进制 Android XML（AXML / Binary XML）解析器。

纯标准库实现，解析 APK 中编译过的 AndroidManifest.xml 与
res/xml/network_security_config.xml。不依赖 aapt / androguard。

参考 AOSP 头文件：
  frameworks/base/include/androidfw/ResourceTypes.h
"""

from __future__ import annotations

import struct

ANDROID_NS = "http://schemas.android.com/apk/res/android"
TOOLS_NS = "http://schemas.android.com/tools"

# 顶层 chunk 类型
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

# 字符串池 flag
UTF8_FLAG = 1 << 8

# typed value 的 dataType
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

_DIMENSION_UNITS = ("px", "dip", "sp", "pt", "in", "mm")
_FRACTION_UNITS = ("%", "%p")


class AXMLError(Exception):
    """AXML 数据格式异常。"""


class _Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        v = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def take(self, n: int) -> bytes:
        v = self.data[self.pos : self.pos + n]
        self.pos += n
        return v


class Element:
    """极简 XML 元素，属性按 (命名空间, 本地名) 索引。"""

    def __init__(self, tag: str, ns: str | None, parent: "Element | None"):
        self.tag = tag
        self.ns = ns
        self.parent = parent
        self.children: list[Element] = []
        # 元素的 CDATA 文本（如 <domain>legacy.example.com</domain>）
        self.text: str | None = None
        # (ns_uri 或 None, local_name) -> 解析后的 Python 值
        self.attrs: dict[tuple[str | None, str], object] = {}
        # 同上键 -> 原始字符串（typed value 之外的兜底）
        self.raw_attrs: dict[tuple[str | None, str], str] = {}

    # ---- 属性访问 ----
    def get(self, name: str, ns: str | None = ANDROID_NS, default=None):
        """取属性；android: 命名空间是默认命名空间。"""
        return self.attrs.get((ns, name), default)

    def get_raw(self, name: str, ns: str | None = ANDROID_NS, default=None):
        return self.raw_attrs.get((ns, name), default)

    def all_attrs(self) -> dict[str, object]:
        """展平为 {前缀:本地名: 值}，仅用于报告展示。"""
        out = {}
        for (ns, name), val in self.attrs.items():
            if ns is None:
                out[name] = val
            elif ns == ANDROID_NS:
                out[f"android:{name}"] = val
            else:
                out[f"{{{ns}}}{name}"] = val
        return out

    # ---- 树遍历 ----
    def findall(self, tag: str) -> list["Element"]:
        return [c for c in self.children if c.tag == tag]

    def find(self, tag: str) -> "Element | None":
        for c in self.children:
            if c.tag == tag:
                return c
        return None

    def iter(self, tag: str | None = None):
        if tag is None or self.tag == tag:
            yield self
        for c in self.children:
            yield from c.iter(tag)

    def __repr__(self):
        return f"<Element {self.tag} attrs={list(self.all_attrs())}>"


def _decode_length16(cur: _Cursor) -> int:
    # UTF-16 字符串长度前缀为 u16：高位置 1 时双 u16 形式
    v = cur.u16()
    if v & 0x8000:
        v = ((v & 0x7FFF) << 16) | cur.u16()
    return v


def _decode_length8(cur: _Cursor) -> tuple[int, int]:
    """返回 (utf16 长度, utf8 长度)，并推进游标。"""
    utf16_len = cur.u8()
    if utf16_len & 0x80:
        utf16_len = ((utf16_len & 0x7F) << 8) | cur.u8()
    utf8_len = cur.u8()
    if utf8_len & 0x80:
        utf8_len = ((utf8_len & 0x7F) << 8) | cur.u8()
    return utf16_len, utf8_len


class AXMLParser:
    """把一段二进制 AXML 字节流解析成 :class:`Element` 树。"""

    def __init__(self, data: bytes):
        if len(data) < 8:
            raise AXMLError("数据过短，不可能是 AXML")
        self.cur = _Cursor(data)
        self.strings: list[str] = []
        self._ns_map: dict[str, str] = {}  # uri -> prefix

    # ---- 字符串池 ----
    def _parse_string_pool(self, chunk_size: int):
        cur = self.cur
        chunk_start = cur.pos - 8  # 进入本方法前已读过 chunk 头 8 字节
        string_count = cur.u32()
        style_count = cur.u32()
        flags = cur.u32()
        strings_start = cur.u32()
        styles_start = cur.u32()
        offsets = [cur.u32() for _ in range(string_count)]
        is_utf8 = bool(flags & UTF8_FLAG)
        # stringsStart 相对本 pool chunk 起点；chunk 在文件中的起点为 chunk_start
        strings_base = chunk_start + strings_start
        # 注：AOSP 实测 stringsStart 已含 8 字节 ResChunk_header，即相对 chunk 起点

        for off in offsets:
            pos = strings_base + off
            try:
                if is_utf8:
                    sub = _Cursor(self.cur.data)
                    sub.pos = pos
                    _utf16, utf8_len = _decode_length8(sub)
                    raw = sub.take(utf8_len)
                    self.strings.append(raw.decode("utf-8", errors="replace"))
                else:
                    sub = _Cursor(self.cur.data)
                    sub.pos = pos
                    n = _decode_length16(sub)
                    raw = sub.take(n * 2)
                    self.strings.append(raw.decode("utf-16-le", errors="replace"))
            except IndexError:
                raise AXMLError("字符串池索引越界")

        self.cur.pos = chunk_start + chunk_size  # 跳过整个 chunk（含 style 区）

    def _s(self, idx: int) -> str | None:
        if idx == 0xFFFFFFFF or idx < 0 or idx >= len(self.strings):
            return None
        return self.strings[idx]

    # ---- typed value ----
    def _typed_value(self, data_type: int, data: int, raw_idx: int):
        raw = self._s(raw_idx)
        if data_type == TYPE_STRING:
            return raw
        if data_type == TYPE_NULL:
            return raw  # 常见于框架引用缺失，退回原始字符串
        if data_type == TYPE_INT_BOOLEAN:
            return data != 0
        if data_type == TYPE_REFERENCE:
            return f"@{data:08x}"
        if data_type == TYPE_ATTRIBUTE:
            return f"?{data:08x}"
        if data_type == TYPE_FLOAT:
            return struct.unpack("<f", struct.pack("<I", data))[0]
        if data_type == TYPE_INT_DEC:
            return data
        if data_type == TYPE_INT_HEX:
            return data
        if data_type == TYPE_DIMENSION:
            unit = _DIMENSION_UNITS[data & 0x7]
            val = struct.unpack("<f", struct.pack("<I", data & 0xFFFFFF00))[0]
            return f"{val:g}{unit}"
        if data_type == TYPE_FRACTION:
            unit = _FRACTION_UNITS[data & 0x3]
            base = (data >> 4) & 0x7
            val = struct.unpack("<f", struct.pack("<I", data & 0xFFFFFF00))[0]
            _ = base
            return f"{val:g}{unit}"
        if 0x1C <= data_type <= 0x1F:  # 各类颜色值
            return f"#{data:08x}"
        # 其它整型子类一律按整数处理
        return data

    # ---- 主入口 ----
    def parse(self) -> Element:
        cur = self.cur
        # 文件头：ResChunk_header（type=RES_XML_TYPE, headerSize=8, size=文件总长）
        file_type = cur.u16()
        header_size = cur.u16()
        file_size = cur.u32()
        if file_type != RES_XML_TYPE:
            raise AXMLError(
                f"魔数不匹配：期望 0x{RES_XML_TYPE:04x}，得到 0x{file_type:04x}"
            )
        if header_size != 8:
            raise AXMLError(f"XML 文件头大小异常：{header_size}")
        if file_size > len(cur.data):
            raise AXMLError("声明的文件大小超过实际数据长度")

        root: Element | None = None
        stack: list[Element] = []

        while cur.pos < min(file_size, len(cur.data)):
            chunk_start = cur.pos
            ctype = cur.u16()
            _header_size = cur.u16()
            chunk_size = cur.u32()
            if chunk_size < 8 or chunk_start + chunk_size > len(cur.data):
                raise AXMLError(f"chunk 尺寸非法：type=0x{ctype:04x} size={chunk_size}")

            if ctype == RES_STRING_POOL_TYPE:
                self._parse_string_pool(chunk_size)
                continue

            if ctype == RES_XML_RESOURCE_MAP_TYPE:
                cur.pos = chunk_start + chunk_size  # 资源 ID 映射，审计不需要
                continue

            if ctype in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
                _line = cur.u32()
                _comment = cur.u32()
                prefix = self._s(cur.u32())
                uri = self._s(cur.u32())
                if ctype == RES_XML_START_NAMESPACE_TYPE and prefix and uri:
                    self._ns_map[uri] = prefix
                cur.pos = chunk_start + chunk_size
                continue

            if ctype == RES_XML_CDATA_TYPE:
                _line = cur.u32()
                _comment = cur.u32()
                raw_idx = cur.u32()
                _size = cur.u16()
                _res0 = cur.u8()
                _data_type = cur.u8()
                _data = cur.u32()
                text = self._s(raw_idx)
                if text and stack:
                    # 文本归属当前栈顶元素；忽略纯空白
                    if text.strip():
                        stack[-1].text = (
                            text if stack[-1].text is None
                            else stack[-1].text + text
                        )
                cur.pos = chunk_start + chunk_size
                continue

            if ctype == RES_XML_START_ELEMENT_TYPE:
                _line = cur.u32()
                _comment = cur.u32()
                ns = self._s(cur.u32())
                name = self._s(cur.u32())
                if name is None:
                    raise AXMLError("元素名索引为空")
                attr_start = cur.u16()
                attr_size = cur.u16()
                attr_count = cur.u16()
                _id_idx = cur.u16()
                _class_idx = cur.u16()
                _style_idx = cur.u16()
                # attrStart 相对 ResXMLTree_node 体（chunk+8）；标准值 20，
                # 故属性区文件偏移 = chunk_start + 8 + attrStart
                cur.pos = chunk_start + 8 + attr_start
                elem = Element(name, ns, stack[-1] if stack else None)
                for _ in range(attr_count):
                    a_ns = self._s(cur.u32())
                    a_name = self._s(cur.u32())
                    raw_idx = cur.u32()
                    _size = cur.u16()
                    _res0 = cur.u8()
                    data_type = cur.u8()
                    data = cur.u32()
                    if a_name is None:
                        continue
                    value = self._typed_value(data_type, data, raw_idx)
                    key = (a_ns, a_name)
                    elem.attrs[key] = value
                    if raw_idx != 0xFFFFFFFF:
                        elem.raw_attrs[key] = self._s(raw_idx)
                if stack:
                    stack[-1].children.append(elem)
                else:
                    root = elem
                stack.append(elem)
                cur.pos = chunk_start + chunk_size
                continue

            if ctype == RES_XML_END_ELEMENT_TYPE:
                _line = cur.u32()
                _comment = cur.u32()
                _ns = self._s(cur.u32())
                _name = self._s(cur.u32())
                if stack:
                    stack.pop()
                cur.pos = chunk_start + chunk_size
                continue

            # 未知 chunk：按声明尺寸跳过而不是报错，兼容新平台扩展
            cur.pos = chunk_start + chunk_size

        if root is None:
            raise AXMLError("AXML 中没有任何元素")
        return root


def parse_axml(data: bytes) -> Element:
    """便捷入口：解析 AXML 字节流并返回根元素。"""
    return AXMLParser(data).parse()
