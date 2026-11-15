"""APK 容器读取。

APK 即 ZIP，本模块手动解析中央目录（EOCD / Central Directory），
原因是需要拿到原始偏移以定位 *APK Signing Block*（v2/v3 签名块
夹在最后一个本地文件与中央目录之间，zipfile 看不到它）。

条目内容按需解压，只使用标准库 zlib。
"""

from __future__ import annotations

import struct
import zlib

EOCD_SIG = 0x06054B50
CENTRAL_SIG = 0x02014B50
LOCAL_SIG = 0x04034B50

# APK Signing Block（AOSP ApkSigningBlockUtils）
# magic 实为 16 字节（含结尾空格与数字），尾部布局：u64 size + 16 字节 magic
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SIG_BLOCK_FOOTER = 8 + len(APK_SIG_BLOCK_MAGIC)  # 24
ALGO_ID_V2 = 0x7109871A
ALGO_ID_V3 = 0xF05368C0
ALGO_ID_V31 = 0x1B93AD61
SIG_BLOCK_IDS = {
    ALGO_ID_V2: "v2",
    ALGO_ID_V3: "v3",
    ALGO_ID_V31: "v3.1",
}


class APKError(Exception):
    pass


class ZipEntry:
    def __init__(
        self,
        name: str,
        method: int,
        comp_size: int,
        uncomp_size: int,
        local_header_off: int,
        crc32: int,
    ):
        self.name = name
        self.method = method  # 0=stored, 8=deflate
        self.comp_size = comp_size
        self.uncomp_size = uncomp_size
        self.local_header_off = local_header_off
        self.crc32 = crc32

    def __repr__(self):
        return f"<ZipEntry {self.name} method={self.method}>"


class APKFile:
    """整个 APK 读入内存（审计场景下文件通常不大），便于随机访问。"""

    def __init__(self, data: bytes):
        self.data = data
        self.entries: dict[str, ZipEntry] = {}
        self._eocd_off = -1
        self._cd_off = -1
        self._cd_size = 0
        self._sig_block: dict[int, bytes] | None = None
        self._sig_block_off: int | None = None
        self._parse()

    # ------------------------------------------------------------------
    @classmethod
    def open(cls, path: str) -> "APKFile":
        with open(path, "rb") as fh:
            return cls(fh.read())

    # ------------------------------------------------------------------
    def _find_eocd(self) -> int:
        # EOCD 最大长度 22 + 65535 注释
        start = max(0, len(self.data) - (22 + 65535))
        tail = self.data[start:]
        idx = tail.rfind(struct.pack("<I", EOCD_SIG))
        if idx < 0:
            raise APKError("找不到 ZIP EOCD，不是合法 APK/ZIP")
        return start + idx

    def _parse(self):
        data = self.data
        eocd = self._find_eocd()
        self._eocd_off = eocd
        (
            _sig,
            _disk,
            _cd_disk,
            _cd_entries_disk,
            total_entries,
            cd_size,
            cd_off,
            _comment_len,
        ) = struct.unpack_from("<IHHHHIIH", data, eocd)
        self._cd_off = cd_off
        self._cd_size = cd_size

        pos = cd_off
        for _ in range(total_entries):
            if struct.unpack_from("<I", data, pos)[0] != CENTRAL_SIG:
                raise APKError(f"中央目录条目魔数错误 @0x{pos:x}")
            (
                _sig,
                _ver_made,
                _ver_need,
                flags,
                method,
                _mod_time,
                _mod_date,
                crc32,
                comp_size,
                uncomp_size,
                name_len,
                extra_len,
                comment_len,
                _disk_start,
                _int_attr,
                _ext_attr,
                local_off,
            ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, pos)
            name = data[pos + 46 : pos + 46 + name_len].decode("utf-8", "replace")
            if flags & 0x800:
                # 语言编码标志位：按 UTF-8 已处理，兜底
                pass
            self.entries[name] = ZipEntry(
                name, method, comp_size, uncomp_size, local_off, crc32
            )
            pos += 46 + name_len + extra_len + comment_len

    # ------------------------------------------------------------------
    def has(self, name: str) -> bool:
        return name in self.entries

    def names(self) -> list[str]:
        return list(self.entries)

    def read(self, name: str) -> bytes:
        """读取并校验一个条目内容。"""
        entry = self.entries.get(name)
        if entry is None:
            raise KeyError(name)
        data = self.data
        pos = entry.local_header_off
        if struct.unpack_from("<I", data, pos)[0] != LOCAL_SIG:
            raise APKError(f"{name}: 本地文件头魔数错误")
        n_len = struct.unpack_from("<H", data, pos + 26)[0]
        e_len = struct.unpack_from("<H", data, pos + 28)[0]
        payload = pos + 30 + n_len + e_len
        raw = data[payload : payload + entry.comp_size]
        if entry.method == 0:
            out = raw
        elif entry.method == 8:
            out = zlib.decompress(raw, -15)
        else:
            raise APKError(f"{name}: 不支持的压缩方式 {entry.method}")
        if len(out) != entry.uncomp_size:
            raise APKError(f"{name}: 解压后尺寸不匹配")
        if zlib.crc32(out) & 0xFFFFFFFF != entry.crc32:
            raise APKError(f"{name}: CRC32 校验失败")
        return out

    # ------------------------------------------------------------------
    # APK Signing Block（v2 / v3）
    # ------------------------------------------------------------------
    def signing_block(self) -> dict[int, bytes] | None:
        """返回 {block_id: value_bytes}，没有签名块则返回 None。"""
        if self._sig_block is not None:
            return self._sig_block

        data = self.data
        cd_off = self._cd_off
        # 中央目录前为 24 字节尾部：size_of_block(u64) + magic(16)
        footer = cd_off - APK_SIG_BLOCK_FOOTER
        if footer < 0 or data[footer + 8 : footer + 24] != APK_SIG_BLOCK_MAGIC:
            return None
        size_of_block = struct.unpack_from("<Q", data, footer)[0]
        block_start = cd_off - size_of_block - 8  # 前面还有一个 uint64 size
        if block_start < 0:
            raise APKError("APK Signing Block 尺寸越界")
        if struct.unpack_from("<Q", data, block_start)[0] != size_of_block:
            raise APKError("APK Signing Block 首尾 size 不一致")

        pairs: dict[int, bytes] = {}
        p = block_start + 8
        end = footer  # 尾部（含第二个 size + magic）之前
        while p < end:
            pair_len = struct.unpack_from("<Q", data, p)[0]
            p += 8
            if pair_len < 4 or p + pair_len > end:
                raise APKError("签名块 ID-value 对长度非法")
            block_id = struct.unpack_from("<I", data, p)[0]
            pairs[block_id] = data[p + 4 : p + pair_len]
            p += pair_len
        self._sig_block = pairs
        self._sig_block_off = block_start
        return pairs

    def signing_schemes(self) -> dict[str, bytes]:
        """返回存在的方案，如 {'v2': <bytes>, 'v3': <bytes>}。"""
        block = self.signing_block()
        if not block:
            return {}
        return {
            name: block[bid]
            for bid, name in SIG_BLOCK_IDS.items()
            if bid in block
        }

    def content_before_sig_block(self) -> bytes:
        """v2/v3 摘要覆盖的“签名块之前全部内容”。"""
        block = self.signing_block()
        if block is None:
            # 没有签名块时，摘要覆盖到中央目录之前
            return self.data[: self._cd_off]
        return self.data[: self._sig_block_off]

    def central_directory(self) -> bytes:
        return self.data[self._cd_off : self._eocd_off]

    def eocd(self) -> bytes:
        return self.data[self._eocd_off :]
