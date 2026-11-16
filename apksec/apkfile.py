"""Low-level APK container reader.

Implements just enough ZIP to read the central directory, inflate entries with
size limits, and locate the APK Signing Block (which holds the v2/v3
signatures).  The stdlib ``zipfile`` module would not expose where the signing
block starts, which is required for content-digest verification.
"""

from __future__ import annotations

import mmap
import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import Iterator, Optional

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
EOCD_SIGNATURE = b"PK\x05\x06"
CD_SIGNATURE = b"PK\x01\x02"
LFH_SIGNATURE = b"PK\x03\x04"

MAX_ENTRY_SIZE = 64 * 1024 * 1024  # decompressed, per entry
MAX_TOTAL_UNCOMPRESSED = 512 * 1024 * 1024
MAX_EOCD_SEARCH = 1024 * 1024

V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61
VERITY_PADDING_BLOCK_ID = 0x42726577

COMPRESSION_NAMES = {0: "stored", 8: "deflated", 12: "bzip2", 93: "zstd"}


class ApkFormatError(ValueError):
    pass


@dataclass
class ZipEntry:
    name: str
    compress_type: int
    flags: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_header_offset: int
    _apk: "ApkFile" = field(repr=False, default=None)

    @property
    def is_directory(self) -> bool:
        return self.name.endswith("/")

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & 0x1)

    def read(self, max_size: int = MAX_ENTRY_SIZE) -> bytes:
        return self._apk.read_entry(self, max_size=max_size)


@dataclass
class SigningBlock:
    offset: int  # offset of the uint64 size prefix
    size: int  # total bytes including trailing size + magic
    pairs: dict[int, bytes]
    ordered_ids: list[int]


class ApkFile:
    """A read-only APK backed by mmap."""

    def __init__(self, path: str):
        self.path = path
        self.size = os.path.getsize(path)
        if self.size == 0:
            raise ApkFormatError("empty file")
        with open(path, "rb") as fh:
            self.data: bytes | mmap.mmap = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            self._parse()
        except Exception:
            if isinstance(self.data, mmap.mmap):
                self.data.close()
            raise

    def close(self) -> None:
        if isinstance(self.data, mmap.mmap) and not self.data.closed:
            self.data.close()

    def __enter__(self) -> "ApkFile":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- parsing ---------------------------------------------------------
    def _parse(self) -> None:
        self.eocd_offset = self._find_eocd()
        eocd = self.eocd_offset
        (
            _sig,
            disk_no,
            cd_disk,
            _entries_disk,
            entry_count,
            cd_size,
            cd_offset,
            comment_len,
        ) = struct.unpack_from("<4sHHHHIIH", self.data, eocd)
        if disk_no != 0 or cd_disk != 0:
            raise ApkFormatError("multi-disk ZIP archives are not supported")
        if eocd + 22 + comment_len > self.size:
            raise ApkFormatError("EOCD comment exceeds file")
        if entry_count == 0xFFFF or cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            raise ApkFormatError("ZIP64 archives are not supported")
        if cd_offset + cd_size > eocd:
            raise ApkFormatError("central directory out of bounds")
        self.cd_offset = cd_offset
        self.cd_size = cd_size
        self.entries: list[ZipEntry] = []
        self._by_name: dict[str, ZipEntry] = {}
        off = cd_offset
        for i in range(entry_count):
            if off + 46 > cd_offset + cd_size:
                raise ApkFormatError("truncated central directory")
            sig = self.data[off : off + 4]
            if sig != CD_SIGNATURE:
                raise ApkFormatError(f"bad central directory signature at entry {i}")
            (
                _sig,
                _ver_made,
                _ver_need,
                flags,
                method,
                _mtime,
                _mdate,
                crc,
                comp_size,
                uncomp_size,
                name_len,
                extra_len,
                comment_l,
                _disk_start,
                _int_attrs,
                _ext_attrs,
                local_off,
            ) = struct.unpack_from("<4sHHHHHHIIIHHHHHII", self.data, off)
            name_raw = self.data[off + 46 : off + 46 + name_len]
            if len(name_raw) != name_len:
                raise ApkFormatError("truncated entry name")
            name = name_raw.decode("utf-8", errors="replace")
            entry = ZipEntry(
                name=name,
                compress_type=method,
                flags=flags,
                crc32=crc,
                compressed_size=comp_size,
                uncompressed_size=uncomp_size,
                local_header_offset=local_off,
                _apk=self,
            )
            self.entries.append(entry)
            # Duplicate names: Android tooling rejects them; keep the first one
            # for lookups but record the duplicate for the signature checker.
            self._by_name.setdefault(name, entry)
            off += 46 + name_len + extra_len + comment_l
        self.duplicate_names = len(self.entries) != len(self._by_name)
        self.signing_block = self._find_signing_block()

    def _find_eocd(self) -> int:
        start = max(0, self.size - MAX_EOCD_SEARCH - 22)
        tail = self.data[start : self.size]
        pos = tail.rfind(EOCD_SIGNATURE)
        while pos != -1:
            abs_pos = start + pos
            if abs_pos + 22 <= self.size:
                comment_len = struct.unpack_from("<H", self.data, abs_pos + 20)[0]
                if abs_pos + 22 + comment_len == self.size:
                    return abs_pos
            pos = tail.rfind(EOCD_SIGNATURE, 0, pos)
        raise ApkFormatError("no ZIP end-of-central-directory record found")

    def _find_signing_block(self) -> Optional[SigningBlock]:
        cd = self.cd_offset
        if cd < 32:
            return None
        if self.data[cd - 16 : cd] != APK_SIG_BLOCK_MAGIC:
            return None
        block_size = struct.unpack_from("<Q", self.data, cd - 24)[0]
        if block_size < 24 or block_size > cd:
            raise ApkFormatError("invalid APK Signing Block size")
        start = cd - block_size - 8
        if start < 0:
            raise ApkFormatError("APK Signing Block extends before start of file")
        if struct.unpack_from("<Q", self.data, start)[0] != block_size:
            raise ApkFormatError("APK Signing Block size fields disagree")
        pairs: dict[int, bytes] = {}
        ordered: list[int] = []
        off = start + 8
        end = cd - 24
        while off < end:
            if off + 12 > end:
                raise ApkFormatError("truncated APK Signing Block pair")
            length = struct.unpack_from("<Q", self.data, off)[0]
            if length < 4 or off + 8 + length > end:
                raise ApkFormatError("invalid APK Signing Block pair length")
            bid = struct.unpack_from("<I", self.data, off + 8)[0]
            value = bytes(self.data[off + 12 : off + 8 + length])
            pairs.setdefault(bid, value)
            ordered.append(bid)
            off += 8 + length
        return SigningBlock(
            offset=start, size=block_size + 8, pairs=pairs, ordered_ids=ordered
        )

    # -- entry access ----------------------------------------------------
    def get_entry(self, name: str) -> Optional[ZipEntry]:
        return self._by_name.get(name)

    def read_entry(self, entry: ZipEntry, max_size: int = MAX_ENTRY_SIZE) -> bytes:
        if entry.encrypted:
            raise ApkFormatError(f"entry {entry.name!r} is encrypted")
        if entry.uncompressed_size > max_size:
            raise ApkFormatError(
                f"entry {entry.name!r} declares {entry.uncompressed_size} bytes, "
                f"exceeding the {max_size} byte limit"
            )
        off = entry.local_header_offset
        if off + 30 > self.size:
            raise ApkFormatError("local file header out of bounds")
        if self.data[off : off + 4] != LFH_SIGNATURE:
            raise ApkFormatError(f"bad local file header for {entry.name!r}")
        name_len, extra_len = struct.unpack_from("<HH", self.data, off + 26)
        data_off = off + 30 + name_len + extra_len
        if data_off + entry.compressed_size > self.size:
            raise ApkFormatError("entry data out of bounds")
        raw = bytes(self.data[data_off : data_off + entry.compressed_size])
        if entry.compress_type == 0:
            out = raw
        elif entry.compress_type == 8:
            out = _inflate_limited(raw, max_size)
        else:
            raise ApkFormatError(
                f"unsupported compression method {entry.compress_type} "
                f"({COMPRESSION_NAMES.get(entry.compress_type, 'unknown')}) "
                f"for {entry.name!r}"
            )
        if len(out) != entry.uncompressed_size:
            raise ApkFormatError(
                f"size mismatch for {entry.name!r}: got {len(out)}, "
                f"expected {entry.uncompressed_size}"
            )
        if zlib.crc32(out) & 0xFFFFFFFF != entry.crc32 & 0xFFFFFFFF:
            raise ApkFormatError(f"CRC mismatch for {entry.name!r}")
        return out

    def read_entry_safe(self, name: str, max_size: int = MAX_ENTRY_SIZE) -> Optional[bytes]:
        entry = self.get_entry(name)
        if entry is None:
            return None
        return self.read_entry(entry, max_size=max_size)

    def iter_entries(self) -> Iterator[ZipEntry]:
        return iter(self.entries)


def _inflate_limited(raw: bytes, max_size: int) -> bytes:
    """Inflate ``raw`` but refuse to produce more than ``max_size`` bytes."""
    d = zlib.decompressobj(-15)
    out = bytearray()
    chunk_size = 64 * 1024
    pos = 0
    while pos < len(raw):
        chunk = raw[pos : pos + chunk_size]
        pos += chunk_size
        try:
            piece = d.decompress(chunk, max_size + 1 - len(out))
        except zlib.error as exc:
            raise ApkFormatError(f"corrupt deflate stream: {exc}") from exc
        out.extend(piece)
        if len(out) > max_size:
            raise ApkFormatError("decompressed entry exceeds size limit")
        if d.eof:
            break
    try:
        out.extend(d.flush())
    except zlib.error as exc:
        raise ApkFormatError(f"corrupt deflate stream: {exc}") from exc
    if len(out) > max_size:
        raise ApkFormatError("decompressed entry exceeds size limit")
    return bytes(out)
