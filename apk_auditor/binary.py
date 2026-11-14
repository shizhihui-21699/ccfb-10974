"""Little-endian binary parsing primitives.

Only the standard library is used, so the auditor has zero third-party
dependencies and can be dropped onto any machine with a Python 3 runtime.
"""

from __future__ import annotations

import struct
from typing import List


class BinaryReader:
    """Cursor over a bytes buffer with little-endian accessors."""

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def remaining(self) -> int:
        return len(self.data) - self.pos

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

    def i32(self) -> int:
        v = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return v

    def i64(self) -> int:
        v = struct.unpack_from("<q", self.data, self.pos)[0]
        self.pos += 8
        return v

    def be_u32(self) -> int:
        """Big-endian uint32 (APK Signature Scheme v2/v3 block fields)."""
        v = struct.unpack_from(">I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def be_len_prefixed_u32(self) -> bytes:
        """Read a big-endian uint32-length-prefixed byte sequence."""
        n = self.be_u32()
        return self.read(n)

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(
                f"short read: wanted {n} bytes at {self.pos}, have {self.remaining()}"
            )
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def skip(self, n: int) -> None:
        self.read(n)

    def sub_reader(self, n: int) -> "BinaryReader":
        return BinaryReader(self.read(n))

    def len_prefixed_u32(self) -> bytes:
        """Read a uint32-length-prefixed byte sequence (APK Signing Block style)."""
        n = self.u32()
        return self.read(n)


def decode_length8(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode a UTF-8 style length used by AXML string pools.

    Returns (length, new_pos). High-bit set means a two-byte extended length.
    """
    first = buf[pos]
    if first & 0x80 == 0:
        return first, pos + 1
    second = buf[pos + 1]
    return ((first & 0x7F) << 8) | second, pos + 2


def decode_length16(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode a UTF-16 style length (in *characters*)."""
    first = struct.unpack_from("<H", buf, pos)[0]
    if first & 0x8000 == 0:
        return first, pos + 2
    second = struct.unpack_from("<H", buf, pos + 2)[0]
    return ((first & 0x7FFF) << 16) | second, pos + 4


def align4(n: int) -> int:
    return (n + 3) & ~3
