"""Minimal DER (ASN.1) reader and writer.

Only what is needed to inspect X.509 certificates, PKCS#7 SignedData blobs and
to build test fixtures: definite lengths, low tag numbers, no BER indefinite
form.  Everything is bounds checked because inputs come from untrusted APKs.
"""

from __future__ import annotations

from dataclasses import dataclass


class DerError(ValueError):
    pass


MAX_DER_DEPTH = 64


@dataclass(frozen=True)
class Tlv:
    tag: int
    header_len: int
    value: bytes
    start: int  # offset of tag byte
    end: int  # offset just past value

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self, depth: int = 0) -> list["Tlv"]:
        return parse_all(self.value, depth=depth)

    def lone(self) -> "Tlv":
        """Return the only child of a constructed value."""
        kids = self.children()
        if len(kids) != 1:
            raise DerError(f"expected exactly one child, got {len(kids)}")
        return kids[0]

    def oid(self) -> str:
        if self.tag != 0x06:
            raise DerError(f"not an OID (tag 0x{self.tag:02x})")
        return decode_oid(self.value)

    def as_int(self) -> int:
        if self.tag not in (0x02, 0x0A):
            raise DerError(f"not an INTEGER (tag 0x{self.tag:02x})")
        if not self.value:
            raise DerError("empty INTEGER")
        return int.from_bytes(self.value, "big", signed=True)

    def as_octets(self) -> bytes:
        if self.tag == 0x04:
            return self.value
        if self.tag == 0x03:  # BIT STRING: first byte is unused-bit count
            if not self.value:
                raise DerError("empty BIT STRING")
            unused = self.value[0]
            if unused > 7:
                raise DerError("invalid BIT STRING padding")
            return self.value[1:]
        raise DerError(f"not an octet/bit string (tag 0x{self.tag:02x})")

    def raw(self) -> bytes:
        """Re-encode this TLV with a minimal (DER) length."""
        return tlv(self.tag, self.value)

    def as_text(self) -> str:
        if self.tag == 0x1E:  # BMPString
            return self.value.decode("utf-16-be", errors="replace")
        if self.tag in (0x0C,):  # UTF8String
            return self.value.decode("utf-8", errors="replace")
        return self.value.decode("latin-1", errors="replace")


def read_tlv(data: bytes, off: int = 0, *, depth: int = 0) -> Tlv:
    if depth > MAX_DER_DEPTH:
        raise DerError("DER nesting too deep")
    if off < 0 or off + 2 > len(data):
        raise DerError("truncated DER header")
    start = off
    tag = data[off]
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not supported")
    length_byte = data[off + 1]
    off += 2
    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x80:
        raise DerError("indefinite length is not supported")
    else:
        n = length_byte & 0x7F
        if n > 4:
            raise DerError("DER length too large")
        if off + n > len(data):
            raise DerError("truncated DER length")
        length = int.from_bytes(data[off : off + n], "big")
        off += n
    if length < 0 or off + length > len(data):
        raise DerError("DER value exceeds buffer")
    return Tlv(
        tag=tag,
        header_len=off - start,
        value=data[off : off + length],
        start=start,
        end=off + length,
    )


def parse_all(data: bytes, depth: int = 0) -> list[Tlv]:
    if depth > MAX_DER_DEPTH:
        raise DerError("DER nesting too deep")
    out: list[Tlv] = []
    off = 0
    while off < len(data):
        t = read_tlv(data, off, depth=depth)
        out.append(t)
        off = t.end
    return out


def decode_oid(raw: bytes) -> str:
    if not raw:
        raise DerError("empty OID")
    first = raw[0]
    parts = [first // 40, first % 40]
    value = 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def encode_oid(oid: str) -> bytes:
    arcs = [int(p) for p in oid.split(".")]
    if len(arcs) < 2:
        raise DerError("OID needs at least two arcs")
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        if arc < 0:
            raise DerError("negative OID arc")
        chunks = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunks.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(chunks))
    return bytes(body)


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(items))


def integer(value: int) -> bytes:
    """DER INTEGER encoding (two's complement, minimal length, sign byte)."""
    if value == 0:
        return tlv(0x02, b"\x00")
    if value > 0:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:  # keep the value positive
            body = b"\x00" + body
        return tlv(0x02, body)
    body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return tlv(0x02, body)


def octets(value: bytes) -> bytes:
    return tlv(0x04, value)


def bit_string(value: bytes, unused: int = 0) -> bytes:
    return tlv(0x03, bytes([unused]) + value)


def null() -> bytes:
    return b"\x05\x00"


def oid(value: str) -> bytes:
    return tlv(0x06, encode_oid(value))


def utf8(value: str) -> bytes:
    return tlv(0x0C, value.encode("utf-8"))


def ctx(tag_no: int, value: bytes, constructed: bool = True) -> bytes:
    return tlv(0xA0 | tag_no if constructed else 0x80 | tag_no, value)
