"""Minimal deterministic ZIP writer and APK signer (v1 + v2 + v3).

Used by the fixture builder so the test corpus is byte-for-byte reproducible
and needs no Java toolchain.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import Iterable

from . import keys

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


@dataclass
class ZipMember:
    name: str
    data: bytes
    compress: bool = True
    method: int = 8  # 8 deflate, 0 store
    _payload: bytes = b""
    _crc: int = 0
    _offset: int = 0

    def prepare(self) -> None:
        self._crc = zlib.crc32(self.data) & 0xFFFFFFFF
        if self.method == 8:
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
            self._payload = compressor.compress(self.data) + compressor.flush()
        else:
            self._payload = self.data


def _dos_time():
    # 2024-01-01 00:00:00, fixed for reproducibility.
    return 0, (2024 - 1980) << 9 | 1 << 5 | 1


class ZipWriter:
    def __init__(self):
        self.members: list[ZipMember] = []

    def add(self, name: str, data: bytes, compress: bool = True) -> None:
        self.members.append(
            ZipMember(name=name, data=data, method=8 if compress else 0)
        )

    def add_stored(self, name: str, data: bytes) -> None:
        self.members.append(ZipMember(name=name, data=data, method=0))

    def build(self) -> bytes:
        out = bytearray()
        central = bytearray()
        for member in self.members:
            member.prepare()
            member._offset = len(out)
            name_bytes = member.name.encode("utf-8")
            mtime, mdate = _dos_time()
            out += struct.pack(
                "<4sHHHHHIIIHH",
                b"PK\x03\x04",
                20,
                0,
                member.method,
                mtime,
                mdate,
                member._crc,
                len(member._payload),
                len(member.data),
                len(name_bytes),
                0,
            )
            out += name_bytes
            out += member._payload

            central += struct.pack(
                "<4sHHHHHHIIIHHHHHII",
                b"PK\x01\x02",
                20,
                20,
                0,
                member.method,
                mtime,
                mdate,
                member._crc,
                len(member._payload),
                len(member.data),
                len(name_bytes),
                0,
                0,
                0,
                0,
                0,
                member._offset,
            )
            central += name_bytes
        cd_offset = len(out)
        out += central
        out += struct.pack(
            "<4sHHHHIIH",
            b"PK\x05\x06",
            0,
            0,
            len(self.members),
            len(self.members),
            len(central),
            cd_offset,
            0,
        )
        return bytes(out)


# ---------------------------------------------------------------------------
# v1 (JAR) signing
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _mf_section(name: str, digest: bytes) -> bytes:
    lines = [f"Name: {name}", f"SHA-256-Digest: {_b64(digest)}"]
    wrapped = []
    for line in lines:
        # 72-byte line limit per the JAR spec.
        while len(line.encode()) > 72:
            wrapped.append(line[:72])
            line = " " + line[72:]
        wrapped.append(line)
    return ("\r\n".join(wrapped) + "\r\n").encode()


def _scheme_number(scheme) -> str:
    """Normalise ``"v2"`` / ``2`` / ``V2`` to ``"2"`` for the SF attribute."""
    text = str(scheme).strip().lower().lstrip("v")
    return text


def sign_v1(
    members: Iterable[ZipMember],
    key: keys.PrivateKey,
    cert: bytes,
    signed_attributes: bool = True,
    protected_schemes: tuple[int, ...] = (),
) -> dict[str, bytes]:
    """Return META-INF entries implementing JAR signing over ``members``."""
    manifest = bytearray(b"Manifest-Version: 1.0\r\nCreated-By: apksec-fixture\r\n\r\n")
    sections: dict[str, bytes] = {}
    for member in members:
        if member.name.upper().startswith("META-INF/"):
            continue
        section = _mf_section(member.name, hashlib.sha256(member.data).digest())
        sections[member.name] = section
        manifest += section + b"\r\n"
    manifest_bytes = bytes(manifest)

    sf = bytearray(
        b"Signature-Version: 1.0\r\n"
        + f"SHA-256-Digest-Manifest: {_b64(hashlib.sha256(manifest_bytes).digest())}\r\n"
        .encode()
        + b"Created-By: apksec-fixture\r\n"
    )
    if protected_schemes:
        # Anti-stripping protection: tells old platforms that newer signature
        # schemes must also be present.
        sf += (
            "X-Android-APK-Signed: "
            + ", ".join(_scheme_number(s) for s in protected_schemes)
            + "\r\n"
        ).encode()
    sf += b"\r\n"
    for name, section in sections.items():
        # The digest covers the MANIFEST.MF section exactly as written,
        # including its terminating blank line.
        digest = hashlib.sha256(section + b"\r\n").digest()
        line = f"Name: {name}\r\nSHA-256-Digest: {_b64(digest)}\r\n\r\n"
        sf += line.encode()
    sf_bytes = bytes(sf)
    if signed_attributes:
        pkcs7 = keys.build_pkcs7(key, cert, sf_bytes)
    else:
        pkcs7 = keys.build_pkcs7_unsigned_attrs(key, cert, sf_bytes)
    return {
        "META-INF/MANIFEST.MF": manifest_bytes,
        "META-INF/CERT.SF": sf_bytes,
        "META-INF/CERT.RSA": pkcs7,
    }


# ---------------------------------------------------------------------------
# v2 / v3 signing
# ---------------------------------------------------------------------------


def _lp(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def _content_digest_chunks(prefix: bytes, cd: bytes, eocd: bytes) -> bytes:
    chunk_digests = []
    for section in (prefix, cd, eocd):
        if not section:
            # An empty section still contributes one (empty) chunk digest.
            sections = [b""]
        else:
            sections = [section[off : off + 1024 * 1024] for off in range(0, len(section), 1024 * 1024)]
        for chunk in sections:
            d = hashlib.sha256()
            d.update(b"\xa5")
            d.update(struct.pack("<I", len(chunk)))
            d.update(chunk)
            chunk_digests.append(d.digest())
    top = hashlib.sha256()
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunk_digests)))
    for cd_ in chunk_digests:
        top.update(cd_)
    return top.digest()


def _build_signer(
    signed_data_extra: bytes,
    key: keys.PrivateKey,
    cert: bytes,
    content_digest: bytes,
    signer_prefix: bytes = b"",
) -> bytes:
    alg = key.apk_sig_algorithm("sha256")
    # Every field is a length-prefixed sequence whose records are themselves
    # length-prefixed (algorithm id + length-prefixed value).
    digests = _lp(_lp(struct.pack("<I", alg) + _lp(content_digest)))
    certs = _lp(_lp(cert))
    signed_data = digests + certs + signed_data_extra + _lp(b"")
    signature = key.sign("sha256", signed_data)
    signatures = _lp(struct.pack("<I", alg) + _lp(signature))
    return (
        _lp(signed_data) + signer_prefix + _lp(signatures) + _lp(key.public_spki())
    )


V3_MIN_PLATFORM = 28  # APK Signature Scheme v3 first exists on Android 9
MAX_SDK = 0x7FFFFFFF


def sign_apk_v2_v3(
    payload: bytes,
    cd_offset: int,
    cd_size: int,
    key: keys.PrivateKey,
    cert: bytes,
    schemes: tuple[str, ...] = ("v2", "v3"),
    min_sdk: int = 24,
    max_sdk: int = MAX_SDK,
) -> bytes:
    """Insert an APK Signing Block into ``payload`` (a complete ZIP)."""
    eocd = bytearray(payload[-22:])
    if eocd[:4] != b"PK\x05\x06":
        raise ValueError("payload does not end with an EOCD record")
    cd = payload[cd_offset : cd_offset + cd_size]
    # The signing block is inserted before the central directory, so its
    # offset in the signed APK equals the original central directory offset.
    block_offset = cd_offset
    # First pass: compute with block_offset = cd_offset (block is inserted
    # before the central directory, so this is exact).
    unsigned_prefix = payload[:cd_offset]
    eocd_for_digest = bytearray(eocd)
    struct.pack_into("<I", eocd_for_digest, 16, block_offset)
    digest = _content_digest_chunks(unsigned_prefix, cd, bytes(eocd_for_digest))

    pairs = bytearray()
    if "v2" in schemes:
        signer = _build_signer(b"", key, cert, digest)
        # The block value is a length-prefixed sequence of signers.
        value = _lp(_lp(signer))
        pairs += struct.pack("<QI", len(value) + 4, 0x7109871A) + value
    if "v3" in schemes:
        # The v3 signer's SDK range is the platform range where v3 is used,
        # which starts at API 28 (not at the app's own minSdkVersion).
        v3_min = max(min_sdk, V3_MIN_PLATFORM)
        extra = struct.pack("<II", v3_min, max_sdk)
        # v3 carries min/max SDK both inside the signed data and, unsigned, in
        # the signer block.
        signer = _build_signer(extra, key, cert, digest, signer_prefix=extra)
        value = _lp(_lp(signer))
        pairs += struct.pack("<QI", len(value) + 4, 0xF05368C0) + value

    body = bytes(pairs)
    block_size = len(body) + 8 + 16  # pairs + size field + magic
    block = (
        struct.pack("<Q", block_size)
        + body
        + struct.pack("<Q", block_size)
        + APK_SIG_BLOCK_MAGIC
    )
    new_cd_offset = cd_offset + len(block)
    new_eocd = bytearray(eocd)
    struct.pack_into("<I", new_eocd, 16, new_cd_offset)
    return unsigned_prefix + block + cd + bytes(new_eocd)
