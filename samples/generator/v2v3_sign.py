"""APK Signature Scheme v2/v3 signing-block writer.

Structures mirror AOSP platform/tools/apksig (constants cross-checked against
V2SchemeConstants / V3SchemeConstants / SignatureAlgorithm):

    v2 signer  = len(signedData) || len(signatures) || len(publicKey)
    v3 signer  = len(signedData) || minSdk(u32) || maxSdk(u32)
                 || len(signatures) || len(publicKey)
    signedData = len(digests) || len(certificates) [v3: minSdk maxSdk len(attrs)]
    signature  = algoId(u32) || len(sigBytes)
    digest     = algoId(u32) || len(digestBytes)

RSA PKCS#1 v1.5 with SHA-256 (algorithm id 0x0103) is used, which every
Android 7.0+ device and our openssl-based verifier support.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile

from apk_auditor.signing import (
    APK_SIG_BLOCK_MAGIC,
    V2_BLOCK_ID,
    V3_BLOCK_ID,
    chunked_digest,
    find_eocd,
)

ALGO_RSA_PKCS1_SHA256 = 0x0103


def _u32(n: int) -> bytes:
    """Little-endian uint32 (APK Signing Block container framing)."""
    return struct.pack("<I", n & 0xFFFFFFFF)


def _u64(n: int) -> bytes:
    """Little-endian uint64 (APK Signing Block container framing)."""
    return struct.pack("<Q", n & 0xFFFFFFFFFFFFFFFF)


def _be32(n: int) -> bytes:
    """Big-endian uint32 (all in-block v2/v3 protocol fields)."""
    return struct.pack(">I", n & 0xFFFFFFFF)


def _lp(data: bytes) -> bytes:
    """Big-endian uint32 length-prefixed blob (v2/v3 length-prefixed slices)."""
    return _be32(len(data)) + data


def _read_public_key_der(cert_der_path: str, key_pem_path: str) -> bytes:
    # Extract SubjectPublicKeyInfo from the certificate.
    out = subprocess.run(
        ["openssl", "x509", "-in", cert_der_path, "-inform", "DER",
         "-pubkey", "-noout"],
        check=True, capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory() as td:
        pem = os.path.join(td, "pub.pem")
        der = os.path.join(td, "pub.der")
        with open(pem, "wb") as fh:
            fh.write(out)
        subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", pem,
             "-outform", "DER", "-out", der],
            check=True, capture_output=True,
        )
        with open(der, "rb") as fh:
            return fh.read()


def _rsa_pkcs1_sign(key_pem: str, data: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        data_path = os.path.join(td, "data.bin")
        sig_path = os.path.join(td, "sig.bin")
        with open(data_path, "wb") as fh:
            fh.write(data)
        subprocess.run(
            [
                "openssl", "dgst", "-sha256", "-sign", key_pem,
                "-out", sig_path, data_path,
            ],
            check=True, capture_output=True,
        )
        with open(sig_path, "rb") as fh:
            return fh.read()


def _digest_record(segments: list[bytes]) -> bytes:
    """A single digest record body: algoId(BE u32) + prefixed digest."""
    digest = chunked_digest(segments, "sha256")
    return _be32(ALGO_RSA_PKCS1_SHA256) + _lp(digest)


def _signature_record(signed_data: bytes, key_pem: str) -> bytes:
    """A single signature record body: algoId(BE u32) + prefixed signature."""
    sig = _rsa_pkcs1_sign(key_pem, signed_data)
    return _be32(ALGO_RSA_PKCS1_SHA256) + _lp(sig)


def _build_signed_data(
    segments: list[bytes], cert_der: bytes, is_v3: bool,
    min_sdk: int, max_sdk: int,
) -> bytes:
    # Field layout: each field is a length-prefixed slice.
    #   digests:      _lp(record)   (one record here)
    #   certificates: _lp(_lp(cert))
    parts = [
        _lp(_digest_record(segments)),
        _lp(_lp(cert_der)),
    ]
    if is_v3:
        parts.append(_be32(min_sdk))
        parts.append(_be32(max_sdk))
        parts.append(_lp(b""))  # additional attributes
    return b"".join(parts)


def _build_signer(
    segments: list[bytes],
    cert_der: bytes,
    pubkey_der: bytes,
    key_pem: str,
    is_v3: bool,
    min_sdk: int,
    max_sdk: int,
) -> bytes:
    signed_data = _build_signed_data(segments, cert_der, is_v3, min_sdk, max_sdk)
    # signatures field is a length-prefixed slice holding the record body.
    signatures = _lp(_signature_record(signed_data, key_pem))
    if is_v3:
        body = (
            _lp(signed_data)
            + _be32(min_sdk)
            + _be32(max_sdk)
            + signatures
            + _lp(pubkey_der)
        )
    else:
        body = _lp(signed_data) + signatures + _lp(pubkey_der)
    return _lp(body)


def _build_pair(pair_id: int, value: bytes) -> bytes:
    # pair = uint64(pair-size) || uint32(id) || value
    # pair-size counts the ID field plus the value.
    return _u64(4 + len(value)) + _u32(pair_id) + value


def sign_v2_v3(
    apk_path: str,
    key_pem: str,
    cert_der_path: str,
    schemes: tuple[str, ...] = ("v2", "v3"),
    min_sdk: int = 24,
    max_sdk: int = 0x7FFFFFFF,
) -> None:
    with open(apk_path, "rb") as fh:
        data = fh.read()
    with open(cert_der_path, "rb") as fh:
        cert_der = fh.read()
    pubkey_der = _read_public_key_der(cert_der_path, key_pem)

    eocd, cd_offset = find_eocd(data)
    # Content segments protected by the digest: everything before the signing
    # block and the central directory + EOCD (whose CD offset we must patch).
    before = data[:cd_offset]
    cd_and_eocd = bytearray(data[cd_offset:])

    # First build the pairs once to measure the block size, so the EOCD's
    # central-directory offset can be patched BEFORE computing content
    # digests (verification derives the digest over exactly the patched bytes).
    def build_pairs(segments: list[bytes]) -> bytes:
        blob = b""
        for scheme in schemes:
            is_v3 = scheme == "v3"
            # _build_signer already returns a length-prefixed signer; a
            # single-signer sequence is exactly that, and the pair value is
            # the sequence itself (AOSP reads one outer length prefix).
            signer = _build_signer(
                segments, cert_der, pubkey_der, key_pem,
                is_v3, min_sdk, max_sdk,
            )
            block_id = V3_BLOCK_ID if is_v3 else V2_BLOCK_ID
            blob += _build_pair(block_id, signer)
        return blob

    # Measure pass with an unpatched segment-2 to size the block.
    measure_pairs = build_pairs([before, bytes(cd_and_eocd)])
    # Per AOSP: the uint64 size field counts everything except itself, i.e.
    # pairs + trailing size field (8) + magic (16). The physical block on
    # disk is 8 bytes longer (the leading size field itself).
    measure_size_field = len(measure_pairs) + 8 + 16
    measure_physical_block = measure_size_field + 8
    # Patch central-directory offset in the EOCD copy. EOCD layout:
    # signature(4) disk(2) cdDisk(2) diskEntries(2) totalEntries(2)
    # cdSize(4) cdOffset(4) commentLen(2) -> cdOffset sits 16 bytes into the
    # EOCD record itself, which may be preceded by central-directory entries.
    eocd_rel = bytes(cd_and_eocd).rfind(b"PK\x05\x06")
    if eocd_rel < 0:
        raise RuntimeError("EOCD not found in central directory tail")
    new_cd_offset = len(before) + measure_physical_block
    struct.pack_into("<I", cd_and_eocd, eocd_rel + 16, new_cd_offset)

    # Real pass: digests now cover the final patched central directory.
    pairs_blob = build_pairs([before, bytes(cd_and_eocd)])
    size_of_block = len(pairs_blob) + 8 + 16
    if size_of_block != measure_size_field:
        # Deterministic signing (no randomness in block length) makes this
        # impossible; guard anyway against layout drift.
        raise RuntimeError("signing block size changed between passes")

    # Assemble the signing block.
    # Layout: u64(size-of-block) || pairs || u64(size-of-block) || magic(16)
    # size-of-block excludes its own leading uint64.
    signing_block = (
        _u64(size_of_block)
        + pairs_blob
        + _u64(size_of_block)
        + APK_SIG_BLOCK_MAGIC
    )

    out = before + signing_block + bytes(cd_and_eocd)
    with open(apk_path, "wb") as fh:
        fh.write(out)
