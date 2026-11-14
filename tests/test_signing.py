"""Tests for APK signature scheme detection and verification.

These build fresh signed samples into a temp directory (no reliance on the
committed samples/apks artifacts), exercising v1/v2/v3 end to end including a
tampered APK. openssl is required (present in the project environment).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "samples")):
    if p not in sys.path:
        sys.path.insert(0, p)

from apk_auditor.signing import (  # noqa: E402
    analyze_v1,
    analyze_v2_v3,
    chunked_digest,
    signing_block_segments,
)
from generator.build_samples import (  # noqa: E402
    build_unsigned_apk,
    good_manifest,
    good_netsec,
)
from generator.keygen import generate_rsa_key, generate_weak_sha1_key  # noqa: E402
from generator.v1_sign import sign_v1  # noqa: E402
from generator.v2v3_sign import sign_v2_v3  # noqa: E402


class ChunkedDigestTests(unittest.TestCase):
    def test_matches_known_single_chunk_structure(self) -> None:
        # The digest is H(0x5a || count || per-chunk H(0xa5||len||data)).
        import hashlib
        import struct

        data = b"hello" * 100
        chunk_h = hashlib.sha256(b"\xa5" + struct.pack("<I", len(data)) + data).digest()
        expected = hashlib.sha256(
            b"\x5a" + struct.pack("<I", 1) + chunk_h
        ).digest()
        self.assertEqual(chunked_digest([data], "sha256"), expected)

    def test_empty_segment_produces_no_chunks(self) -> None:
        import hashlib
        import struct

        # Two segments, one empty: only the non-empty one yields a chunk.
        nonempty = b"x"
        expected = hashlib.sha256(
            b"\x5a"
            + struct.pack("<I", 1)
            + hashlib.sha256(b"\xa5" + struct.pack("<I", 1) + b"x").digest()
        ).digest()
        self.assertEqual(chunked_digest([b"", nonempty], "sha256"), expected)


class SignatureEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="apk-sig-test-")
        self.key = generate_rsa_key(self.tmp, "k")
        self.weak = generate_weak_sha1_key(self.tmp, "w")
        self.apk = os.path.join(self.tmp, "app.apk")
        build_unsigned_apk(self.apk, good_manifest(), good_netsec())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_v1_v2_v3_chain_verifies(self) -> None:
        sign_v1(self.apk, self.key.key_pem, self.key.cert_pem, "sha256")
        sign_v2_v3(self.apk, self.key.key_pem, self.key.cert_der, ("v2", "v3"))

        with zipfile.ZipFile(self.apk) as zf:
            v1 = analyze_v1(zf)
        with open(self.apk, "rb") as fh:
            raw = fh.read()
        v2v3 = analyze_v2_v3(raw, signing_block_segments(raw))

        self.assertTrue(v1.present and v1.structural_ok)
        self.assertTrue(v1.verified)
        self.assertTrue(v1.digest_match)
        self.assertFalse(v1.weak_hash)

        for scheme in ("v2", "v3"):
            check = v2v3[scheme]
            self.assertTrue(check.present, f"{scheme} should be present")
            self.assertTrue(check.structural_ok, f"{scheme} structure: {check.errors}")
            self.assertTrue(check.verified, f"{scheme} verify: {check.errors}")
            self.assertTrue(check.digest_match, f"{scheme} digest: {check.errors}")
            self.assertTrue(
                any("0x0103" in a for a in check.algorithms),
                f"{scheme} should list RSA-PKCS1-SHA256",
            )

    def test_v1_only_with_sha1_flags_weak_hash(self) -> None:
        sign_v1(self.apk, self.weak.key_pem, self.weak.cert_pem, "sha1")
        with zipfile.ZipFile(self.apk) as zf:
            v1 = analyze_v1(zf)
        self.assertTrue(v1.present)
        self.assertTrue(v1.weak_hash)

        with open(self.apk, "rb") as fh:
            raw = fh.read()
        v2v3 = analyze_v2_v3(raw, signing_block_segments(raw))
        self.assertFalse(v2v3["v2"].present)
        self.assertFalse(v2v3["v3"].present)

    def test_tampering_breaks_digests_but_keeps_structure(self) -> None:
        sign_v1(self.apk, self.key.key_pem, self.key.cert_pem, "sha256")
        sign_v2_v3(self.apk, self.key.key_pem, self.key.cert_der, ("v2", "v3"))

        # Flip a byte in the STORED marker entry's content region.
        with zipfile.ZipFile(self.apk) as zf:
            info = zf.getinfo("assets/tamper_marker.bin")
            off = info.header_offset + 30 + len(info.filename) + len(info.extra)
        with open(self.apk, "rb") as fh:
            blob = bytearray(fh.read())
        blob[off + 10] ^= 0xFF
        with open(self.apk, "wb") as fh:
            fh.write(bytes(blob))

        with open(self.apk, "rb") as fh:
            raw = fh.read()
        v2v3 = analyze_v2_v3(raw, signing_block_segments(raw))
        for scheme in ("v2", "v3"):
            check = v2v3[scheme]
            self.assertTrue(check.present)
            self.assertTrue(check.structural_ok)  # block parses...
            self.assertFalse(check.digest_match)  # ...but digest mismatches


if __name__ == "__main__":
    unittest.main()
