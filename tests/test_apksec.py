"""Test suite for apksec.  Run with ``python3 -m unittest discover -s tests``.

Only the standard library is used.  Fixtures are generated into a temporary
directory so the tests exercise the full pipeline (binary XML -> manifest
model -> signatures -> rules) on real APK bytes.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from apksec import (  # noqa: E402
    apkfile,
    arsc,
    audit,
    binxml,
    crypto,
    der,
    manifest,
    nsc,
    report,
    risk,
    signature,
    x509,
)
from tools.apkbuild import axml, fixtures, keys, zipsign  # noqa: E402


_FIXTURE_DIR: str | None = None
_FIXTURES: dict[str, fixtures.Fixture] = {}


def setUpModule() -> None:
    global _FIXTURE_DIR
    _FIXTURE_DIR = tempfile.mkdtemp(prefix="apksec-fixtures-")
    for fx in fixtures.build_all(_FIXTURE_DIR):
        _FIXTURES[fx.name] = fx


def fixture_path(name: str) -> str:
    assert _FIXTURE_DIR is not None
    return os.path.join(_FIXTURE_DIR, name)


def rule_ids(result: report.AuditResult) -> set[str]:
    return {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# DER / crypto
# ---------------------------------------------------------------------------


class DerTests(unittest.TestCase):
    def test_integer_roundtrip_including_high_bit(self):
        for value in (0, 1, 127, 128, 255, 256, 65537, 2**2047 + 5):
            encoded = der.integer(value)
            parsed = der.read_tlv(encoded, 0)
            self.assertEqual(parsed.as_int(), value)

    def test_length_forms(self):
        for size in (0, 1, 127, 128, 300, 70000):
            blob = der.octets(b"x" * size)
            parsed = der.read_tlv(blob, 0)
            self.assertEqual(len(parsed.value), size)

    def test_truncated_input_is_rejected(self):
        blob = der.octets(b"abcd")
        with self.assertRaises(der.DerError):
            der.read_tlv(blob[:-1], 0)

    def test_indefinite_length_rejected(self):
        with self.assertRaises(der.DerError):
            der.read_tlv(b"\x30\x80\x00\x00", 0)

    def test_deep_nesting_is_bounded(self):
        blob = b"\x05\x00"
        for _ in range(200):
            blob = der.seq(blob)
        with self.assertRaises(der.DerError):
            node = der.read_tlv(blob, 0)
            for depth in range(300):
                node = node.children(depth)[0]

    def test_oid_roundtrip(self):
        for oid in ("1.2.840.113549.1.1.11", "2.5.4.3", "1.3.6.1.4.1.11129.2.1.17"):
            self.assertEqual(der.decode_oid(der.encode_oid(oid)), oid)


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = keys.generate_rsa_key("crypto-test-rsa", 1024)
        cls.ec = keys.generate_ec_key("crypto-test-ec", 256)

    def test_rsa_pkcs1v15_good_and_tampered(self):
        sig = self.rsa.sign("sha256", b"payload")
        key = self.rsa.public_key
        self.assertTrue(crypto._rsa_pkcs1v15_verify(key.rsa, "sha256", sig, b"payload"))
        self.assertFalse(crypto._rsa_pkcs1v15_verify(key.rsa, "sha256", sig, b"payloaX"))
        self.assertFalse(crypto._rsa_pkcs1v15_verify(key.rsa, "sha1", sig, b"payload"))

    def test_rsa_rejects_wrong_length_signature(self):
        sig = self.rsa.sign("sha256", b"payload")
        key = self.rsa.public_key
        self.assertFalse(
            crypto._rsa_pkcs1v15_verify(key.rsa, "sha256", sig[:-1], b"payload")
        )

    def test_rsa_pss_verify(self):
        # Build a PSS signature by hand: PSS is randomised, so verify the
        # implementation against a signature produced from the same key with a
        # known salt.
        key = self.rsa
        hash_name = "sha256"
        h_len = 32
        k = key.size_bytes
        salt = b"\x11" * h_len
        m_hash = crypto.digest(hash_name, b"pss message")
        h = crypto.digest(hash_name, b"\x00" * 8 + m_hash + salt)
        em_len = k
        ps = b"\x00" * (em_len - h_len - h_len - 2)
        db = ps + b"\x01" + salt
        masked = bytes(
            a ^ b
            for a, b in zip(db, crypto._mgf1(hash_name, h, em_len - h_len - 1))
        )
        em = masked + h + b"\xbc"
        sig = pow(int.from_bytes(em, "big"), key.d, key.n).to_bytes(
            key.size_bytes, "big"
        )
        self.assertTrue(
            crypto._rsa_pss_verify(key.public_key.rsa, hash_name, sig, b"pss message")
        )
        self.assertFalse(
            crypto._rsa_pss_verify(key.public_key.rsa, hash_name, sig, b"pss messagX")
        )

    def test_ecdsa_good_and_tampered(self):
        sig = self.ec.sign("sha256", b"ecdsa payload")
        curve, point = self.ec.public_key.ec
        self.assertTrue(
            crypto._ecdsa_verify(curve, point, "sha256", sig, b"ecdsa payload")
        )
        self.assertFalse(
            crypto._ecdsa_verify(curve, point, "sha256", sig, b"ecdsa payloaX")
        )

    def test_ecdsa_rejects_out_of_range_values(self):
        curve = self.ec.curve
        bad = der.seq(der.integer(0), der.integer(1))
        self.assertFalse(
            crypto._ecdsa_verify(curve, self.ec.public_point, "sha256", bad, b"x")
        )
        bad2 = der.seq(der.integer(1), der.integer(curve.n))
        self.assertFalse(
            crypto._ecdsa_verify(curve, self.ec.public_point, "sha256", bad2, b"x")
        )

    def test_parse_key_rejects_off_curve_point(self):
        spki = bytearray(self.ec.public_spki())
        # Flip a byte inside the EC point.
        spki[-5] ^= 0xFF
        with self.assertRaises(crypto.CryptoError):
            crypto.parse_public_key(bytes(spki))


class CertificateTests(unittest.TestCase):
    def test_self_signed_certificate_fields(self):
        key = keys.generate_rsa_key("cert-test", 1024)
        blob, meta = keys.make_certificate(key, "Cert Test", org="Acme", country="DE")
        cert = x509.parse_certificate(blob)
        self.assertEqual(cert.subject_cn, "Cert Test")
        self.assertEqual(cert.subject, cert.issuer)
        self.assertTrue(cert.self_signed)
        self.assertTrue(cert.self_signed_valid)

    def test_ec_certificate(self):
        key = keys.generate_ec_key("cert-test-ec", 256)
        blob, _ = keys.make_certificate(key, "EC Cert")
        cert = x509.parse_certificate(blob)
        self.assertEqual(cert.public_key.kind, "ec")
        self.assertTrue(cert.self_signed_valid)

    def test_garbage_certificate_raises(self):
        with self.assertRaises(x509.CertificateError):
            x509.parse_certificate(b"\x30\x03\x02\x01")
        with self.assertRaises(x509.CertificateError):
            x509.parse_certificate(b"not a certificate")


# ---------------------------------------------------------------------------
# Binary XML / ARSC parsing
# ---------------------------------------------------------------------------


class BinXmlTests(unittest.TestCase):
    def _manifest_bytes(self) -> bytes:
        b = axml.AxmlBuilder()
        b.start(
            "manifest",
            [axml.A("package", "com.test.app", ns=None), axml.A("versionCode", 7, ns=None)],
        )
        b.start("uses-sdk", [axml.A("minSdkVersion", 21), axml.A("targetSdkVersion", 33)])
        b.end("uses-sdk")
        b.start("application", [axml.A("debuggable", True), axml.A("allowBackup", False)])
        b.end("application")
        b.end("manifest")
        return b.to_bytes()

    def test_roundtrip_structure(self):
        doc = binxml.parse_axml(self._manifest_bytes())
        self.assertEqual(doc.root.name, "manifest")
        self.assertEqual(doc.root.value("package", ns=None), "com.test.app")
        app = next(doc.root.children_named("application"))
        self.assertTrue(app.flag("debuggable"))
        self.assertFalse(app.flag("allowBackup"))
        sdk = next(doc.root.children_named("uses-sdk"))
        self.assertEqual(sdk.int_value("targetSdkVersion"), 33)

    def test_attribute_resource_ids(self):
        doc = binxml.parse_axml(self._manifest_bytes())
        app = next(doc.root.children_named("application"))
        attr = app.attr("debuggable")
        self.assertIsNotNone(attr)
        self.assertEqual(attr.res_id, 0x0101000F)

    def test_truncated_input_raises(self):
        data = self._manifest_bytes()
        for cut in (4, 8, 16, len(data) // 2, len(data) - 1):
            with self.assertRaises(binxml.BinXmlError):
                binxml.parse_axml(data[:cut])

    def test_absurd_string_count_rejected(self):
        data = bytearray(self._manifest_bytes())
        # Overwrite the string-pool count with a huge value.
        struct.pack_into("<I", data, 8 + 8, 0x00FFFFFF)
        with self.assertRaises(binxml.BinXmlError):
            binxml.parse_axml(bytes(data))

    def test_absurd_chunk_size_rejected(self):
        data = bytearray(self._manifest_bytes())
        struct.pack_into("<I", data, 4, 0x7FFFFFF0)
        with self.assertRaises(binxml.BinXmlError):
            binxml.parse_axml(bytes(data))

    def test_plain_xml_rejected(self):
        with self.assertRaises(binxml.BinXmlError):
            binxml.parse_axml(b"<manifest package='x'/>")


class ArscTests(unittest.TestCase):
    def test_lookup_by_id(self):
        builder = axml.ArscBuilder(package_name="com.test.app")
        res_id = builder.add("xml", "network_security_config", "res/xml/network_security_config.xml")
        builder.add("string", "app_name", "Test App")
        table = arsc.parse_arsc(builder.to_bytes())
        self.assertEqual(table.lookup_name(res_id), "xml/network_security_config")
        hit = table.lookup(res_id)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[1].key, "network_security_config")
        self.assertEqual(table.string_value(hit[1]), "res/xml/network_security_config.xml")

    def test_unknown_id_returns_none(self):
        builder = axml.ArscBuilder(package_name="com.test.app")
        builder.add("xml", "x", "res/xml/x.xml")
        table = arsc.parse_arsc(builder.to_bytes())
        self.assertIsNone(table.lookup_name(0x7F0F0001))

    def test_truncated_table_raises(self):
        builder = axml.ArscBuilder()
        builder.add("xml", "x", "res/xml/x.xml")
        data = builder.to_bytes()
        with self.assertRaises((arsc.ArscError, binxml.BinXmlError)):
            arsc.parse_arsc(data[: len(data) // 2])


# ---------------------------------------------------------------------------
# Zip / signing block parsing
# ---------------------------------------------------------------------------


class ApkContainerTests(unittest.TestCase):
    def test_reads_entries(self):
        path = fixture_path("hardened.apk")
        with apkfile.ApkFile(path) as apk:
            self.assertIsNotNone(apk.get_entry("AndroidManifest.xml"))
            self.assertIsNotNone(apk.signing_block)
            ids = apk.signing_block.ordered_ids
            self.assertIn(apkfile.V2_BLOCK_ID, ids)
            self.assertIn(apkfile.V3_BLOCK_ID, ids)

    def test_crc_mismatch_rejected(self):
        payload = zipsign.ZipWriter()
        payload.add_stored("a.txt", b"hello world" * 10)
        data = bytearray(payload.build())
        # Corrupt a byte of the stored payload.
        idx = data.find(b"hello world")
        data[idx] = ord("j")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(bytes(data))
            name = fh.name
        try:
            with apkfile.ApkFile(name) as apk:
                with self.assertRaises(apkfile.ApkFormatError):
                    apk.get_entry("a.txt").read()
        finally:
            os.unlink(name)

    def test_zip_bomb_entry_is_bounded(self):
        # Declares a huge uncompressed size; must refuse before inflating.
        payload = zipsign.ZipWriter()
        payload.add("big", b"\x00" * 1000)
        data = bytearray(payload.build())
        # Patch the declared uncompressed size in local + central headers.
        loc = struct.unpack_from("<I", data, data.find(b"PK\x01\x02") + 42)[0]
        struct.pack_into("<I", data, loc + 22, 0x7F000000)
        cd = data.find(b"PK\x01\x02")
        struct.pack_into("<I", data, cd + 24, 0x7F000000)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(bytes(data))
            name = fh.name
        try:
            with apkfile.ApkFile(name) as apk:
                with self.assertRaises(apkfile.ApkFormatError):
                    apk.get_entry("big").read()
        finally:
            os.unlink(name)

    def test_not_a_zip_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(b"this is definitely not a zip file")
            name = fh.name
        try:
            with self.assertRaises(apkfile.ApkFormatError):
                apkfile.ApkFile(name)
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# Manifest model
# ---------------------------------------------------------------------------


class ManifestModelTests(unittest.TestCase):
    def test_component_export_rules(self):
        b = axml.AxmlBuilder()
        b.start("manifest", [axml.A("package", "p", ns=None)])
        b.start("application", [])
        b.start("activity", [axml.A("name", "A1")])
        b.start("intent-filter", [])
        b.start("action", [axml.A("name", "a.B")])
        b.end("action")
        b.end("intent-filter")
        b.end("activity")
        b.start("service", [axml.A("name", "S1"), axml.A("exported", False)])
        b.end("service")
        b.start("receiver", [axml.A("name", "R1"), axml.A("exported", True)])
        b.end("receiver")
        b.end("application")
        b.end("manifest")
        mf = manifest.parse_manifest_bytes(b.to_bytes())
        by_name = {c.name: c for c in mf.components}
        self.assertIsNone(by_name["A1"].exported)
        self.assertTrue(by_name["A1"].implicitly_exported)
        self.assertTrue(by_name["A1"].is_exported)
        self.assertFalse(by_name["S1"].is_exported)
        self.assertTrue(by_name["R1"].is_exported)

    def test_provider_authorities_split(self):
        b = axml.AxmlBuilder()
        b.start("manifest", [axml.A("package", "p", ns=None)])
        b.start("application", [])
        b.start(
            "provider",
            [
                axml.A("name", "P"),
                axml.A("authorities", "p.a;p.b"),
                axml.A("exported", True),
            ],
        )
        b.end("provider")
        b.end("application")
        b.end("manifest")
        mf = manifest.parse_manifest_bytes(b.to_bytes())
        self.assertEqual(mf.components[0].authorities, ["p.a", "p.b"])

    def test_target_sdk_defaults_to_min_sdk(self):
        b = axml.AxmlBuilder()
        b.start("manifest", [axml.A("package", "p", ns=None)])
        b.start("uses-sdk", [axml.A("minSdkVersion", 19)])
        b.end("uses-sdk")
        b.start("application", [])
        b.end("application")
        b.end("manifest")
        mf = manifest.parse_manifest_bytes(b.to_bytes())
        self.assertEqual(mf.target_sdk, 19)

    def test_duplicate_provider_authority_warns(self):
        b = axml.AxmlBuilder()
        b.start("manifest", [axml.A("package", "p", ns=None)])
        b.start("application", [])
        for name in ("P1", "P2"):
            b.start(
                "provider",
                [axml.A("name", name), axml.A("authorities", "shared.auth")],
            )
            b.end("provider")
        b.end("application")
        b.end("manifest")
        mf = manifest.parse_manifest_bytes(b.to_bytes())
        self.assertTrue(any("duplicate provider authority" in w for w in mf.warnings))


# ---------------------------------------------------------------------------
# Network security config
# ---------------------------------------------------------------------------


class NetworkSecurityConfigTests(unittest.TestCase):
    def _parse(self, **kwargs) -> nsc.NscConfig:
        builder = axml.AxmlBuilder()
        b = builder
        b.start("network-security-config")
        if "base_cleartext" in kwargs:
            b.start("base-config", [axml.A("cleartextTrafficPermitted", kwargs["base_cleartext"], ns=None)])
        if kwargs.get("user_ca"):
            b.start("trust-anchors")
            b.start("certificates", [axml.A("src", "user", ns=None)])
            b.end("certificates")
            b.end("trust-anchors")
        if "base_cleartext" in kwargs:
            b.end("base-config")
        for host, cleartext in kwargs.get("domains", []):
            b.start("domain-config", [axml.A("cleartextTrafficPermitted", cleartext, ns=None)])
            b.start("domain", [axml.A("name", host, ns=None)])
            b.end("domain")
            b.end("domain-config")
        b.end("network-security-config")
        doc = binxml.parse_axml(b.to_bytes())
        return nsc.parse_nsc_document(doc, "res/xml/nsc.xml")

    def test_base_cleartext_false(self):
        cfg = self._parse(base_cleartext=False)
        self.assertFalse(cfg.base_cleartext)

    def test_domain_overrides(self):
        cfg = self._parse(base_cleartext=False, domains=[("a.example", True)])
        self.assertEqual(len(cfg.domains), 1)
        self.assertTrue(cfg.domains[0].cleartext)
        self.assertEqual([d.domain for d in cfg.domains_allowing_cleartext()], ["a.example"])

    def test_user_ca_detected(self):
        cfg = self._parse(base_cleartext=False, user_ca=True)
        self.assertTrue(cfg.base_trust.user)

    def test_effective_policy_defaults_by_target_sdk(self):
        mf = manifest.Manifest(target_sdk=22)
        policy = nsc.compute_effective_policy(mf, nsc.NscConfig())
        self.assertTrue(policy.cleartext_global)
        self.assertTrue(policy.trusts_user_cas)

        mf2 = manifest.Manifest(target_sdk=34)
        policy2 = nsc.compute_effective_policy(mf2, nsc.NscConfig())
        self.assertFalse(policy2.cleartext_global)
        self.assertFalse(policy2.trusts_user_cas)

    def test_nsc_overrides_platform_default(self):
        mf = manifest.Manifest(target_sdk=34)
        cfg = self._parse(base_cleartext=True)
        policy = nsc.compute_effective_policy(mf, cfg)
        self.assertTrue(policy.cleartext_global)
        self.assertEqual(policy.cleartext_source, "network_security_config base-config")

    def test_nested_domain_config_inherits(self):
        b = axml.AxmlBuilder()
        b.start("network-security-config")
        b.start("domain-config", [axml.A("cleartextTrafficPermitted", True, ns=None)])
        b.start("domain", [axml.A("name", "parent.example", ns=None)])
        b.end("domain")
        b.start("domain-config")
        b.start("domain", [axml.A("name", "child.parent.example", ns=None)])
        b.end("domain")
        b.end("domain-config")
        b.end("domain-config")
        b.end("network-security-config")
        cfg = nsc.parse_nsc_document(binxml.parse_axml(b.to_bytes()), "x")
        self.assertEqual({d.domain for d in cfg.domains}, {"parent.example", "child.parent.example"})
        self.assertTrue(all(d.cleartext for d in cfg.domains))


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


class SignatureTests(unittest.TestCase):
    def test_hardened_has_all_schemes_verified(self):
        with apkfile.ApkFile(fixture_path("hardened.apk")) as apk:
            result = signature.analyze_signatures(apk)
        self.assertEqual(result.schemes_present(), [1, 2, 3])
        self.assertTrue(result.v1.verified)
        self.assertTrue(result.v2.verified)
        self.assertTrue(result.v3.verified)

    def test_v2_only_fixture(self):
        with apkfile.ApkFile(fixture_path("v2_only.apk")) as apk:
            result = signature.analyze_signatures(apk)
        self.assertEqual(result.schemes_present(), [2])
        self.assertTrue(result.v2.verified)
        self.assertFalse(result.v3.present)

    def test_ec_signature_verifies(self):
        with apkfile.ApkFile(fixture_path("ec_signed.apk")) as apk:
            result = signature.analyze_signatures(apk)
        self.assertTrue(result.v2.verified)
        self.assertTrue(result.v3.verified)
        cert = result.v2.signers[0].certificates[0]
        self.assertEqual(cert.public_key.kind, "ec")

    def test_repackaged_archive_detected(self):
        with apkfile.ApkFile(fixture_path("repackaged.apk")) as apk:
            result = signature.analyze_signatures(apk)
        self.assertTrue(result.v1.present)
        self.assertIn("classes2.dex", result.v1.uncovered_entries)

    def test_tampered_v2_content_digest_detected(self):
        # Flip one byte of the (stored) classes.dex payload.  The signing block
        # itself stays intact, so only the content digest can catch this.
        path = fixture_path("v2_only.apk")
        with apkfile.ApkFile(path) as apk:
            entry = apk.get_entry("classes.dex")
            local = entry.local_header_offset
        name_len, extra_len = struct.unpack_from("<HH", b"", 0) if False else (0, 0)
        with open(path, "rb") as fh:
            data = bytearray(fh.read())
        name_len, extra_len = struct.unpack_from("<HH", data, local + 26)
        payload_off = local + 30 + name_len + extra_len
        data[payload_off] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(bytes(data))
            bad = fh.name
        try:
            with apkfile.ApkFile(bad) as apk:
                result = signature.analyze_signatures(apk)
            self.assertTrue(result.v2.present)
            self.assertFalse(result.v2.verified)
            messages = " ".join(result.v2.errors + result.errors).lower()
            self.assertTrue(
                "digest mismatch" in messages or "signature" in messages,
                messages,
            )
        finally:
            os.unlink(bad)

    def test_unsigned_has_no_schemes(self):
        with apkfile.ApkFile(fixture_path("unsigned.apk")) as apk:
            result = signature.analyze_signatures(apk)
        self.assertEqual(result.schemes_present(), [])

    def test_v2_wrong_certificate_detected(self):
        # Re-sign the payload with a different key but keep the v2 block: the
        # signer's public key no longer matches the certificate.
        key_a = keys.generate_rsa_key("mismatch-a", 1024)
        cert_a, _ = keys.make_certificate(key_a, "Signer A")
        payload = zipsign.ZipWriter()
        payload.add("AndroidManifest.xml", b"<x/>")
        data = payload.build()
        eocd = data.rfind(b"PK\x05\x06")
        cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
        signed = zipsign.sign_apk_v2_v3(
            data, cd_offset, cd_size, key_a, cert_a, schemes=("v2",)
        )
        # Corrupt the certificate inside the block: flip a byte in the cert DER.
        marker = cert_a[:16]
        idx = signed.find(marker)
        self.assertGreater(idx, 0)
        tampered = bytearray(signed)
        tampered[idx + 40] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(bytes(tampered))
            path = fh.name
        try:
            with apkfile.ApkFile(path) as apk:
                result = signature.analyze_signatures(apk)
            self.assertFalse(result.v2.verified)
            self.assertTrue(result.v2.errors or result.errors)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Rule engine and end-to-end audit
# ---------------------------------------------------------------------------


class RuleTests(unittest.TestCase):
    def test_hardened_app_has_only_informational_findings(self):
        result = audit.audit_apk(fixture_path("hardened.apk"))
        severities = {f.severity for f in result.findings}
        self.assertLessEqual(severities, {"info"}, result.findings)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.grade, "A")
        self.assertEqual(result.signatures.schemes_present(), [1, 2, 3])
        self.assertTrue(result.signatures.v2.verified)
        self.assertTrue(result.signatures.v3.verified)

    def test_terrible_app_flags_expected_rules(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        expected = set(_FIXTURES["terrible.apk"].expected_rules)
        missing = expected - rule_ids(result)
        self.assertFalse(missing, f"missing rules: {sorted(missing)}")
        self.assertEqual(result.grade, "F")
        self.assertGreater(result.score, 70)

    def test_hardened_app_lacks_expected_bad_rules(self):
        result = audit.audit_apk(fixture_path("hardened.apk"))
        absent = set(_FIXTURES["hardened.apk"].absent_rules)
        self.assertFalse(absent & rule_ids(result))

    def test_missing_exported_detected(self):
        result = audit.audit_apk(fixture_path("missing_exported.apk"))
        self.assertIn("COMP-EXPORTED-MISSING", rule_ids(result))

    def test_launcher_activity_is_not_flagged_as_exported_risk(self):
        result = audit.audit_apk(fixture_path("v2_only.apk"))
        self.assertNotIn("ACTIVITY-EXPORTED-NO-PERMISSION", rule_ids(result))

    def test_deep_link_exposure_explained(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        finding = next(
            f for f in result.findings if f.rule_id == "INTENT-FILTER-EXPOSURE"
        )
        self.assertIn("BROWSABLE", finding.detail)
        self.assertIn("autoVerify", finding.detail)

    def test_receiver_findings_mention_system_broadcasts(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        receiver_details = [
            f.detail
            for f in result.findings
            if f.component and f.component.endswith("PushReceiver")
        ]
        self.assertTrue(any("广播" in d for d in receiver_details))

    def test_v2_only_flags_missing_v3(self):
        result = audit.audit_apk(fixture_path("v2_only.apk"))
        self.assertIn("SIG-NO-V3", rule_ids(result))
        self.assertNotIn("SIG-V1-ONLY", rule_ids(result))

    def test_repackaged_gets_high_severity_unsigned_entries(self):
        result = audit.audit_apk(fixture_path("repackaged.apk"))
        finding = next(
            f for f in result.findings if f.rule_id == "SIG-UNSIGNED-ENTRIES"
        )
        self.assertIn(finding.severity, ("critical", "high"))

    def test_unsigned_app_is_critical(self):
        result = audit.audit_apk(fixture_path("unsigned.apk"))
        self.assertIn("SIG-NONE", rule_ids(result))
        finding = next(f for f in result.findings if f.rule_id == "SIG-NONE")
        self.assertEqual(finding.severity, "critical")

    def test_unresolved_nsc_reported(self):
        result = audit.audit_apk(fixture_path("unresolved_nsc.apk"))
        self.assertIn("NSC-UNPARSEABLE", rule_ids(result))
        self.assertIsNotNone(result.policy.nsc.parse_error)

    def test_provider_guarded_by_unknown_permission(self):
        result = audit.audit_apk(fixture_path("ec_signed.apk"))
        self.assertIn("PROVIDER-EXPORTED-GUARDED", rule_ids(result))

    def test_findings_sorted_by_severity(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        order = [risk.SEVERITY_ORDER.index(f.severity) for f in result.findings]
        self.assertEqual(order, sorted(order))

    def test_score_and_grade_are_bounded(self):
        for name in _FIXTURES:
            if name.endswith(("broken_manifest.apk", "text_manifest.apk")):
                continue
            result = audit.audit_apk(fixture_path(name))
            self.assertGreaterEqual(result.score, 0)
            self.assertLessEqual(result.score, 100)
            self.assertIn(result.grade, "ABCDF")


class DetailedRuleTests(unittest.TestCase):
    """Targeted assertions on message content and severity for key rules."""

    def test_debuggable_is_critical_and_explains_impact(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        finding = next(f for f in result.findings if f.rule_id == "APP-DEBUGGABLE")
        self.assertEqual(finding.severity, "critical")
        self.assertIn("adb", finding.detail)
        self.assertTrue(finding.remediation)

    def test_cleartext_rules_explain_source(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        allowed = next(f for f in result.findings if f.rule_id == "NET-CLEARTEXT-ALLOWED")
        self.assertEqual(allowed.severity, "high")
        self.assertIn("base-config", allowed.detail)
        domain = next(f for f in result.findings if f.rule_id == "NET-CLEARTEXT-DOMAIN")
        self.assertIn("pay.sketchy.example", domain.title)

    def test_user_ca_rules(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        trust = next(f for f in result.findings if f.rule_id == "NET-USER-CA-TRUST")
        self.assertEqual(trust.severity, "high")
        self.assertIn("trust-anchors", trust.detail)

    def test_debug_cert_flagged(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        finding = next(f for f in result.findings if f.rule_id == "SIG-DEBUG-CERT")
        self.assertEqual(finding.severity, "high")
        self.assertIn("Android Debug", finding.evidence[0])

    def test_sig_invalid_explained_for_repackaged_apk(self):
        result = audit.audit_apk(fixture_path("repackaged.apk"))
        finding = next(f for f in result.findings if f.rule_id == "SIG-INVALID")
        self.assertEqual(finding.severity, "critical")
        self.assertIn("未覆盖", finding.detail)

    def test_permission_rules(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        weak = next(f for f in result.findings if f.rule_id == "PERM-WEAK-PROTECTION")
        self.assertIn("normal", weak.title)
        high_risk = [
            f for f in result.findings if f.rule_id == "PERM-HIGH-RISK"
        ]
        self.assertTrue(high_risk)
        self.assertTrue(all("android.permission" in f.evidence[0] for f in high_risk))

    def test_grant_uri_permissions_flagged(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        self.assertIn("PROVIDER-GRANT-URI", rule_ids(result))

    def test_receiver_severity_raised_for_system_broadcasts(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        finding = next(
            f for f in result.findings if f.rule_id == "RECEIVER-EXPORTED-NO-PERMISSION"
        )
        self.assertEqual(finding.severity, "high")

    def test_allow_backup_default_and_explicit(self):
        explicit = audit.audit_apk(fixture_path("terrible.apk"))
        self.assertIn("APP-ALLOW-BACKUP", rule_ids(explicit))
        default = audit.audit_apk(fixture_path("unsigned.apk"))
        self.assertIn("APP-ALLOW-BACKUP-DEFAULT", rule_ids(default))

    def test_low_sdk_rules(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        self.assertIn("APP-LOW-TARGET-SDK", rule_ids(result))
        self.assertIn("APP-LOW-MIN-SDK", rule_ids(result))
        self.assertIn("APP-LEGACY-STORAGE", rule_ids(result))

    def test_signature_coverage_mentions_min_sdk(self):
        result = audit.audit_apk(fixture_path("v2_only.apk"))
        finding = next(f for f in result.findings if f.rule_id == "SIG-COVERAGE")
        self.assertIn("minSdk=24", finding.evidence[0])

    def test_pinning_and_debug_overrides_are_info(self):
        result = audit.audit_apk(fixture_path("hardened.apk"))
        for rule in ("NSC-PINNING-PRESENT", "NSC-DEBUG-OVERRIDES"):
            finding = next(f for f in result.findings if f.rule_id == rule)
            self.assertEqual(finding.severity, "info")

    def test_bad_self_signature_detected(self):
        # Flip a byte inside the certificate's signature value so the
        # self-signature no longer verifies.
        key = keys.generate_rsa_key("bad-selfsig", 1024)
        cert_der, _ = keys.make_certificate(key, "Broken Selfsig")
        blob = bytearray(cert_der)
        blob[-5] ^= 0xFF
        # A corrupted signature still parses; the self-signature check must
        # report False rather than raise or wrongly claim validity.
        parsed = x509.parse_certificate(bytes(blob))
        self.assertIs(parsed.self_signed_valid, False)
        rule_ids_found = {
            f.rule_id
            for f in risk.check_signatures(
                signature.SignatureReport(
                    v1=signature.SchemeResult(scheme=1),
                    v2=signature.SchemeResult(
                        scheme=2,
                        present=True,
                        verified=True,
                        signers=[
                            signature.Signer(scheme=2, certificates=[parsed], verified=True)
                        ],
                    ),
                    v3=signature.SchemeResult(scheme=3),
                ),
                manifest.Manifest(),
            )
        }
        self.assertIn("SIG-CERT-BAD-SELFSIG", rule_ids_found)


class RuleCoverageTests(unittest.TestCase):
    """Every rule must be reachable from some input (no dead rules)."""

    def _audit_manifest(self, builder, *, schemes=("v2", "v3"), key=None, cert=None):
        if key is None or cert is None:
            key, cert = fixtures.release_key()
        b = axml.AxmlBuilder()
        builder(b)
        apk = fixtures.build_signed(
            [
                ("AndroidManifest.xml", b.to_bytes(), True),
                ("classes.dex", fixtures.STUB_DEX, True),
            ],
            key,
            cert,
            schemes,
            min_sdk=24,
        )
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(apk)
            path = fh.name
        try:
            return audit.audit_apk(path)
        finally:
            os.unlink(path)

    def test_manifest_without_application(self):
        def build(b):
            b.start("manifest", [axml.A("package", "com.t.noapp", ns=None)])
            b.end("manifest")

        result = self._audit_manifest(build)
        self.assertIn("MANIFEST-NO-APPLICATION", rule_ids(result))

    def test_testonly_shared_uid_and_native_libs(self):
        def build(b):
            b.start(
                "manifest",
                [
                    axml.A("package", "com.t.flags", ns=None),
                    axml.A("sharedUserId", "com.t.shared", ns=None),
                ],
            )
            b.start("uses-sdk", [axml.A("minSdkVersion", 24), axml.A("targetSdkVersion", 30)])
            b.end("uses-sdk")
            b.start(
                "application",
                [
                    axml.A("testOnly", True),
                    axml.A("extractNativeLibs", True),
                    axml.A("allowBackup", False),
                ],
            )
            b.end("application")
            b.end("manifest")

        result = self._audit_manifest(build)
        for rule in ("APP-TEST-ONLY", "APP-SHARED-UID", "APP-EXTRACT-NATIVE-LIBS"):
            self.assertIn(rule, rule_ids(result))

    def test_component_kinds_and_alias(self):
        def build(b):
            b.start("manifest", [axml.A("package", "com.t.comp", ns=None)])
            b.start("uses-sdk", [axml.A("minSdkVersion", 24), axml.A("targetSdkVersion", 30)])
            b.end("uses-sdk")
            b.start("application", [axml.A("allowBackup", False)])
            b.start("activity", [axml.A("name", "Target"), axml.A("exported", False)])
            b.end("activity")
            b.start(
                "activity-alias",
                [
                    axml.A("name", "Alias"),
                    axml.A("targetActivity", "Target"),
                    axml.A("exported", True),
                ],
            )
            b.end("activity-alias")
            b.start(
                "service",
                [
                    axml.A("name", "Svc"),
                    axml.A("exported", True),
                    axml.A("permission", "android.permission.BIND_JOB_SERVICE"),
                ],
            )
            b.end("service")
            # exported=false with a retained intent-filter is dead config
            b.start("activity", [axml.A("name", "DeadFilter"), axml.A("exported", False)])
            b.start("intent-filter", [])
            b.start("action", [axml.A("name", "com.t.DEAD")])
            b.end("action")
            b.end("intent-filter")
            b.end("activity")
            # receivers with exported=false keep filters legitimately (e.g.
            # protected system broadcasts), so they are not flagged.
            b.start("receiver", [axml.A("name", "Rcv"), axml.A("exported", False)])
            b.start("intent-filter", [axml.A("priority", 10)])
            b.start("action", [axml.A("name", "android.intent.action.BOOT_COMPLETED")])
            b.end("action")
            b.end("intent-filter")
            b.end("receiver")
            b.end("application")
            b.end("manifest")

        result = self._audit_manifest(build)
        self.assertIn("ACTIVITY-ALIAS", rule_ids(result))
        self.assertIn("COMP-FILTER-IGNORED", rule_ids(result))
        flagged = {f.component for f in result.findings if f.rule_id == "COMP-FILTER-IGNORED"}
        self.assertEqual(flagged, {"DeadFilter"})
        service_findings = [
            f
            for f in result.findings
            if f.component == "Svc" and f.rule_id == "SERVICE-EXPORTED-NO-PERMISSION"
        ]
        self.assertFalse(service_findings)

    def test_implicit_export_with_permission(self):
        def build(b):
            b.start("manifest", [axml.A("package", "com.t.imp", ns=None)])
            b.start("uses-sdk", [axml.A("minSdkVersion", 24), axml.A("targetSdkVersion", 30)])
            b.end("uses-sdk")
            b.start("permission", [
                axml.A("name", "com.t.PERM"),
                axml.A("protectionLevel", ("hex", 0x02)),
            ])
            b.end("permission")
            b.start("application", [axml.A("allowBackup", False)])
            b.start("activity", [axml.A("name", "Guarded"), axml.A("permission", "com.t.PERM")])
            b.start("intent-filter", [])
            b.start("action", [axml.A("name", "com.t.ACTION")])
            b.end("action")
            b.end("intent-filter")
            b.end("activity")
            b.end("application")
            b.end("manifest")

        result = self._audit_manifest(build)
        self.assertIn("COMP-IMPLICIT-EXPORT", rule_ids(result))
        finding = next(f for f in result.findings if f.rule_id == "COMP-IMPLICIT-EXPORT")
        self.assertEqual(finding.severity, "medium")

    def test_wildcard_provider_authority(self):
        def build(b):
            b.start("manifest", [axml.A("package", "com.t.wild", ns=None)])
            b.start("uses-sdk", [axml.A("minSdkVersion", 24), axml.A("targetSdkVersion", 30)])
            b.end("uses-sdk")
            b.start("application", [axml.A("allowBackup", False)])
            b.start(
                "provider",
                [
                    axml.A("name", "P"),
                    axml.A("authorities", "com.t.*"),
                    axml.A("exported", True),
                ],
            )
            b.end("provider")
            b.end("application")
            b.end("manifest")

        result = self._audit_manifest(build)
        self.assertIn("PROVIDER-WILDCARD-AUTHORITY", rule_ids(result))

    def test_nsc_without_base_config(self):
        arsc = axml.ArscBuilder(package_name="com.t.nsc")
        res_id = arsc.add("xml", "nsc", "res/xml/nsc.xml")
        nsc_builder = axml.AxmlBuilder()
        nsc_builder.start("network-security-config")
        nsc_builder.start("domain-config", [axml.A("cleartextTrafficPermitted", False, ns=None)])
        nsc_builder.start("domain", [axml.A("name", "example.com", ns=None)])
        nsc_builder.end("domain")
        nsc_builder.end("domain-config")
        nsc_builder.end("network-security-config")

        b = axml.AxmlBuilder()
        b.start("manifest", [axml.A("package", "com.t.nsc", ns=None)])
        b.start("uses-sdk", [axml.A("minSdkVersion", 24), axml.A("targetSdkVersion", 30)])
        b.end("uses-sdk")
        b.start(
            "application",
            [
                axml.A("allowBackup", False),
                axml.A("networkSecurityConfig", ("ref", res_id)),
            ],
        )
        b.end("application")
        b.end("manifest")

        key, cert = fixtures.release_key()
        members = [
            ("AndroidManifest.xml", b.to_bytes(), True),
            ("resources.arsc", arsc.to_bytes(), True),
            ("res/xml/nsc.xml", nsc_builder.to_bytes(), True),
            ("classes.dex", fixtures.STUB_DEX, True),
        ]
        apk = fixtures.build_signed(members, key, cert, ("v2", "v3"), min_sdk=24)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(apk)
            path = fh.name
        try:
            result = audit.audit_apk(path)
        finally:
            os.unlink(path)
        self.assertIn("NSC-NO-BASE-CONFIG", rule_ids(result))

    def test_weak_rsa_and_expired_cert(self):
        import datetime as dt

        key = keys.generate_rsa_key("weak-key", 1024)
        cert, _ = keys.make_certificate(
            key,
            "Weak Signer",
            days_valid=1,
            not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        )

        def build(b):
            b.start("manifest", [axml.A("package", "com.t.weak", ns=None)])
            b.start("uses-sdk", [axml.A("minSdkVersion", 24), axml.A("targetSdkVersion", 30)])
            b.end("uses-sdk")
            b.start("application", [axml.A("allowBackup", False)])
            b.end("application")
            b.end("manifest")

        result = self._audit_manifest(build, key=key, cert=cert)
        self.assertIn("SIG-WEAK-RSA", rule_ids(result))
        self.assertIn("SIG-CERT-EXPIRED", rule_ids(result))

    def test_multiple_certificates_across_schemes(self):
        key_a = keys.generate_rsa_key("cross-a", 1024)
        cert_a, _ = keys.make_certificate(key_a, "Signer A")
        key_b = keys.generate_rsa_key("cross-b", 1024)
        cert_b, _ = keys.make_certificate(key_b, "Signer B")
        b = axml.AxmlBuilder()
        b.start("manifest", [axml.A("package", "com.t.cross", ns=None)])
        b.start("uses-sdk", [axml.A("minSdkVersion", 24), axml.A("targetSdkVersion", 30)])
        b.end("uses-sdk")
        b.start("application", [axml.A("allowBackup", False)])
        b.end("application")
        b.end("manifest")
        zw = zipsign.ZipWriter()
        zw.add("AndroidManifest.xml", b.to_bytes())
        zw.add("classes.dex", fixtures.STUB_DEX)
        meta = zipsign.sign_v1(zw.members, key_a, cert_a)
        for name, data in meta.items():
            zw.add_stored(name, data)
        payload = zw.build()
        eocd = payload.rfind(b"PK\x05\x06")
        cd_size, cd_offset = struct.unpack_from("<II", payload, eocd + 12)
        signed = zipsign.sign_apk_v2_v3(
            payload, cd_offset, cd_size, key_b, cert_b, schemes=("v2", "v3"), min_sdk=24
        )
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(signed)
            path = fh.name
        try:
            result = audit.audit_apk(path)
        finally:
            os.unlink(path)
        self.assertIn("SIG-MULTIPLE-CERTS", rule_ids(result))


class FixtureExpectationTests(unittest.TestCase):
    def test_every_fixture_matches_its_declared_expectations(self):
        """Each fixture declares the rules it must / must not raise."""
        for name, fx in _FIXTURES.items():
            if not fx.expected_rules and not fx.absent_rules:
                continue
            with self.subTest(fixture=name):
                if name in ("broken_manifest.apk", "text_manifest.apk"):
                    continue
                result = audit.audit_apk(fixture_path(name))
                ids = rule_ids(result)
                self.assertFalse(
                    set(fx.expected_rules) - ids,
                    f"{name} missing {sorted(set(fx.expected_rules) - ids)}",
                )
                self.assertFalse(
                    set(fx.absent_rules) & ids,
                    f"{name} unexpectedly has {sorted(set(fx.absent_rules) & ids)}",
                )


class SignatureCrossCheckTests(unittest.TestCase):
    """Checks that mirror what Google's apksig library concludes.

    Each expectation here was confirmed against apksig 8.6.1 / JDK 26 while
    developing the fixtures.
    """

    def test_hardened_matches_apksig(self):
        result = audit.audit_apk(fixture_path("hardened.apk"))
        self.assertTrue(result.signatures.v1.verified)
        self.assertTrue(result.signatures.v2.verified)
        self.assertTrue(result.signatures.v3.verified)
        self.assertEqual(sorted(result.signatures.v1.protected_schemes), [2, 3])

    def test_terrible_v1_verifies_but_has_no_v2_v3(self):
        result = audit.audit_apk(fixture_path("terrible.apk"))
        self.assertTrue(result.signatures.v1.verified)
        self.assertFalse(result.signatures.v2.present)
        self.assertFalse(result.signatures.v3.present)

    def test_repackaged_matches_apksig_error(self):
        result = audit.audit_apk(fixture_path("repackaged.apk"))
        self.assertIn("classes2.dex", result.signatures.v1.uncovered_entries)
        self.assertIn("SIG-UNSIGNED-ENTRIES", rule_ids(result))

    def test_anti_stripping_missing_detected(self):
        # Strip the attribute by re-signing v1 without protected schemes.
        key, cert = fixtures.release_key()
        b = axml.AxmlBuilder()
        b.start("manifest", [axml.A("package", "com.test.strip", ns=None)])
        b.start("uses-sdk", [axml.A("minSdkVersion", 21), axml.A("targetSdkVersion", 30)])
        b.end("uses-sdk")
        b.start("application", [])
        b.end("application")
        b.end("manifest")
        zw = zipsign.ZipWriter()
        zw.add("AndroidManifest.xml", b.to_bytes())
        zw.add("classes.dex", fixtures.STUB_DEX)
        meta = zipsign.sign_v1(zw.members, key, cert)
        for name, data in meta.items():
            zw.add_stored(name, data)
        payload = zw.build()
        eocd = payload.rfind(b"PK\x05\x06")
        cd_size, cd_offset = struct.unpack_from("<II", payload, eocd + 12)
        signed = zipsign.sign_apk_v2_v3(
            payload, cd_offset, cd_size, key, cert, schemes=("v2", "v3"), min_sdk=21
        )
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(signed)
            path = fh.name
        try:
            result = audit.audit_apk(path)
        finally:
            os.unlink(path)
        self.assertIn("SIG-STRIPPING-PROTECTION-MISSING", rule_ids(result))


class AuditErrorTests(unittest.TestCase):
    def test_broken_manifest_raises_audit_error(self):
        with self.assertRaises(audit.AuditError):
            audit.audit_apk(fixture_path("broken_manifest.apk"))

    def test_text_manifest_explains_compiled_xml(self):
        with self.assertRaises(audit.AuditError) as ctx:
            audit.audit_apk(fixture_path("text_manifest.apk"))
        self.assertIn("plain-text", str(ctx.exception))

    def test_missing_file(self):
        with self.assertRaises(audit.AuditError):
            audit.audit_apk("/nonexistent/file.apk")

    def test_apk_without_manifest(self):
        zw = zipsign.ZipWriter()
        zw.add("classes.dex", b"dex\n035\x00")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(zw.build())
            path = fh.name
        try:
            with self.assertRaises(audit.AuditError):
                audit.audit_apk(path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Reporting and CLI
# ---------------------------------------------------------------------------


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.result = audit.audit_apk(fixture_path("terrible.apk"))

    def test_json_is_valid_and_complete(self):
        payload = json.loads(report.render_json(self.result))
        self.assertEqual(payload["package"]["name"], "com.example.sketchy.wallpaper")
        self.assertIn("signatures", payload)
        self.assertIsInstance(payload["findings"], list)
        self.assertIn("components", payload)
        self.assertTrue(payload["components"])

    def test_markdown_contains_findings(self):
        md = report.render_markdown(self.result)
        self.assertIn("# APK 安全审计报告", md)
        self.assertIn("严重", md)
        self.assertIn("PROVIDER-EXPORTED-NO-PERMISSION", md)

    def test_text_contains_key_sections(self):
        text = report.render_text(self.result)
        for section in ("基本信息", "网络安全配置", "签名", "组件", "风险发现"):
            self.assertIn(section, text)

    def test_text_render_does_not_emit_ansi_when_disabled(self):
        self.assertNotIn("\033[", report.render_text(self.result, color=False))


class CliTests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "apksec", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_audit_json_output(self):
        proc = self._run("audit", fixture_path("hardened.apk"), "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["grade"], "A")

    def test_fail_on_threshold(self):
        proc = self._run(
            "audit", fixture_path("terrible.apk"), "--fail-on", "critical,high"
        )
        self.assertEqual(proc.returncode, 1)

    def test_fail_on_not_triggered(self):
        proc = self._run(
            "audit", fixture_path("hardened.apk"), "--fail-on", "critical,high"
        )
        self.assertEqual(proc.returncode, 0)

    def test_dump_subcommand(self):
        proc = self._run("dump", fixture_path("hardened.apk"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("<manifest>", proc.stdout)
        self.assertIn("debuggable", proc.stdout)

    def test_sig_subcommand(self):
        proc = self._run("sig", fixture_path("hardened.apk"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schemes"], ["v1", "v2", "v3"])

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.md")
            proc = self._run(
                "audit", fixture_path("hardened.apk"), "--format", "markdown", "-o", out
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out, encoding="utf-8") as fh:
                self.assertIn("APK 安全审计报告", fh.read())

    def test_broken_apk_exit_code(self):
        proc = self._run("audit", fixture_path("broken_manifest.apk"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not valid binary XML", proc.stderr)


class RobustnessTests(unittest.TestCase):
    """Hostile input must produce errors, never tracebacks or hangs."""

    def _audit_bytes(self, data: bytes):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(data)
            path = fh.name
        try:
            return audit.audit_apk(path)
        finally:
            os.unlink(path)

    def _mutate_manifest(self, mutate) -> bytes:
        with apkfile.ApkFile(fixture_path("hardened.apk")) as apk:
            manifest_data = apk.read_entry_safe("AndroidManifest.xml")
            members = [
                (e.name, apk.read_entry(e), e.compress_type == 8)
                for e in apk.iter_entries()
                if not e.name.startswith("META-INF/")
            ]
        mutated = mutate(bytearray(manifest_data))
        zw = zipsign.ZipWriter()
        for name, data, compress in members:
            if name == "AndroidManifest.xml":
                data = bytes(mutated)
            zw.add(name, data, compress=compress)
        return zw.build()

    def test_random_manifest_mutations_do_not_crash(self):
        import random

        rng = random.Random(1234)
        with apkfile.ApkFile(fixture_path("hardened.apk")) as apk:
            base = bytearray(apk.read_entry_safe("AndroidManifest.xml"))
        for _ in range(40):
            mutated = bytearray(base)
            for _ in range(rng.randint(1, 8)):
                pos = rng.randrange(len(mutated))
                mutated[pos] = rng.randrange(256)
            zw = zipsign.ZipWriter()
            zw.add("AndroidManifest.xml", bytes(mutated))
            zw.add("classes.dex", fixtures.STUB_DEX)
            try:
                self._audit_bytes(zw.build())
            except audit.AuditError:
                pass
            except (apkfile.ApkFormatError, binxml.BinXmlError, arsc.ArscError):
                pass

    def test_truncated_apk_does_not_crash(self):
        with open(fixture_path("hardened.apk"), "rb") as fh:
            data = fh.read()
        for cut in (10, 100, len(data) // 3, len(data) - 20):
            with self.assertRaises((apkfile.ApkFormatError, audit.AuditError)):
                self._audit_bytes(data[:cut])

    def test_decompression_limits_apply(self):
        self.assertEqual(apkfile.MAX_ENTRY_SIZE, 64 * 1024 * 1024)
        self.assertEqual(binxml.MAX_XML_DEPTH, 256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
