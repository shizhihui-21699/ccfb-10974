#!/usr/bin/env python3
"""apk_audit 单元测试（纯标准库 unittest，无需第三方依赖）。

用 tests/axmlwriter 自造 AXML、tests/apksigner_lite 自造签名块，
覆盖解析往返、导出判定、网络配置、签名校验与篡改检测。
"""

import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from apk_audit.axml import ANDROID_NS, parse_axml
from apk_audit.manifest import analyze_manifest
from apk_audit.netconfig import analyze_network_config
from apk_audit.apkfile import APKFile
from apk_audit.signatures import analyze_signatures
from apk_audit.auditor import audit_apk
from apk_audit.rules import CRITICAL, HIGH, MEDIUM, LOW

from tests.axmlwriter import AXMLWriter, Node
from tests import apksigner_lite as signer
import tests.build_fixtures as bf

A = ANDROID_NS


def attr(ns, name, value):
    return (ns, name), value


def android(name, value):
    return attr(A, name, value)


class TestAXMLRoundTrip(unittest.TestCase):
    def _roundtrip(self, root):
        return parse_axml(AXMLWriter().write(root))

    def test_string_and_int_attrs(self):
        root = Node("manifest", dict([
            attr(None, "package", "com.demo.app"),
            android("versionCode", 42),
            android("versionName", "1.0.0"),
        ]))
        elem = self._roundtrip(root)
        self.assertEqual(elem.tag, "manifest")
        self.assertEqual(elem.get("package", ns=None), "com.demo.app")
        self.assertEqual(elem.get("versionCode"), 42)
        self.assertEqual(elem.get("versionName"), "1.0.0")

    def test_boolean_attrs(self):
        root = Node("application", dict([
            android("debuggable", True),
            android("allowBackup", False),
        ]))
        elem = self._roundtrip(root)
        self.assertIs(elem.get("debuggable"), True)
        self.assertIs(elem.get("allowBackup"), False)

    def test_cdata_text_roundtrip(self):
        root = Node("network-security-config", children=[
            Node("domain-config", children=[
                Node("domain", dict([android("includeSubdomains", True)]),
                     text="legacy.example.com"),
            ]),
        ])
        elem = self._roundtrip(root)
        domain = elem.find("domain-config").find("domain")
        self.assertEqual(domain.text, "legacy.example.com")
        self.assertIs(domain.get("includeSubdomains"), True)

    def test_utf16_string_pool_decode(self):
        # 手工构造规范的 UTF-16 ResStringPool，覆盖非 UTF8 解码分支
        from apk_audit.axml import (
            AXMLParser, RES_XML_TYPE, RES_STRING_POOL_TYPE,
        )
        strings = ["ok", "ab", "hello"]
        offsets = []
        body = bytearray()
        for s in strings:
            offsets.append(len(body))
            body += len(s).to_bytes(2, "little") + s.encode("utf-16-le") + b"\x00\x00"
        while len(body) % 4:
            body += b"\x00"
        n = len(strings)
        ss = 28 + 4 * n
        total = ss + len(body)
        head = (
            struct.pack(
                "<HHIIIII", RES_STRING_POOL_TYPE, 28, total, n, 0, 0, ss
            ) + b"\x00" * 4
        )
        pool = head + b"".join(struct.pack("<I", o) for o in offsets) + bytes(body)
        doc = struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(pool)) + pool
        parser = AXMLParser(doc)
        parser.cur.pos = 16
        parser._parse_string_pool(total)
        self.assertEqual(parser.strings, strings)

    def test_nested_tree_and_namespace(self):
        root = Node("manifest", dict([attr(None, "package", "x")]), children=[
            Node("application", children=[
                Node("activity", dict([android("name", ".Main"),
                                       android("exported", True)])),
                Node("service", dict([android("name", ".Svc"),
                                      android("exported", False)])),
            ]),
        ])
        elem = self._roundtrip(root)
        app = elem.find("application")
        self.assertIsNotNone(app)
        kinds = {c.tag: c for c in app.children}
        self.assertIn("activity", kinds)
        self.assertIn("service", kinds)
        self.assertIs(kinds["activity"].get("exported"), True)
        self.assertIs(kinds["service"].get("exported"), False)

    def test_intent_filter_data_extraction(self):
        activity = Node("activity", dict([android("name", ".Deeplink")]), children=[
            Node("intent-filter", children=[
                Node("action", dict([android("name", "android.intent.action.VIEW")])),
                Node("data", dict([android("scheme", "https"),
                                   android("host", "example.com")])),
            ]),
        ])
        model = analyze_manifest(_wrap_manifest_with_app(activity))
        comp = model.components[0]
        f = comp.intent_filters[0]
        self.assertEqual(f.actions, ["android.intent.action.VIEW"])
        self.assertEqual(f.schemes, ["https"])
        self.assertEqual(f.hosts, ["example.com"])


def _wrap_manifest_with_app(app_child):
    """把单个组件节点包成合法 manifest 字节流供 ManifestAnalyzer 使用。"""
    app = Node("application", children=[app_child])
    manifest = Node("manifest", dict([
        attr(None, "package", "com.wrap"),
    ]), children=[
        Node("uses-sdk", dict([android("minSdkVersion", 26),
                               android("targetSdkVersion", 34)])),
        app,
    ])
    return AXMLWriter().write(manifest)


class TestExportedResolution(unittest.TestCase):
    def _analyze(self, target_sdk, components_xml, min_sdk=26):
        app = Node("application", children=components_xml)
        manifest = Node("manifest", dict([attr(None, "package", "p")]),
                        children=[
                            Node("uses-sdk", dict([
                                android("minSdkVersion", min_sdk),
                                android("targetSdkVersion", target_sdk),
                            ])),
                            app,
                        ])
        return analyze_manifest(AXMLWriter().write(manifest))

    def test_explicit_false(self):
        model = self._analyze(34, [
            Node("service", dict([android("name", ".S"),
                                  android("exported", False)]))
        ])
        self.assertFalse(model.components[0].effective_exported)

    def test_filter_implies_exported_legacy(self):
        # targetSdk<31 且含 filter、未声明 -> 历史默认导出
        model = self._analyze(28, [
            Node("receiver", dict([android("name", ".R")]), children=[
                Node("intent-filter", children=[
                    Node("action", dict([android("name", "x")])),
                ]),
            ]),
        ])
        self.assertTrue(model.components[0].effective_exported)

    def test_filter_requires_explicit_on_api31(self):
        model = self._analyze(34, [
            Node("activity", dict([android("name", ".A")]), children=[
                Node("intent-filter", children=[
                    Node("action", dict([android("name", "x")])),
                ]),
            ]),
        ])
        comp = model.components[0]
        self.assertFalse(comp.effective_exported)
        self.assertIn("targetSdk>=31", comp.exported_source)

    def test_provider_legacy_exported_min_sdk_below_17(self):
        model = self._analyze(16, [
            Node("provider", dict([android("name", ".P"),
                                   android("authorities", "p.prov")])),
        ], min_sdk=16)
        self.assertTrue(model.components[0].effective_exported)


class TestNetworkConfig(unittest.TestCase):
    def test_cleartext_and_user_ca_detected(self):
        root = Node("network-security-config", children=[
            Node("base-config", dict([android("cleartextTrafficPermitted", True)]),
                 children=[
                     Node("trust-anchors", children=[
                         Node("certificates", dict([android("src", "system")])),
                         Node("certificates", dict([android("src", "user")])),
                     ]),
                 ]),
        ])
        model = analyze_network_config(AXMLWriter().write(root))
        self.assertTrue(model.any_cleartext_permitted)
        self.assertTrue(model.base_trust_user_ca)

    def test_secure_config(self):
        root = Node("network-security-config", children=[
            Node("base-config", dict([android("cleartextTrafficPermitted", False)]),
                 children=[
                     Node("trust-anchors", children=[
                         Node("certificates", dict([android("src", "system")])),
                     ]),
                 ]),
        ])
        model = analyze_network_config(AXMLWriter().write(root))
        self.assertFalse(model.any_cleartext_permitted)
        self.assertFalse(model.any_user_ca_trusted)


class TestSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.cert = signer.prepare_keystore(
            os.path.join(os.path.dirname(__file__), "_keystore_tmp")
        )

    def _build_signed_apk(self, schemes):
        entries = {
            "AndroidManifest.xml": AXMLWriter().write(
                Node("manifest", dict([attr(None, "package", "sig.test")]))
            ),
            "classes.dex": b"dex\n035\x00" + b"\x00" * 100,
        }
        if "v1" in schemes:
            entries.update(signer.build_v1_meta(entries))
        zb = signer.ZipBuilder()
        for name, data in sorted(entries.items()):
            zb.add(name, data)
        apk = zb.build()
        if "v2" in schemes or "v3" in schemes:
            eocd = apk.rfind(struct.pack("<I", signer.EOCD_SIG))
            cd_off = struct.unpack_from("<I", apk, eocd + 16)[0]
            signer_block = signer.make_signer_block(apk[:cd_off], self.key)
            pairs = []
            if "v2" in schemes:
                pairs.append((signer.ALGO_ID_V2, signer_block))
            if "v3" in schemes:
                pairs.append((
                    signer.ALGO_ID_V3,
                    bf.struct_pack_sdk_range() + signer._lp(signer_block),
                ))
            apk = signer.insert_multi_scheme_block(apk, pairs)
        return apk

    def test_full_schemes_verify(self):
        import tempfile
        apk_bytes = self._build_signed_apk(("v1", "v2", "v3"))
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(apk_bytes)
            path = fh.name
        apk = APKFile.open(path)
        sigs = analyze_signatures(apk)
        self.assertTrue(sigs["v1"].present)
        self.assertTrue(sigs["v2"].present)
        self.assertTrue(sigs["v3"].present)
        self.assertIs(sigs["v1"].crypto_verified, True)
        self.assertIs(sigs["v2"].digest_matches_apk, True)
        self.assertIs(sigs["v3"].digest_matches_apk, True)
        os.unlink(path)

    def test_tampering_breaks_v2_digest(self):
        import tempfile
        apk_bytes = bytearray(self._build_signed_apk(("v2",)))
        # 篡改签名块之前的某个字节（classes.dex 区域，偏移 200）
        apk_bytes[200] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(apk_bytes)
            path = fh.name
        apk = APKFile.open(path)
        sigs = analyze_signatures(apk)
        self.assertIs(sigs["v2"].digest_matches_apk, False)
        os.unlink(path)

    def test_unsigned_apk(self):
        import tempfile
        apk_bytes = self._build_signed_apk(())
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(apk_bytes)
            path = fh.name
        result = audit_apk(path)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("SIG_NONE", rule_ids)
        os.unlink(path)


class TestRuleSeverity(unittest.TestCase):
    def test_debuggable_is_critical(self):
        result = audit_apk(
            _fixture_path("insecure-debug.apk")
        )
        dbg = [f for f in result.findings if f.rule_id == "MANIFEST_DEBUGGABLE"]
        self.assertTrue(dbg)
        self.assertEqual(dbg[0].severity, CRITICAL)

    def test_secure_apk_no_high_or_critical(self):
        result = audit_apk(_fixture_path("secure-release.apk"))
        bad = [f for f in result.findings if f.severity in (CRITICAL, HIGH)]
        self.assertEqual(bad, [])

    def test_launcher_activity_not_high(self):
        result = audit_apk(_fixture_path("secure-release.apk"))
        launcher = [f for f in result.findings
                    if f.rule_id == "COMP_EXPORTED_LAUNCHER"]
        self.assertTrue(launcher)
        self.assertEqual(launcher[0].severity, LOW)


def _fixture_path(name):
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests", "fixtures", name,
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
