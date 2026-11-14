"""Tests for manifest risk classification and network security config."""

from __future__ import annotations

import io
import os
import sys
import unittest
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apk_auditor.axml import AxmlAttribute, AxmlNode  # noqa: E402
from apk_auditor.axml_writer import ANDROID_NS, AxmlWriter  # noqa: E402
from apk_auditor.manifest_analysis import (  # noqa: E402
    CRITICAL,
    HIGH,
    MEDIUM,
    INFO,
    analyze_network_security,
    analyze_risks,
    parse_manifest,
)


def _attr(name: str, value, rid: int | None = None) -> AxmlAttribute:
    from apk_auditor.axml import (
        TYPE_INT_BOOLEAN,
        TYPE_INT_DEC,
        TYPE_STRING,
    )

    if isinstance(value, bool):
        dtype, raw = TYPE_INT_BOOLEAN, None
    elif isinstance(value, int):
        dtype, raw = TYPE_INT_DEC, None
    else:
        dtype, raw = TYPE_STRING, str(value)
    return AxmlAttribute(ANDROID_NS, name, name, value, raw, dtype, "", rid)


def _node(tag: str, attrs: dict | None = None, children: list | None = None,
          text: str | None = None) -> AxmlNode:
    n = AxmlNode(tag, None)
    for k, v in (attrs or {}).items():
        n.attributes[k] = _attr(k, v)
    n.children = children or []
    n.text = text
    return n


def _build_manifest(app_attrs: dict, components: list, target: int = 34,
                    min_sdk: int = 24) -> bytes:
    root = _node(
        "manifest",
        {"package": "com.rule.test", "versionName": "1.0", "versionCode": 1},
        [
            _node("uses-sdk", {"minSdkVersion": min_sdk, "targetSdkVersion": target}),
            _node("application", app_attrs, components),
        ],
    )
    return AxmlWriter().write(root)


def _rule_ids(findings) -> set:
    return {f.rule_id for f in findings}


class ApplicationFlagTests(unittest.TestCase):
    def test_debuggable_and_testonly_are_high(self) -> None:
        blob = _build_manifest(
            {"debuggable": True, "testOnly": True, "allowBackup": False}, []
        )
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        ids = _rule_ids(findings)
        self.assertIn("MANIFEST-DEBUGGABLE", ids)
        self.assertIn("MANIFEST-TESTONLY", ids)
        self.assertTrue(
            all(f.level == HIGH for f in findings
                if f.rule_id in ("MANIFEST-DEBUGGABLE", "MANIFEST-TESTONLY"))
        )

    def test_allow_backup_explicit_true_is_medium(self) -> None:
        blob = _build_manifest({"allowBackup": True}, [])
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        rule = next(f for f in findings if f.rule_id == "MANIFEST-ALLOWBACKUP")
        self.assertEqual(rule.level, MEDIUM)

    def test_allow_backup_default_info_on_old_target(self) -> None:
        blob = _build_manifest({}, [], target=28)
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        self.assertIn("MANIFEST-ALLOWBACKUP-DEFAULT", _rule_ids(findings))

    def test_cleartext_flag_is_medium(self) -> None:
        blob = _build_manifest({"usesCleartextTraffic": True}, [])
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        self.assertIn("MANIFEST-CLEARTEXT", _rule_ids(findings))


class ComponentTests(unittest.TestCase):
    def test_unguarded_exported_service_is_high(self) -> None:
        svc = _node("service", {"name": "com.x.Svc", "exported": True})
        blob = _build_manifest({}, [svc])
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        rule = next(f for f in findings if f.rule_id == "COMP-SERVICE-EXPORT")
        self.assertEqual(rule.level, HIGH)

    def test_deeplink_activity_is_high(self) -> None:
        activity = _node(
            "activity",
            {"name": "com.x.Link", "exported": True},
            [
                _node(
                    "intent-filter",
                    {},
                    [
                        _node("action", {"name": "android.intent.action.VIEW"}),
                        _node("data", {"scheme": "https", "host": "x.com"}),
                    ],
                )
            ],
        )
        blob = _build_manifest({}, [activity])
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        self.assertIn("COMP-ACTIVITY-DEEPLINK", _rule_ids(findings))

    def test_plain_launcher_activity_is_info(self) -> None:
        activity = _node(
            "activity",
            {"name": "com.x.Main", "exported": True},
            [
                _node(
                    "intent-filter",
                    {},
                    [
                        _node("action", {"name": "android.intent.action.MAIN"}),
                        _node(
                            "category",
                            {"name": "android.intent.category.LAUNCHER"},
                        ),
                    ],
                )
            ],
        )
        blob = _build_manifest({}, [activity])
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        rule = next(f for f in findings if f.rule_id == "COMP-LAUNCHER")
        self.assertEqual(rule.level, INFO)

    def test_implicit_export_on_modern_target_is_flagged(self) -> None:
        # No exported attr but has an intent-filter, targetSdk 34.
        receiver = _node(
            "receiver",
            {"name": "com.x.Recv"},
            [_node("intent-filter", {},
                   [_node("action", {"name": "com.x.PING"})])],
        )
        blob = _build_manifest({}, [receiver], target=34)
        _, info = parse_manifest(blob)
        comp = info.components[0]
        self.assertTrue(comp.implicit_export)
        findings = analyze_risks(info, None)
        self.assertIn("COMP-IMPLICIT-EXPORT", _rule_ids(findings))

    def test_exported_provider_with_grant_uri(self) -> None:
        provider = _node(
            "provider",
            {
                "name": "com.x.Prov",
                "exported": True,
                "authorities": "com.x.prov",
                "grantUriPermissions": True,
            },
        )
        blob = _build_manifest({}, [provider])
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        rule = next(f for f in findings if f.rule_id == "COMP-PROVIDER-EXPORT")
        self.assertEqual(rule.level, HIGH)
        self.assertIn("grantUriPermissions", rule.detail)


class NetworkSecurityTests(unittest.TestCase):
    def _zip_with_nsc(self, nsc_root: AxmlNode) -> zipfile.ZipFile:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("res/xml/nsc.xml", AxmlWriter().write(nsc_root))
        buf.seek(0)
        return zipfile.ZipFile(buf, "r")

    def test_user_ca_is_high_and_cleartext_medium(self) -> None:
        root = _node(
            "network-security-config",
            {},
            [
                _node(
                    "base-config",
                    {"cleartextTrafficPermitted": True},
                    [
                        _node(
                            "trust-anchors",
                            {},
                            [
                                _node("certificates", {"src": "system"}),
                                _node("certificates", {"src": "user"}),
                            ],
                        )
                    ],
                )
            ],
        )
        zf = self._zip_with_nsc(root)
        ns = analyze_network_security(zf, None)
        self.assertTrue(ns.user_cas_trusted)
        self.assertTrue(ns.cleartext_permitted)
        ids = _rule_ids(ns.findings)
        self.assertIn("NSC-USER-CA", ids)
        self.assertIn("NSC-CLEARTEXT", ids)
        levels = {f.rule_id: f.level for f in ns.findings}
        self.assertEqual(levels["NSC-USER-CA"], HIGH)
        self.assertEqual(levels["NSC-CLEARTEXT"], MEDIUM)

    def test_hardened_config_has_no_ca_or_cleartext_findings(self) -> None:
        root = _node(
            "network-security-config",
            {},
            [
                _node(
                    "base-config",
                    {"cleartextTrafficPermitted": False},
                    [_node("trust-anchors", {},
                           [_node("certificates", {"src": "system"})])],
                )
            ],
        )
        zf = self._zip_with_nsc(root)
        ns = analyze_network_security(zf, None)
        ids = _rule_ids(ns.findings)
        self.assertNotIn("NSC-USER-CA", ids)
        self.assertNotIn("NSC-CLEARTEXT", ids)


class CustomPermissionTests(unittest.TestCase):
    def test_normal_protection_level_is_medium(self) -> None:
        root = _node(
            "manifest",
            {"package": "com.p"},
            [
                _node("application", {}, []),
                _node("permission", {
                    "name": "com.p.WEAK",
                    "protectionLevel": "normal",
                }),
            ],
        )
        blob = AxmlWriter().write(root)
        _, info = parse_manifest(blob)
        findings = analyze_risks(info, None)
        self.assertIn("PERM-CUSTOM-WEAK", _rule_ids(findings))


if __name__ == "__main__":
    unittest.main()
