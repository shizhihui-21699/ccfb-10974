"""End-to-end audit tests against the four synthetic sample APKs.

Rebuilds the samples first so the suite is self-contained. Run from root:
    python3 -I -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "samples")):
    if p not in sys.path:
        sys.path.insert(0, p)

from apk_auditor.audit import audit_apk  # noqa: E402

APK_DIR = os.path.join(_ROOT, "samples", "apks")


def _build_samples_once() -> None:
    subprocess.run(
        [sys.executable, "-I",
         os.path.join(_ROOT, "samples", "generator", "build_samples.py")],
        cwd=_ROOT,
        check=True,
        capture_output=True,
    )


class SampleAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _build_samples_once()

    def _audit(self, name: str):
        return audit_apk(os.path.join(APK_DIR, name))

    def test_good_app_is_clean(self) -> None:
        r = self._audit("good-app.apk")
        self.assertIsNone(r.manifest.debuggable) if False else None
        self.assertFalse(r.manifest.debuggable)
        self.assertFalse(r.manifest.allow_backup)
        for scheme in ("v1", "v2", "v3"):
            check = r.signatures[scheme]
            self.assertTrue(check.present)
            self.assertTrue(check.verified, f"{scheme}: {check.errors}")
            self.assertTrue(check.digest_match, f"{scheme}: {check.errors}")
        # Only INFO-level launcher finding expected.
        self.assertTrue(
            all(f.level == "INFO" for f in r.findings),
            [f"{f.level}:{f.rule_id}" for f in r.findings],
        )

    def test_insecure_app_triggers_all_major_rules(self) -> None:
        r = self._audit("insecure-app.apk")
        ids = {f.rule_id for f in r.findings}
        for expected in (
            "MANIFEST-DEBUGGABLE",
            "MANIFEST-TESTONLY",
            "MANIFEST-ALLOWBACKUP",
            "MANIFEST-CLEARTEXT",
            "NSC-USER-CA",
            "NSC-CLEARTEXT",
            "COMP-ACTIVITY-DEEPLINK",
            "COMP-SERVICE-EXPORT",
            "COMP-RECEIVER-EXPORT",
            "COMP-PROVIDER-EXPORT",
            "PERM-CUSTOM-WEAK",
        ):
            self.assertIn(expected, ids)
        self.assertEqual(r.rating_label, "高危")
        self.assertGreaterEqual(r.score_value, 60)

    def test_legacy_v1_sha1(self) -> None:
        r = self._audit("legacy-v1-sha1-app.apk")
        ids = {f.rule_id for f in r.findings}
        self.assertTrue(r.signatures["v1"].present)
        self.assertTrue(r.signatures["v1"].weak_hash)
        self.assertFalse(r.signatures["v2"].present)
        self.assertIn("SIG-NO-V2V3", ids)
        self.assertIn("SIG-WEAK-HASH", ids)

    def test_tampered_app_is_critical(self) -> None:
        r = self._audit("tampered-app.apk")
        verify_rules = {
            f.rule_id for f in r.findings if f.rule_id.endswith("VERIFY-FAIL")
        }
        self.assertIn("SIG-V1-VERIFY-FAIL", verify_rules)
        self.assertIn("SIG-V2-VERIFY-FAIL", verify_rules)
        self.assertIn("SIG-V3-VERIFY-FAIL", verify_rules)
        self.assertTrue(
            any(f.level == "CRITICAL" for f in r.findings),
            "tampered APK must produce a CRITICAL finding",
        )

    def test_json_report_is_serializable(self) -> None:
        import json

        r = self._audit("insecure-app.apk")
        payload = json.loads(json.dumps(r.to_dict(), ensure_ascii=False))
        self.assertEqual(payload["package"], "com.example.insecure")
        self.assertIn("risk", payload)
        self.assertIn("signatures", payload)


if __name__ == "__main__":
    unittest.main()
