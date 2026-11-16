"""Audit orchestration: open an APK, parse everything, run the rules."""

from __future__ import annotations

import os
from typing import Optional

from . import apkfile, arsc, binxml, manifest as manifest_mod, nsc as nsc_mod, risk, signature
from .report import AuditResult

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ARSC_BYTES = 64 * 1024 * 1024


class AuditError(RuntimeError):
    pass


def audit_apk(path: str) -> AuditResult:
    if not os.path.isfile(path):
        raise AuditError(f"file not found: {path}")
    errors: list[str] = []
    with apkfile.ApkFile(path) as apk:
        manifest_data = apk.read_entry_safe("AndroidManifest.xml", max_size=MAX_MANIFEST_BYTES)
        if manifest_data is None:
            raise AuditError("AndroidManifest.xml not found in APK")
        if manifest_data.lstrip()[:1] == b"<":
            raise AuditError(
                "AndroidManifest.xml is plain-text XML, not compiled binary XML. "
                "This is what a hand-edited or repackaged APK looks like; the platform "
                "would reject it. Rebuild the manifest with aapt2."
            )
        try:
            mf = manifest_mod.parse_manifest_bytes(manifest_data)
        except binxml.BinXmlError as exc:
            raise AuditError(
                "AndroidManifest.xml is not valid binary XML and could not be parsed: "
                f"{exc}"
            ) from exc

        res_table: Optional[arsc.ResourceTable] = None
        arsc_data = apk.read_entry_safe("resources.arsc", max_size=MAX_ARSC_BYTES)
        if arsc_data is not None:
            try:
                res_table = arsc.parse_arsc(arsc_data)
            except (arsc.ArscError, binxml.BinXmlError) as exc:
                errors.append(f"resources.arsc could not be parsed: {exc}")
        elif mf.network_security_config and mf.network_security_config.startswith("@"):
            errors.append("resources.arsc missing; resource references cannot be resolved")

        nsc_cfg = nsc_mod.load_nsc(apk, mf, res_table)
        policy = nsc_mod.compute_effective_policy(mf, nsc_cfg)

        try:
            sig_report = signature.analyze_signatures(apk)
        except (apkfile.ApkFormatError, signature.SignatureError) as exc:
            raise AuditError(f"APK signature analysis failed: {exc}") from exc

        findings: list[risk.Finding] = []
        findings.extend(risk.check_application(mf))
        findings.extend(risk.check_components(mf))
        findings.extend(risk.check_network(mf, policy))
        findings.extend(risk.check_signatures(sig_report, mf))
        findings.sort(key=lambda f: f.sort_key)

        entry_count = len(apk.entries)
        size = apk.size

    return AuditResult(
        path=path,
        manifest=mf,
        policy=policy,
        signatures=sig_report,
        findings=findings,
        apk_size=size,
        entry_count=entry_count,
        errors=errors,
    )
