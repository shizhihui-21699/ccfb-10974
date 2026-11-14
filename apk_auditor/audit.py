"""Top-level APK audit orchestration."""

from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .manifest_analysis import (
    Finding,
    INFO,
    ManifestInfo,
    NetSecConfig,
    analyze_network_security,
    analyze_risks,
    overall_level,
    parse_manifest,
    rating,
    score,
)
from .signing import SigCheck, analyze_v1, analyze_v2_v3, signing_block_segments


@dataclass
class AuditResult:
    apk_path: str
    file_size: int
    manifest: Optional[ManifestInfo]
    netsec: Optional[NetSecConfig]
    signatures: Dict[str, SigCheck]
    findings: List[Finding]
    parse_errors: List[str] = field(default_factory=list)

    @property
    def score_value(self) -> int:
        return score(self.findings)

    @property
    def rating_label(self) -> str:
        return rating(self.score_value)

    @property
    def worst_level(self) -> str:
        return overall_level(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apk": os.path.basename(self.apk_path),
            "file_size": self.file_size,
            "package": self.manifest.package if self.manifest else None,
            "version_name": self.manifest.version_name if self.manifest else None,
            "version_code": self.manifest.version_code if self.manifest else None,
            "sdk": {
                "minSdkVersion": self.manifest.min_sdk if self.manifest else None,
                "targetSdkVersion": self.manifest.target_sdk
                if self.manifest
                else None,
            },
            "application": _app_dict(self.manifest),
            "components": [_component_dict(c) for c in self.manifest.components]
            if self.manifest
            else [],
            "permissions": {
                "uses": self.manifest.uses_permissions if self.manifest else [],
                "custom": self.manifest.custom_permissions if self.manifest else [],
            },
            "network_security_config": _netsec_dict(self.netsec),
            "signatures": {
                scheme: _sig_dict(check)
                for scheme, check in self.signatures.items()
            },
            "risk": {
                "score": self.score_value,
                "rating": self.rating_label,
                "worst_level": self.worst_level,
                "findings": [_finding_dict(f) for f in self.findings],
            },
            "parse_errors": self.parse_errors,
        }


def _app_dict(manifest: Optional[ManifestInfo]) -> Dict[str, Any]:
    if manifest is None:
        return {}
    return {
        "debuggable": manifest.debuggable,
        "allowBackup": manifest.allow_backup,
        "testOnly": manifest.test_only,
        "usesCleartextTraffic": manifest.uses_cleartext,
        "networkSecurityConfig": manifest.network_security_config,
    }


def _component_dict(comp: Any) -> Dict[str, Any]:
    return {
        "kind": comp.kind,
        "name": comp.name,
        "exported": comp.exported,
        "implicit_export": comp.implicit_export,
        "has_intent_filter": comp.has_intent_filter,
        "permission": comp.permission,
        "enabled": comp.enabled,
        "intent_filters": comp.filters,
    }


def _netsec_dict(netsec: Optional[NetSecConfig]) -> Optional[Dict[str, Any]]:
    if netsec is None:
        return None
    return {
        "cleartextTrafficPermitted": netsec.cleartext_permitted,
        "trustUserCas": netsec.user_cas_trusted,
        "trustSystemCas": netsec.system_cas_trusted,
        "domainRules": netsec.domain_rules,
        "pinSets": netsec.pin_sets,
        "parse_error": netsec.parse_error,
    }


def _sig_dict(check: SigCheck) -> Dict[str, Any]:
    return {
        "present": check.present,
        "structural_ok": check.structural_ok,
        "verified": check.verified,
        "content_digest_match": check.digest_match,
        "algorithms": check.algorithms,
        "signers": check.signer_subjects,
        "weak_hash": check.weak_hash,
        "errors": check.errors,
        "details": check.details,
    }


def _finding_dict(f: Finding) -> Dict[str, Any]:
    return {
        "level": f.level,
        "rule_id": f.rule_id,
        "title": f.title,
        "detail": f.detail,
        "location": f.location,
        "recommendation": f.recommendation,
    }


def audit_apk(path: str) -> AuditResult:
    parse_errors: List[str] = []
    file_size = os.path.getsize(path)
    with open(path, "rb") as fh:
        raw = fh.read()

    manifest: Optional[ManifestInfo] = None
    netsec: Optional[NetSecConfig] = None
    findings: List[Finding] = []

    with zipfile.ZipFile(path, "r") as zf:
        if "AndroidManifest.xml" not in zf.namelist():
            raise ValueError(f"{path}: APK 内缺少 AndroidManifest.xml")
        try:
            _root, manifest = parse_manifest(zf.read("AndroidManifest.xml"))
        except Exception as exc:  # noqa: BLE001
            parse_errors.append(f"AndroidManifest 解析失败: {exc}")

        if manifest is not None:
            try:
                netsec = analyze_network_security(
                    zf, manifest.network_security_config
                )
            except Exception as exc:  # noqa: BLE001
                parse_errors.append(f"network_security_config 分析失败: {exc}")
            findings = analyze_risks(manifest, netsec)

        # Signatures -----------------------------------------------------
        sig_v1 = analyze_v1(zf)

    segments = signing_block_segments(raw)
    sig_v2_v3 = analyze_v2_v3(raw, segments)
    signatures = {"v1": sig_v1, **sig_v2_v3}
    findings.extend(_signature_findings(signatures))

    result = AuditResult(
        apk_path=path,
        file_size=file_size,
        manifest=manifest,
        netsec=netsec,
        signatures=signatures,
        findings=findings,
        parse_errors=parse_errors,
    )
    return result


def _signature_findings(
    signatures: Dict[str, SigCheck]
) -> List[Finding]:
    out: List[Finding] = []
    v1, v2, v3 = signatures["v1"], signatures["v2"], signatures["v3"]
    present = [s for s in ("v1", "v2", "v3") if signatures[s].present]
    if not present:
        out.append(
            Finding(
                level="CRITICAL",
                title="APK 未检测到任何签名 (v1/v2/v3 均缺失)",
                detail=(
                    "无签名 APK 无法在正常 Android 设备上安装，常见于被篡改后"
                    "剥离签名块的样本；来源不可信，禁止上架。"
                ),
                location="META-INF / APK Signing Block",
                recommendation="使用正式发布密钥通过 apksigner 重新签名。",
                rule_id="SIG-NONE",
            )
        )
        return out

    if not v2.present and not v3.present:
        out.append(
            Finding(
                level="HIGH",
                title="仅使用 v1 (JAR) 签名，缺少 v2/v3 签名方案",
                detail=(
                    "v1 签名存在已知缺陷（部分覆盖、易被 strip/注入攻击，"
                    "Android 7.0+ 优先验证 v2），且 Android 11+ targetSdk 30 "
                    "要求至少 v2。仅 v1 包在新系统上会被拒绝安装。"
                ),
                location="APK Signing Block",
                recommendation=(
                    "用 apksigner 启用 v2+v3 签名；保留 v1 仅用于兼容 Android 6 "
                    "及以下设备。"
                ),
                rule_id="SIG-NO-V2V3",
            )
        )
    elif v2.present and not v3.present:
        out.append(
            Finding(
                level=INFO,
                title="缺少 v3 签名（已有 v2）",
                detail=(
                    "v3 在 v2 基础上支持密钥轮换与 SDK 版本绑定，targetSdk 30+ "
                    "推荐启用；缺少 v3 不影响完整性校验强度。"
                ),
                location="APK Signing Block",
                recommendation="发布流水线增加 --v3-signing-enabled true。",
                rule_id="SIG-NO-V3",
            )
        )

    for scheme, check in signatures.items():
        if not check.present:
            continue
        if check.present and not check.structural_ok:
            out.append(
                Finding(
                    level="HIGH",
                    title=f"{scheme} 签名块结构损坏",
                    detail="; ".join(check.errors) or "签名块无法解析",
                    location="APK Signing Block",
                    recommendation="重新签名并核对打包流程是否破坏了签名块。",
                    rule_id=f"SIG-{scheme.upper()}-MALFORMED",
                )
            )
            continue
        if check.digest_match is False or (check.present and check.errors and not check.verified):
            out.append(
                Finding(
                    level="CRITICAL",
                    title=f"{scheme} 签名校验失败——APK 可能已被篡改",
                    detail="; ".join(check.errors) or "内容摘要或密码学验签未通过",
                    location="APK Signing Block",
                    recommendation=(
                        "隔离该样本并溯源；篡改后的 APK 不得安装或分发。"
                    ),
                    rule_id=f"SIG-{scheme.upper()}-VERIFY-FAIL",
                )
            )
        if check.weak_hash:
            out.append(
                Finding(
                    level="MEDIUM",
                    title=f"{scheme} 签名使用 SHA-1 弱哈希",
                    detail=(
                        "v1 清单中存在 SHA-1-Digest，SHA-1 已被实践证明可碰撞，"
                        "存在被构造同摘要恶意条目的风险。"
                    ),
                    location="META-INF",
                    recommendation="升级签名工具链，统一使用 SHA-256 及以上。",
                    rule_id="SIG-WEAK-HASH",
                )
            )

    if v1.present and v2.present and v3.present:
        # All three schemes present; any verification failure is already
        # emitted above as its own CRITICAL finding.
        pass
    return out
