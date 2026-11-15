"""审计编排：把 APK 容器、Manifest、网络配置、签名、规则引擎串起来。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .apkfile import APKFile
from .manifest import ManifestModel, analyze_manifest
from .netconfig import NetworkSecurityModel, analyze_network_config
from .rules import Finding, RuleEngine, score_findings
from .signatures import analyze_signatures

MANIFEST_PATH = "AndroidManifest.xml"
NET_CONFIG_PREFIX = "res/xml/"


@dataclass
class AuditResult:
    apk_path: str
    ok: bool
    error: str | None
    manifest: ManifestModel | None = None
    network_config: NetworkSecurityModel | None = None
    network_config_path: str | None = None
    signatures: dict | None = None
    findings: list[Finding] = field(default_factory=list)
    score: dict | None = None

    def to_dict(self) -> dict:
        return {
            "apk_path": self.apk_path,
            "ok": self.ok,
            "error": self.error,
            "manifest": _manifest_dict(self.manifest) if self.manifest else None,
            "network_config": asdict(self.network_config)
            if self.network_config
            else None,
            "network_config_path": self.network_config_path,
            "signatures": _signatures_dict(self.signatures) if self.signatures else None,
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score,
        }


def _manifest_dict(m: ManifestModel) -> dict:
    return {
        "package": m.package,
        "version_name": m.version_name,
        "version_code": m.version_code,
        "shared_user_id": m.shared_user_id,
        "min_sdk": m.min_sdk,
        "target_sdk": m.target_sdk,
        "max_sdk": m.max_sdk,
        "app_flags": m.app_flags,
        "network_security_config": m.network_security_config,
        "uses_permissions": m.uses_permissions,
        "uses_permissions_sdk23": m.uses_permissions_sdk23,
        "custom_permissions": [asdict(p) for p in m.custom_permissions],
        "components": [
            {
                "kind": c.kind,
                "name": c.name,
                "exported_attr": c.exported,
                "effective_exported": c.effective_exported,
                "exported_source": c.exported_source,
                "permission": c.permission,
                "read_permission": c.read_permission,
                "write_permission": c.write_permission,
                "enabled": c.enabled,
                "grant_uri_permissions": c.grant_uri_permissions,
                "intent_filters": [asdict(f) for f in c.intent_filters],
            }
            for c in m.components
        ],
    }


def _signatures_dict(sigs: dict) -> dict:
    out = {}
    for name, val in sigs.items():
        d = asdict(val)
        out[name] = d
    return out


def audit_apk(path: str) -> AuditResult:
    result = AuditResult(apk_path=path, ok=False, error=None)
    try:
        apk = APKFile.open(path)
    except (OSError, Exception) as exc:  # noqa: BLE001 - 顶层兜底，写进报告
        result.error = f"打开/解析 APK 失败：{exc}"
        return result

    try:
        if not apk.has(MANIFEST_PATH):
            result.error = "APK 内找不到 AndroidManifest.xml"
            return result
        manifest = analyze_manifest(apk.read(MANIFEST_PATH))
        result.manifest = manifest

        # network_security_config：manifest 指向的路径，缺省兜底常见位置
        nc_path = manifest.network_security_config
        candidates = []
        if nc_path:
            ref = str(nc_path)
            candidates.append(ref[1:] if ref.startswith("@") else ref)
        candidates.append(f"{NET_CONFIG_PREFIX}network_security_config.xml")
        for cand in candidates:
            if apk.has(cand):
                try:
                    result.network_config = analyze_network_config(apk.read(cand))
                    result.network_config_path = cand
                except (ValueError, Exception) as exc:  # noqa: BLE001
                    result.network_config_path = cand
                    result.findings.append(Finding(
                        "NETCONFIG_PARSE_FAIL", "HIGH",
                        "network_security_config 解析失败",
                        f"文件 {cand} 无法解析：{exc}",
                    ))
                break

        result.signatures = analyze_signatures(apk)
        result.findings = RuleEngine(
            manifest, result.network_config, result.signatures
        ).evaluate()
        result.score = score_findings(result.findings)
        result.ok = True
    except Exception as exc:  # noqa: BLE001
        result.error = f"审计过程异常：{type(exc).__name__}: {exc}"
    return result
