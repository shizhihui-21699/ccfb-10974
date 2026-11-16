"""Report rendering: human-readable text, JSON and Markdown."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from . import manifest as manifest_mod, risk as risk_mod, signature as sig_mod
from .nsc import EffectivePolicy

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

ANSI = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;36m",
    "info": "\033[1;90m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


@dataclass
class AuditResult:
    path: str
    manifest: manifest_mod.Manifest
    policy: EffectivePolicy
    signatures: sig_mod.SignatureReport
    findings: list[risk_mod.Finding]
    apk_size: int = 0
    entry_count: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def raw_score(self) -> float:
        """Unclamped point total (exposed in JSON for trend tracking)."""
        per_rule: dict[str, list[str]] = {}
        for f in self.findings:
            per_rule.setdefault(f.rule_id, []).append(f.severity)
        total = 0.0
        for severities in per_rule.values():
            weight = risk_mod.SEVERITY_WEIGHT[severities[0]]
            multiplier = min(
                risk_mod.MAX_REPEAT_MULTIPLIER,
                1 + risk_mod.REPEAT_FACTOR * (len(severities) - 1),
            )
            total += weight * multiplier
        return total

    @property
    def score(self) -> int:
        """0-100 risk score; higher means riskier."""
        return int(min(100, round(self.raw_score)))

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 70:
            grade = "F"
        elif score >= 50:
            grade = "D"
        elif score >= 30:
            grade = "C"
        elif score >= 12:
            grade = "B"
        else:
            grade = "A"
        # A single severe finding must not be averaged away by a large number
        # of harmless ones: the worst severity present bounds the grade.
        order = risk_mod.SEVERITY_ORDER
        worst = min(
            (order.index(f.severity) for f in self.findings), default=len(order) - 1
        )
        ceiling = {
            order.index("critical"): "D",
            order.index("high"): "C",
            order.index("medium"): "C",
            order.index("low"): "B",
        }.get(worst)
        if ceiling is not None:
            grades = ["A", "B", "C", "D", "F"]
            if grades.index(grade) < grades.index(ceiling):
                grade = ceiling
        return grade

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in risk_mod.SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def to_dict(self) -> dict:
        m = self.manifest
        counts = self.counts()
        return {
            "file": self.path,
            "apk_size": self.apk_size,
            "entry_count": self.entry_count,
            "risk_score": self.score,
            "raw_score": round(self.raw_score, 1),
            "grade": self.grade,
            "severity_counts": counts,
            "package": {
                "name": m.package,
                "version_name": m.version_name,
                "version_code": m.version_code,
                "min_sdk": m.min_sdk,
                "target_sdk": m.target_sdk,
                "max_sdk": m.max_sdk,
                "shared_user_id": m.shared_user_id,
                "label": m.app_label,
            },
            "application": {
                "debuggable": m.debuggable,
                "allow_backup": m.allow_backup,
                "uses_cleartext_traffic": m.uses_cleartext_traffic,
                "network_security_config": m.network_security_config,
                "test_only": m.test_only,
                "extract_native_libs": m.extract_native_libs,
                "request_legacy_storage": m.request_legacy_storage,
            },
            "network": {
                "cleartext_allowed": self.policy.cleartext_global,
                "cleartext_source": self.policy.cleartext_source,
                "trusts_user_cas": self.policy.trusts_user_cas,
                "user_ca_source": self.policy.user_ca_source,
                "config_path": self.policy.nsc.path,
                "config_resolved_via": self.policy.nsc.resolved_via,
                "config_error": self.policy.nsc.parse_error,
                "cleartext_domains": [
                    d.domain for d in self.policy.nsc.domains_allowing_cleartext()
                ],
                "user_ca_domains": [
                    d.domain for d in self.policy.nsc.domains_trusting_user_certs()
                ],
            },
            "permissions": [
                {"name": name, "max_sdk": max_sdk}
                for name, max_sdk in m.uses_permissions
            ],
            "declared_permissions": [
                {
                    "name": p.name,
                    "protection_level": p.protection_level,
                    "flags": p.protection_flags,
                }
                for p in m.declared_permissions
            ],
            "components": [
                {
                    "kind": c.kind,
                    "name": c.name,
                    "exported": c.is_exported,
                    "exported_explicit": c.exported is not None,
                    "permission": c.permission,
                    "read_permission": c.read_permission,
                    "write_permission": c.write_permission,
                    "authorities": c.authorities,
                    "intent_filters": [
                        {
                            "actions": f.actions,
                            "categories": f.categories,
                            "data": f.data,
                        }
                        for f in c.intent_filters
                    ],
                }
                for c in m.components
            ],
            "signatures": {
                "schemes": [f"v{s}" for s in self.signatures.schemes_present()],
                "v1": self._scheme_dict(self.signatures.v1),
                "v2": self._scheme_dict(self.signatures.v2),
                "v3": self._scheme_dict(self.signatures.v3),
                "v3.1": self._scheme_dict(self.signatures.v31),
                "errors": self.signatures.errors,
            },
            "findings": [f.to_dict() for f in self.findings],
            "manifest_warnings": m.warnings,
            "errors": self.errors,
        }

    @staticmethod
    def _scheme_dict(res: Optional[sig_mod.SchemeResult]) -> dict:
        if res is None:
            return {"present": False}
        return {
            "present": res.present,
            "verified": res.verified,
            "signers": [
                {
                    "verified": s.verified,
                    "certificates": [c.summary() for c in s.certificates],
                    "algorithms": [
                        sig_mod.SIG_ALG_NAMES.get(a, f"0x{a:04x}")
                        for a in s.signature_algorithms
                    ],
                    "errors": s.errors,
                    "warnings": s.warnings,
                }
                for s in res.signers
            ],
            "errors": res.errors,
            "warnings": res.warnings,
        }


def _nsc_display(result: AuditResult) -> Optional[str]:
    """Show the resolved file for a network security config reference."""
    ref = result.manifest.network_security_config
    if not ref:
        return None
    nsc_cfg = result.policy.nsc
    if nsc_cfg.path:
        return f"{nsc_cfg.path}  ({nsc_cfg.resolved_via or ref})"
    if nsc_cfg.found and nsc_cfg.resolved_via:
        return f"{nsc_cfg.resolved_via}  <unresolved>"
    return ref


def render_text(result: AuditResult, color: bool = False) -> str:
    def c(sev: str, text: str) -> str:
        if not color:
            return text
        return f"{ANSI.get(sev, '')}{text}{ANSI['reset']}"

    def badge(sev: str) -> str:
        return c(sev, f"[{SEVERITY_LABEL[sev]}]")

    m = result.manifest
    lines: list[str] = []
    lines.append(c("bold", "=" * 78))
    lines.append(c("bold", f" APK 安全审计报告  {result.path}"))
    lines.append(c("bold", "=" * 78))
    counts = result.counts()
    summary = "  ".join(
        badge(s) + str(counts[s]) for s in risk_mod.SEVERITY_ORDER if counts[s]
    )
    if not summary:
        summary = badge("info") + " 0"
    lines.append(f"风险评分: {result.score}/100   等级: {result.grade}    {summary}")
    lines.append(
        f"文件大小: {result.apk_size / 1024:.0f} KiB   条目数: {result.entry_count}"
    )
    if result.errors:
        lines.append("")
        lines.append(c("high", "审计过程中出现错误:"))
        for e in result.errors:
            lines.append(f"  ! {e}")

    lines.append("")
    lines.append(c("bold", "─" * 78))
    lines.append(c("bold", " 基本信息"))
    lines.append(c("bold", "─" * 78))
    lines.append(f"  package        : {m.package or '<missing>'}")
    lines.append(f"  version        : {m.version_name or '?'} ({m.version_code if m.version_code is not None else '?'})")
    lines.append(f"  SDK            : min={m.min_sdk} target={m.target_sdk} max={m.max_sdk}")
    if m.shared_user_id:
        lines.append(f"  sharedUserId   : {m.shared_user_id}")

    lines.append("")
    lines.append(c("bold", "─" * 78))
    lines.append(c("bold", " 应用级配置"))
    lines.append(c("bold", "─" * 78))

    def tri(value: Optional[bool]) -> str:
        if value is None:
            return "未声明"
        return "true" if value else "false"

    for label, value, sev in (
        ("debuggable", m.debuggable, "critical" if m.debuggable else "info"),
        ("allowBackup", m.allow_backup, "medium" if m.allow_backup else "info"),
        ("usesCleartextTraffic", m.uses_cleartext_traffic, "high" if m.uses_cleartext_traffic else "info"),
        ("testOnly", m.test_only, "medium" if m.test_only else "info"),
        ("networkSecurityConfig", _nsc_display(result), "info"),
        ("fullBackupContent", m.full_backup_content, "info"),
        ("dataExtractionRules", m.data_extraction_rules, "info"),
    ):
        text = tri(value) if isinstance(value, (bool, type(None))) else str(value)
        marker = "  " if sev == "info" else c(sev, "* ")
        lines.append(f" {marker}{label:<24}: {text}")

    lines.append("")
    lines.append(c("bold", "─" * 78))
    lines.append(c("bold", " 网络安全配置"))
    lines.append(c("bold", "─" * 78))
    p = result.policy
    lines.append(
        f"  明文流量全局允许: {'是' if p.cleartext_global else '否'}  ({p.cleartext_source})"
    )
    lines.append(
        f"  信任用户 CA     : {'是' if p.trusts_user_cas else '否'}  ({p.user_ca_source})"
    )
    if p.nsc.found:
        lines.append(f"  配置文件        : {p.nsc.path or '<unresolved>'}  (via {p.nsc.resolved_via})")
        if p.nsc.parse_error:
            lines.append(f"  解析错误        : {p.nsc.parse_error}")
        if p.nsc.base_pins:
            lines.append(f"  固定证书(pin)   : {len(p.nsc.base_pins)} 个")
        for d in p.nsc.domains:
            bits = [f"domain={d.domain}"]
            if d.cleartext is not None:
                bits.append(("明文允许" if d.cleartext else "禁止明文"))
            if d.trust is not None:
                srcs = [s for s, v in (("system", d.trust.system), ("user", d.trust.user)) if v]
                if d.trust.bundled:
                    srcs.append(f"bundled×{len(d.trust.bundled)}")
                bits.append("trust=" + ",".join(srcs))
            if d.pins:
                bits.append(f"pins×{len(d.pins)}")
            lines.append("    · " + "  ".join(bits))
        for w in p.nsc.warnings:
            lines.append(f"    ! {w}")
    else:
        lines.append("  未配置 network_security_config（使用平台默认）")

    lines.append("")
    lines.append(c("bold", "─" * 78))
    lines.append(c("bold", " 签名"))
    lines.append(c("bold", "─" * 78))
    sig = result.signatures
    lines.append(
        "  方案: "
        + (", ".join(f"v{s}" for s in sig.schemes_present()) or "无")
    )
    for label, res in (
        ("v1", sig.v1),
        ("v2", sig.v2),
        ("v3", sig.v3),
        ("v3.1", sig.v31),
    ):
        if res is None or not res.present:
            continue
        state = c("info", "通过") if res.verified else c("critical", "失败")
        lines.append(f"  {label:<5}: 存在, 校验{state}")
        for signer in res.signers:
            for cert in signer.certificates:
                lines.append(f"         证书: {cert.subject}")
                lines.append(
                    f"               有效期 {cert.not_before.date() if cert.not_before else '?'} ~ "
                    f"{cert.not_after.date() if cert.not_after else '?'}"
                    + ("  (已过期)" if cert.expired else "")
                )
                lines.append(f"               公钥 {cert.public_key.description}  SHA-256 {cert.sha256[:32]}…")
            if signer.signature_algorithms:
                names = [sig_mod.SIG_ALG_NAMES.get(a, f"0x{a:04x}") for a in signer.signature_algorithms]
                lines.append(f"         算法: {', '.join(names)}")
        for e in res.errors:
            lines.append(c("critical", f"         错误: {e}"))

    lines.append("")
    lines.append(c("bold", "─" * 78))
    lines.append(c("bold", f" 权限（{len(m.uses_permissions)} 个申请, {len(m.declared_permissions)} 个自定义）"))
    lines.append(c("bold", "─" * 78))
    for name, max_sdk in m.uses_permissions:
        risky = (
            name in manifest_mod.HIGH_RISK_PERMISSIONS
            or name in manifest_mod.DANGEROUS_PERMISSIONS
        )
        suffix = f"  (maxSdk={max_sdk})" if max_sdk is not None else ""
        prefix = c("medium", "* ") if risky else "  "
        lines.append(f" {prefix}{name}{suffix}")
    for decl in m.declared_permissions:
        lines.append(
            f"  [自定义] {decl.name}  protectionLevel={decl.protection_level}"
            + (f" flags={decl.protection_flags}" if decl.protection_flags else "")
        )

    lines.append("")
    lines.append(c("bold", "─" * 78))
    exported = [comp for comp in m.components if comp.is_exported]
    lines.append(c("bold", f" 组件（共 {len(m.components)} 个，导出 {len(exported)} 个）"))
    lines.append(c("bold", "─" * 78))
    icon = {
        "activity": "A",
        "activity-alias": "a",
        "service": "S",
        "receiver": "R",
        "provider": "P",
    }
    for comp in sorted(m.components, key=lambda x: (not x.is_exported, x.kind, x.name)):
        flag = c("high", "导出") if comp.is_exported else c("info", "内部")
        guard = f" perm={comp.permission}" if comp.permission else ""
        lines.append(f"  [{icon.get(comp.kind, '?')}] {flag} {comp.name}{guard}")
        if comp.authorities:
            lines.append(f"      authorities: {';'.join(comp.authorities)}")
        for flt in comp.intent_filters:
            lines.append(f"      filter: {flt.describe()}")

    lines.append("")
    lines.append(c("bold", "─" * 78))
    lines.append(c("bold", f" 风险发现（{len(result.findings)} 条）"))
    lines.append(c("bold", "─" * 78))
    if not result.findings:
        lines.append("  未发现风险项。")
    for i, f in enumerate(result.findings, 1):
        lines.append("")
        lines.append(f" {badge(f.severity)} {i}. {f.title}")
        lines.append(f"    规则: {f.rule_id}" + (f"   组件: {f.component}" if f.component else ""))
        for ln in f.detail.splitlines():
            lines.append(f"    {ln}")
        if f.evidence:
            lines.append(c("dim", "    证据:"))
            for ev in f.evidence[:8]:
                lines.append(c("dim", f"      - {ev}"))
        if f.remediation:
            lines.append(f"    建议: {f.remediation}")
    lines.append("")
    return "\n".join(lines)


def render_json(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def render_markdown(result: AuditResult) -> str:
    m = result.manifest
    counts = result.counts()
    lines = [
        "# APK 安全审计报告",
        "",
        f"- 文件：`{result.path}`",
        f"- 包名：`{m.package}`",
        f"- 版本：{m.version_name} ({m.version_code})",
        f"- 风险评分：**{result.score}/100**（等级 {result.grade}）",
        "- 统计："
        + "，".join(
            f"{SEVERITY_LABEL[s]} {counts[s]}" for s in risk_mod.SEVERITY_ORDER if counts[s]
        ),
        "",
        "## 概览",
        "",
        "| 项 | 值 |",
        "| --- | --- |",
        f"| minSdk / targetSdk | {m.min_sdk} / {m.target_sdk} |",
        f"| debuggable | {m.debuggable} |",
        f"| allowBackup | {m.allow_backup} |",
        f"| 明文流量 | {'允许' if result.policy.cleartext_global else '禁止'}（{result.policy.cleartext_source}） |",
        f"| 信任用户 CA | {'是' if result.policy.trusts_user_cas else '否'}（{result.policy.user_ca_source}） |",
        f"| 签名方案 | {', '.join(f'v{s}' for s in result.signatures.schemes_present()) or '无'} |",
        "",
        "## 风险发现",
        "",
    ]
    for f in result.findings:
        lines.append(f"### [{SEVERITY_LABEL[f.severity]}] {f.title}")
        lines.append("")
        lines.append(f"- 规则：`{f.rule_id}`")
        if f.component:
            lines.append(f"- 组件：`{f.component}`")
        lines.append("")
        lines.append(f.detail)
        if f.evidence:
            lines.append("")
            lines.append("证据：")
            lines.append("")
            for ev in f.evidence:
                lines.append(f"- `{ev}`")
        if f.remediation:
            lines.append("")
            lines.append(f"**建议**：{f.remediation}")
        lines.append("")
    return "\n".join(lines)
