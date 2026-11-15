"""终端文本报告渲染（带 ANSI 颜色，可 --no-color 关闭）。"""

from __future__ import annotations

from .auditor import AuditResult
from .rules import CRITICAL, HIGH, MEDIUM, LOW, INFO

_COLORS = {
    CRITICAL: "\033[1;41m",  # 红底加粗
    HIGH: "\033[1;31m",      # 亮红
    MEDIUM: "\033[33m",      # 黄
    LOW: "\033[36m",         # 青
    INFO: "\033[2;37m",      # 灰
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


class Renderer:
    def __init__(self, color: bool = True):
        self.color = color

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.color else text

    def _sev(self, sev: str) -> str:
        return self._c(f"{sev:<8}", _COLORS.get(sev, ""))

    def render(self, r: AuditResult) -> str:
        lines: list[str] = []
        lines.append(self._c("=" * 78, _BOLD))
        lines.append(self._c(f"APK 静态审计报告：{r.apk_path}", _BOLD))
        lines.append(self._c("=" * 78, _BOLD))

        if not r.ok:
            lines.append(self._c(f"[错误] {r.error}", _COLORS[HIGH]))
            return "\n".join(lines)

        self._section_manifest(r, lines)
        self._section_components(r, lines)
        self._section_permissions(r, lines)
        self._section_network(r, lines)
        self._section_signatures(r, lines)
        self._section_findings(r, lines)
        self._section_score(r, lines)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def _section_manifest(self, r: AuditResult, lines: list[str]):
        m = r.manifest
        lines.append(self._c("\n■ 基础信息", _BOLD))
        lines.append(f"  包名            : {m.package}")
        lines.append(
            f"  版本            : {m.version_name} (code={m.version_code})"
        )
        lines.append(
            f"  SDK             : min={m.min_sdk} target={m.target_sdk} max={m.max_sdk}"
        )
        if m.shared_user_id:
            lines.append(f"  sharedUserId    : {m.shared_user_id}")
        lines.append("  应用标志        :")
        if m.app_flags:
            for k, v in m.app_flags.items():
                flag_color = _COLORS[HIGH] if k in ("debuggable", "testOnly") and v else ""
                lines.append(
                    f"    - {k:<22}= {self._c(str(v), flag_color)}"
                )
        else:
            lines.append("    （未声明特殊标志）")

    def _section_components(self, r: AuditResult, lines: list[str]):
        m = r.manifest
        lines.append(self._c("\n■ 组件与导出面", _BOLD))
        if not m.components:
            lines.append("  （无组件）")
            return
        for c in m.components:
            if c.effective_exported:
                state = self._c("已导出", _COLORS[HIGH])
            elif c.exported is False:
                state = self._c("未导出", _COLORS[LOW])
            else:
                state = self._c("默认不导出", _DIM)
            perm = c.permission or c.read_permission or c.write_permission or "无权限保护"
            lines.append(f"  [{c.kind:<14}] {c.name}")
            lines.append(f"      状态: {state}  依据: {c.exported_source}")
            lines.append(f"      权限: {perm}")
            for f in c.intent_filters:
                bits = []
                if f.actions:
                    bits.append("action=" + ",".join(f.actions))
                if f.categories:
                    bits.append("category=" + ",".join(f.categories))
                if f.schemes:
                    bits.append("scheme=" + ",".join(f.schemes))
                if f.hosts:
                    bits.append("host=" + ",".join(f.hosts))
                if f.mime_types:
                    bits.append("mime=" + ",".join(f.mime_types))
                lines.append(f"      intent-filter: {' | '.join(bits)}")

    def _section_permissions(self, r: AuditResult, lines: list[str]):
        m = r.manifest
        lines.append(self._c("\n■ 权限", _BOLD))
        lines.append(f"  uses-permission（{len(m.uses_permissions)} 项）:")
        for p in m.uses_permissions:
            lines.append(f"    - {p}")
        if m.uses_permissions_sdk23:
            lines.append(f"  uses-permission-sdk-23: {m.uses_permissions_sdk23}")
        if m.custom_permissions:
            lines.append("  自定义权限:")
            for cp in m.custom_permissions:
                lines.append(f"    - {cp.name}  protectionLevel={cp.protection_level}")

    def _section_network(self, r: AuditResult, lines: list[str]):
        lines.append(self._c("\n■ 网络安全配置", _BOLD))
        nc = r.network_config
        if nc is None:
            lines.append(self._c(
                "  未提供 network_security_config.xml（targetSdk>=28 走系统安全默认）",
                _DIM,
            ))
            return
        lines.append(f"  配置文件        : {r.network_config_path}")
        lines.append(f"  base 明文       : {nc.base_cleartext}")
        lines.append(
            f"  base 信任用户CA : {nc.base_trust_user_ca}  "
            f"信任系统CA: {nc.base_trust_system_ca}"
        )
        lines.append(
            f"  debug 明文      : {nc.debug_overrides_cleartext}  "
            f"debug 信任用户CA: {nc.debug_trust_user_ca}"
        )
        for rule in nc.domain_rules:
            lines.append(
                f"  domain-config   : 域名={rule.domains or '未列'} "
                f"明文={rule.cleartext} 用户CA={rule.trust_user_ca}"
            )

    def _section_signatures(self, r: AuditResult, lines: list[str]):
        lines.append(self._c("\n■ 签名方案", _BOLD))
        sigs = r.signatures
        v1 = sigs["v1"]
        lines.append(
            f"  v1 (JAR)       : {'存在' if v1.present else self._c('缺失', _COLORS[HIGH])}"
        )
        if v1.present:
            lines.append(f"      MANIFEST 条目数: {v1.manifest_entries}")
            lines.append(f"      .SF 文件      : {v1.sf_files}")
            lines.append(f"      PKCS#7 文件   : {v1.pkcs7_files}")
            if v1.crypto_verified is True:
                lines.append("      PKCS#7 验证   : " + self._c("通过", _COLORS[LOW]))
                if v1.signer_subject:
                    lines.append(f"      签名者        : {v1.signer_subject}")
            elif v1.crypto_verified is False:
                lines.append("      PKCS#7 验证   : " + self._c("失败", _COLORS[CRITICAL]))
            else:
                lines.append("      PKCS#7 验证   : 未执行（无 openssl）")
        for name in ("v2", "v3", "v3.1"):
            res = sigs[name]
            if not res.present:
                lines.append(
                    f"  {name:<15}: {self._c('缺失', _COLORS[HIGH])}"
                )
                continue
            digest_state = "—"
            if res.digest_matches_apk is True:
                digest_state = self._c("摘要校验通过", _COLORS[LOW])
            elif res.digest_matches_apk is False:
                digest_state = self._c("摘要不一致", _COLORS[CRITICAL])
            lines.append(
                f"  {name:<15}: 存在  签名者数={res.signers} "
                f"算法={res.digest_algorithms} {digest_state}"
            )

    def _section_findings(self, r: AuditResult, lines: list[str]):
        lines.append(self._c("\n■ 风险发现", _BOLD))
        if not r.findings:
            lines.append("  未发现风险项。")
            return
        for idx, f in enumerate(r.findings, 1):
            lines.append("")
            head = f"{idx:>2}. [{self._sev(f.severity).strip() if not self.color else f.severity}] {f.title}"
            lines.append(
                f"{idx:>2}. {self._sev(f.severity)} {f.title}"
            )
            if f.component:
                lines.append(f"      组件 : {f.component}")
            lines.append(f"      规则 : {f.rule_id}")
            lines.append(f"      说明 : {f.detail}")
            if f.recommendation:
                lines.append(self._c(f"      建议 : {f.recommendation}", _DIM))

    def _section_score(self, r: AuditResult, lines: list[str]):
        s = r.score
        lines.append(self._c("\n■ 结论", _BOLD))
        counts = s["counts"]
        lines.append(
            "  计数: "
            + "  ".join(
                self._c(f"{sev}={counts[sev]}", _COLORS.get(sev, ""))
                for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            )
        )
        score_color = (
            _COLORS[CRITICAL] if counts[CRITICAL]
            else _COLORS[HIGH] if counts[HIGH]
            else _COLORS[MEDIUM] if counts[MEDIUM]
            else _COLORS[LOW]
        )
        lines.append(
            f"  评分: {self._c(str(s['score']) + '/100', score_color)}   "
            f"分级: {self._c(s['grade'], score_color)}"
        )
