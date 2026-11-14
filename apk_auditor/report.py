"""Human-readable (Chinese, terminal) and JSON report rendering."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .audit import AuditResult
from .manifest_analysis import LEVEL_ORDER

_LEVEL_TAG = {
    "CRITICAL": "严重",
    "HIGH": "高危",
    "MEDIUM": "中危",
    "INFO": "信息",
}

_COLOR = {
    "CRITICAL": "\033[95m",  # magenta
    "HIGH": "\033[91m",      # red
    "MEDIUM": "\033[93m",    # yellow
    "INFO": "\033[96m",      # cyan
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _level(level: str, color: bool) -> str:
    tag = f"[{_LEVEL_TAG.get(level, level)}]"
    if not color:
        return tag
    return f"{_COLOR.get(level, '')}{_BOLD}{tag}{_RESET}"


def _line(c: str = "-", n: int = 72) -> str:
    return c * n


def render_text(result: AuditResult, color: bool = True) -> str:
    out: List[str] = []
    m = result.manifest
    out.append(_line("="))
    out.append(f"APK 静态安全审计报告  {_BOLD if color else ''}{result.apk_path}{_RESET if color else ''}")
    out.append(
        f"文件大小: {result.file_size:,} 字节    风险评分: "
        f"{result.score_value}/100    评级: {result.rating_label}"
    )
    out.append(_line("="))

    if result.parse_errors:
        out.append("\n[解析错误]")
        for e in result.parse_errors:
            out.append(f"  ! {e}")

    # ------------------------------------------------------------- 基本信息
    out.append("\n■ 基本信息")
    if m is not None:
        rows = [
            ("包名 package", m.package),
            ("versionName / versionCode", f"{m.version_name} / {m.version_code}"),
            ("minSdkVersion", m.min_sdk),
            ("targetSdkVersion", m.target_sdk),
        ]
        for k, v in rows:
            out.append(f"  {k:<28}: {v}")
    else:
        out.append("  (Manifest 解析失败，无基本信息)")

    # --------------------------------------------------------- application
    out.append("\n■ application 关键配置")
    if m is not None:
        app_rows = [
            ("debuggable", m.debuggable),
            ("allowBackup", m.allow_backup),
            ("testOnly", m.test_only),
            ("usesCleartextTraffic", m.uses_cleartext),
            ("networkSecurityConfig", m.network_security_config),
        ]
        for k, v in app_rows:
            out.append(f"  {k:<28}: {v}")

    # ----------------------------------------------------------- 权限
    if m is not None:
        out.append("\n■ 权限")
        if m.uses_permissions:
            for p in m.uses_permissions:
                extra = f"  (maxSdk={p['maxSdkVersion']})" if p.get("maxSdkVersion") else ""
                out.append(f"  uses-permission {p.get('name')}{extra}")
        else:
            out.append("  (无 uses-permission)")
        for cp in m.custom_permissions:
            out.append(
                f"  {cp['tag']} {cp.get('name')}  "
                f"protectionLevel={cp.get('protectionLevel')}"
            )

    # ----------------------------------------------------------- 组件
    if m is not None:
        out.append("\n■ 四大组件")
        exported = [c for c in m.components if c.exported]
        internal = [c for c in m.components if not c.exported]
        out.append(
            f"  组件总数 {len(m.components)}，导出 {len(exported)}，"
            f"未导出 {len(internal)}"
        )
        for comp in m.components:
            mark = "导出" if comp.exported else "内部"
            implicit = " (隐式导出!)" if comp.implicit_export else ""
            perm = f"  permission={comp.permission}" if comp.permission else ""
            out.append(
                f"  - [{mark}] {comp.kind:<14} {comp.name}{implicit}{perm}"
            )
            for f in comp.filters:
                if f["actions"]:
                    out.append(f"      action   : {', '.join(f['actions'])}")
                if f["categories"]:
                    out.append(f"      category : {', '.join(f['categories'])}")
                for d in f["data"]:
                    out.append(f"      data     : {d}")

    # ------------------------------------------------- network security
    ns = result.netsec
    out.append("\n■ network_security_config")
    if ns is None:
        out.append("  未配置（使用平台默认策略）")
    else:
        if ns.parse_error:
            out.append(f"  ! {ns.parse_error}")
        out.append(f"  cleartextTrafficPermitted : {ns.cleartext_permitted}")
        out.append(f"  信任用户 CA (user)         : {ns.user_cas_trusted}")
        out.append(f"  信任系统 CA (system)       : {ns.system_cas_trusted}")
        for rule in ns.domain_rules:
            out.append(
                f"  domain-config {rule['domains']}: "
                f"cleartext={rule['cleartext']}, userCA={rule['user_cas']}, "
                f"pins={len(rule['pins'])}"
            )

    # ----------------------------------------------------------- 签名
    out.append("\n■ 签名方案 v1 / v2 / v3")
    for scheme in ("v1", "v2", "v3"):
        check = result.signatures[scheme]
        if not check.present:
            out.append(f"  {scheme}: 未检测到")
            continue
        status = []
        status.append("结构OK" if check.structural_ok else "结构损坏")
        if check.digest_match is True:
            status.append("内容摘要匹配")
        elif check.digest_match is False:
            status.append("内容摘要不匹配")
        if check.verified:
            status.append("密码学验签通过")
        elif scheme != "v1" or check.structural_ok:
            status.append("验签未通过/未执行")
        weak = "，SHA-1弱哈希" if check.weak_hash else ""
        out.append(
            f"  {scheme}: 存在 | {', '.join(status)}{weak}"
        )
        if check.algorithms:
            out.append(f"      算法: {', '.join(check.algorithms)}")
        for subj in check.signer_subjects:
            out.append(f"      签名者: {subj}")
        if check.details:
            out.append(f"      详情: {check.details}")
        for err in check.errors:
            out.append(f"      ! {err}")

    # ----------------------------------------------------------- 风险
    out.append("\n■ 风险清单")
    if not result.findings:
        out.append("  未发现风险项，基线检查通过。")
    else:
        ordered = sorted(
            result.findings,
            key=lambda f: (LEVEL_ORDER[f.level], f.rule_id),
        )
        for i, f in enumerate(ordered, 1):
            out.append("")
            out.append(
                f"{i:>2}. {_level(f.level, color)} {f.title}  "
                f"{_DIM if color else ''}[{f.rule_id}]{_RESET if color else ''}"
            )
            if f.location:
                out.append(f"    位置: {f.location}")
            out.append(f"    说明: {f.detail}")
            if f.recommendation:
                out.append(f"    建议: {f.recommendation}")

    counts = {lv: 0 for lv in ("CRITICAL", "HIGH", "MEDIUM", "INFO")}
    for f in result.findings:
        counts[f.level] += 1
    out.append("")
    out.append(_line())
    out.append(
        "统计: 严重 {CRITICAL} | 高危 {HIGH} | 中危 {MEDIUM} | 信息 {INFO}"
        .format(**counts)
    )
    out.append(
        f"结论: 评分 {result.score_value}/100，综合评级【{result.rating_label}】"
    )
    out.append(_line())
    return "\n".join(out)


def render_json(result: AuditResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=indent)
