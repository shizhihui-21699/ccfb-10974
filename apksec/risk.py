"""Risk rules.

Each rule turns parsed facts (manifest, network config, signatures) into
:class:`Finding` objects.  Severity is assigned by impact, not by how easy the
issue is to spot:

* critical - trivially exploitable by any other app / data exposure at scale
             (e.g. an exported ContentProvider with no permission).
* high     - a real attack path that needs low effort (exported activity with
             a deep link, debuggable release build, cleartext traffic to all
             hosts, user CAs trusted).
* medium   - meaningful weakness, exploitation needs specific preconditions
             (backups enabled, v1-only signing, exported system broadcast
             receiver with no permission).
* low      - hygiene issues that weaken defence in depth.
* info     - context an auditor should know, not a vulnerability.

A score is derived from the findings so builds can be compared over time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import manifest as manifest_mod, nsc as nsc_mod, signature as sig_mod

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
# Points per finding.  A repeat of the same rule counts half again, because ten
# exported providers are not ten independent weaknesses but they do widen the
# attack surface.
SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
REPEAT_FACTOR = 0.5
MAX_REPEAT_MULTIPLIER = 2.0

PRIVILEGED_BROADCAST_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_FULLY_REMOVED",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.PHONE_STATE",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.SMS_DELIVER",
    "android.provider.Telephony.WAP_PUSH_DELIVER",
    "android.provider.Telephony.SECRET_CODE",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.TIME_SET",
    "android.intent.action.TIMEZONE_CHANGED",
    "android.app.action.ACTION_PASSWORD_CHANGED",
    "android.app.action.DEVICE_ADMIN_ENABLED",
    "android.intent.action.INPUT_METHOD_CHANGED",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.HEADSET_PLUG",
    "android.intent.action.MEDIA_MOUNTED",
    "android.intent.action.CONNECTIVITY_CHANGE",
}

SYSTEM_PROTECTED_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "无障碍服务",
    "android.permission.BIND_DEVICE_ADMIN": "设备管理器",
    "android.permission.BIND_VPN_SERVICE": "VPN 服务",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "通知监听",
    "android.permission.BIND_INPUT_METHOD": "输入法",
    "android.permission.BIND_WALLPAPER": "壁纸服务",
    "android.permission.BIND_JOB_SERVICE": "JobService",
    "android.permission.BIND_QUICK_SETTINGS_TILE": "快捷设置",
    "android.permission.BIND_APPWIDGET": "桌面小部件",
    "android.permission.BIND_CHOOSER_TARGET_SERVICE": "分享目标",
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    category: str  # manifest | component | network | signature | permission
    component: Optional[str] = None
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    @property
    def sort_key(self) -> tuple[int, str]:
        return (SEVERITY_ORDER.index(self.severity), self.rule_id)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "category": self.category,
            "component": self.component,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    detail: str,
    category: str,
    *,
    component: Optional[str] = None,
    evidence: Optional[list[str]] = None,
    remediation: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        category=category,
        component=component,
        evidence=evidence or [],
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# Application level
# ---------------------------------------------------------------------------


def check_application(mf: manifest_mod.Manifest) -> list[Finding]:
    out: list[Finding] = []
    if not mf.has_application:
        out.append(
            _finding(
                "MANIFEST-NO-APPLICATION",
                "high",
                "缺少 <application> 元素",
                "清单中没有 <application> 节点，Android 无法安装该 APK；"
                "也可能是清单被破坏或使用了非标准打包方式。",
                "manifest",
                remediation="重新用 aapt2 / AGP 生成清单。",
            )
        )
        return out

    if mf.debuggable is True:
        out.append(
            _finding(
                "APP-DEBUGGABLE",
                "critical",
                "应用可调试（android:debuggable=\"true\"）",
                "任何持有 adb 的用户都能 attach 到进程、读取内存、以应用身份执行代码"
                "（run-as 或调试器注入），可绕过绝大部分应用层保护。发布包不应开启。",
                "manifest",
                evidence=["android:debuggable=true"],
                remediation="发布构建移除 debuggable；用正式签名并校验 BuildConfig.DEBUG。",
            )
        )

    if mf.test_only is True:
        out.append(
            _finding(
                "APP-TEST-ONLY",
                "medium",
                "标记为 testOnly 的测试包",
                "android:testOnly=\"true\" 的 APK 只能通过 adb install -t 安装，"
                "说明这是测试构建；测试构建通常带有调试开关与测试后门。",
                "manifest",
                evidence=["android:testOnly=true"],
                remediation="确认交付物是否为正式构建。",
            )
        )

    if mf.allow_backup is True:
        detail = (
            "android:allowBackup=\"true\" 允许通过 adb backup 或云备份导出应用私有数据目录。"
            "在 debuggable 或物理接触场景下可直接获取 token、数据库等敏感数据。"
        )
        evidence = ["android:allowBackup=true"]
        severity = "medium"
        if mf.target_sdk is not None and mf.target_sdk >= 31 and not (
            mf.data_extraction_rules or mf.full_backup_content
        ):
            detail += (
                " 目标 SDK >= 31 时未配置 dataExtractionRules / fullBackupContent，"
                "备份范围包含全部私有文件。"
            )
            severity = "medium"
        out.append(
            _finding(
                "APP-ALLOW-BACKUP",
                severity,
                "允许应用数据备份",
                detail,
                "manifest",
                evidence=evidence,
                remediation=(
                    '设置 android:allowBackup="false"，或提供 '
                    "android:dataExtractionRules 只备份非敏感数据。"
                ),
            )
        )
    elif mf.allow_backup is None:
        out.append(
            _finding(
                "APP-ALLOW-BACKUP-DEFAULT",
                "low",
                "未显式声明 allowBackup（默认 true）",
                "android:allowBackup 默认值为 true，因此应用私有数据默认会被备份。",
                "manifest",
                evidence=["android:allowBackup 未声明"],
                remediation='显式声明 android:allowBackup="false"。',
            )
        )

    if mf.shared_user_id:
        out.append(
            _finding(
                "APP-SHARED-UID",
                "high",
                f"使用 sharedUserId={mf.shared_user_id}",
                "sharedUserId 让多个应用共享同一 UID 与数据目录，任一成员的漏洞都会"
                "危及整组应用的数据；该属性自 API 29 起已废弃。",
                "manifest",
                evidence=[f"android:sharedUserId={mf.shared_user_id}"],
                remediation="移除 sharedUserId，改用 ContentProvider / 签名级权限共享数据。",
            )
        )

    if mf.extract_native_libs is True:
        out.append(
            _finding(
                "APP-EXTRACT-NATIVE-LIBS",
                "low",
                "extractNativeLibs=true",
                "安装时把 .so 解压到应用数据目录，使原生库可被其他具备文件读取权限的"
                "进程/备份获取，也增大了包体积；更重要的是，在可写目录中的 .so 更容易被替换。",
                "manifest",
                evidence=["android:extractNativeLibs=true"],
                remediation='设置 android:extractNativeLibs="false" 并让 .so 保持对齐。',
            )
        )

    if mf.request_legacy_storage is True:
        out.append(
            _finding(
                "APP-LEGACY-STORAGE",
                "low",
                "requestLegacyExternalStorage 开启",
                "在 Android 10 上退回到宽松的共享存储模型，扩大了对其他应用文件的访问面。",
                "manifest",
                evidence=["android:requestLegacyExternalStorage=true"],
                remediation="适配分区存储。",
            )
        )

    if mf.min_sdk is not None and mf.min_sdk < 21:
        out.append(
            _finding(
                "APP-LOW-MIN-SDK",
                "low",
                f"minSdkVersion={mf.min_sdk} 过低",
                "低版本平台缺少现代安全机制（如 APK Signature Scheme v2、"
                "默认禁止明文、分区存储），设备侧攻击面更大。",
                "manifest",
                evidence=[f"android:minSdkVersion={mf.min_sdk}"],
                remediation="评估是否仍需支持 API 21 以下设备。",
            )
        )

    if mf.target_sdk is None or mf.target_sdk < 28:
        out.append(
            _finding(
                "APP-LOW-TARGET-SDK",
                "medium",
                f"targetSdkVersion={mf.target_sdk} 较低",
                "targetSdk < 28 时平台默认允许明文 HTTP 且信任用户安装的 CA，"
                "同时还逃避了后续版本的一系列安全收紧（导出组件必须显式声明、"
                "隐式 PendingIntent 限制等）。",
                "manifest",
                evidence=[f"android:targetSdkVersion={mf.target_sdk}"],
                remediation="提升 targetSdk 到当前 Google Play 要求的版本。",
            )
        )

    for perm, why in sorted(
        (p, w) for p, w in manifest_mod.HIGH_RISK_PERMISSIONS.items()
        if p in mf.permissions_named()
    ):
        out.append(
            _finding(
                "PERM-HIGH-RISK",
                "medium",
                f"申请高敏感权限 {perm.split('.')[-1]}",
                f"{perm}：{why}。此类权限一旦被滥用可读取屏幕内容、静默安装或长期驻留。",
                "permission",
                evidence=[perm],
                remediation="确认业务确需该权限，并在代码中限制其能力范围。",
            )
        )

    if mf.declared_permissions:
        for decl in mf.declared_permissions:
            level = decl.protection_level or ""
            if level in ("normal", "dangerous"):
                out.append(
                    _finding(
                        "PERM-WEAK-PROTECTION",
                        "medium",
                        f"自定义权限 {decl.name} 保护级别为 {level}",
                        "自定义权限使用 normal/dangerous 级别时，其他应用也能申请并"
                        "获得该权限（dangerous 需用户授权），组件等同半公开。"
                        "应使用 signature 级别或直接不导出组件。",
                        "permission",
                        evidence=[f"{decl.name} protectionLevel={level}"],
                        remediation="改用 signature|privileged 保护级别。",
                    )
                )
    return out


# ---------------------------------------------------------------------------
# Components and intent filters
# ---------------------------------------------------------------------------


def explain_intent_filter(
    comp: manifest_mod.Component, filters: list[manifest_mod.IntentFilter]
) -> list[str]:
    """Explain the exposure of a component's intent filters as a whole.

    Notes are aggregated across filters rather than repeated per filter: a
    component with four deep links should produce one explanation of what can
    reach it, not four copies of the same warning.
    """
    notes: list[str] = []
    actions: set[str] = set()
    categories: set[str] = set()
    schemes: set[str] = set()
    hosts: set[str] = set()
    verified_hosts: set[str] = set()
    unverified_http_hosts: set[str] = set()
    wildcard_host = False
    wildcard_mime = False
    has_data = False
    for flt in filters:
        actions |= set(flt.actions)
        categories |= set(flt.categories)
        for data in flt.data:
            has_data = True
            if "scheme" in data:
                schemes.add(data["scheme"].lower())
            if "host" in data:
                host = data["host"]
                hosts.add(host)
                if host in ("*", "") or "*" in host:
                    wildcard_host = True
                if data.get("scheme", "").lower() in ("http", "https"):
                    if flt.auto_verify:
                        verified_hosts.add(host)
                    else:
                        unverified_http_hosts.add(host)
            if "*" in data.get("mimeType", ""):
                wildcard_mime = True

    browsable = "android.intent.category.BROWSABLE" in categories
    if {"android.intent.action.VIEW", "android.intent.action.SEND"} & actions:
        notes.append("处理 VIEW/SEND 外部意图，可被任意应用或浏览器唤起")
    if browsable:
        notes.append("声明 BROWSABLE，可被浏览器或网页中的链接直接唤起，无需用户点击应用图标")
    http_hosts = ""
    if unverified_http_hosts:
        notes.append(
            "以下 http/https host 所在 filter 未开启 autoVerify，任何应用都可以注册同一 "
            "host/scheme 来截获本应发送给本应用的链接（深度链接劫持）："
            + ", ".join(sorted(unverified_http_hosts))
        )
        http_hosts = ", ".join(sorted(unverified_http_hosts))
    if verified_hosts:
        notes.append(
            "以下 host 使用 App Links 校验（autoVerify=true），系统会验证域名归属："
            + ", ".join(sorted(verified_hosts))
        )
    custom = sorted(
        s for s in schemes if s not in ("http", "https", "file", "content", "android-app")
    )
    if custom and browsable:
        notes.append(
            "自定义 scheme（" + ", ".join(custom) + "）：其他应用可声明相同 scheme 抢占，"
            "且本组件收到的参数不可信，需对 path/query 做严格校验"
        )
    exposed_hosts = sorted(h for h in hosts if h not in ("*", "") and "*" not in h)
    if browsable and exposed_hosts and not http_hosts:
        notes.append("可被外部触发的 host：" + ", ".join(exposed_hosts))
    if wildcard_mime:
        notes.append("MIME 类型使用通配符，任何内容提供者都可能匹配到该组件")
    if wildcard_host:
        notes.append(
            "host 使用通配符（*）：任意域名都能匹配到这个组件，无法用自动校验确认来源，"
            "必须自行校验所有传入参数"
        )
    if comp.kind == "receiver":
        privileged = sorted(actions & PRIVILEGED_BROADCAST_ACTIONS)
        if privileged:
            notes.append(
                "监听系统广播（" + ", ".join(a.rsplit('.', 1)[-1] for a in privileged) + "）："
                "其他应用可伪造同名广播（受保护广播除外），若在 onReceive 中直接信任 "
                "extras 会导致越权或持久化驻留"
            )
    if comp.kind == "provider" and filters:
        notes.append("ContentProvider 的 intent-filter 极少需要，导出即意味着可被任意应用查询")
    if not has_data and browsable:
        notes.append("声明了 BROWSABLE 但没有 data 元素，任意应用都能显式唤起该组件")
    return notes


def _filter_evidence(filters: list[manifest_mod.IntentFilter], max_len: int = 400) -> list[str]:
    """Describe filters compactly; a pathPattern-heavy filter can be huge."""
    out = []
    for flt in filters:
        text = flt.describe()
        if len(text) > max_len:
            text = text[:max_len] + f"… ({len(text)} chars)"
        out.append(text)
    return out


def _is_launcher_filter(flt: manifest_mod.IntentFilter) -> bool:
    if flt.data:
        return False
    return (
        set(flt.actions) == {"android.intent.action.MAIN"}
        and "android.intent.category.LAUNCHER" in flt.categories
    )


def _is_launcher_only(comp: manifest_mod.Component) -> bool:
    """True when every filter is a plain MAIN/LAUNCHER entry.

    A launcher activity is exported by design and reachable only through the
    home screen, so it is not an exposure in itself.
    """
    if not comp.intent_filters:
        return False
    return all(_is_launcher_filter(f) for f in comp.intent_filters)


def _has_launcher_filter(comp: manifest_mod.Component) -> bool:
    return any(_is_launcher_filter(f) for f in comp.intent_filters)


def _component_evidence(comp: manifest_mod.Component) -> list[str]:
    ev = [f"android:name={comp.name}"]
    if comp.exported is None:
        ev.append("android:exported 未声明")
    else:
        ev.append(f"android:exported={str(comp.exported).lower()}")
    if comp.permission:
        ev.append(f"android:permission={comp.permission}")
    if comp.read_permission:
        ev.append(f"android:readPermission={comp.read_permission}")
    if comp.write_permission:
        ev.append(f"android:writePermission={comp.write_permission}")
    if comp.authorities:
        ev.append("android:authorities=" + ";".join(comp.authorities))
    return ev


def check_components(mf: manifest_mod.Manifest) -> list[Finding]:
    out: list[Finding] = []
    for comp in mf.components:
        filters = comp.intent_filters
        notes = explain_intent_filter(comp, filters) if filters else []

        launcher_only = comp.kind in ("activity", "activity-alias") and _is_launcher_only(comp)

        # --- Android 12+ explicit exported requirement ---
        if filters and comp.exported is None and not launcher_only:
            if mf.target_sdk is not None and mf.target_sdk >= 31:
                out.append(
                    _finding(
                        "COMP-EXPORTED-MISSING",
                        "high",
                        f"{comp.kind} {comp.name} 声明了 intent-filter 但未显式指定 android:exported",
                        "targetSdk >= 31 时带有 intent-filter 的组件必须显式声明 "
                        "android:exported，否则安装直接失败（INSTALL_PARSE_FAILED_MANIFEST_MALFORMED）。"
                        "若目标设备 targetSdk 较低，则会按旧规则隐式导出。",
                        "component",
                        component=comp.name,
                        evidence=_component_evidence(comp),
                        remediation='显式声明 android:exported="true"/"false"。',
                    )
                )
            else:
                guarded = bool(comp.permission) or (
                    comp.kind == "provider"
                    and bool(comp.read_permission or comp.write_permission)
                )
                if guarded:
                    # A permission-protected component that relies on the legacy
                    # implicit-export rule: the developer probably assumed it was
                    # private, so the explicit/missing declaration is the issue.
                    out.append(
                        _finding(
                            "COMP-IMPLICIT-EXPORT",
                            "medium",
                            f"{comp.kind} {comp.name} 未声明 android:exported，依赖旧版隐式导出规则",
                            "该组件带有 intent-filter 且有权限保护。targetSdk < 31 时平台会"
                            "按“有 filter 即导出”处理，权限一旦被声明为 normal/dangerous，"
                            "其他应用就可能申请到权限并访问它；targetSdk >= 31 则直接安装失败。",
                            "component",
                            component=comp.name,
                            evidence=_component_evidence(comp)
                            + [f"intent-filter: {t}" for t in _filter_evidence(filters)],
                            remediation='显式声明 android:exported，避免依赖平台的隐式规则。',
                        )
                    )

        if comp.declared_exported_false_but_filters and comp.kind != "receiver":
            out.append(
                _finding(
                    "COMP-FILTER-IGNORED",
                    "info",
                    f"{comp.kind} {comp.name} 声明 exported=false 却保留了 intent-filter",
                    "intent-filter 在 exported=false 时不会被其他应用匹配，"
                    "通常是重构后遗留的死配置，也可能掩盖了本意是导出的入口。",
                    "component",
                    component=comp.name,
                    evidence=_component_evidence(comp),
                )
            )

        if not comp.is_exported:
            continue

        # --- exported component checks ---
        if comp.kind == "provider":
            has_guard = bool(
                comp.permission or comp.read_permission or comp.write_permission
            )
        else:
            has_guard = bool(comp.permission)

        if comp.kind == "provider":
            if not has_guard:
                out.append(
                    _finding(
                        "PROVIDER-EXPORTED-NO-PERMISSION",
                        "critical",
                        f"导出的 ContentProvider {comp.name} 未设置任何权限",
                        "任意应用都可以通过 ContentResolver 查询、插入、修改或删除该 "
                        "provider 的数据（authorities: "
                        + ", ".join(comp.authorities or ["<none>"])
                        + "）。这是最常见的第三方 APK 数据泄露根因。",
                        "component",
                        component=comp.name,
                        evidence=_component_evidence(comp)
                        + [f"intent-filter: {t}" for t in _filter_evidence(filters)],
                        remediation=(
                            '声明 android:exported="false"；确需共享时使用 signature 级 '
                            "android:permission，并限制 android:grantUriPermissions。"
                        ),
                    )
                )
            else:
                perm_names = [
                    p
                    for p in (comp.permission, comp.read_permission, comp.write_permission)
                    if p
                ]
                weak = [
                    p
                    for p in perm_names
                    if any(
                        d.name == p and d.protection_level in ("normal", "dangerous")
                        for d in mf.declared_permissions
                    )
                ]
                system_guarded = all(
                    p in SYSTEM_PROTECTED_PERMISSIONS
                    or p.startswith("android.permission.")
                    for p in perm_names
                )
                declared_names = {d.name for d in mf.declared_permissions} | set(
                    SYSTEM_PROTECTED_PERMISSIONS
                )
                undeclared = [
                    p for p in perm_names if p not in declared_names
                ]
                if system_guarded:
                    severity = "low"
                    reason = (
                        "保护权限是平台权限，普通应用无法获得，实际暴露面很小；"
                        "但该 provider 仍可被持有该平台权限的系统组件访问。"
                    )
                elif undeclared:
                    severity = "high"
                    reason = (
                        "权限 " + ", ".join(undeclared) + " 未在本 APK 或平台中定义。"
                        "任何应用都可以自行声明同名权限（默认 normal 级别）并获得访问权，"
                        "因此这里等同于没有保护。"
                    )
                elif weak:
                    severity = "high"
                    reason = "自定义权限级别为 normal/dangerous，其他应用申请后即可访问该 provider；"
                elif comp.read_permission is None or comp.write_permission is None:
                    severity = "medium"
                    reason = "读写权限未分别限制，只需要只读能力的调用方也可能写入数据；"
                else:
                    severity = "medium"
                    reason = "权限保护的有效性依赖保护级别与 provider 内部的调用方校验。"
                out.append(
                    _finding(
                        "PROVIDER-EXPORTED-GUARDED",
                        severity,
                        f"导出的 ContentProvider {comp.name} 仅靠权限保护",
                        f"provider 已导出并声明权限（{', '.join(perm_names)}）。" + reason,
                        "component",
                        component=comp.name,
                        evidence=_component_evidence(comp),
                        remediation=(
                            '声明 android:exported="false"；确需共享时使用 signature 级权限，'
                            "并在 provider 内部按调用方 UID 校验。"
                        ),
                    )
                )
            if comp.grant_uri_permissions is True:
                out.append(
                    _finding(
                        "PROVIDER-GRANT-URI",
                        "high",
                        f"Provider {comp.name} 开启 grantUriPermissions",
                        "被授权方可以通过 ContentResolver 长期访问特定 URI，"
                        "若配合路径遍历或未校验的 path 参数，可越过权限读取任意文件。",
                        "component",
                        component=comp.name,
                        evidence=_component_evidence(comp),
                        remediation="如非必要关闭 grantUriPermissions，或使用 FileProvider 并限制 paths。",
                    )
                )
            if comp.authorities:
                for auth in comp.authorities:
                    if auth in ("*", "") or auth.endswith(".*"):
                        out.append(
                            _finding(
                                "PROVIDER-WILDCARD-AUTHORITY",
                                "high",
                                f"Provider authority 使用通配符：{auth}",
                                "通配符 authority 会与任意匹配的应用冲突或暴露数据。",
                                "component",
                                component=comp.name,
                                evidence=[f"android:authorities={auth}"],
                            )
                        )
            continue

        if has_guard:
            continue

        launcher_only = comp.kind in ("activity", "activity-alias") and _is_launcher_only(comp)
        launcher_entry = comp.kind in ("activity", "activity-alias") and _has_launcher_filter(
            comp
        )
        if launcher_only:
            continue

        if comp.kind in ("activity", "activity-alias"):
            if launcher_entry:
                # The launcher entry must be exported; extra deep-link filters
                # on the same component are covered by INTENT-FILTER-EXPOSURE.
                continue
            severity = "high" if filters else "medium"
            detail = (
                "导出且未加权限的 Activity 可被任意应用通过显式 Intent 启动。"
            )
            if filters:
                detail += (
                    "配合 intent-filter，还可被浏览器或任意应用以隐式 Intent 唤起；"
                    "若组件从 Intent extras/data 读取参数而不校验来源，可能导致越权操作、"
                    "UI 欺骗（界面劫持）或本地数据泄露。"
                )
            out.append(
                _finding(
                    "ACTIVITY-EXPORTED-NO-PERMISSION",
                    severity,
                    f"导出的 Activity {comp.name} 未受权限保护",
                    detail,
                    "component",
                    component=comp.name,
                    evidence=_component_evidence(comp)
                    + [f"intent-filter: {t}" for t in _filter_evidence(filters)],
                    remediation=(
                        '不需要外部启动时 android:exported="false"；'
                        "需要时加 signature 级权限，并校验 getCallingPackage()/Intent 来源与参数。"
                    ),
                )
            )
            if comp.kind == "activity-alias" and comp.target_activity:
                out.append(
                    _finding(
                        "ACTIVITY-ALIAS",
                        "info",
                        f"Activity alias {comp.name} 转发到 {comp.target_activity}",
                        "别名可绕过针对目标 Activity 的 exported 限制；攻击面以目标 Activity 实际能力为准。",
                        "component",
                        component=comp.name,
                        evidence=[f"android:targetActivity={comp.target_activity}"],
                    )
                )
        elif comp.kind == "service":
            severity = "high" if filters else "medium"
            out.append(
                _finding(
                    "SERVICE-EXPORTED-NO-PERMISSION",
                    severity,
                    f"导出的 Service {comp.name} 未受权限保护",
                    "任意应用都可以 startService / bindService 到该组件。"
                    "若服务执行特权操作（下载、安装、文件处理）且信任调用方传入的参数，"
                    "会造成越权；bindService 还能通过 Binder 直接调用其接口方法。",
                    "component",
                    component=comp.name,
                    evidence=_component_evidence(comp)
                    + [f"intent-filter: {t}" for t in _filter_evidence(filters)],
                    remediation='不需要外部调用时 android:exported="false"，或加 signature 级权限。',
                )
            )
        elif comp.kind == "receiver":
            has_privileged = any(
                set(f.actions) & PRIVILEGED_BROADCAST_ACTIONS for f in filters
            )
            severity = "high" if (filters and has_privileged) else "medium"
            out.append(
                _finding(
                    "RECEIVER-EXPORTED-NO-PERMISSION",
                    severity,
                    f"导出的 BroadcastReceiver {comp.name} 未受权限保护",
                    "任意应用都能向其发送广播。若 onReceive 依据未校验的 extras/action "
                    "执行动作（下载、写文件、启动组件、修改配置），可被用来触发特权逻辑；"
                    "系统广播接收器还可能被伪造的广播唤醒。",
                    "component",
                    component=comp.name,
                    evidence=_component_evidence(comp)
                    + [f"intent-filter: {t}" for t in _filter_evidence(filters)],
                    remediation=(
                        '不需要外部广播时 android:exported="false"；'
                        "动态注册时使用 RECEIVER_NOT_EXPORTED，并对 action/extras 做白名单校验。"
                    ),
                )
            )

        if notes and not launcher_only:
            out.append(
                _finding(
                    "INTENT-FILTER-EXPOSURE",
                    "medium" if comp.kind != "provider" else "high",
                    f"{comp.name} 的 intent-filter 暴露面",
                    "\n".join(notes),
                    "component",
                    component=comp.name,
                    evidence=_filter_evidence(filters),
                    remediation="校验 Intent 来源与所有参数，避免把外部输入直接用于文件路径、SQL、WebView 或命令执行。",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


def check_network(
    mf: manifest_mod.Manifest, policy: nsc_mod.EffectivePolicy
) -> list[Finding]:
    out: list[Finding] = []
    cfg = policy.nsc

    if cfg.found and cfg.parse_error:
        out.append(
            _finding(
                "NSC-UNPARSEABLE",
                "medium",
                "networkSecurityConfig 无法解析",
                f"清单引用了网络安全配置，但审计器无法读取/解析：{cfg.parse_error}。"
                "该配置可能被混淆或使用了非标准资源布局，需人工确认实际策略。",
                "network",
                evidence=[f"resolved_via={cfg.resolved_via}"],
            )
        )

    if policy.cleartext_global:
        explicit = cfg.found and cfg.parse_error is None and cfg.base_cleartext is True
        severity = "high" if explicit else "medium"
        out.append(
            _finding(
                "NET-CLEARTEXT-ALLOWED",
                severity,
                "全局允许明文 HTTP 流量",
                f"判定依据：{policy.cleartext_source}。明文流量可被同一网络下的攻击者"
                "窃听或篡改（登录凭据、token、业务数据）。",
                "network",
                evidence=[policy.cleartext_source],
                remediation=(
                    '设置 android:usesCleartextTraffic="false"，或在 network security config '
                    '中用 base-config cleartextTrafficPermitted="false"，仅对确需的域名开白名单。'
                ),
            )
        )
    for rule in cfg.domains_allowing_cleartext():
        out.append(
            _finding(
                "NET-CLEARTEXT-DOMAIN",
                "high",
                f"域名 {rule.domain} 允许明文流量",
                "domain-config 中显式允许该域名（含子域名："
                + ("是" if rule.include_subdomains else "否")
                + "）使用明文 HTTP。",
                "network",
                evidence=[f"domain={rule.domain} cleartextTrafficPermitted=true"],
                remediation="改用 HTTPS 并移除该白名单。",
            )
        )

    if policy.trusts_user_cas:
        out.append(
            _finding(
                "NET-USER-CA-TRUST",
                "high",
                "信任用户安装的 CA 证书",
                f"判定依据：{policy.user_ca_source}。用户 CA 由设备所有者安装，"
                "恶意软件、公司代理或物理接触者都可安装自签 CA 并中间人解密 HTTPS 流量。"
                "第三方 APK 常借此抓包调试，但同样给攻击者留下后门。",
                "network",
                evidence=[policy.user_ca_source],
                remediation=(
                    'base-config 中 <trust-anchors><certificates src="system"/> 只信任系统 CA；'
                    "抓包需求放到 debuggable 的 debug-overrides 中。"
                ),
            )
        )
    for rule in cfg.domains_trusting_user_certs():
        out.append(
            _finding(
                "NET-USER-CA-DOMAIN",
                "high",
                f"域名 {rule.domain} 信任用户 CA",
                "该域名可通过用户安装的证书进行中间人解密。",
                "network",
                evidence=[f"domain={rule.domain} trust-anchors includes user"],
            )
        )

    if cfg.found and cfg.parse_error is None:
        if cfg.base_trust is None and cfg.domains and not cfg.base_cleartext:
            out.append(
                _finding(
                    "NSC-NO-BASE-CONFIG",
                    "info",
                    "network security config 未定义 base-config",
                    "未声明的策略回退到平台默认值；对 targetSdk < 24 的应用，"
                    "默认仍信任用户 CA。",
                    "network",
                )
            )
        if cfg.has_debug_overrides:
            out.append(
                _finding(
                    "NSC-DEBUG-OVERRIDES",
                    "info" if not mf.debuggable else "medium",
                    "network security config 包含 debug-overrides",
                    "debug-overrides 只在 android:debuggable=true 时生效。该 APK "
                    + (
                        "是可调试的，因此覆盖策略当前生效"
                        + (
                            "（cleartextTrafficPermitted=" + str(cfg.debug_cleartext) + "）"
                            if cfg.debug_cleartext is not None
                            else ""
                        )
                        + (
                            "，并信任用户 CA，可被中间人抓包。"
                            if cfg.debug_trust and cfg.debug_trust.user
                            else "。"
                        )
                        if mf.debuggable
                        else "不可调试，覆盖策略当前不生效（仅影响 debug 构建）。"
                    ),
                    "network",
                    evidence=["debug-overrides present"],
                )
            )
        if cfg.base_pins or any(d.pins for d in cfg.domains):
            pinned = [d.domain for d in cfg.domains if d.pins] or ["<base-config>"]
            out.append(
                _finding(
                    "NSC-PINNING-PRESENT",
                    "info",
                    "启用了证书固定（certificate pinning）",
                    "固定证书可抵抗中间人，但如果 pin 的证书即将过期且没有备份 pin，"
                    "会造成应用无法联网。固定域名：" + ", ".join(pinned),
                    "network",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------


def check_signatures(
    report: sig_mod.SignatureReport, mf: manifest_mod.Manifest
) -> list[Finding]:
    out: list[Finding] = []
    present = report.schemes_present()

    if not present:
        out.append(
            _finding(
                "SIG-NONE",
                "critical",
                "APK 未签名或签名无法识别",
                "没有发现 v1/v2/v3 任一签名方案的有效签名块。未签名 APK 无法安装"
                "（除非使用 adb install --bypass-low-target-sdk-block 等特殊手段），"
                "包内容也可能在传输后被替换。",
                "signature",
                remediation="发布前用 apksigner 签名 v2+v3。",
            )
        )
        return out

    failed = []
    for label, res in (("v1", report.v1), ("v2", report.v2), ("v3", report.v3), ("v3.1", report.v31)):
        if res is not None and res.present and not res.verified:
            failed.append(label)
    if failed:
        reasons = []
        for label in failed:
            res = getattr(report, {"v1": "v1", "v2": "v2", "v3": "v3", "v3.1": "v31"}[label])
            reasons.extend(res.errors if res is not None else [])
        detail = "签名块存在但无法通过校验。"
        if any("not covered by MANIFEST.MF" in r for r in reasons):
            detail = (
                "v1 签名清单未覆盖归档中的全部条目——签名后被追加或替换了文件，"
                "这是重打包/二次打包的典型特征。"
            )
        elif any("digest mismatch" in r.lower() for r in reasons):
            detail = (
                "内容摘要与签名块不符——APK 在签名后至少有一个条目被修改，"
                "这是重打包（二次打包）的直接证据。"
            )
        elif any("does not verify" in r.lower() or "failed" in r.lower() for r in reasons):
            detail = (
                "签名无法通过密码学校验：证书与私钥不匹配、签名被破坏，"
                "或使用了审计器不支持的算法。"
            )
        if reasons:
            detail += " 具体错误：" + "; ".join(reasons[:6])
        out.append(
            _finding(
                "SIG-INVALID",
                "critical",
                "签名校验失败：" + ", ".join(failed),
                detail,
                "signature",
                evidence=reasons[:10],
                remediation="重新构建并签名，不要修改已签名的 APK。",
            )
        )
    uncovered = getattr(report.v1, "uncovered_entries", [])
    if uncovered:
        has_dex = any(n.endswith(".dex") or n.startswith("classes") for n in uncovered)
        protected_by_v2 = report.v2.verified or report.v3.verified
        if protected_by_v2:
            severity = "info"
            detail = (
                "这些条目未出现在 META-INF/MANIFEST.MF 中；v1 签名因此判定失败，"
                "但 v2/v3 签名覆盖整个 ZIP，实际内容仍受完整性保护。"
            )
        elif has_dex:
            severity = "critical"
            detail = (
                "v1(JAR) 签名只校验 MANIFEST.MF 中列出的条目，未列出的文件会被安装并加载。"
                "攻击者可以在签名后直接追加 dex / so / 资源文件实现代码注入，而签名校验仍然通过。"
                "该 APK 只受 v1 保护，因此额外条目完全未签名。"
            )
        else:
            severity = "high"
            detail = (
                "这些条目未出现在 MANIFEST.MF 中，v1 签名不覆盖它们；"
                "在只有 v1 签名的 APK 上，这类文件可被任意追加而不会被检测。"
            )
        if report.v1.present and not report.v1.verified and not protected_by_v2:
            severity = "critical"
        out.append(
            _finding(
                "SIG-UNSIGNED-ENTRIES",
                severity,
                f"{len(uncovered)} 个归档条目未被签名覆盖",
                detail,
                "signature",
                evidence=uncovered[:10],
                remediation="使用 v2+v3 签名（覆盖整个归档），或在 v1 场景下重新签名并校验所有条目。",
            )
        )


    # Which scheme actually protects which install base.
    min_sdk = mf.min_sdk if mf.min_sdk is not None else 1
    gaps: list[str] = []
    if min_sdk < 24 and 2 not in present and 3 not in present:
        gaps.append(
            "API < 24 的设备只支持 v1；没有 v2 时这些设备得不到整包完整性保护"
        )
    if min_sdk < 28 and 3 not in present:
        gaps.append("API < 28 的设备使用 v2（无 v3 密钥轮换能力）")
    if min_sdk >= 28 and not (2 in present or 3 in present):
        gaps.append("minSdk >= 28 但没有 v2/v3，Android 会拒绝安装")
    if gaps:
        out.append(
            _finding(
                "SIG-COVERAGE",
                "info",
                "签名方案与 minSdk 的覆盖关系",
                "；".join(gaps) + "。",
                "signature",
                evidence=[f"minSdk={min_sdk}", "schemes=" + ",".join(f"v{s}" for s in present)],
            )
        )

    if 1 in present and 2 not in present and 3 not in present:
        out.append(
            _finding(
                "SIG-V1-ONLY",
                "medium",
                "仅使用 v1（JAR）签名",
                "v1 签名不保护 ZIP 元数据（文件名、压缩方式等），存在 Janus "
                "(CVE-2017-13156) 等绕过风险；Android 7.0+ 优先使用 v2，v1 仅在为"
                "旧设备兼容时保留。",
                "signature",
                evidence=["schemes=" + ",".join(f"v{s}" for s in present)],
                remediation="至少启用 v2 与 v3（apksigner 默认）。",
            )
        )
    elif 3 not in present:
        out.append(
            _finding(
                "SIG-NO-V3",
                "low",
                "缺少 v3 签名（密钥轮换不支持）",
                "没有 v3 签名时无法进行签名密钥轮换；v2 本身仍可正常校验。",
                "signature",
                evidence=["schemes=" + ",".join(f"v{s}" for s in present)],
                remediation="用 apksigner 启用 --v3-signing-enabled true。",
            )
        )

    # Certificate checks
    certs = {}
    for signer in report.all_signers():
        if signer.certificates:
            certs.setdefault(signer.certificates[0].sha256, signer.certificates[0])
    for cert in certs.values():
        if "CN=Android Debug" in cert.subject or "O=Android" in cert.subject and "Debug" in cert.subject:
            out.append(
                _finding(
                    "SIG-DEBUG-CERT",
                    "high",
                    "使用 Android 调试证书签名",
                    f"签名证书为 {cert.subject}，任何人用默认 debug keystore 都能生成"
                    "同样的证书；无法证明发布者身份，也无法安全地做签名校验/升级。",
                    "signature",
                    evidence=[f"subject={cert.subject}"],
                    remediation="使用受控的发布密钥签名。",
                )
            )
        if cert.expired:
            out.append(
                _finding(
                    "SIG-CERT-EXPIRED",
                    "low",
                    f"签名证书已过期（{cert.not_after}）",
                    "Android 不因证书过期拒绝安装已签名的应用，但证书过期会影响"
                    "依赖证书有效期的下游信任判断。",
                    "signature",
                    evidence=[f"subject={cert.subject}", f"not_after={cert.not_after}"],
                )
            )
        if cert.self_signed_valid is False:
            out.append(
                _finding(
                    "SIG-CERT-BAD-SELFSIG",
                    "medium",
                    "签名证书的自签名无效",
                    "证书 subject == issuer 但自签名校验失败，说明证书被手工拼装过，"
                    "通常出现在批量生成的测试/伪造签名工具中。",
                    "signature",
                    evidence=[f"subject={cert.subject}"],
                )
            )
        if cert.public_key.kind == "rsa" and cert.public_key.rsa is not None:
            bits = cert.public_key.rsa.n.bit_length()
            if bits < 2048:
                out.append(
                    _finding(
                        "SIG-WEAK-RSA",
                        "medium",
                        f"签名密钥长度仅 {bits} 位",
                        "1024 位 RSA 已可被资源充足者分解，不应再用于签名。",
                        "signature",
                        evidence=[f"RSA-{bits}"],
                    )
                )

    # Anti-stripping: an APK that carries v2/v3 but whose v1 signature does not
    # declare them can be downgraded to v1-only on older devices.
    if 1 in present and (2 in present or 3 in present) and report.v1.verified:
        declared = set(report.v1.protected_schemes)
        expected = {s for s in (2, 3) if s in present}
        if not declared & expected:
            out.append(
                _finding(
                    "SIG-STRIPPING-PROTECTION-MISSING",
                    "medium",
                    "v1 签名未声明 v2/v3（可被降级剥离）",
                    "META-INF/CERT.SF 中缺少 X-Android-APK-Signed 属性，"
                    "因此在只支持 v1 的旧设备上，攻击者可以剥掉 v2/v3 签名块并替换"
                    "v1 签名（Janus 类降级）。apksigner 在同时启用 v1+v2/v3 时会自动写入该属性。",
                    "signature",
                    evidence=[
                        "X-Android-APK-Signed 缺失",
                        "schemes=" + ",".join(f"v{s}" for s in present),
                    ],
                    remediation="用 apksigner 同时启用 v1 与 v2/v3 重新签名。",
                )
            )

    # Cross-scheme consistency: v1 and v2/v3 should describe the same signer.
    digests = report.cert_digests()
    if len(digests) > 1:
        out.append(
            _finding(
                "SIG-MULTIPLE-CERTS",
                "high",
                "不同签名方案使用了不同证书",
                "v1 与 v2/v3 的签名者证书不一致。正常情况下应由同一密钥签名；"
                "不一致可能是二次签名（先签后重签）或被塞入了额外证书。",
                "signature",
                evidence=[f"{d[:16]}… -> {','.join(sorted(s))}" for d, s in digests.items()],
            )
        )
    return out
