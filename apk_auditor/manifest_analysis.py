"""AndroidManifest + network_security_config analysis and risk classification.

Risk levels follow a four-tier model used throughout the report:

    CRITICAL  可直接导致设备/数据失陷的暴露面，通常无需额外条件
    HIGH      显著降低攻击门槛，需要少量用户交互或特定条件
    MEDIUM    扩大攻击面或违反加固基线，利用需要前置条件
    INFO      信息收集项与最佳实践建议
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .axml import AxmlNode, parse_axml

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
INFO = "INFO"
LEVEL_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# Permissions that hand an installed app directly exploitable power.
DANGEROUS_OR_SENSITIVE_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PRIVILEGED",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}

# Action names that mean an exported component is reachable from a browser
# or another app with zero special permissions.
BROWSER_ACTIONS = {
    "android.intent.action.VIEW",
}
LAUNCHER_ACTIONS = {
    "android.intent.action.MAIN",
}
RISKY_SERVICE_ACTIONS = {
    "android.intent.action.BIND_JOB_SERVICE",
}


@dataclass
class Finding:
    level: str
    title: str
    detail: str
    location: str = ""
    recommendation: str = ""
    rule_id: str = ""


@dataclass
class Component:
    kind: str
    name: str
    exported: Optional[bool]
    has_intent_filter: bool
    implicit_export: bool
    permission: Optional[str]
    filters: List[Dict[str, List[str]]]
    enabled: Optional[bool]
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ManifestInfo:
    package: str
    version_name: Optional[str]
    version_code: Any
    min_sdk: Any
    target_sdk: Any
    debuggable: bool
    allow_backup: Optional[bool]
    test_only: bool
    uses_cleartext: Optional[bool]
    network_security_config: Optional[str]
    components: List[Component]
    uses_permissions: List[Dict[str, Any]]
    custom_permissions: List[Dict[str, Any]]
    application_attrs: Dict[str, Any]
    findings: List[Finding] = field(default_factory=list)


def _bool(node: AxmlNode, attr: str) -> Optional[bool]:
    v = node.get(attr)
    if isinstance(v, bool):
        return v
    return None


def _collect_filters(node: AxmlNode) -> List[Dict[str, List[str]]]:
    out = []
    for f in node.findall("intent-filter"):
        actions = [
            c.get("name") for c in f.findall("action") if c.get("name")
        ]
        categories = [
            c.get("name") for c in f.findall("category") if c.get("name")
        ]
        data = []
        for d in f.findall("data"):
            parts = []
            for key in (
                "scheme",
                "host",
                "port",
                "path",
                "pathPrefix",
                "pathPattern",
                "mimeType",
            ):
                v = d.get(key)
                if v:
                    parts.append(f"{key}={v}")
            data.append("; ".join(parts))
        out.append(
            {"actions": actions, "categories": categories, "data": data}
        )
    return out


def parse_manifest(data: bytes) -> tuple[AxmlNode, ManifestInfo]:
    root = parse_axml(data)
    if root.name != "manifest":
        raise ValueError(
            f"manifest 根标签应为 <manifest>，实际为 <{root.name}>"
        )

    app = root.find("application")
    app_attrs: Dict[str, Any] = {}
    if app is not None:
        app_attrs = {k: a.value for k, a in app.attributes.items()}

    components: List[Component] = []
    if app is not None:
        for child in app.children:
            if child.name not in COMPONENT_TAGS:
                continue
            filters = _collect_filters(child)
            exported = _bool(child, "exported")
            has_filter = bool(filters)
            implicit = exported is None and has_filter
            # activity-alias inherits target's export semantics only in part;
            # treat explicit attribute as authoritative.
            if child.name == "activity-alias" and exported is None:
                implicit = has_filter
            effective_exported = exported if exported is not None else (
                True if implicit else False
            )
            comp = Component(
                kind=child.name,
                name=child.get("name") or "(unnamed)",
                exported=effective_exported,
                has_intent_filter=has_filter,
                implicit_export=implicit,
                permission=child.get("permission"),
                filters=filters,
                enabled=_bool(child, "enabled"),
                raw={k: a.value for k, a in child.attributes.items()},
            )
            components.append(comp)

    uses_sdk = root.find("uses-sdk")
    min_sdk = uses_sdk.get("minSdkVersion") if uses_sdk is not None else None
    target_sdk = (
        uses_sdk.get("targetSdkVersion") if uses_sdk is not None else None
    )

    uses_permissions = []
    for up in root.findall("uses-permission"):
        uses_permissions.append(
            {
                "name": up.get("name"),
                "maxSdkVersion": up.get("maxSdkVersion"),
                "usesPermissionFlags": up.get("usesPermissionFlags"),
            }
        )

    custom_permissions = []
    for tag in ("permission", "permission-tree"):
        for p in root.findall(tag):
            custom_permissions.append(
                {
                    "tag": tag,
                    "name": p.get("name"),
                    "protectionLevel": p.get("protectionLevel"),
                }
            )

    info = ManifestInfo(
        package=root.get("package") or "",
        version_name=root.get("versionName"),
        version_code=root.get("versionCode"),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        debuggable=_bool(app, "debuggable") if app is not None else False,
        allow_backup=_bool(app, "allowBackup") if app is not None else None,
        test_only=_bool(app, "testOnly") if app is not None else False,
        uses_cleartext=_bool(app, "usesCleartextTraffic")
        if app is not None
        else None,
        network_security_config=app.get("networkSecurityConfig")
        if app is not None
        else None,
        components=components,
        uses_permissions=uses_permissions,
        custom_permissions=custom_permissions,
        application_attrs=app_attrs,
    )
    return root, info


# --------------------------------------------------- network security config
@dataclass
class NetSecConfig:
    cleartext_permitted: bool
    user_cas_trusted: bool
    system_cas_trusted: bool
    domain_rules: List[Dict[str, Any]]
    pin_sets: List[Dict[str, Any]]
    findings: List[Finding] = field(default_factory=list)
    parse_error: Optional[str] = None


def analyze_network_security(
    zf: zipfile.ZipFile, config_ref: Optional[str]
) -> Optional[NetSecConfig]:
    """Locate and parse res/xml/<config>. The reference is a resource ID
    (@0x........) we cannot resolve without resources.arsc, so when the exact
    path is unknown we scan every compiled XML under res/xml/ for a root tag
    of <network-security-config>."""
    candidate = None
    if config_ref and not str(config_ref).startswith("@0x"):
        candidate = str(config_ref)
    xml_entries = [
        n
        for n in zf.namelist()
        if n.startswith("res/xml/") and n.lower().endswith(".xml")
    ]
    target_entry = None
    if candidate and candidate in zf.namelist():
        target_entry = candidate
    else:
        for name in xml_entries:
            try:
                node = parse_axml(zf.read(name))
            except Exception:
                continue
            if node.name == "network-security-config":
                target_entry = name
                break
    if target_entry is None:
        if config_ref is not None:
            return NetSecConfig(
                cleartext_permitted=False,
                user_cas_trusted=False,
                system_cas_trusted=True,
                domain_rules=[],
                pin_sets=[],
                parse_error=(
                    f"manifest 引用了 networkSecurityConfig={config_ref}，"
                    "但 APK 内找不到对应文件"
                ),
            )
        return None

    try:
        root = parse_axml(zf.read(target_entry))
    except Exception as exc:  # noqa: BLE001
        return NetSecConfig(
            cleartext_permitted=False,
            user_cas_trusted=False,
            system_cas_trusted=True,
            domain_rules=[],
            pin_sets=[],
            parse_error=f"{target_entry} 解析失败: {exc}",
        )

    findings: List[Finding] = []
    base_config = root.find("base-config")
    cleartext_global = False
    user_cas = False
    system_cas = True
    domain_rules: List[Dict[str, Any]] = []
    pin_sets: List[Dict[str, Any]] = []

    def read_trust_anchors(node: Optional[AxmlNode]) -> tuple[bool, bool]:
        if node is None:
            return False, True
        u = s = False
        any_anchor = False
        for ta in node.findall("trust-anchors"):
            for cert in ta.findall("certificates"):
                any_anchor = True
                src = cert.get("src")
                if src == "user":
                    u = True
                elif src == "system":
                    s = True
        if any_anchor and not s:
            s = False
        return u, s

    if base_config is not None:
        ct = base_config.get("cleartextTrafficPermitted")
        if isinstance(ct, bool):
            cleartext_global = ct
        u, s = read_trust_anchors(base_config)
        user_cas = user_cas or u
        system_cas = s

    for dc in root.findall("domain-config"):
        domains = [
            d.get("name") for d in dc.findall("domain") if d.get("name")
        ]
        ct = dc.get("cleartextTrafficPermitted")
        cleartext = cleartext_global if not isinstance(ct, bool) else ct
        u, s = read_trust_anchors(dc)
        pins = []
        for ps in dc.findall("pin-set"):
            for pin in ps.findall("pin"):
                pins.append(
                    {
                        "digest": pin.get("digest"),
                        "value": (pin.text or "").strip() if pin.text else "",
                    }
                )
        rule = {
            "domains": domains,
            "cleartext": cleartext,
            "user_cas": u,
            "system_cas": s,
            "pins": pins,
        }
        domain_rules.append(rule)
        if cleartext:
            cleartext_global = True
        if u:
            user_cas = True
        if pins:
            pin_sets.append({"domains": domains, "pins": pins})

    if user_cas:
        findings.append(
            Finding(
                level=HIGH,
                title="network_security_config 信任用户自定义 CA",
                detail=(
                    "<trust-anchors> 包含 src=\"user\"，用户/攻击者手动安装的"
                    "证书可对该应用的 HTTPS 流量实施中间人解密，等同于关闭传输层"
                    "防窃听保护。生产包不应出现该配置。"
                ),
                location=target_entry,
                recommendation=(
                    '删除 <certificates src="user" .../>，仅保留 src="system"，'
                    "调试需求通过 debug-overrides 限定。"
                ),
                rule_id="NSC-USER-CA",
            )
        )
    if cleartext_global:
        findings.append(
            Finding(
                level=MEDIUM,
                title="network_security_config 放开明文流量",
                detail=(
                    "base-config 或某条 domain-config 设置 "
                    "cleartextTrafficPermitted=\"true\"，相关域名允许 HTTP 明文"
                    "传输，存在窃听与中间人篡改风险。"
                ),
                location=target_entry,
                recommendation=(
                    "全局显式设置 cleartextTrafficPermitted=\"false\"，逐域名"
                    "收敛例外并推动服务端 HTTPS 化。"
                ),
                rule_id="NSC-CLEARTEXT",
            )
        )
    if not pin_sets:
        findings.append(
            Finding(
                level=INFO,
                title="未配置证书固定 (pin-set)",
                detail=(
                    "没有任何 domain-config 配置 <pin-set>，在系统 CA 被攻破或"
                    "企业代理场景下缺少二次防护。"
                ),
                location=target_entry,
                recommendation="对核心业务域名增加 SPKI 证书固定。",
                rule_id="NSC-NO-PIN",
            )
        )

    return NetSecConfig(
        cleartext_permitted=cleartext_global,
        user_cas_trusted=user_cas,
        system_cas_trusted=system_cas,
        domain_rules=domain_rules,
        pin_sets=pin_sets,
        findings=findings,
    )


# ------------------------------------------------------------- risk analysis
def analyze_risks(
    info: ManifestInfo,
    netsec: Optional[NetSecConfig],
    target_sdk_default: int = 0,
) -> List[Finding]:
    findings: List[Finding] = []
    target = info.target_sdk if isinstance(info.target_sdk, int) else target_sdk_default

    # --------------------------------------------------- application-level
    if info.debuggable:
        findings.append(
            Finding(
                level=HIGH,
                title="android:debuggable=\"true\" 出现在生产清单",
                detail=(
                    "应用可被任意调试器 (adb/jdwp) 附加，攻击者可读取进程内存、"
                    "绕过本地校验、动态注入代码。生产版本必须关闭。"
                ),
                location="application",
                recommendation="发布构建移除 debuggable，或仅在 debug 变体设置。",
                rule_id="MANIFEST-DEBUGGABLE",
            )
        )
    if info.test_only:
        findings.append(
            Finding(
                level=HIGH,
                title="android:testOnly=\"true\"",
                detail=(
                    "testOnly 应用只能通过 adb/IDE 安装，出现于分发渠道说明构建"
                    "流程泄漏了调试产物。"
                ),
                location="application",
                recommendation="检查 CI 发布流水线，禁止 testOnly 包进入分发。",
                rule_id="MANIFEST-TESTONLY",
            )
        )

    # allowBackup: default true until API 31; still risky when explicit.
    if info.allow_backup is True:
        findings.append(
            Finding(
                level=MEDIUM,
                title="android:allowBackup=\"true\"",
                detail=(
                    "应用数据可通过 adb backup / 设备迁移导出，本地存储的 token、"
                    "账号信息可能被物理接触设备的攻击者获取。"
                ),
                location="application",
                recommendation=(
                    "设置 allowBackup=\"false\"；确需备份时使用 dataExtractionRules"
                    " 精细化排除敏感文件。"
                ),
                rule_id="MANIFEST-ALLOWBACKUP",
            )
        )
    elif info.allow_backup is None and target and target < 31:
        findings.append(
            Finding(
                level=INFO,
                title="未显式声明 allowBackup (旧版 targetSdk 默认为 true)",
                detail=(
                    f"targetSdkVersion={target} (<31)，allowBackup 缺省为 true，"
                    "存在与显式开启相同的数据备份暴露面。"
                ),
                location="application",
                recommendation='显式声明 android:allowBackup="false" 或配置备份规则。',
                rule_id="MANIFEST-ALLOWBACKUP-DEFAULT",
            )
        )

    # Cleartext: manifest flag + NSC combined view.
    nsc_cleartext = bool(netsec and netsec.cleartext_permitted)
    nsc_missing_error = bool(netsec and netsec.parse_error)
    if info.uses_cleartext is True or nsc_cleartext:
        findings.append(
            Finding(
                level=MEDIUM,
                title="允许 HTTP 明文流量",
                detail=(
                    "usesCleartextTraffic=\"true\""
                    + ("，且 network_security_config 也放行了明文" if nsc_cleartext else "")
                    + "，HTTP 请求可被网络侧窃听/篡改。"
                ),
                location="application",
                recommendation=(
                    '设置 usesCleartextTraffic="false"，全部接口迁移 HTTPS，'
                    "必要例外收敛到具体域名。"
                ),
                rule_id="MANIFEST-CLEARTEXT",
            )
        )
    elif info.uses_cleartext is None and target and target < 28 and not nsc_cleartext:
        findings.append(
            Finding(
                level=INFO,
                title="未显式关闭明文流量 (API < 28 默认允许)",
                detail=(
                    f"targetSdkVersion={target} (<28) 时系统默认允许明文 HTTP，"
                    "建议显式关闭。"
                ),
                location="application",
                recommendation='设置 android:usesCleartextTraffic="false"。',
                rule_id="MANIFEST-CLEARTEXT-DEFAULT",
            )
        )
    if nsc_missing_error:
        findings.append(
            Finding(
                level=MEDIUM,
                title="networkSecurityConfig 引用无法解析",
                detail=netsec.parse_error or "",
                location="application",
                recommendation="核对 res/xml 路径与资源引用，确保配置随包发布。",
                rule_id="NSC-MISSING",
            )
        )
    if netsec:
        findings.extend(netsec.findings)

    # --------------------------------------------------------- permissions
    for perm in info.uses_permissions:
        name = perm.get("name") or ""
        if name in DANGEROUS_OR_SENSITIVE_PERMS:
            findings.append(
                Finding(
                    level=INFO,
                    title=f"申请敏感权限: {name}",
                    detail=(
                        "运行时敏感权限，需在业务场景中确认最小化授予；权限本身"
                        "不是漏洞，但扩大了数据泄露面。"
                    ),
                    location="uses-permission",
                    recommendation="核对该权限是否为功能必需，移除非必要申请。",
                    rule_id="PERM-SENSITIVE",
                )
            )
    for cp in info.custom_permissions:
        level = cp.get("protectionLevel")
        if level in ("normal", None) and cp.get("tag") == "permission":
            findings.append(
                Finding(
                    level=MEDIUM,
                    title=(
                        f"自定义权限 {cp.get('name')} 使用 "
                        f"protectionLevel={level or 'normal(默认)'}"
                    ),
                    detail=(
                        "normal 级别自定义权限可被任意第三方应用声明获取，"
                        "无法真正保护导出组件；应使用 signature 级别。"
                    ),
                    location=cp.get("tag") or "permission",
                    recommendation=(
                        '设置 android:protectionLevel="signature"，使仅同签名'
                        "应用可持有该权限。"
                    ),
                    rule_id="PERM-CUSTOM-WEAK",
                )
            )

    # ---------------------------------------------------------- components
    findings.extend(_component_findings(info, target))
    return findings


def _component_findings(info: ManifestInfo, target: int) -> List[Finding]:
    out: List[Finding] = []
    for comp in info.components:
        loc = f"{comp.kind}[{comp.name}]"
        if not comp.exported:
            if comp.implicit_export:
                # implicit_export true implies exported effective true; skip.
                pass
            continue

        all_actions = {
            a for f in comp.filters for a in f["actions"]
        }
        has_browser = bool(all_actions & BROWSER_ACTIONS)
        has_launcher = bool(all_actions & LAUNCHER_ACTIONS)
        guarded = bool(comp.permission)

        if comp.kind == "activity":
            if has_launcher and not has_browser and len(comp.filters) == 1:
                # Plain launcher icon: expected exposure.
                level = INFO
                title = "启动器 Activity 对外导出（预期行为）"
                detail = "MAIN/LAUNCHER 入口需要导出，确认其不接收敏感 deep link 参数。"
                rule = "COMP-LAUNCHER"
            elif has_browser:
                level = HIGH
                title = "导出 Activity 注册了 VIEW deep link，可被浏览器/任意应用调起"
                detail = (
                    "携带 http(s)/自定义 scheme 的 VIEW intent-filter 使该组件"
                    "可从网页或恶意应用唤起；若未校验调用方与参数，存在越权操作、"
                    "URL 跳转、参数注入风险。"
                )
                rule = "COMP-ACTIVITY-DEEPLINK"
            else:
                level = MEDIUM
                title = "导出的 Activity 可被第三方应用调起"
                detail = (
                    "导出 Activity 是组件越权的主要入口，需确认内部所有功能都做"
                    "了调用方校验，且不通过 intent extras 传递敏感指令。"
                )
                rule = "COMP-ACTIVITY-EXPORT"
        elif comp.kind == "activity-alias":
            level = MEDIUM
            title = "导出的 activity-alias 暴露目标 Activity"
            detail = (
                "activity-alias 的导出属性独立于目标 Activity，常被遗漏；其"
                "intent-filter 同样可被外部利用。"
            )
            rule = "COMP-ALIAS-EXPORT"
        elif comp.kind == "service":
            if guarded:
                level = MEDIUM
                title = f"导出 Service 受权限 {comp.permission} 保护"
                detail = (
                    "导出 Service 仍可被持有对应权限的应用绑定；确认权限为 "
                    "signature 级别且 onBind 内部有二次校验。"
                )
            else:
                level = HIGH
                title = "导出 Service 无权限保护"
                detail = (
                    "任意应用可 startService/bindService 调用其导出接口，"
                    "历史上大量远程命令执行、文件读写漏洞出自此类组件。"
                )
            rule = "COMP-SERVICE-EXPORT"
        elif comp.kind == "receiver":
            if guarded:
                level = MEDIUM
                title = f"导出 Receiver 受权限 {comp.permission} 保护"
                detail = "确认保护权限为 signature 级别，并校验 onReceive 的 action。"
            else:
                level = HIGH
                title = "导出 BroadcastReceiver 无权限保护"
                detail = (
                    "任意应用可向其投递伪造广播，触发组件内逻辑；若处理 intent "
                    "extras 中的指令/URL，可导致越权操作。"
                )
            rule = "COMP-RECEIVER-EXPORT"
        else:  # provider
            level = HIGH
            title = "导出 ContentProvider"
            detail = (
                "ContentProvider 导出后可被第三方应用 query/insert/update/openFile，"
                "历史漏洞多为路径穿越与数据批量泄露；必须检查 readPermission/"
                "writePermission、grantUriPermissions 与 path-permission 配置。"
            )
            rule = "COMP-PROVIDER-EXPORT"
            grant = comp.raw.get("grantUriPermissions")
            if grant is True:
                detail += (
                    " 该 Provider 还开启了 grantUriPermissions，URI 临时授权"
                    "可能绕过读写权限限制。"
                )

        if comp.implicit_export and target and target >= 31:
            out.append(
                Finding(
                    level=HIGH,
                    title=f"{loc} 依赖 intent-filter 隐式导出但未显式声明 exported",
                    detail=(
                        "targetSdkVersion>=31 时，带 intent-filter 的组件必须显式"
                        "声明 android:exported，否则安装失败；低版本设备上则会"
                        "静默导出，行为不可控。"
                    ),
                    location=loc,
                    recommendation='显式设置 android:exported="true|false"。',
                    rule_id="COMP-IMPLICIT-EXPORT",
                )
            )
        if comp.implicit_export and (not target or target < 31):
            detail_extra = (
                " 该组件未显式设置 exported，因含 intent-filter 在 API<31 上被"
                "系统隐式导出——这是最常见的意外暴露来源。"
            )
            detail += detail_extra

        rec = {
            "COMP-ACTIVITY-DEEPLINK": (
                "对 deep link 参数做白名单校验，敏感操作要求调用方为可信应用或"
                "增加用户确认；非必要的 scheme/host 立即移除。"
            ),
            "COMP-SERVICE-EXPORT": (
                '无需跨应用调用时设置 exported="false"；必须导出时增加 '
                'signature 级自定义权限并在 onBind/onStartCommand 校验。'
            ),
            "COMP-RECEIVER-EXPORT": (
                '本地广播改用 LocalBroadcastManager/上下文注册并 exported="false"；'
                "必须跨应用时用 signature 权限保护并校验 action。"
            ),
            "COMP-PROVIDER-EXPORT": (
                '非共享数据一律 exported="false"；必须导出时配置 readPermission/'
                "writePermission 与 path-permission，关闭 grantUriPermissions。"
            ),
        }.get(
            rule,
            '无需对外暴露时设置 android:exported="false"；必须导出时加 signature '
            "级权限并校验调用方包名/签名。",
        )

        out.append(
            Finding(
                level=level,
                title=title,
                detail=detail,
                location=loc,
                recommendation=rec,
                rule_id=rule,
            )
        )
    return out


def overall_level(findings: List[Finding]) -> str:
    if not findings:
        return INFO
    return min((f.level for f in findings), key=lambda x: LEVEL_ORDER[x])


def score(findings: List[Finding]) -> int:
    """0 (clean) .. 100 (worst). Weighted from finding counts."""
    weights = {CRITICAL: 25, HIGH: 12, MEDIUM: 5, INFO: 1}
    raw = sum(weights[f.level] for f in findings)
    return min(100, raw)


def rating(score_value: int) -> str:
    if score_value >= 60:
        return "高危"
    if score_value >= 30:
        return "中危"
    if score_value > 0:
        return "低危"
    return "通过"
