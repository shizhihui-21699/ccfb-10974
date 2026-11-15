"""风险规则引擎。

分级标准（团队约定，可在报告中直接引用）：
  CRITICAL  可直接导致设备/数据被攻破：debug 标志、暴露且无保护的敏感组件
  HIGH      显著放大攻击面或削弱签名/信任：明文流量、用户 CA、备份、签名缺失
  MEDIUM    需要特定条件才可利用：带权限保护的导出组件、危险权限
  LOW       加固/规范类问题：显式 exported 缺失、权限保护级别偏弱
  INFO      仅作事实记录
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .manifest import Component, ManifestModel
from .netconfig import NetworkSecurityModel
from .signatures import V1Result, V2V3Result

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}
SEVERITY_SCORE_DELTA = {CRITICAL: 40, HIGH: 15, MEDIUM: 6, LOW: 2, INFO: 0}

# Android 运行时危险权限（protectionLevel=dangerous 的常见集合）
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.ACTIVITY_RECOGNITION",
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    component: str | None = None
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "component": self.component,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


# ----------------------------------------------------------------------
# intent-filter 风险说明
# ----------------------------------------------------------------------
def _filter_risk_note(comp: Component) -> str:
    notes = []
    for f in comp.intent_filters:
        if f.is_launcher:
            notes.append("启动器入口（MAIN/LAUNCHER），属正常对外暴露")
            continue
        if f.schemes:
            notes.append(
                f"注册 deep link（scheme={','.join(sorted(set(f.schemes)))}"
                f"{'，host=' + ','.join(sorted(set(f.hosts))) if f.hosts else ''}），"
                "任意 App/网页可构造 URI 调起，需校验参数防越权与跳转劫持"
            )
        if f.mime_types:
            notes.append(
                f"按 MIME 类型接收数据（{','.join(sorted(set(f.mime_types)))}），"
                "外部可向其投递文件/内容，必须做内容校验"
            )
        if any(a.endswith(".SEND") or ".SEND_" in a or a.endswith(".VIEW")
               or a.endswith(".EDIT") for a in f.actions):
            notes.append("处理 VIEW/EDIT/SEND 类动作，直接接收外部输入，注意注入与越权")
        if any(a.endswith(".BOOT_COMPLETED") for a in f.actions):
            notes.append("监听开机广播，可被唤醒，注意拒绝服务与资源滥用")
        if not notes:
            actions = ",".join(f.actions) or "（无显式 action）"
            notes.append(f"隐式 Intent 触发（action={actions}），外部 App 可发起调用")
    return "；".join(dict.fromkeys(notes))  # 去重保序


def _is_protected(comp: Component) -> bool:
    return bool(comp.permission or comp.read_permission or comp.write_permission)


# ----------------------------------------------------------------------
# 主评估器
# ----------------------------------------------------------------------
class RuleEngine:
    def __init__(
        self,
        manifest: ManifestModel,
        netcfg: NetworkSecurityModel | None,
        sigs: dict,
    ):
        self.m = manifest
        self.nc = netcfg
        self.sigs = sigs
        self.findings: list[Finding] = []

    def evaluate(self) -> list[Finding]:
        self._check_app_flags()
        self._check_components()
        self._check_permissions()
        self._check_network()
        self._check_signatures()
        self.findings.sort(
            key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.component or "")
        )
        return self.findings

    # ------------------------------------------------------------------
    def _check_app_flags(self):
        flags = self.m.app_flags
        if flags.get("debuggable") is True:
            self.findings.append(Finding(
                "MANIFEST_DEBUGGABLE", CRITICAL,
                "应用可调试（android:debuggable=true）",
                "debuggable 应用可被 adb/jdwp 附加调试，攻击者能读取运行时内存、"
                "绕过业务逻辑与证书校验，等同于开放调试后门。",
                evidence={"flag": flags.get("debuggable")},
                recommendation="发布构建必须移除 debuggable 或显式设为 false。",
            ))
        if flags.get("testOnly") is True:
            self.findings.append(Finding(
                "MANIFEST_TEST_ONLY", HIGH,
                "应用标记为 testOnly",
                "testOnly 应用仅供测试分发，可被 adb 以特殊模式安装并暴露测试入口，"
                "不应出现在第三方交付的正式包中。",
                recommendation="确认该包是否为误发的测试构建。",
            ))
        if flags.get("allowBackup") is True:
            self.findings.append(Finding(
                "MANIFEST_ALLOW_BACKUP", HIGH,
                "允许应用数据备份（android:allowBackup=true）",
                "允许 adb backup 或设备迁移导出应用私有数据，本地敏感数据（token、"
                "缓存凭证）可能被物理接触设备者取走。",
                evidence={"flag": True},
                recommendation="无备份需求时设 allowBackup=false；确需备份则配置"
                               " fullBackupContent/dataExtractionRules 排除敏感文件。",
            ))
        elif "allowBackup" not in flags:
            self.findings.append(Finding(
                "MANIFEST_BACKUP_DEFAULT", LOW,
                "未显式声明 allowBackup",
                "未声明时默认允许备份，建议显式关闭以避免私有数据被备份导出。",
                recommendation="显式设置 android:allowBackup。",
            ))

        # 明文流量：manifest 直开
        if flags.get("usesCleartextTraffic") is True:
            self.findings.append(Finding(
                "NET_CLEARTEXT_MANIFEST", HIGH,
                "Manifest 全局允许明文流量（usesCleartextTraffic=true）",
                "应用可发起 HTTP 等明文请求，链路中间人可窃听/篡改传输内容。",
                evidence={"flag": True},
                recommendation="设为 false，改用 HTTPS，并在 network_security_config "
                               "中按需收紧。",
            ))

    # ------------------------------------------------------------------
    def _check_components(self):
        target = self.m.target_sdk
        for comp in self.m.components:
            # API31+ 含 filter 却没写 exported —— 安装期问题
            if (
                comp.exported is None
                and comp.has_filter
                and target is not None and target >= 31
            ):
                self.findings.append(Finding(
                    "MANIFEST_EXPORTED_MISSING_ATTR", LOW,
                    f"{comp.kind} 含 intent-filter 但未声明 android:exported",
                    "targetSdkVersion>=31 时该组合会导致安装失败；同时显式声明可避免"
                    "不同平台默认值差异带来的意外暴露。",
                    component=comp.name,
                    recommendation="对需要对外的组件显式 exported=true，其余设 false。",
                ))

            if not comp.effective_exported:
                continue

            protected = _is_protected(comp)
            note = _filter_risk_note(comp) if comp.has_filter else "无 intent-filter，仅能通过显式 Intent 调起"
            base_evidence = {
                "kind": comp.kind,
                "exported_source": comp.exported_source,
                "permission": comp.permission,
                "readPermission": comp.read_permission,
                "writePermission": comp.write_permission,
                "intent_filters": [
                    {
                        "actions": f.actions,
                        "categories": f.categories,
                        "schemes": f.schemes,
                        "hosts": f.hosts,
                        "mime_types": f.mime_types,
                    }
                    for f in comp.intent_filters
                ],
            }

            # provider 默认更敏感（直接暴露数据面）
            if comp.kind == "provider":
                if comp.grant_uri_permissions:
                    sev = CRITICAL if not protected else HIGH
                    self.findings.append(Finding(
                        "COMP_EXPORTED_PROVIDER_GRANTURI", sev,
                        f"导出的 ContentProvider 开启 grant-uri-permission",
                        f"导出 Provider 且允许 URI 临时授权，可绕过其读写权限访问数据。"
                        f"暴露依据：{comp.exported_source}。{note}",
                        component=comp.name, evidence=base_evidence,
                        recommendation="非必要不导出；收紧 grant-uri-permission 范围并"
                                       "设置 readPermission/writePermission。",
                    ))
                elif not protected:
                    self.findings.append(Finding(
                        "COMP_EXPORTED_PROVIDER_UNPROTECTED", CRITICAL,
                        "导出的 ContentProvider 无权限保护",
                        f"任意应用可通过 ContentResolver 访问该 Provider 的数据。"
                        f"暴露依据：{comp.exported_source}。{note}",
                        component=comp.name, evidence=base_evidence,
                        recommendation="设置 signature 级读写权限或设 exported=false。",
                    ))
                else:
                    self.findings.append(Finding(
                        "COMP_EXPORTED_PROVIDER_PROTECTED", MEDIUM,
                        "导出的 ContentProvider（带权限保护）",
                        f"Provider 已导出且声明了访问权限，仍需确认权限级别是否为 "
                        f"signature。{note}",
                        component=comp.name, evidence=base_evidence,
                        recommendation="优先使用 signature 保护级别。",
                    ))
                continue

            if not protected:
                # 纯启动器入口（仅 MAIN/LAUNCHER，无其它分派面）属正常暴露，
                # 降为 LOW 提示而非高危
                only_launcher = (
                    comp.has_filter
                    and len(comp.intent_filters) == 1
                    and comp.intent_filters[0].is_launcher
                    and not comp.intent_filters[0].schemes
                    and not comp.intent_filters[0].mime_types
                )
                # 无任何权限保护的导出组件
                if comp.kind == "activity":
                    if only_launcher:
                        self.findings.append(Finding(
                            "COMP_EXPORTED_LAUNCHER", LOW,
                            "导出的启动器 Activity（MAIN/LAUNCHER）",
                            f"该 Activity 是应用桌面入口，导出属预期行为。"
                            f"暴露依据：{comp.exported_source}。仍需确认其不接受"
                            "外部可控的敏感参数。",
                            component=comp.name, evidence=base_evidence,
                            recommendation="保持现状即可；勿在 launcher Activity 暴露"
                                           "未鉴权的敏感操作。",
                        ))
                        continue
                    sev = HIGH
                    title = "导出的 Activity 无权限保护"
                    detail = (
                        "任意应用可启动该 Activity；若其承载敏感功能或接收外部参数，"
                        "可能导致越权操作、Task 劫持或界面仿冒。"
                    )
                elif comp.kind == "service":
                    sev = CRITICAL
                    title = "导出的 Service 无权限保护"
                    detail = (
                        "任意应用可绑定/启动该 Service 并触发其内部逻辑，可能造成"
                        "未授权操作或后台资源滥用。"
                    )
                elif comp.kind == "receiver":
                    sev = HIGH
                    title = "导出的 BroadcastReceiver 无权限保护"
                    detail = (
                        "任意应用可伪造广播事件触发该 Receiver，可能导致业务流程被"
                        "恶意驱动或拒绝服务。"
                    )
                else:  # activity-alias
                    sev = HIGH
                    title = "导出的 activity-alias 无权限保护"
                    detail = "activity-alias 导出后等同于被别名的 Activity 对外暴露。"
                self.findings.append(Finding(
                    f"COMP_EXPORTED_{comp.kind.upper().replace('-', '_')}_UNPROTECTED",
                    sev, title,
                    f"{detail} 暴露依据：{comp.exported_source}。{note}",
                    component=comp.name, evidence=base_evidence,
                    recommendation="非必要设 exported=false；必须对外时加 signature 权限。",
                ))
            else:
                self.findings.append(Finding(
                    f"COMP_EXPORTED_{comp.kind.upper().replace('-', '_')}_PROTECTED",
                    MEDIUM,
                    f"导出的 {comp.kind}（带权限保护）",
                    f"组件已导出并声明权限，攻击面取决于该权限的保护级别。{note}",
                    component=comp.name, evidence=base_evidence,
                    recommendation="确认权限 protectionLevel=signature；dangerous/normal "
                                   "级别仍可被第三方申请调用。",
                ))

    # ------------------------------------------------------------------
    def _check_permissions(self):
        custom = {p.name: p for p in self.m.custom_permissions}
        for name in self.m.uses_permissions:
            if name in DANGEROUS_PERMISSIONS:
                self.findings.append(Finding(
                    "PERM_DANGEROUS", MEDIUM,
                    f"申请运行时危险权限：{name}",
                    "危险权限可访问用户隐私/敏感能力，需确认与业务功能匹配，避免过度申请。",
                    evidence={"permission": name},
                    recommendation="遵循最小权限原则，移除不必要的危险权限。",
                ))
        for cperm in self.m.custom_permissions:
            level = cperm.protection_level.lower()
            if "signature" not in level:
                self.findings.append(Finding(
                    "PERM_CUSTOM_WEAK_PROTECTION", LOW,
                    f"自定义权限 {cperm.name} 保护级别偏弱（{cperm.protection_level}）",
                    "normal/dangerous 级别的自定义权限可被任意第三方应用申请，"
                    "用于保护导出组件时形同虚设。",
                    component=cperm.name,
                    evidence={"protectionLevel": cperm.protection_level},
                    recommendation="组件间内部通信改用 signature 保护级别。",
                ))
        if self.m.shared_user_id:
            self.findings.append(Finding(
                "MANIFEST_SHARED_UID", LOW,
                f"使用 sharedUserId（{self.m.shared_user_id}）",
                "sharedUserId 已废弃且要求同签名共享 UID，扩大单点失陷后的影响面。",
                recommendation="新应用不应使用 sharedUserId。",
            ))

    # ------------------------------------------------------------------
    def _check_network(self):
        nc = self.nc
        if nc is None:
            # 无配置文件：targetSdk>=28 默认禁明文，<28 默认允许
            target = self.m.target_sdk
            if target is not None and target < 28:
                self.findings.append(Finding(
                    "NET_CLEARTEXT_DEFAULT_OLD", HIGH,
                    "未配置 network_security_config 且 targetSdk<28",
                    "targetSdkVersion 低于 28 时系统默认允许全部明文流量，"
                    "且无独立 CA/域名策略。",
                    recommendation="升级 targetSdk 并提供 network_security_config 显式禁明文。",
                ))
            else:
                self.findings.append(Finding(
                    "NET_NO_CONFIG", INFO,
                    "未提供 network_security_config",
                    "targetSdk>=28 默认禁止明文、只信任系统 CA，属安全默认值；"
                    "建议仍显式提供配置以便固化策略。",
                ))
            return

        if nc.any_cleartext_permitted:
            where = []
            if nc.base_cleartext is True:
                where.append("base-config")
            if nc.debug_overrides_cleartext is True:
                where.append("debug-overrides")
                self.findings.append(Finding(
                    "NET_DEBUG_CLEARTEXT", MEDIUM,
                    "debug-overrides 允许明文",
                    "debug-overrides 仅在 debuggable 包生效；若调试配置流入正式包"
                    "将扩大明文面，需确认构建变体隔离。",
                ))
            where += [
                f"domain-config({','.join(r.domains) or '未列域名'})"
                for r in nc.domain_rules if r.cleartext is True
            ]
            self.findings.append(Finding(
                "NET_CLEARTEXT_CONFIG", HIGH,
                "network_security_config 允许明文流量",
                f"以下规则放开了 cleartextTrafficPermitted：{'; '.join(where)}。"
                "明文 HTTP 流量可被中间人窃听或篡改。",
                evidence={"rules": where},
                recommendation="全局关闭明文；确需兼容的域名用最小化 domain-config 白名单。",
            ))

        if nc.base_trust_user_ca:
            self.findings.append(Finding(
                "NET_USER_CA_BASE", HIGH,
                "base-config 信任用户安装的 CA",
                "信任用户 CA 意味着用户/攻击者导入的抓包证书可解密全部 HTTPS 流量，"
                "便利抓包的同时打开了中间人入口。",
                recommendation="移除 <certificates src=\"user\"/>，仅信任系统 CA。",
            ))
        if nc.debug_trust_user_ca:
            self.findings.append(Finding(
                "NET_USER_CA_DEBUG", MEDIUM,
                "debug-overrides 信任用户 CA",
                "调试覆盖项信任用户 CA（常见抓包配置），仅 debuggable 包生效；"
                "确认未带入正式构建。",
                recommendation="确保 release 变体不包含 debug-overrides。",
            ))
        for r in nc.domain_rules:
            if r.trust_user_ca:
                self.findings.append(Finding(
                    "NET_USER_CA_DOMAIN", HIGH,
                    "domain-config 信任用户 CA",
                    f"针对域名 {','.join(r.domains) or '（未显式列域名）'} 信任用户 CA，"
                    "这些域名的 HTTPS 可被用户导入证书中间人。",
                    recommendation="删除该 trust-anchors 中的 user 证书源。",
                ))

    # ------------------------------------------------------------------
    def _check_signatures(self):
        v1: V1Result = self.sigs["v1"]
        v2: V2V3Result = self.sigs["v2"]
        v3: V2V3Result = self.sigs["v3"]
        v31: V2V3Result = self.sigs["v3.1"]

        present = {
            "v1": v1.present,
            "v2": v2.present,
            "v3": v3.present,
            "v3.1": v31.present,
        }
        if not any(present.values()):
            self.findings.append(Finding(
                "SIG_NONE", CRITICAL,
                "APK 没有任何签名",
                "未签名 APK 无法在正常设备安装，出现该结果通常意味着文件损坏或被篡改。",
                recommendation="拒绝该交付物并要求重新签名。",
            ))
            return

        # v3.1 是 Android 13+ 的密钥轮转增强，属可选项，不参与完整性判定
        core_missing = [
            name for name in ("v1", "v2", "v3") if not present[name]
        ]
        if core_missing:
            self.findings.append(Finding(
                "SIG_SCHEME_MISSING", HIGH,
                f"核心签名方案不完整，缺少：{', '.join(core_missing)}",
                "v2/v3 是针对整包的现代签名，能防 META-INF 注入与降级；仅 v1 的包"
                "（JAR 签名）存在已知绕过面。v1 用于兼容 Android 7.0 以下，"
                "v2/v3 应同时提供。",
                evidence={"present": present},
                recommendation="使用 apksigner 同时启用 v2+v3（minSdk<24 时保留 v1）。",
            ))
        else:
            extra = "，且含可选 v3.1" if present["v3.1"] else "（v3.1 为可选项，缺失不影响）"
            self.findings.append(Finding(
                "SIG_ALL_PRESENT", INFO,
                "v1/v2/v3 核心签名方案齐全",
                f"三种核心签名块均存在{extra}。",
                evidence={"present": present},
            ))

        # v1 完整性
        if v1.present:
            if v1.entry_digest_mismatches or v1.sf_digest_mismatches:
                self.findings.append(Finding(
                    "SIG_V1_DIGEST_MISMATCH", CRITICAL,
                    "v1 签名摘要与实际内容不一致",
                    "存在条目的摘要与 MANIFEST.MF/.SF 记录不符，说明签名后文件被改动。",
                    evidence={
                        "entry_mismatches": v1.entry_digest_mismatches,
                        "sf_mismatches": v1.sf_digest_mismatches,
                    },
                    recommendation="按篡改件处理，拒绝上线。",
                ))
            if v1.crypto_verified is False:
                self.findings.append(Finding(
                    "SIG_V1_CRYPTO_FAIL", CRITICAL,
                    "v1 PKCS#7 密码学验证失败",
                    f".SF 与证书签名无法通过验证：{v1.crypto_error or '签名无效'}。",
                    recommendation="按篡改/伪造件处理。",
                ))

        # v2/v3 摘要与实际 APK 内容比对
        for res in (v2, v3, v31):
            if not res.present:
                continue
            if res.parse_error:
                self.findings.append(Finding(
                    "SIG_PARSE_ERROR", HIGH,
                    f"{res.scheme} 签名块解析失败",
                    f"签名块结构异常：{res.parse_error}",
                    recommendation="确认打包/签名工具链是否被破坏。",
                ))
            elif res.digest_matches_apk is False:
                self.findings.append(Finding(
                    "SIG_DIGEST_MISMATCH", CRITICAL,
                    f"{res.scheme} 内容摘要与 APK 实际内容不一致",
                    f"算法 {','.join(res.digest_mismatch_algos)} 的签名摘要校验失败，"
                    "签名块之后 APK 内容被改动。",
                    recommendation="按篡改件处理。",
                ))


# ----------------------------------------------------------------------
# 汇总评分
# ----------------------------------------------------------------------
def score_findings(findings: list[Finding]) -> dict:
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    score = 100
    for f in findings:
        counts[f.severity] += 1
        score -= SEVERITY_SCORE_DELTA[f.severity]
    score = max(0, score)

    if counts[CRITICAL]:
        grade = "高危（不通过）"
    elif counts[HIGH]:
        grade = "高风险（需整改后复审）"
    elif counts[MEDIUM]:
        grade = "中风险（建议整改）"
    elif counts[LOW]:
        grade = "低风险（可选优化）"
    else:
        grade = "通过"
    return {"score": score, "grade": grade, "counts": counts}
