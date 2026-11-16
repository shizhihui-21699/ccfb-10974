"""Semantic model of AndroidManifest.xml built on top of the AXML parser.

Produces a :class:`Manifest` with components (activity, service, receiver,
provider), intent filters, permissions and the application-level flags an
auditor cares about (debuggable, allowBackup, cleartext, testOnly, ...).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

from . import binxml
from .binxml import Document, Element

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "读取短信",
    "android.permission.RECEIVE_SMS": "接收短信",
    "android.permission.SEND_SMS": "发送短信",
    "android.permission.READ_CALL_LOG": "读取通话记录",
    "android.permission.WRITE_CALL_LOG": "写入通话记录",
    "android.permission.CALL_PHONE": "拨打电话",
    "android.permission.READ_CONTACTS": "读取联系人",
    "android.permission.WRITE_CONTACTS": "写入联系人",
    "android.permission.READ_CALENDAR": "读取日历",
    "android.permission.WRITE_CALENDAR": "写入日历",
    "android.permission.ACCESS_FINE_LOCATION": "精确定位",
    "android.permission.ACCESS_COARSE_LOCATION": "粗略定位",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "后台定位",
    "android.permission.CAMERA": "相机",
    "android.permission.RECORD_AUDIO": "录音",
    "android.permission.READ_EXTERNAL_STORAGE": "读取外部存储",
    "android.permission.WRITE_EXTERNAL_STORAGE": "写入外部存储",
    "android.permission.READ_MEDIA_IMAGES": "读取图片",
    "android.permission.READ_MEDIA_VIDEO": "读取视频",
    "android.permission.READ_MEDIA_AUDIO": "读取音频",
    "android.permission.READ_PHONE_STATE": "读取电话状态",
    "android.permission.READ_PHONE_NUMBERS": "读取本机号码",
    "android.permission.PROCESS_OUTGOING_CALLS": "监听外拨电话",
    "android.permission.BODY_SENSORS": "身体传感器",
    "android.permission.ACTIVITY_RECOGNITION": "活动识别",
    "android.permission.GET_ACCOUNTS": "读取账户",
    "android.permission.READ_CONTACTS": "读取联系人",
    "android.permission.QUERY_ALL_PACKAGES": "枚举已安装应用",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "管理所有文件",
    "android.permission.SYSTEM_ALERT_WINDOW": "悬浮窗",
    "android.permission.REQUEST_INSTALL_PACKAGES": "安装应用",
    "android.permission.PACKAGE_USAGE_STATS": "使用情况统计",
    "android.permission.POST_NOTIFICATIONS": "发送通知",
}

HIGH_RISK_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "无障碍服务（可读取屏幕、代操作）",
    "android.permission.BIND_DEVICE_ADMIN": "设备管理器",
    "android.permission.BIND_VPN_SERVICE": "VPN 服务",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "通知读取",
    "android.permission.BIND_INPUT_METHOD": "输入法",
    "android.permission.SYSTEM_ALERT_WINDOW": "悬浮窗",
    "android.permission.REQUEST_INSTALL_PACKAGES": "静默安装风险",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "挂载文件系统",
    "android.permission.WRITE_SETTINGS": "修改系统设置",
    "android.permission.WRITE_SECURE_SETTINGS": "修改安全设置",
    "android.permission.READ_LOGS": "读取系统日志",
    "android.permission.REBOOT": "重启设备",
    "android.permission.MASTER_CLEAR": "恢复出厂",
}


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[dict[str, str]] = field(default_factory=list)
    priority: Optional[int] = None
    auto_verify: Optional[bool] = None

    @property
    def has_browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories

    @property
    def has_default(self) -> bool:
        return "android.intent.category.DEFAULT" in self.categories

    def schemes(self) -> list[str]:
        return [d["scheme"] for d in self.data if "scheme" in d]

    def hosts(self) -> list[str]:
        return [d["host"] for d in self.data if "host" in d]

    def describe(self) -> str:
        parts = []
        if self.actions:
            parts.append("action=" + ",".join(self.actions))
        if self.categories:
            parts.append("category=" + ",".join(self.categories))
        for d in self.data:
            bits = " ".join(f"{k}={v}" for k, v in d.items())
            parts.append(f"data({bits})")
        return " | ".join(parts)


@dataclass
class Component:
    kind: str  # activity | activity-alias | service | receiver | provider
    name: str
    exported: Optional[bool]  # None means "not declared"
    enabled: Optional[bool]
    permission: Optional[str]
    process: Optional[str]
    direct_boot_aware: Optional[bool]
    intent_filters: list[IntentFilter] = field(default_factory=list)
    # provider-specific
    authorities: list[str] = field(default_factory=list)
    grant_uri_permissions: Optional[bool] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    has_forward_target: bool = False  # targetActivity on activity-alias
    target_activity: Optional[str] = None

    @property
    def implicitly_exported(self) -> bool:
        return self.exported is None and bool(self.intent_filters)

    @property
    def is_exported(self) -> bool:
        if self.exported is not None:
            return self.exported
        return bool(self.intent_filters)

    @property
    def declared_exported_false_but_filters(self) -> bool:
        return self.exported is False and bool(self.intent_filters)


@dataclass
class PermissionDecl:
    name: str
    protection_level: Optional[str]
    protection_flags: str
    permission_group: Optional[str]


@dataclass
class Manifest:
    package: str = ""
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    shared_user_id: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    max_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    uses_permissions: list[tuple[str, Optional[int]]] = field(default_factory=list)
    declared_permissions: list[PermissionDecl] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    application: Optional[Element] = None
    debuggable: Optional[bool] = None
    allow_backup: Optional[bool] = None
    full_backup_content: Optional[str] = None
    data_extraction_rules: Optional[str] = None
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    test_only: Optional[bool] = None
    has_application: bool = False
    application_name: Optional[str] = None
    app_label: Optional[str] = None
    task_reparenting: Optional[bool] = None
    request_legacy_storage: Optional[bool] = None
    extract_native_libs: Optional[bool] = None
    root: Optional[Element] = None
    raw_document: Optional[Document] = None
    warnings: list[str] = field(default_factory=list)

    def permissions_named(self) -> set[str]:
        return {name for name, _ in self.uses_permissions}

    def components_of(self, kind: str) -> list[Component]:
        return [c for c in self.components if c.kind == kind]

    def exported_components(self) -> list[Component]:
        return [c for c in self.components if c.is_exported]

    def iter_intent_filters(self) -> Iterator[tuple[Component, IntentFilter]]:
        for comp in self.components:
            for f in comp.intent_filters:
                yield comp, f


def _component_from(el: Element) -> Component:
    kind = el.name
    comp = Component(
        kind=kind,
        name=el.value("name") or "<unknown>",
        exported=el.flag("exported"),
        enabled=el.flag("enabled"),
        permission=el.value("permission"),
        process=el.value("process"),
        direct_boot_aware=el.flag("directBootAware"),
        grant_uri_permissions=el.flag("grantUriPermissions"),
        read_permission=el.value("readPermission"),
        write_permission=el.value("writePermission"),
    )
    if kind == "provider":
        auth = el.value("authorities") or ""
        comp.authorities = [a.strip() for a in auth.split(";") if a.strip()]
    if kind == "activity-alias":
        comp.target_activity = el.value("targetActivity")
        comp.has_forward_target = bool(comp.target_activity)
    for f_el in el.children_named("intent-filter"):
        flt = IntentFilter(
            priority=f_el.int_value("priority"),
            auto_verify=f_el.flag("autoVerify"),
        )
        for child in f_el.children:
            if child.name == "action":
                a = child.value("name")
                if a:
                    flt.actions.append(a)
            elif child.name == "category":
                c = child.value("name")
                if c:
                    flt.categories.append(c)
            elif child.name == "data":
                d: dict[str, str] = {}
                for key in (
                    "scheme",
                    "host",
                    "port",
                    "path",
                    "pathPrefix",
                    "pathPattern",
                    "pathAdvancedPattern",
                    "pathSuffix",
                    "mimeType",
                    "ssp",
                    "sspPrefix",
                    "sspPattern",
                ):
                    v = child.value(key)
                    if v:
                        d[key] = v
                if d:
                    flt.data.append(d)
        comp.intent_filters.append(flt)
    return comp


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        # Previews use codenames such as "S" / "Tiramisu" / "VanillaIceCream".
        return None


def parse_manifest(document: Document) -> Manifest:
    m = Manifest(raw_document=document)
    root = document.root
    if root is None:
        m.warnings.append("manifest has no root element")
        return m
    m.root = root
    if root.name != "manifest":
        m.warnings.append(f"root element is <{root.name}>, not <manifest>")
    m.package = root.value("package", ns=None) or ""
    if not m.package:
        m.warnings.append("manifest declares an empty package name")
    m.version_code = root.int_value("versionCode")
    m.version_name = root.value("versionName")
    m.shared_user_id = root.value("sharedUserId")
    m.compile_sdk = _int_or_none(root.value("compileSdkVersion", ns=None))

    for child in root.children:
        if child.name == "uses-sdk":
            m.min_sdk = child.int_value("minSdkVersion")
            m.target_sdk = child.int_value("targetSdkVersion")
            m.max_sdk = child.int_value("maxSdkVersion")
            if m.target_sdk is None:
                explicit = child.value("targetSdkVersion")
                if explicit is None and m.min_sdk is not None:
                    m.target_sdk = m.min_sdk  # platform default
        elif child.name == "uses-permission":
            name = child.value("name")
            if name:
                m.uses_permissions.append((name, child.int_value("maxSdkVersion")))
        elif child.name == "uses-permission-sdk-23":
            name = child.value("name")
            if name:
                m.uses_permissions.append((name, child.int_value("maxSdkVersion")))
        elif child.name == "permission":
            name = child.value("name")
            level = child.int_value("protectionLevel")
            if name:
                m.declared_permissions.append(
                    PermissionDecl(
                        name=name,
                        protection_level=(
                            _protection_level_str(level) if level is not None else None
                        ),
                        protection_flags=_protection_flags_str(level or 0),
                        permission_group=child.value("permissionGroup"),
                    )
                )
        elif child.name == "application":
            if m.has_application:
                m.warnings.append("multiple <application> elements")
            m.has_application = True
            m.application = child
            _read_application(m, child)
        elif child.name in COMPONENT_TAGS:
            m.warnings.append(f"<{child.name}> declared outside <application>")
            m.components.append(_component_from(child))
    if not m.has_application:
        m.warnings.append("manifest has no <application> element")
    _detect_duplicates(m)
    return m


def _read_application(m: Manifest, app: Element) -> None:
    m.debuggable = app.flag("debuggable")
    m.allow_backup = app.flag("allowBackup")
    m.full_backup_content = app.value("fullBackupContent")
    m.data_extraction_rules = app.value("dataExtractionRules")
    m.uses_cleartext_traffic = app.flag("usesCleartextTraffic")
    m.network_security_config = app.value("networkSecurityConfig")
    m.test_only = app.flag("testOnly")
    m.application_name = app.value("name")
    m.app_label = app.value("label")
    m.task_reparenting = app.flag("allowTaskReparenting")
    m.request_legacy_storage = app.flag("requestLegacyExternalStorage")
    m.extract_native_libs = app.flag("extractNativeLibs")
    for child in app.children:
        if child.name in COMPONENT_TAGS:
            comp = _component_from(child)
            if child.name == "provider":
                # Merged manifest may list provider split across elements;
                # duplicates are detected later.
                pass
            m.components.append(comp)
        elif child.name == "meta-data":
            pass
        elif child.name in ("activity", "service", "receiver", "provider"):
            pass


def _detect_duplicates(m: Manifest) -> None:
    seen_providers: dict[str, int] = {}
    for comp in m.components:
        if comp.kind == "provider":
            for auth in comp.authorities:
                if auth in seen_providers:
                    m.warnings.append(
                        f"duplicate provider authority {auth!r} "
                        f"declared by {comp.name}"
                    )
                seen_providers[auth] = seen_providers.get(auth, 0) + 1
    names: dict[tuple[str, str], int] = {}
    for comp in m.components:
        key = (comp.kind, comp.name)
        names[key] = names.get(key, 0) + 1
    for (kind, name), count in names.items():
        if count > 1:
            m.warnings.append(f"duplicate <{kind}> declaration for {name}")


_PROTECTION_BASE = {
    0x00: "normal",
    0x01: "dangerous",
    0x02: "signature",
    0x03: "signatureOrSystem",
    0x04: "internal",
}


def _protection_level_str(level: int) -> str:
    return _PROTECTION_BASE.get(level & 0xF, f"0x{level & 0xF:x}")


def _protection_flags_str(level: int) -> str:
    names = []
    masks = {
        0x10: "privileged",
        0x20: "development",
        0x40: "appop",
        0x80: "pre23",
        0x100: "installer",
        0x200: "verifier",
        0x400: "preinstalled",
        0x800: "setup",
        0x1000: "instant",
        0x2000: "ephemeral",
        0x4000: "movedToInstaller",
        0x8000: "runtime",
    }
    for bit, name in masks.items():
        if level & bit:
            names.append(name)
    return "|".join(names)


def parse_manifest_bytes(data: bytes) -> Manifest:
    return parse_manifest(binxml.parse_axml(data))
