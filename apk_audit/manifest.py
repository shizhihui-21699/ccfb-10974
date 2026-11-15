"""AndroidManifest 分析模型。

从二进制 AXML 解析出的元素树中抽取审计关心的结构化信息：
  - 包名 / SDK / 应用标志（debuggable、allowBackup、usesCleartextTraffic…）
  - 自定义权限与 uses-permission
  - 四大组件 + activity-alias，含导出判定与 intent-filter
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .axml import ANDROID_NS, Element, parse_axml

COMPONENT_TAGS = ("activity", "service", "receiver", "provider", "activity-alias")
# 含 intent-filter 时的历史默认导出状态（API 31 之前）
DEFAULT_EXPORTED_WITH_FILTER = {
    "activity": True,
    "service": True,
    "receiver": True,
    "activity-alias": True,
    "provider": False,  # provider 历史默认导出（仅 minSdk<17），见下方专门处理
}


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    mime_types: list[str] = field(default_factory=list)

    @property
    def is_launcher(self) -> bool:
        return (
            "android.intent.action.MAIN" in self.actions
            and "android.intent.category.LAUNCHER" in self.categories
        )

    @property
    def has_dispatch(self) -> bool:
        """是否包含可被外部触发的分派动作（非纯内部 category）。"""
        return bool(self.actions or self.schemes or self.mime_types)


@dataclass
class Component:
    kind: str
    name: str
    exported: bool | None               # 显式声明值，None = 未声明
    effective_exported: bool            # 结合默认规则算出的实际暴露状态
    exported_source: str                # 判定依据，用于报告解释
    permission: str | None              # android:permission
    read_permission: str | None
    write_permission: str | None
    enabled: bool
    intent_filters: list[IntentFilter]
    grant_uri_permissions: bool
    raw: dict

    @property
    def has_filter(self) -> bool:
        return bool(self.intent_filters)


@dataclass
class CustomPermission:
    name: str
    protection_level: str
    raw: dict


@dataclass
class ManifestModel:
    package: str
    version_name: str | None
    version_code: str | None
    shared_user_id: str | None
    min_sdk: int | None
    target_sdk: int | None
    max_sdk: int | None
    app_flags: dict
    components: list[Component]
    uses_permissions: list[str]
    uses_permissions_sdk23: list[str]   # uses-permission-sdk-23
    custom_permissions: list[CustomPermission]
    network_security_config: str | None
    root: Element


def _as_bool(v, default=False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).lower() == "true"


def _int_or_none(v):
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        # 平台预览版 targetSdk 可能是代号字符串（如 "UpsideDownCake"）
        return None


def _parse_filter(elem: Element) -> IntentFilter:
    f = IntentFilter()
    for child in elem.children:
        if child.tag == "action":
            name = child.get("name")
            if name:
                f.actions.append(str(name))
        elif child.tag == "category":
            name = child.get("name")
            if name:
                f.categories.append(str(name))
        elif child.tag == "data":
            scheme = child.get("scheme")
            host = child.get("host")
            mime = child.get("mimeType")
            if scheme:
                f.schemes.append(str(scheme))
            if host:
                f.hosts.append(str(host))
            if mime:
                f.mime_types.append(str(mime))
    return f


class ManifestAnalyzer:
    def __init__(self, data: bytes):
        self.root = parse_axml(data)
        if self.root.tag != "manifest":
            raise ValueError("AXML 根元素不是 <manifest>")

    # ------------------------------------------------------------------
    def analyze(self) -> ManifestModel:
        root = self.root
        app = root.find("application")

        model = ManifestModel(
            package=str(root.get("package", ns=None, default="")),
            version_name=root.get("versionName"),
            version_code=str(root.get("versionCode")) if root.get("versionCode") is not None else None,
            shared_user_id=root.get("sharedUserId"),
            min_sdk=None,
            target_sdk=None,
            max_sdk=None,
            app_flags=self._app_flags(app),
            components=[],
            uses_permissions=[],
            uses_permissions_sdk23=[],
            custom_permissions=[],
            network_security_config=None,
            root=root,
        )
        self._extract_sdks(root, model)
        self._extract_permissions(root, model)
        if app is not None:
            model.network_security_config = app.get("networkSecurityConfig")
            model.components = self._extract_components(app, model)
        return model

    # ------------------------------------------------------------------
    def _app_flags(self, app: Element | None) -> dict:
        if app is None:
            return {}
        flag_names = (
            "debuggable",
            "allowBackup",
            "usesCleartextTraffic",
            "testOnly",
            "allowTaskReparenting",
            "hasCode",
            "persistent",
            "enabled",
        )
        flags = {}
        for name in flag_names:
            v = app.get(name)
            if v is not None:
                flags[name] = _as_bool(v) if isinstance(v, bool) else v
        return flags

    def _extract_sdks(self, root: Element, model: ManifestModel):
        for elem in root.children:
            if elem.tag == "uses-sdk":
                model.min_sdk = _int_or_none(elem.get("minSdkVersion"))
                model.target_sdk = _int_or_none(elem.get("targetSdkVersion"))
                model.max_sdk = _int_or_none(elem.get("maxSdkVersion"))

    def _extract_permissions(self, root: Element, model: ManifestModel):
        for elem in root.children:
            if elem.tag == "uses-permission":
                name = elem.get("name")
                if name:
                    model.uses_permissions.append(str(name))
            elif elem.tag == "uses-permission-sdk-23":
                name = elem.get("name")
                if name:
                    model.uses_permissions_sdk23.append(str(name))
            elif elem.tag == "permission":
                name = elem.get("name")
                if name:
                    model.custom_permissions.append(
                        CustomPermission(
                            name=str(name),
                            protection_level=str(
                                elem.get("protectionLevel", default="normal")
                            ),
                            raw=elem.all_attrs(),
                        )
                    )

    # ------------------------------------------------------------------
    def _extract_components(self, app: Element, model: ManifestModel) -> list[Component]:
        out: list[Component] = []
        for elem in app.children:
            if elem.tag not in COMPONENT_TAGS:
                continue
            name = str(elem.get("name", default=""))
            exported_attr = elem.get("exported")
            exported = None if exported_attr is None else _as_bool(exported_attr)
            filters = [
                _parse_filter(c) for c in elem.children if c.tag == "intent-filter"
            ]
            grant = any(
                c.tag == "grant-uri-permission" for c in elem.children
            )

            effective, source = self._resolve_exported(
                elem.tag, exported, bool(filters), model
            )
            out.append(
                Component(
                    kind=elem.tag,
                    name=name,
                    exported=exported,
                    effective_exported=effective,
                    exported_source=source,
                    permission=elem.get("permission"),
                    read_permission=elem.get("readPermission"),
                    write_permission=elem.get("writePermission"),
                    enabled=_as_bool(elem.get("enabled"), default=True),
                    intent_filters=filters,
                    grant_uri_permissions=grant,
                    raw=elem.all_attrs(),
                )
            )
        return out

    def _resolve_exported(
        self,
        kind: str,
        exported: bool | None,
        has_filter: bool,
        model: ManifestModel,
    ) -> tuple[bool, str]:
        """按平台版本规则计算组件的实际暴露状态。"""
        if exported is not None:
            if exported:
                return True, "显式 android:exported=\"true\""
            return False, "显式 android:exported=\"false\""

        target = model.target_sdk
        # API 31+：含 intent-filter 必须显式声明，否则安装失败；
        # 无 filter 的组件默认不导出
        if target is not None and target >= 31:
            if has_filter:
                return False, "targetSdk>=31 且未声明 exported（含 filter，安装期将被拒）"
            return False, "未声明 exported，默认不导出"

        if has_filter:
            default = DEFAULT_EXPORTED_WITH_FILTER[kind]
            if default:
                return True, "含 intent-filter 且未声明 exported，历史默认导出"
            # provider 含 filter 的情形仍走 provider 规则
        if kind == "provider":
            # minSdkVersion < 17 时 provider 默认导出；>=17 默认不导出
            if model.min_sdk is not None and model.min_sdk < 17:
                return True, "provider 且 minSdk<17，历史默认导出"
            return False, "provider 默认不导出（minSdk>=17）"
        return False, "未声明 exported，默认不导出"


def analyze_manifest(data: bytes) -> ManifestModel:
    return ManifestAnalyzer(data).analyze()
