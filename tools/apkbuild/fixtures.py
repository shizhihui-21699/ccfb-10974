"""Build the APK fixture corpus used by the auditor's tests and demo.

Every fixture is generated from source in this package; nothing is downloaded.
The corpus covers one well-configured app and a range of badly configured
ones, so rules can be tested against both positives and negatives.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from . import axml, keys, zipsign
from .axml import A

STUB_DEX = bytes.fromhex(
    "6465780a30333500000000000000000000000000000000000000000000000000"
)


@dataclass
class Fixture:
    name: str
    apk: bytes
    description: str
    expected_rules: list[str] = field(default_factory=list)
    absent_rules: list[str] = field(default_factory=list)


class ManifestBuilder:
    """Fluent builder that emits an AXML manifest."""

    def __init__(self, package: str):
        self.b = axml.AxmlBuilder()
        self.package = package
        self.arsc = axml.ArscBuilder(package_name=package)

    # -- helpers ---------------------------------------------------------
    def build(self) -> bytes:
        return self.b.to_bytes()

    def finish(self) -> tuple[bytes, bytes]:
        return self.b.to_bytes(), self.arsc.to_bytes()


def _manifest_root(
    b: axml.AxmlBuilder, package: str, version_code: int, version_name: str
) -> None:
    b.start(
        "manifest",
        [
            A("versionCode", version_code, ns=None),
            A("versionName", version_name, ns=None),
            A("package", package, ns=None),
        ],
    )


def _uses_sdk(b: axml.AxmlBuilder, min_sdk: int, target_sdk: Optional[int]) -> None:
    attrs = [A("minSdkVersion", min_sdk)]
    if target_sdk is not None:
        attrs.append(A("targetSdkVersion", target_sdk))
    b.start("uses-sdk", attrs)
    b.end("uses-sdk")


def _permission(b: axml.AxmlBuilder, name: str) -> None:
    b.start("uses-permission", [A("name", name)])
    b.end("uses-permission")


def _component(
    b: axml.AxmlBuilder,
    tag: str,
    name: str,
    extra: Optional[list[A]] = None,
    filters: Optional[list[dict]] = None,
) -> None:
    attrs = [A("name", name)] + (extra or [])
    b.start(tag, attrs)
    for flt in filters or []:
        _intent_filter(b, flt)
    b.end(tag)


def _intent_filter(b: axml.AxmlBuilder, spec: dict) -> None:
    attrs = []
    if "priority" in spec:
        attrs.append(A("priority", spec["priority"]))
    if "autoVerify" in spec:
        attrs.append(A("autoVerify", spec["autoVerify"]))
    b.start("intent-filter", attrs)
    for action in spec.get("actions", []):
        b.start("action", [A("name", action)])
        b.end("action")
    for category in spec.get("categories", []):
        b.start("category", [A("name", category)])
        b.end("category")
    for data in spec.get("data", []):
        d_attrs = []
        for key in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType"):
            if key in data:
                d_attrs.append(A(key, data[key]))
        b.start("data", d_attrs)
        b.end("data")
    b.end("intent-filter")


def _nsc_xml(
    base_cleartext: Optional[bool] = None,
    debug_overrides: Optional[dict] = None,
    domains: Optional[list[dict]] = None,
    base_trust: Optional[list[str]] = None,
    pins: Optional[list[str]] = None,
) -> bytes:
    """Build a compiled network_security_config.xml."""
    b = axml.AxmlBuilder()
    b.start("network-security-config")
    base_attrs = []
    if base_cleartext is not None:
        base_attrs.append(A("cleartextTrafficPermitted", base_cleartext, ns=None))
    if base_trust or pins:
        b.start("base-config", base_attrs)
        if base_trust:
            b.start("trust-anchors")
            for src in base_trust:
                b.start("certificates", [A("src", src, ns=None)])
                b.end("certificates")
            b.end("trust-anchors")
        if pins:
            b.start("pin-set", [A("expiration", "2030-01-01", ns=None)])
            for pin in pins:
                b.start("pin", [A("digest", pin, ns=None)])
                b.end("pin")
            b.end("pin-set")
        b.end("base-config")
    elif base_attrs:
        b.start("base-config", base_attrs)
        b.end("base-config")

    for dom in domains or []:
        attrs = []
        if "cleartext" in dom:
            attrs.append(A("cleartextTrafficPermitted", dom["cleartext"], ns=None))
        b.start("domain-config", attrs)
        for host in dom["hosts"]:
            b.start(
                "domain",
                [
                    A("includeSubdomains", dom.get("include_subdomains", True), ns=None),
                    A("name", host, ns=None),
                ],
            )
            b.end("domain")
        if "trust" in dom:
            b.start("trust-anchors")
            for src in dom["trust"]:
                b.start("certificates", [A("src", src, ns=None)])
                b.end("certificates")
            b.end("trust-anchors")
        b.end("domain-config")

    if debug_overrides is not None:
        attrs = []
        if "cleartext" in debug_overrides:
            attrs.append(
                A("cleartextTrafficPermitted", debug_overrides["cleartext"], ns=None)
            )
        b.start("debug-overrides", attrs)
        if debug_overrides.get("trust"):
            b.start("trust-anchors")
            for src in debug_overrides["trust"]:
                b.start("certificates", [A("src", src, ns=None)])
                b.end("certificates")
            b.end("trust-anchors")
        b.end("debug-overrides")
    b.end("network-security-config")
    return b.to_bytes()


def _assemble(
    manifest: bytes,
    arsc: Optional[bytes],
    extra_files: Optional[dict[str, bytes]] = None,
    dex: Optional[bytes] = None,
) -> bytes:
    zw = zipsign.ZipWriter()
    zw.add("AndroidManifest.xml", manifest)
    if arsc is not None:
        zw.add("resources.arsc", arsc)
    for name, data in sorted((extra_files or {}).items()):
        zw.add(name, data)
    zw.add("classes.dex", dex or STUB_DEX)
    return zw.build()


def _sign(
    payload: bytes,
    key: keys.PrivateKey,
    cert: bytes,
    schemes: tuple[str, ...],
    min_sdk: int = 24,
) -> bytes:
    # Locate the central directory from the EOCD.
    eocd_off = payload.rfind(b"PK\x05\x06")
    if eocd_off < 0:
        raise ValueError("no EOCD")
    cd_size, cd_offset = struct.unpack_from("<II", payload, eocd_off + 12)
    if "v1" in schemes:
        # v1 signs the archive before the v2/v3 block is inserted, so rebuild
        # the ZIP with META-INF entries included.
        raise ValueError("v1 must be applied by build_v1 first")
    return zipsign.sign_apk_v2_v3(
        payload, cd_offset, cd_size, key, cert, schemes=schemes, min_sdk=min_sdk
    )


def build_signed(
    members: list[tuple[str, bytes, bool]],
    key: keys.PrivateKey,
    cert: bytes,
    schemes: tuple[str, ...],
    min_sdk: int = 24,
) -> bytes:
    """Assemble members, apply v1 signing if requested, then v2/v3."""
    if "v1" in schemes:
        zw = zipsign.ZipWriter()
        for name, data, compress in members:
            zw.add(name, data, compress=compress)
        # Signed attributes are only understood by API 19+.
        meta = zipsign.sign_v1(
            zw.members,
            key,
            cert,
            signed_attributes=min_sdk >= 19,
            protected_schemes=tuple(s for s in schemes if s in ("v2", "v3")),
        )
        for name, data in meta.items():
            zw.add_stored(name, data)
        payload = zw.build()
    else:
        zw = zipsign.ZipWriter()
        for name, data, compress in members:
            zw.add(name, data, compress=compress)
        payload = zw.build()
    hard = tuple(s for s in schemes if s in ("v2", "v3"))
    if hard:
        payload = _sign(payload, key, cert, hard, min_sdk=min_sdk)
    return payload


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_RELEASE_KEY: Optional[keys.RsaPrivateKey] = None
_RELEASE_CERT: Optional[bytes] = None


def release_key() -> tuple[keys.RsaPrivateKey, bytes]:
    global _RELEASE_KEY, _RELEASE_CERT
    if _RELEASE_KEY is None:
        _RELEASE_KEY = keys.generate_rsa_key("apksec-fixture-release-key", 2048)
        _RELEASE_CERT, _ = keys.make_certificate(
            _RELEASE_KEY,
            "Northwind Mobile Release",
            org="Northwind Labs",
            country="US",
            days_valid=3650,
        )
        # Re-issue with an earlier epoch so the certificate is valid today.
        _RELEASE_CERT, _ = keys.make_certificate(
            _RELEASE_KEY,
            "Northwind Mobile Release",
            org="Northwind Labs",
            country="US",
            days_valid=8000,
        )
    return _RELEASE_KEY, _RELEASE_CERT


def debug_key() -> tuple[keys.PrivateKey, bytes]:
    key = keys.generate_rsa_key("apksec-fixture-android-debug", 2048)
    cert, _ = keys.make_certificate(
        key,
        "Android Debug",
        org="Android",
        country="US",
        days_valid=5000,
    )
    return key, cert


def _members(manifest: bytes, arsc: Optional[bytes], extra: Optional[dict[str, bytes]] = None):
    out: list[tuple[str, bytes, bool]] = [("AndroidManifest.xml", manifest, True)]
    if arsc is not None:
        out.append(("resources.arsc", arsc, True))
    for name, data in sorted((extra or {}).items()):
        out.append((name, data, True))
    out.append(("classes.dex", STUB_DEX, True))
    return out


# --- 1. A clean, well-configured app ---------------------------------------


def fixture_hardened() -> Fixture:
    pkg = "com.northwind.hardened"
    b = axml.AxmlBuilder()
    arsc = axml.ArscBuilder(package_name=pkg)
    _manifest_root(b, pkg, 42, "1.4.2")
    _uses_sdk(b, 26, 34)
    _permission(b, "android.permission.INTERNET")
    _permission(b, "android.permission.ACCESS_NETWORK_STATE")
    b.start(
        "application",
        [
            A("allowBackup", False),
            A("debuggable", False),
            A("usesCleartextTraffic", False),
            A("networkSecurityConfig", ("ref", arsc.add("xml", "network_security_config", "res/xml/network_security_config.xml"))),
            A("label", "Hardened"),
            A("icon", "@mipmap/ic_launcher"),
        ],
    )
    _component(
        b,
        "activity",
        pkg + ".MainActivity",
        [A("exported", True)],
        [
            {
                "actions": ["android.intent.action.MAIN"],
                "categories": ["android.intent.category.LAUNCHER"],
            }
        ],
    )
    _component(
        b,
        "activity",
        pkg + ".SettingsActivity",
        [A("exported", False)],
    )
    _component(
        b,
        "receiver",
        pkg + ".BootReceiver",
        [A("exported", False)],
        [
            {
                "actions": ["android.intent.action.BOOT_COMPLETED"],
            }
        ],
    )
    _component(
        b,
        "provider",
        pkg + ".DataProvider",
        [
            A("exported", False),
            A("authorities", pkg + ".provider"),
            A("grantUriPermissions", False),
        ],
    )
    b.end("application")
    b.end("manifest")
    manifest = b.to_bytes()

    nsc = _nsc_xml(
        base_cleartext=False,
        base_trust=["system"],
        debug_overrides={"trust": ["user"]},
        domains=[
            {
                "hosts": ["api.northwind.example"],
                "cleartext": False,
                "trust": ["system"],
            }
        ],
        pins=["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
    )
    members = _members(
        manifest,
        arsc.to_bytes(),
        {"res/xml/network_security_config.xml": nsc},
    )
    key, cert = release_key()
    apk = build_signed(members, key, cert, ("v1", "v2", "v3"), min_sdk=26)
    return Fixture(
        name="hardened.apk",
        apk=apk,
        description="配置正确的对照样本：不可调试、禁止备份、禁止明文、只信任系统 CA、组件不导出、v1+v2+v3 签名、非调试证书。",
        expected_rules=[],
        absent_rules=[
            "APP-DEBUGGABLE",
            "APP-ALLOW-BACKUP",
            "NET-CLEARTEXT-ALLOWED",
            "NET-USER-CA-TRUST",
            "SIG-V1-ONLY",
            "SIG-NO-V3",
            "COMP-EXPORTED-MISSING",
            "PROVIDER-EXPORTED-NO-PERMISSION",
            "ACTIVITY-EXPORTED-NO-PERMISSION",
        ],
    )


# --- 2. Massively misconfigured third-party app ---------------------------


def fixture_terrible() -> Fixture:
    pkg = "com.example.sketchy.wallpaper"
    b = axml.AxmlBuilder()
    arsc = axml.ArscBuilder(package_name=pkg)
    _manifest_root(b, pkg, 7, "1.0.7")
    _uses_sdk(b, 18, 22)
    for perm in (
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.READ_LOGS",
        "android.permission.READ_EXTERNAL_STORAGE",
    ):
        _permission(b, perm)
    b.start(
        "permission",
        [
            A("name", pkg + ".ACCESS_DATA"),
            A("protectionLevel", ("hex", 0x00)),
        ],
    )
    b.end("permission")
    b.start(
        "application",
        [
            A("debuggable", True),
            A("allowBackup", True),
            A("usesCleartextTraffic", True),
            A("requestLegacyExternalStorage", True),
            A("networkSecurityConfig", ("ref", arsc.add("xml", "network_security_config", "res/xml/network_security_config.xml"))),
            A("label", "Sketchy Wallpapers HD"),
        ],
    )
    b.start("activity", [A("name", pkg + ".SplashActivity")])
    _intent_filter(
        b,
        {
            "actions": ["android.intent.action.MAIN"],
            "categories": ["android.intent.category.LAUNCHER"],
        },
    )
    b.end("activity")
    # Exported deep-link activity with no permission
    b.start("activity", [A("name", pkg + ".WebViewActivity")])
    _intent_filter(
        b,
        {
            "actions": ["android.intent.action.VIEW"],
            "categories": [
                "android.intent.category.DEFAULT",
                "android.intent.category.BROWSABLE",
            ],
            "data": [
                {"scheme": "http", "host": "*", "pathPrefix": "/open"},
                {"scheme": "sketchy", "host": "open"},
            ],
        },
    )
    b.end("activity")
    # Implicitly exported service with an intent filter
    _component(
        b,
        "service",
        pkg + ".DownloadService",
        [],
        [{"actions": ["com.example.sketchy.DOWNLOAD"]}],
    )
    # Exported receiver listening for system broadcasts, no permission
    _component(
        b,
        "receiver",
        pkg + ".PushReceiver",
        [],
        [
            {
                "actions": [
                    "android.intent.action.BOOT_COMPLETED",
                    "android.provider.Telephony.SMS_RECEIVED",
                    "com.example.sketchy.PUSH",
                ]
            }
        ],
    )
    # Fully exported provider over the whole external storage authority
    _component(
        b,
        "provider",
        pkg + ".FileProvider",
        [
            A("exported", True),
            A("authorities", pkg + ".files;" + pkg + ".cache"),
            A("grantUriPermissions", True),
        ],
    )
    b.end("application")
    b.end("manifest")
    manifest = b.to_bytes()

    nsc = _nsc_xml(
        base_cleartext=True,
        base_trust=["system", "user"],
        domains=[{"hosts": ["pay.sketchy.example"], "cleartext": True, "trust": ["system", "user"]}],
    )
    members = _members(
        manifest,
        arsc.to_bytes(),
        {"res/xml/network_security_config.xml": nsc},
    )
    key, cert = debug_key()
    apk = build_signed(members, key, cert, ("v1",), min_sdk=18)
    return Fixture(
        name="terrible.apk",
        apk=apk,
        description="配置极差的第三方 APK：debuggable、允许备份、全局明文、信任用户 CA、导出且无权限的 Activity/Service/Receiver/Provider、仅 v1 签名、调试证书、targetSdk 22。",
        expected_rules=[
            "APP-DEBUGGABLE",
            "APP-ALLOW-BACKUP",
            "APP-LOW-TARGET-SDK",
            "APP-LEGACY-STORAGE",
            "NET-CLEARTEXT-ALLOWED",
            "NET-CLEARTEXT-DOMAIN",
            "NET-USER-CA-TRUST",
            "NET-USER-CA-DOMAIN",
            "SIG-V1-ONLY",
            "SIG-DEBUG-CERT",
            "PROVIDER-EXPORTED-NO-PERMISSION",
            "PROVIDER-GRANT-URI",
            "ACTIVITY-EXPORTED-NO-PERMISSION",
            "SERVICE-EXPORTED-NO-PERMISSION",
            "RECEIVER-EXPORTED-NO-PERMISSION",
            "INTENT-FILTER-EXPOSURE",
            "PERM-WEAK-PROTECTION",
            "PERM-HIGH-RISK",
        ],
    )


# --- 3. Android 12 missing android:exported -------------------------------


def fixture_missing_exported() -> Fixture:
    pkg = "com.example.modern"
    b = axml.AxmlBuilder()
    _manifest_root(b, pkg, 12, "3.0.0")
    _uses_sdk(b, 24, 33)
    b.start("application", [A("allowBackup", False)])
    # Installs only below API 31; on 31+ the package manager rejects it.
    _component(
        b,
        "activity",
        pkg + ".ShareActivity",
        [],
        [
            {
                "actions": ["android.intent.action.SEND"],
                "categories": ["android.intent.category.DEFAULT"],
                "data": [{"mimeType": "text/plain"}],
            }
        ],
    )
    _component(b, "activity", pkg + ".MainActivity", [A("exported", True)], [
        {"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}
    ])
    b.end("application")
    b.end("manifest")
    key, cert = release_key()
    apk = build_signed(_members(b.to_bytes(), None), key, cert, ("v2", "v3"), min_sdk=24)
    return Fixture(
        name="missing_exported.apk",
        apk=apk,
        description="targetSdk 33 的组件带 intent-filter 却未声明 android:exported —— 在 Android 12+ 上安装即失败。",
        expected_rules=["COMP-EXPORTED-MISSING", "INTENT-FILTER-EXPOSURE"],
        absent_rules=["APP-DEBUGGABLE", "NET-CLEARTEXT-ALLOWED"],
    )


# --- 4. v2 only, no v3, and a user-CA trust on one host -------------------


def fixture_v2_only() -> Fixture:
    pkg = "com.example.legacy"
    b = axml.AxmlBuilder()
    arsc = axml.ArscBuilder(package_name=pkg)
    _manifest_root(b, pkg, 3, "0.9")
    _uses_sdk(b, 24, 29)
    b.start(
        "application",
        [
            A("allowBackup", False),
            A("networkSecurityConfig", ("ref", arsc.add("xml", "nsc", "res/xml/nsc.xml"))),
        ],
    )
    _component(b, "activity", pkg + ".Main", [A("exported", True)], [
        {"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}
    ])
    b.end("application")
    b.end("manifest")
    nsc = _nsc_xml(
        base_cleartext=False,
        base_trust=["system"],
        domains=[
            {"hosts": ["legacy.example"], "trust": ["system", "user"]},
        ],
    )
    key, cert = release_key()
    apk = build_signed(
        _members(b.to_bytes(), arsc.to_bytes(), {"res/xml/nsc.xml": nsc}),
        key,
        cert,
        ("v2",),
        min_sdk=24,
    )
    return Fixture(
        name="v2_only.apk",
        apk=apk,
        description="仅有 v2 签名（缺 v3），且某个域名显式信任用户 CA。",
        expected_rules=["SIG-NO-V3", "NET-USER-CA-DOMAIN"],
        absent_rules=["SIG-V1-ONLY", "NET-CLEARTEXT-ALLOWED"],
    )


# --- 5. Repackaged: v1 manifest digests no longer match -------------------


def fixture_repackaged() -> Fixture:
    pkg = "com.example.repack"
    b = axml.AxmlBuilder()
    _manifest_root(b, pkg, 1, "1.0")
    _uses_sdk(b, 24, 30)
    b.start("application", [A("allowBackup", False)])
    _component(b, "activity", pkg + ".Main", [A("exported", True)], [
        {"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}
    ])
    b.end("application")
    b.end("manifest")
    key, cert = release_key()
    signed = build_signed(_members(b.to_bytes(), None), key, cert, ("v1",), min_sdk=24)

    # Tamper: append a second dex after signing (simulates injected payload).
    apk = bytearray(signed)
    eocd_off = apk.rfind(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack_from("<II", apk, eocd_off + 12)
    extra_dex = bytes.fromhex("6465780a303335000000000000000000") + b"injected-payload" * 8
    # Rebuild the archive with an extra member while keeping old META-INF.
    zw = zipsign.ZipWriter()
    zw.add("AndroidManifest.xml", b.to_bytes())
    zw.add("classes.dex", STUB_DEX)
    zw.add("classes2.dex", extra_dex)
    # Reuse the original signature material (now stale).
    for name in ("META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA"):
        data = _read_member(signed, name)
        zw.add_stored(name, data)
    apk = zw.build()
    return Fixture(
        name="repackaged.apk",
        apk=apk,
        description="重打包样本：签名后向归档中新增了 classes2.dex，但 META-INF 中的摘要未更新。",
        expected_rules=["SIG-UNSIGNED-ENTRIES", "SIG-INVALID"],
        absent_rules=[],
    )


def _read_member(apk: bytes, name: str) -> bytes:
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(apk)) as zf:
        return zf.read(name)


# --- 6. Unsigned ----------------------------------------------------------

def fixture_unsigned() -> Fixture:
    pkg = "com.example.unsigned"
    b = axml.AxmlBuilder()
    _manifest_root(b, pkg, 1, "0.1")
    _uses_sdk(b, 24, 30)
    b.start("application", [])
    _component(b, "activity", pkg + ".Main", [A("exported", True)], [
        {"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}
    ])
    b.end("application")
    b.end("manifest")
    zw = zipsign.ZipWriter()
    zw.add("AndroidManifest.xml", b.to_bytes())
    zw.add("classes.dex", STUB_DEX)
    return Fixture(
        name="unsigned.apk",
        apk=zw.build(),
        description="完全未签名。",
        expected_rules=["SIG-NONE"],
    )


# --- 7. Malformed manifest (bad chunk length) ------------------------------


def fixture_broken_manifest() -> Fixture:
    pkg = "com.example.broken"
    b = axml.AxmlBuilder()
    _manifest_root(b, pkg, 1, "1.0")
    b.start("application", [])
    b.end("application")
    b.end("manifest")
    manifest = bytearray(b.to_bytes())
    # Corrupt the first chunk's declared size so parsing must fail cleanly.
    struct.pack_into("<I", manifest, 4, 0x7FFFFFF0)
    zw = zipsign.ZipWriter()
    zw.add("AndroidManifest.xml", bytes(manifest))
    zw.add("classes.dex", STUB_DEX)
    return Fixture(
        name="broken_manifest.apk",
        apk=zw.build(),
        description="AndroidManifest.xml 的 chunk 长度被破坏，解析器必须报错而不是崩溃。",
    )


# --- 8. Raw-text manifest (not compiled) ----------------------------------


def fixture_text_manifest() -> Fixture:
    text = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.textmanifest" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="21"/>
    <application android:debuggable="true" android:allowBackup="true"/>
</manifest>
"""
    zw = zipsign.ZipWriter()
    zw.add("AndroidManifest.xml", text)
    zw.add("classes.dex", STUB_DEX)
    return Fixture(
        name="text_manifest.apk",
        apk=zw.build(),
        description="AndroidManifest.xml 是未编译的明文 XML（常见于手工改包），应明确报错说明需要编译后的清单。",
    )


# --- 9. Second signer, weaker network config ------------------------------


def fixture_ec_signed() -> Fixture:
    pkg = "com.example.ecsigned"
    b = axml.AxmlBuilder()
    arsc = axml.ArscBuilder(package_name=pkg)
    _manifest_root(b, pkg, 5, "2.1")
    _uses_sdk(b, 24, 31)
    b.start(
        "application",
        [
            A("allowBackup", False),
            A("networkSecurityConfig", ("ref", arsc.add("xml", "nsc", "res/xml/nsc.xml"))),
        ],
    )
    _component(b, "activity", pkg + ".Main", [A("exported", True)], [
        {"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}
    ])
    _component(
        b,
        "provider",
        pkg + ".SyncProvider",
        [
            A("exported", True),
            A("authorities", pkg + ".sync"),
            A("permission", pkg + ".ACCESS_DATA"),
        ],
    )
    b.end("application")
    b.end("manifest")
    nsc = _nsc_xml(base_cleartext=False, base_trust=["system"], domains=[])
    ec = keys.generate_ec_key("apksec-fixture-ec", 256)
    cert, _ = keys.make_certificate(ec, "EC Fixture Signer", org="Example", days_valid=4000)
    apk = build_signed(
        _members(b.to_bytes(), arsc.to_bytes(), {"res/xml/nsc.xml": nsc}),
        ec,
        cert,
        ("v2", "v3"),
        min_sdk=24,
    )
    return Fixture(
        name="ec_signed.apk",
        apk=apk,
        description="ECDSA P-256 签名、provider 导出但仅由未定义权限保护（权限不存在，实际等于无保护）。",
        expected_rules=["PROVIDER-EXPORTED-GUARDED"],
        absent_rules=["APP-DEBUGGABLE", "NET-USER-CA-TRUST", "SIG-NO-V3"],
    )


# --- 10. NSC present but unparsable reference ----------------------------


def fixture_unresolved_nsc() -> Fixture:
    pkg = "com.example.dangling"
    b = axml.AxmlBuilder()
    _manifest_root(b, pkg, 2, "1.1")
    _uses_sdk(b, 24, 30)
    b.start(
        "application",
        [
            A("allowBackup", False),
            # Reference points at a resource that does not exist in the table.
            A("networkSecurityConfig", ("ref", 0x7F0F0001)),
        ],
    )
    _component(b, "activity", pkg + ".Main", [A("exported", True)], [
        {"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}
    ])
    b.end("application")
    b.end("manifest")
    key, cert = release_key()
    apk = build_signed(_members(b.to_bytes(), None), key, cert, ("v2", "v3"), min_sdk=24)
    return Fixture(
        name="unresolved_nsc.apk",
        apk=apk,
        description="清单引用了不存在的网络安全配置资源，审计器应报告无法解析而不是静默按默认策略处理。",
        expected_rules=["NSC-UNPARSEABLE"],
    )


ALL_FIXTURES = [
    fixture_hardened,
    fixture_terrible,
    fixture_missing_exported,
    fixture_v2_only,
    fixture_repackaged,
    fixture_unsigned,
    fixture_broken_manifest,
    fixture_text_manifest,
    fixture_ec_signed,
    fixture_unresolved_nsc,
]


def build_all(out_dir: str) -> list[Fixture]:
    os.makedirs(out_dir, exist_ok=True)
    built = []
    for factory in ALL_FIXTURES:
        fixture = factory()
        path = os.path.join(out_dir, fixture.name)
        with open(path, "wb") as fh:
            fh.write(fixture.apk)
        built.append(fixture)
    return built


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    for fixture in build_all(target):
        print(f"{fixture.name:<28} {len(fixture.apk):>7} bytes  {fixture.description}")
