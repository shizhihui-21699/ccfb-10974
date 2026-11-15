#!/usr/bin/env python3
"""造测试 APK 夹具：正常包、配置很烂的包、混合包、未签名调试包。

用法：
    python3 tests/build_fixtures.py [输出目录]

不依赖 Android SDK：AXML 用 tests/axmlwriter.py 编码，
v1/v2/v3 签名用 tests/apksigner_lite.py + 系统 openssl。
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tests.axmlwriter import ANDROID_NS, AXMLWriter, Node
from tests import apksigner_lite as signer

A = ANDROID_NS


def a(name: str, value):
    """android 命名空间属性的简写。"""
    return (A, name), value


def no_ns(name: str, value):
    return (None, name), value


# ----------------------------------------------------------------------
# Manifest 构造
# ----------------------------------------------------------------------
def manifest_secure() -> Node:
    launcher_filter = Node("intent-filter", children=[
        Node("action", dict([a("name", "android.intent.action.MAIN")])),
        Node("category", dict([a("name", "android.intent.category.LAUNCHER")])),
    ])
    app = Node("application", {
        a("label", "SecureApp"),
        a("debuggable", False),
        a("allowBackup", False),
        a("usesCleartextTraffic", False),
        a("networkSecurityConfig", "@xml/network_security_config"),
    }, children=[
        Node("activity", {
            a("name", "com.example.secure.MainActivity"),
            a("exported", True),
        }, children=[launcher_filter]),
        Node("service", {
            a("name", "com.example.secure.InternalSyncService"),
            a("exported", False),
            a("permission", "com.example.secure.PERM_INTERNAL"),
        }),
        Node("provider", {
            a("name", "com.example.secure.FileProvider"),
            a("authorities", "com.example.secure.files"),
            a("exported", False),
            a("grantUriPermissions", True),
        }),
    ])
    return Node("manifest", {
        no_ns("package", "com.example.secure"),
        a("versionName", "2.4.1"),
        a("versionCode", 20401),
    }, children=[
        Node("uses-sdk", {a("minSdkVersion", 26), a("targetSdkVersion", 34)}),
        Node("uses-permission", {a("name", "android.permission.INTERNET")}),
        Node("permission", {
            a("name", "com.example.secure.PERM_INTERNAL"),
            a("protectionLevel", "signature"),
        }),
        app,
    ])


def manifest_insecure() -> Node:
    app = Node("application", {
        a("label", "RiskyApp"),
        a("debuggable", True),
        a("allowBackup", True),
        a("usesCleartextTraffic", True),
        a("testOnly", True),
        a("networkSecurityConfig", "@xml/network_security_config"),
    }, children=[
        Node("activity", {
            a("name", "com.risky.DeepLinkActivity"),
            a("exported", True),
        }, children=[
            Node("intent-filter", children=[
                Node("action", dict([a("name", "android.intent.action.VIEW")])),
                Node("category", dict([a("name", "android.intent.category.DEFAULT")])),
                Node("category", dict([a("name", "android.intent.category.BROWSABLE")])),
                Node("data", dict([
                    a("scheme", "risky"), a("host", "pay"),
                ])),
            ]),
        ]),
        # 无权限保护的导出 Service
        Node("service", {
            a("name", "com.risky.CommandService"),
            a("exported", True),
        }),
        # 导出 receiver 监听开机
        Node("receiver", {
            a("name", "com.risky.BootReceiver"),
            a("exported", True),
        }, children=[
            Node("intent-filter", children=[
                Node("action", dict([
                    a("name", "android.intent.action.BOOT_COMPLETED"),
                ])),
            ]),
        ]),
        # 导出且 grantUriPermissions 的 provider，无权限
        Node("provider", {
            a("name", "com.risky.LeakProvider"),
            a("authorities", "com.risky.leak"),
            a("exported", True),
            a("grantUriPermissions", True),
        }, children=[
            Node("grant-uri-permission", dict([a("path", "/secrets")])),
        ]),
    ])
    return Node("manifest", {
        no_ns("package", "com.risky.app"),
        a("versionName", "0.9-debug"),
        a("versionCode", 9),
        a("sharedUserId", "android.uid.system"),
    }, children=[
        Node("uses-sdk", {a("minSdkVersion", 21), a("targetSdkVersion", 23)}),
        Node("uses-permission", {a("name", "android.permission.READ_SMS")}),
        Node("uses-permission", {a("name", "android.permission.ACCESS_FINE_LOCATION")}),
        Node("uses-permission", {a("name", "android.permission.CAMERA")}),
        Node("uses-permission", {a("name", "android.permission.READ_EXTERNAL_STORAGE")}),
        Node("permission", {
            a("name", "com.risky.weak.WEAK_PERM"),
            a("protectionLevel", "normal"),
        }),
        app,
    ])


def manifest_mixed() -> Node:
    """好坏参半：用于验证规则逐项命中而非一刀切。"""
    app = Node("application", {
        a("label", "MixedApp"),
        a("debuggable", False),
        # allowBackup 故意不声明 -> LOW
        a("networkSecurityConfig", "@xml/network_security_config"),
    }, children=[
        Node("activity", {
            a("name", "com.mixed.MainActivity"),
            a("exported", True),
        }, children=[
            Node("intent-filter", children=[
                Node("action", dict([a("name", "android.intent.action.MAIN")])),
                Node("category", dict([a("name", "android.intent.category.LAUNCHER")])),
            ]),
        ]),
        # 带 signature 权限保护的导出 service -> MEDIUM
        Node("service", {
            a("name", "com.mixed.PartnerService"),
            a("exported", True),
            a("permission", "com.mixed.PERM_PARTNER"),
        }),
        # 显式关闭导出的 receiver
        Node("receiver", {
            a("name", "com.mixed.InternalReceiver"),
            a("exported", False),
        }),
        # targetSdk 34 但带 filter 不写 exported -> LOW + 安装期问题
        Node("activity", {
            a("name", "com.mixed.ShareActivity"),
        }, children=[
            Node("intent-filter", children=[
                Node("action", dict([a("name", "android.intent.action.SEND")])),
                Node("data", dict([a("mimeType", "text/plain")])),
            ]),
        ]),
    ])
    return Node("manifest", {
        no_ns("package", "com.mixed.app"),
        a("versionName", "1.2.0"),
        a("versionCode", 120),
    }, children=[
        Node("uses-sdk", {a("minSdkVersion", 24), a("targetSdkVersion", 34)}),
        Node("uses-permission", {a("name", "android.permission.INTERNET")}),
        Node("uses-permission", {a("name", "android.permission.RECORD_AUDIO")}),
        Node("permission", {
            a("name", "com.mixed.PERM_PARTNER"),
            a("protectionLevel", "signature"),
        }),
        app,
    ])


def manifest_unsigned() -> Node:
    app = Node("application", {
        a("label", "UnsignedDebug"),
        a("debuggable", True),
        a("allowBackup", True),
    }, children=[
        Node("activity", {
            a("name", "com.unsigned.MainActivity"),
            a("exported", True),
        }, children=[
            Node("intent-filter", children=[
                Node("action", dict([a("name", "android.intent.action.MAIN")])),
                Node("category", dict([a("name", "android.intent.category.LAUNCHER")])),
            ]),
        ]),
    ])
    return Node("manifest", {
        no_ns("package", "com.unsigned.debug"),
        a("versionName", "0.0.1"),
        a("versionCode", 1),
    }, children=[
        Node("uses-sdk", {a("minSdkVersion", 19), a("targetSdkVersion", 22)}),
        app,
    ])


# ----------------------------------------------------------------------
# network_security_config 构造
# ----------------------------------------------------------------------
def netconfig_secure() -> Node:
    return Node("network-security-config", children=[
        Node("base-config", dict([a("cleartextTrafficPermitted", False)]), children=[
            Node("trust-anchors", children=[
                Node("certificates", dict([a("src", "system")])),
            ]),
        ]),
    ])


def netconfig_insecure() -> Node:
    return Node("network-security-config", children=[
        Node("base-config", dict([a("cleartextTrafficPermitted", True)]), children=[
            Node("trust-anchors", children=[
                Node("certificates", dict([a("src", "system")])),
                Node("certificates", dict([a("src", "user")])),
            ]),
        ]),
        Node("debug-overrides", children=[
            Node("trust-anchors", children=[
                Node("certificates", dict([a("src", "user")])),
            ]),
        ]),
        Node("domain-config", dict([
            a("cleartextTrafficPermitted", True),
        ]), children=[
            Node("domain", dict([a("includeSubdomains", True)]), text="legacy.example.com"),
            Node("trust-anchors", children=[
                Node("certificates", dict([a("src", "user")])),
            ]),
        ]),
    ])


def netconfig_mixed() -> Node:
    # 全局禁明文 + 系统 CA，但有一个 debug-overrides 信任用户 CA
    return Node("network-security-config", children=[
        Node("base-config", dict([a("cleartextTrafficPermitted", False)]), children=[
            Node("trust-anchors", children=[
                Node("certificates", dict([a("src", "system")])),
            ]),
        ]),
        Node("debug-overrides", children=[
            Node("trust-anchors", children=[
                Node("certificates", dict([a("src", "user")])),
            ]),
        ]),
    ])


# ----------------------------------------------------------------------
# 打包
# ----------------------------------------------------------------------
def struct_pack_sdk_range() -> bytes:
    """v3 块的 minSdk=24 / maxSdk=0x7fffffff 前缀。"""
    return struct.pack("<II", 24, 0x7FFFFFFF)


def _dex_placeholder(pkg: str) -> bytes:
    # 真实 classes.dex 不是审计关注点，放带魔数的占位内容即可
    return (b"dex\n035\x00" + pkg.encode()).ljust(112, b"\x00")


def build_apk(
    out_path: str,
    manifest_node: Node,
    net_node: Node | None,
    schemes: tuple,
    key_path: str,
):
    manifest_bytes = AXMLWriter().write(manifest_node)
    entries: dict[str, bytes] = {
        "AndroidManifest.xml": manifest_bytes,
        "classes.dex": _dex_placeholder(
            manifest_node.attrs.get((None, "package"), "unknown")
        ),
        "resources.arsc": b"\x02\x00\x0c\x00" + b"\x00" * 28,
    }
    if net_node is not None:
        entries["res/xml/network_security_config.xml"] = AXMLWriter().write(net_node)

    if "v1" in schemes:
        entries.update(signer.build_v1_meta(entries))

    zip_builder = signer.ZipBuilder()
    for name, data in sorted(entries.items()):
        compress = name not in ("resources.arsc",)
        zip_builder.add(name, data, compress=compress)
    apk = zip_builder.build()

    if "v2" in schemes or "v3" in schemes:
        # v2/v3 摘要只覆盖“签名块之前的内容”——即 zip 本地条目部分，
        # 不含中央目录与 EOCD（签名块将插在中央目录之前）
        eocd_pos = apk.rfind(struct.pack("<I", signer.EOCD_SIG))
        cd_off = struct.unpack_from("<I", apk, eocd_pos + 16)[0]
        content_before = apk[:cd_off]
        signer_block = signer.make_signer_block(content_before, key_path)
        pairs = []
        if "v2" in schemes:
            pairs.append((signer.ALGO_ID_V2, signer_block))
        if "v3" in schemes:
            v3_value = (
                struct_pack_sdk_range() + signer._lp(signer_block)
            )
            pairs.append((signer.ALGO_ID_V3, v3_value))
        apk = signer.insert_multi_scheme_block(apk, pairs)

    with open(out_path, "wb") as fh:
        fh.write(apk)
    return out_path


def main(out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    key_path, _cert = signer.prepare_keystore(out_dir)

    specs = [
        ("secure-release.apk", manifest_secure(), netconfig_secure(),
         ("v1", "v2", "v3")),
        ("insecure-debug.apk", manifest_insecure(), netconfig_insecure(),
         ("v1",)),  # 只有 v1，触发签名方案不完整
        ("mixed-config.apk", manifest_mixed(), netconfig_mixed(),
         ("v1", "v2")),  # 缺 v3
        ("unsigned-debug.apk", manifest_unsigned(), None, ()),  # 完全未签名
    ]
    for filename, manifest_node, net_node, schemes in specs:
        path = os.path.join(out_dir, filename)
        build_apk(path, manifest_node, net_node, schemes, key_path)
        print(f"[+] 生成 {path}  签名方案={schemes or '无'}")
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixtures"
    )
    raise SystemExit(main(target))
