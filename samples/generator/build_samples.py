"""Build synthetic test APKs covering clean and deliberately insecure configs.

Run:
    python3 -I samples/generator/build_samples.py
Outputs:
    samples/apks/good-app.apk
    samples/apks/insecure-app.apk
    samples/apks/legacy-v1-sha1-app.apk
    samples/apks/tampered-app.apk
"""

from __future__ import annotations

import os
import sys
import zipfile

# Make both the workspace root (for apk_auditor) and this package importable
# when the script is invoked by path with -I.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
for p in (_ROOT, os.path.dirname(_HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from apk_auditor.axml import AxmlAttribute, AxmlNode
from apk_auditor.axml_writer import ANDROID_NS, AxmlWriter
from generator.keygen import generate_rsa_key, generate_weak_sha1_key
from generator.v1_sign import sign_v1
from generator.v2v3_sign import sign_v2_v3

OUT_DIR = os.path.join(_ROOT, "samples", "apks")
KEY_DIR = os.path.join(_ROOT, "keys")


# ------------------------------------------------------------- tree helpers
def attr(name: str, value, ns: str = ANDROID_NS, rid: int | None = None) -> AxmlAttribute:
    from apk_auditor.axml import (
        TYPE_INT_BOOLEAN,
        TYPE_INT_DEC,
        TYPE_STRING,
    )

    if isinstance(value, bool):
        dtype = TYPE_INT_BOOLEAN
    elif isinstance(value, int):
        dtype = TYPE_INT_DEC
    else:
        dtype = TYPE_STRING
    return AxmlAttribute(
        namespace=ns,
        name=name,
        raw_name=name,
        value=value,
        raw_value=str(value) if dtype == TYPE_STRING else None,
        type=dtype,
        type_name="",
        resource_id=rid,
    )


def node(
    tag: str,
    attrs: dict | None = None,
    children: list | None = None,
    text: str | None = None,
) -> AxmlNode:
    n = AxmlNode(name=tag, namespace=None)
    for k, v in (attrs or {}).items():
        n.attributes[k] = attr(k, v)
    n.children = children or []
    n.text = text
    return n


def write_axml(root: AxmlNode) -> bytes:
    return AxmlWriter(use_android_ns=True).write(root)


# ------------------------------------------------------------- manifest defs
def good_manifest() -> bytes:
    root = node(
        "manifest",
        {
            "package": "com.example.goodapp",
            "versionName": "2.4.1",
            "versionCode": 20401,
        },
        [
            node("uses-sdk", {"minSdkVersion": 24, "targetSdkVersion": 34}),
            node(
                "uses-permission",
                {"name": "android.permission.INTERNET"},
            ),
            node(
                "application",
                {
                    "debuggable": False,
                    "allowBackup": False,
                    "usesCleartextTraffic": False,
                    "networkSecurityConfig": "@0x7f120000",
                    "testOnly": False,
                    "label": "GoodApp",
                },
                [
                    node(
                        "activity",
                        {
                            "name": "com.example.goodapp.MainActivity",
                            "exported": True,
                        },
                        [
                            node(
                                "intent-filter",
                                {},
                                [
                                    node("action", {"name": "android.intent.action.MAIN"}),
                                    node(
                                        "category",
                                        {"name": "android.intent.category.LAUNCHER"},
                                    ),
                                ],
                            )
                        ],
                    ),
                    node(
                        "service",
                        {"name": "com.example.goodapp.SyncService", "exported": False},
                    ),
                    node(
                        "provider",
                        {
                            "name": "com.example.goodapp.InternalProvider",
                            "exported": False,
                            "authorities": "com.example.goodapp.provider",
                        },
                    ),
                ],
            ),
        ],
    )
    return write_axml(root)


def good_netsec() -> bytes:
    root = node(
        "network-security-config",
        {},
        [
            node(
                "base-config",
                {"cleartextTrafficPermitted": False},
                [
                    node(
                        "trust-anchors",
                        {},
                        [node("certificates", {"src": "system"})],
                    )
                ],
            ),
            node(
                "domain-config",
                {"cleartextTrafficPermitted": False},
                [
                    node("domain", {"includeSubdomains": True}, text="api.example.com"),
                    node(
                        "pin-set",
                        {},
                        [
                            node(
                                "pin",
                                {"digest": "SHA-256"},
                                text=(
                                    "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
                                    "abcd1234abcd1234="
                                ),
                            )
                        ],
                    ),
                ],
            ),
        ],
    )
    return write_axml(root)


def insecure_manifest() -> bytes:
    root = node(
        "manifest",
        {
            "package": "com.example.insecure",
            "versionName": "0.9.0",
            "versionCode": 9,
        },
        [
            node("uses-sdk", {"minSdkVersion": 21, "targetSdkVersion": 25}),
            node("uses-permission", {"name": "android.permission.READ_SMS"}),
            node("uses-permission", {"name": "android.permission.RECORD_AUDIO"}),
            node("uses-permission", {"name": "android.permission.SYSTEM_ALERT_WINDOW"}),
            node(
                "uses-permission",
                {"name": "android.permission.REQUEST_INSTALL_PACKAGES"},
            ),
            node(
                "permission",
                {
                    "name": "com.example.insecure.WEAK_PERM",
                    "protectionLevel": "normal",
                },
            ),
            node(
                "application",
                {
                    "debuggable": True,
                    "allowBackup": True,
                    "testOnly": True,
                    "usesCleartextTraffic": True,
                    "networkSecurityConfig": "@0x7f120001",
                    "label": "InsecureApp",
                },
                [
                    # Exported activity with a VIEW deep link, no permission.
                    node(
                        "activity",
                        {
                            "name": "com.example.insecure.DeepLinkActivity",
                            "exported": True,
                        },
                        [
                            node(
                                "intent-filter",
                                {},
                                [
                                    node("action", {"name": "android.intent.action.VIEW"}),
                                    node(
                                        "category",
                                        {"name": "android.intent.category.DEFAULT"},
                                    ),
                                    node(
                                        "category",
                                        {"name": "android.intent.category.BROWSABLE"},
                                    ),
                                    node("data", {"scheme": "insecure", "host": "open"}),
                                ],
                            )
                        ],
                    ),
                    # Implicit export via intent-filter, no exported attr.
                    node(
                        "receiver",
                        {"name": "com.example.insecure.LegacyReceiver"},
                        [
                            node(
                                "intent-filter",
                                {},
                                [node("action", {"name": "com.example.insecure.PING"})],
                            )
                        ],
                    ),
                    # Unguarded exported service.
                    node(
                        "service",
                        {"name": "com.example.insecure.CommandService", "exported": True},
                    ),
                    # Exported provider with URI grants.
                    node(
                        "provider",
                        {
                            "name": "com.example.insecure.FileProvider",
                            "exported": True,
                            "authorities": "com.example.insecure.files",
                            "grantUriPermissions": True,
                        },
                    ),
                    # Internal activity (not exported) for contrast.
                    node(
                        "activity",
                        {"name": "com.example.insecure.SettingsActivity", "exported": False},
                    ),
                ],
            ),
        ],
    )
    return write_axml(root)


def insecure_netsec() -> bytes:
    root = node(
        "network-security-config",
        {},
        [
            node(
                "base-config",
                {"cleartextTrafficPermitted": True},
                [
                    node(
                        "trust-anchors",
                        {},
                        [
                            node("certificates", {"src": "system"}),
                            node("certificates", {"src": "user"}),
                        ],
                    )
                ],
            ),
            node(
                "domain-config",
                {"cleartextTrafficPermitted": True},
                [
                    node("domain", {"includeSubdomains": True}, text="legacy.example.com"),
                ],
            ),
        ],
    )
    return write_axml(root)


def legacy_manifest() -> bytes:
    root = node(
        "manifest",
        {
            "package": "com.example.legacy",
            "versionName": "1.0.0",
            "versionCode": 1,
        },
        [
            node("uses-sdk", {"minSdkVersion": 19, "targetSdkVersion": 22}),
            node("uses-permission", {"name": "android.permission.INTERNET"}),
            node(
                "application",
                {
                    "debuggable": False,
                    # allowBackup omitted -> defaults true on old targets.
                    "usesCleartextTraffic": True,
                    "label": "LegacyApp",
                },
                [
                    node(
                        "activity",
                        {"name": "com.example.legacy.MainActivity", "exported": True},
                        [
                            node(
                                "intent-filter",
                                {},
                                [
                                    node("action", {"name": "android.intent.action.MAIN"}),
                                    node(
                                        "category",
                                        {"name": "android.intent.category.LAUNCHER"},
                                    ),
                                ],
                            )
                        ],
                    )
                ],
            ),
        ],
    )
    return write_axml(root)


# ------------------------------------------------------------- assembly
_MINIMAL_DEX = (
    b"dex\n035\x00"
    + b"\x00" * 96
    + b"apk-audit synthetic test dex - not executable on-device"
)


def build_unsigned_apk(path: str, manifest: bytes, netsec: bytes | None) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", _MINIMAL_DEX)
        zf.writestr(
            "resources.arsc",
            b"\x02\x00\x0c\x00" + b"\x00" * 8,  # placeholder, auditor ignores
        )
        if netsec is not None:
            zf.writestr("res/xml/network_security_config.xml", netsec)
        zf.writestr("assets/readme.txt", "synthetic sample for apk-audit tests\n")
        # An uncompressed (STORED), fixed-size marker. The tampered sample flips
        # a byte here so the ZIP still decompresses but every signature fails.
        marker = zipfile.ZipInfo("assets/tamper_marker.bin")
        marker.compress_type = zipfile.ZIP_STORED
        zf.writestr(marker, b"TAMPER-MARKER:" + b"A" * 48)


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    key = generate_rsa_key(KEY_DIR, "testkey")
    weak_key = generate_weak_sha1_key(KEY_DIR, "weakkey")

    # 1) good-app: hardened manifest, v1+v2+v3 all present and valid.
    good_path = os.path.join(OUT_DIR, "good-app.apk")
    build_unsigned_apk(good_path, good_manifest(), good_netsec())
    sign_v1(good_path, key.key_pem, key.cert_pem, "sha256")
    sign_v2_v3(good_path, key.key_pem, key.cert_der, ("v2", "v3"))

    # 2) insecure-app: everything bad; still fully signed so findings concern
    #    configuration rather than integrity.
    bad_path = os.path.join(OUT_DIR, "insecure-app.apk")
    build_unsigned_apk(bad_path, insecure_manifest(), insecure_netsec())
    sign_v1(bad_path, key.key_pem, key.cert_pem, "sha256")
    sign_v2_v3(bad_path, key.key_pem, key.cert_der, ("v2", "v3"))

    # 3) legacy-v1-sha1-app: v1 only, SHA-1 digests, old targetSdk.
    legacy_path = os.path.join(OUT_DIR, "legacy-v1-sha1-app.apk")
    build_unsigned_apk(legacy_path, legacy_manifest(), None)
    sign_v1(legacy_path, weak_key.key_pem, weak_key.cert_pem, "sha1")

    # 4) tampered-app: take the good app and flip a byte inside the STORED
    #    marker entry without re-signing. Because that entry is uncompressed
    #    the ZIP still opens, but every signature scheme must fail.
    tampered_path = os.path.join(OUT_DIR, "tampered-app.apk")
    with open(good_path, "rb") as fh:
        blob = bytearray(fh.read())
    with zipfile.ZipFile(good_path, "r") as zf:
        info = zf.getinfo("assets/tamper_marker.bin")
        assert info.compress_type == zipfile.ZIP_STORED
        header_off = info.header_offset
        # Local file header is 30 bytes + name + extra; content starts after.
        content_off = (
            header_off
            + 30
            + len(info.filename.encode())
            + len(info.extra)
        )
    blob[content_off + 14] ^= 0xFF  # well inside the marker body
    with open(tampered_path, "wb") as fh:
        fh.write(bytes(blob))

    print("built:")
    for name in sorted(os.listdir(OUT_DIR)):
        p = os.path.join(OUT_DIR, name)
        print(f"  {p}  ({os.path.getsize(p):,} bytes)")


if __name__ == "__main__":
    main()
