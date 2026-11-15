"""最小 ZIP/APK 写入器与 v1/v2/v3 签名实现（测试夹具用）。

只实现 STORE/DEFLATE、无数据描述符的经典 ZIP 布局，以便精确控制
中央目录偏移并在其前面插入 APK Signing Block。

v1：META-INF 清单 + openssl cms 生成 PKCS#7（无 Java 依赖）。
v2/v3：按 AOSP apksig 规范组装 length-prefixed 序列，RSA-PSS
签名通过 openssl pkeyutl 完成。
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import zlib

LOCAL_SIG = 0x04034B50
CENTRAL_SIG = 0x02014B50
EOCD_SIG = 0x06054B50

ALGO_ID_V2 = 0x7109871A
ALGO_ID_V3 = 0xF05368C0

# 签名算法 ID（apksig 规范）
SIG_RSA_PSS_SHA256 = 0x0101
DIGEST_SHA256 = 0x0101


# ----------------------------------------------------------------------
# 最小 ZIP 写入
# ----------------------------------------------------------------------
class ZipBuilder:
    def __init__(self):
        # [(name, method, data_uncompressed)]
        self._entries: list[tuple[str, int, bytes]] = []

    def add(self, name: str, data: bytes, compress: bool = True):
        method = 8 if compress and len(data) > 0 else 0
        self._entries.append((name, method, data))

    def build(self) -> bytes:
        out = bytearray()
        central = bytearray()
        for name, method, raw in self._entries:
            name_b = name.encode("utf-8")
            if method == 8:
                co = zlib.compressobj(6, zlib.DEFLATED, -15)
                payload = co.compress(raw) + co.flush()
            else:
                payload = raw
            crc = zlib.crc32(raw) & 0xFFFFFFFF
            local_off = len(out)
            out += struct.pack(
                "<IHHHHHIIIHH",
                LOCAL_SIG, 20, 0, method, 0, 0,
                crc, len(payload), len(raw),
                len(name_b), 0,
            )
            out += name_b
            out += payload

            central += struct.pack(
                "<IHHHHHHIIIHHHHHII",
                CENTRAL_SIG, 20, 20, 0, method, 0, 0,
                crc, len(payload), len(raw),
                len(name_b), 0, 0, 0, 0, 0, local_off,
            )
            central += name_b

        cd_off = len(out)
        out += central
        eocd = struct.pack(
            "<IHHHHIIH",
            EOCD_SIG, 0, 0,
            len(self._entries), len(self._entries),
            len(central), cd_off, 0,
        )
        out += eocd
        return bytes(out)


# ----------------------------------------------------------------------
# v1（JAR 签名）
# ----------------------------------------------------------------------
def _b64_digest(data: bytes, algo: str = "sha256") -> str:
    import base64

    return base64.b64encode(hashlib.new(algo, data).digest()).decode("ascii")


def _wrap_manifest_lines(line: str) -> bytes:
    """JAR 清单每行最长 72 字节，超长续行。"""
    raw = line.encode("utf-8")
    if len(raw) <= 72:
        return raw + b"\r\n"
    out = raw[:72] + b"\r\n"
    rest = raw[72:]
    while rest:
        out += b" " + rest[:71] + b"\r\n"
        rest = rest[71:]
    return out


def build_v1_meta(entries: dict[str, bytes]) -> dict[str, bytes]:
    """生成 MANIFEST.MF / CERT.SF / CERT.RSA（openssl CMS）。"""
    manifest = bytearray(b"Manifest-Version: 1.0\r\nCreated-By: apk-audit-fixture\r\n\r\n")
    section_blocks: dict[str, bytes] = {}
    for name in sorted(entries):
        block = b""
        block += _wrap_manifest_lines(f"Name: {name}")
        block += f"SHA-256-Digest: {_b64_digest(entries[name])}\r\n".encode()
        block += b"\r\n"
        section_blocks[name] = block
        manifest += block
    manifest_b = bytes(manifest)

    sf = bytearray(
        b"Signature-Version: 1.0\r\n"
        b"Created-By: apk-audit-fixture\r\n"
    )
    sf += f"SHA-256-Digest-Manifest: {_b64_digest(manifest_b)}\r\n\r\n".encode()
    # 逐段摘要
    for name, block in section_blocks.items():
        sf += _wrap_manifest_lines(f"Name: {name}")
        sf += f"SHA-256-Digest: {_b64_digest(block)}\r\n\r\n".encode()
    sf_b = bytes(sf)

    rsa_b = _openssl_cms_sign(sf_b)
    return {
        "META-INF/MANIFEST.MF": manifest_b,
        "META-INF/CERT.SF": sf_b,
        "META-INF/CERT.RSA": rsa_b,
    }


def _openssl_cms_sign(content: bytes) -> bytes:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        with open(f"{td}/content", "wb") as fh:
            fh.write(content)
        proc = subprocess.run(
            [
                "openssl", "cms", "-sign", "-binary",
                "-in", f"{td}/content",
                "-signer", _cert_path(), "-inkey", _key_path(),
                "-outform", "DER", "-nodetach",
            ],
            capture_output=True, check=True,
        )
        return proc.stdout


# ----------------------------------------------------------------------
# v2 / v3（APK Signing Block）
# ----------------------------------------------------------------------
def _lp(value: bytes) -> bytes:
    """uint32 长度前缀。"""
    return struct.pack("<I", len(value)) + value


def _chunked_sha256(data: bytes) -> bytes:
    """AOSP v2/v3 摘要算法：内容按 1MB(0xa00000) 分块，每块前置 u32 长度，
    最后追加一个长度为 0 的终止块，再整体求 SHA-256。"""
    h = hashlib.sha256()
    chunk_size = 0xA00000
    pos = 0
    while pos < len(data):
        part = data[pos : pos + chunk_size]
        h.update(struct.pack("<I", len(part)))
        h.update(part)
        pos += chunk_size
    h.update(struct.pack("<I", 0))
    return h.digest()


def make_signer_block(content_before: bytes, key_path: str) -> bytes:
    """构造单个 signer（v2 与 v3 共用 signer 内部结构）。"""
    digest = _chunked_sha256(content_before)
    digest_record = struct.pack("<I", DIGEST_SHA256) + _lp(digest)
    digests = _lp(_lp(digest_record))

    # 证书链：从 DER 证书读取
    cert_der = _read_cert_der()
    certificates = _lp(_lp(cert_der))
    additional_attrs = _lp(b"")
    signed_data = _lp(digests + certificates + additional_attrs)

    signature = _openssl_pss_sign(signed_data, key_path)
    sig_record = struct.pack("<I", SIG_RSA_PSS_SHA256) + _lp(signature)
    signatures = _lp(_lp(sig_record))
    public_key = _lp(_read_pubkey_der())

    return _lp(signed_data + signatures + public_key)


def _openssl_pss_sign(data: bytes, key_path: str) -> bytes:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        with open(f"{td}/data", "wb") as fh:
            fh.write(data)
        proc = subprocess.run(
            [
                "openssl", "pkeyutl", "-sign",
                "-inkey", key_path,
                "-rawin", "-digest", "sha256",
                "-pkeyopt", "rsa_padding_mode:pss",
                "-pkeyopt", "rsa_pss_saltlen:32",
                "-in", f"{td}/data",
            ],
            capture_output=True, check=True,
        )
        return proc.stdout


def insert_signing_block(apk: bytes, block_id: int, signer_block: bytes,
                         with_sdk_range: bool = False) -> bytes:
    """在中央目录前插入只含单个 ID-value 对的 APK Signing Block。"""
    pair_value = signer_block
    if with_sdk_range:  # v3：minSdk=24, maxSdk=0x7fffffff
        pair_value = struct.pack("<II", 24, 0x7FFFFFFF) + _lp(signer_block)
    return _insert_pairs(apk, [(block_id, pair_value)])


def insert_multi_scheme_block(apk: bytes, pairs: list[tuple[int, bytes]]) -> bytes:
    """一次插入含多个 ID-value 对（v2 + v3 共存）的签名块。

    pairs: [(block_id, value_bytes), ...]，顺序即块内排列顺序。
    """
    return _insert_pairs(apk, pairs)


def _insert_pairs(apk: bytes, id_values: list[tuple[int, bytes]]) -> bytes:
    eocd_pos = apk.rfind(struct.pack("<I", EOCD_SIG))
    if eocd_pos < 0:
        raise ValueError("APK 中找不到 EOCD")
    cd_off = struct.unpack_from("<I", apk, eocd_pos + 16)[0]
    before = apk[:cd_off]
    central_and_eocd = bytearray(apk[cd_off:])

    pairs_blob = bytearray()
    for block_id, value in id_values:
        id_value = struct.pack("<I", block_id) + value
        pairs_blob += struct.pack("<Q", len(id_value)) + id_value

    # 尾部 24 字节：u64 size + 16 字节 magic
    size_of_block = len(pairs_blob) + 24
    block = (
        struct.pack("<Q", size_of_block)
        + bytes(pairs_blob)
        + struct.pack("<Q", size_of_block)
        + b"APK Sig Block 42"
    )

    new_cd_off = cd_off + len(block)
    struct.pack_into(
        "<I", central_and_eocd, (eocd_pos - cd_off) + 16, new_cd_off
    )
    return before + block + bytes(central_and_eocd)


# ----------------------------------------------------------------------
# 证书/密钥缓存（测试夹具统一一套自签名证书）
# ----------------------------------------------------------------------
_CERT_DIR = None


def prepare_keystore(workdir: str) -> tuple[str, str]:
    """生成 RSA 密钥与自签名证书，返回 (key.pem, cert.pem) 路径。"""
    import os

    os.makedirs(workdir, exist_ok=True)
    key_path = os.path.join(workdir, "fixture.key")
    cert_path = os.path.join(workdir, "fixture.crt")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes", "-subj",
            "/CN=apk-audit-fixture/O=SecurityTeam",
        ],
        capture_output=True, check=True,
    )
    global _CERT_DIR
    _CERT_DIR = workdir
    return key_path, cert_path


def _key_path() -> str:
    import os

    return os.path.join(_CERT_DIR, "fixture.key")


def _cert_path() -> str:
    import os

    return os.path.join(_CERT_DIR, "fixture.crt")


def _read_cert_der() -> bytes:
    proc = subprocess.run(
        ["openssl", "x509", "-in", _cert_path(), "-outform", "DER"],
        capture_output=True, check=True,
    )
    return proc.stdout


def _read_pubkey_der() -> bytes:
    proc = subprocess.run(
        ["openssl", "x509", "-in", _cert_path(), "-pubkey", "-noout"],
        capture_output=True, check=True,
    )
    pub_pem = proc.stdout
    proc2 = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pub_pem, capture_output=True, check=True,
    )
    return proc2.stdout
