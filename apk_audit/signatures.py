"""签名方案分析（v1 / v2 / v3 / v3.1）。

- v1：解析 META-INF/MANIFEST.MF、*.SF、PKCS#7（.RSA/.DSA/.EC），
  逐条目比对摘要；PKCS#7 密码学验证可选地调用系统 openssl。
- v2/v3：按 AOSP 规范解析 APK Signing Block 中的 length-prefixed 序列，
  并用标准库 hashlib 复算内容摘要，确认摘要与实际 APK 一致。

全程仅依赖标准库（openssl 仅用于 v1 CMS 密码学验证，缺失时降级）。
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field

from .apkfile import APKFile, ALGO_ID_V2, ALGO_ID_V3, ALGO_ID_V31

JAR_SF_EXTS = (".SF",)
JAR_PKCS7_EXTS = (".RSA", ".DSA", ".EC")


class _SeqReader:
    """APK 签名块里到处使用的 uint32 长度前缀序列。"""

    def __init__(self, data: bytes, start: int = 0, end: int | None = None):
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from("<Q", self.data, self.pos)[0]
        self.pos += 8
        return v

    def length_prefixed(self) -> bytes:
        n = self.u32()
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        if len(out) != n:
            raise ValueError("length-prefixed 序列越界")
        return out

    def remaining(self) -> int:
        return self.end - self.pos


def _chunked_digest(data: bytes, factory) -> bytes:
    """AOSP v2/v3 内容摘要：1MB 分块，块前置 u32 长度，末尾补 0 长度块。"""
    h = factory()
    chunk_size = 0xA00000
    pos = 0
    while pos < len(data):
        part = data[pos : pos + chunk_size]
        h.update(struct.pack("<I", len(part)))
        h.update(part)
        pos += chunk_size
    h.update(struct.pack("<I", 0))
    return h.digest()


@dataclass
class V1Result:
    present: bool = False
    manifest_entries: int = 0
    sf_files: list[str] = field(default_factory=list)
    pkcs7_files: list[str] = field(default_factory=list)
    entry_digest_mismatches: list[str] = field(default_factory=list)
    sf_digest_mismatches: list[str] = field(default_factory=list)
    crypto_verified: bool | None = None     # None=未验证（无 openssl）
    crypto_error: str | None = None
    signer_subject: str | None = None


@dataclass
class V2V3Result:
    scheme: str
    present: bool
    signers: int = 0
    digest_algorithms: list[str] = field(default_factory=list)
    digest_matches_apk: bool | None = None
    digest_mismatch_algos: list[str] = field(default_factory=list)
    min_sdk: int | None = None
    max_sdk: int | None = None
    parse_error: str | None = None


# ----------------------------------------------------------------------
# v1（JAR 签名）
# ----------------------------------------------------------------------
def _parse_manifest_sections(raw: bytes) -> list[dict[str, str]]:
    """按空行切段，每段解析成 key: value（处理续行空格）。"""
    text = raw.decode("utf-8", errors="replace")
    sections: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key = None
    for line in text.splitlines():
        if line == "":
            if current:
                sections.append(current)
            current = {}
            last_key = None
            continue
        if line.startswith((" ", "\t")) and last_key:
            current[last_key] += line[1:]
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
            last_key = key.strip()
    if current:
        sections.append(current)
    return sections


def _digest_of_manifest_section(section: dict[str, str]) -> dict[str, str]:
    """复算一段 manifest 条目的摘要，返回 {算法大写: base64}。"""
    # 段必须以 CRLF 结尾，且整体再补一个 CRLF（空行）
    block = "".join(f"{k}: {v}\r\n" for k, v in section.items()) + "\r\n"
    out = {}
    for key, algo in (("SHA-256-Digest", "sha256"), ("SHA1-Digest", "sha1")):
        if key in section:
            out[algo] = base64.b64encode(
                hashlib.new(algo, block.encode("utf-8")).digest()
            ).decode("ascii")
    return out


def _verify_v1(apk: APKFile) -> V1Result:
    res = V1Result()
    meta = [n for n in apk.names() if n.startswith("META-INF/")]
    sf_files = [n for n in meta if n.upper().endswith(JAR_SF_EXTS)]
    pkcs7 = [
        n
        for n in meta
        if n.upper().endswith(JAR_PKCS7_EXTS)
    ]
    res.sf_files = sf_files
    res.pkcs7_files = pkcs7
    if not sf_files and not pkcs7:
        return res
    res.present = True

    if not apk.has("META-INF/MANIFEST.MF"):
        res.entry_digest_mismatches.append("缺少 META-INF/MANIFEST.MF")
        return res

    manifest_raw = apk.read("META-INF/MANIFEST.MF")
    sections = _parse_manifest_sections(manifest_raw)
    entry_sections = [s for s in sections if "Name" in s]
    res.manifest_entries = len(entry_sections)

    # 1) 每个被签名条目的实际摘要 vs MANIFEST.MF 记录
    for sec in entry_sections:
        name = sec["Name"]
        if not apk.has(name):
            res.entry_digest_mismatches.append(f"{name}: 条目不存在")
            continue
        actual = apk.read(name)
        for key, algo in (("SHA-256-Digest", "sha256"), ("SHA1-Digest", "sha1")):
            if key in sec:
                calc = base64.b64encode(hashlib.new(algo, actual).digest()).decode()
                if calc != sec[key]:
                    res.entry_digest_mismatches.append(f"{name}: {algo} 摘要不一致")
                break

    # 2) .SF 对 MANIFEST.MF 段的摘要
    for sf_name in sf_files:
        sf_sections = _parse_manifest_sections(apk.read(sf_name))
        main = sf_sections[0] if sf_sections else {}
        # 主属性里的整文件摘要
        whole_ok = False
        for key, algo in (
            ("SHA-256-Digest-Manifest", "sha256"),
            ("SHA1-Digest-Manifest", "sha1"),
        ):
            if key in main:
                calc = base64.b64encode(
                    hashlib.new(algo, manifest_raw).digest()
                ).decode()
                if calc != main[key]:
                    res.sf_digest_mismatches.append(
                        f"{sf_name}: {algo} 整文件摘要不一致"
                    )
                else:
                    whole_ok = True
                break
        if whole_ok:
            continue
        # 退化为逐段摘要
        manifest_by_name = {s.get("Name"): s for s in entry_sections}
        for sf_sec in sf_sections:
            name = sf_sec.get("Name")
            if not name or name not in manifest_by_name:
                continue
            calc_map = _digest_of_manifest_section(manifest_by_name[name])
            for algo, calc in calc_map.items():
                key = "SHA-256-Digest" if algo == "sha256" else "SHA1-Digest"
                if key in sf_sec and sf_sec[key] != calc:
                    res.sf_digest_mismatches.append(
                        f"{sf_name}: 条目 {name} 的 {algo} 摘要不一致"
                    )

    # 3) PKCS#7 密码学验证（openssl cms）
    if pkcs7 and shutil.which("openssl"):
        sf_name = sf_files[0] if sf_files else None
        sig_name = pkcs7[0]
        if sf_name:
            try:
                sf_data = apk.read(sf_name)
                sig_data = apk.read(sig_name)
                with tempfile.TemporaryDirectory() as td:
                    sf_path = f"{td}/CERT.SF"
                    sig_path = f"{td}/CERT.P7"
                    with open(sf_path, "wb") as fh:
                        fh.write(sf_data)
                    with open(sig_path, "wb") as fh:
                        fh.write(sig_data)
                    proc = subprocess.run(
                        [
                            "openssl", "cms", "-verify",
                            "-binary", "-inform", "DER",
                            "-in", sig_path,
                            "-content", sf_path,
                            "-noverify", "-out", f"{td}/out",
                        ],
                        capture_output=True,
                    )
                    res.crypto_verified = proc.returncode == 0
                    if proc.returncode != 0:
                        res.crypto_error = proc.stderr.decode(
                            "utf-8", "replace"
                        ).strip()[:200]
                    else:
                        subj = subprocess.run(
                            [
                                "openssl", "pkcs7", "-inform", "DER",
                                "-in", sig_path, "-print_certs", "-noout",
                                "-subject",
                            ],
                            capture_output=True,
                        )
                        res.signer_subject = subj.stdout.decode(
                            "utf-8", "replace"
                        ).strip().split("subject=")[-1][:120] or None
            except (OSError, subprocess.SubprocessError) as exc:
                res.crypto_verified = False
                res.crypto_error = str(exc)[:200]
    return res


# ----------------------------------------------------------------------
# v2 / v3（APK Signing Block）
# ----------------------------------------------------------------------
_DIGEST_ALGO_MAP = {
    0x0101: ("SHA-256", hashlib.sha256),
    0x0102: ("SHA-512", hashlib.sha512),
    0x0103: ("SHA-1", hashlib.sha1),
    0x0104: ("SHA-384", hashlib.sha384),
}
_SIG_ALGO_MAP = {
    0x0101: "RSASSA-PSS with SHA2-256",
    0x0102: "RSASSA-PSS with SHA2-512",
    0x0103: "ECDSA with SHA2-256",
    0x0104: "RSASSA-PKCS1-v1_5 with SHA2-256",
    0x0105: "RSASSA-PKCS1-v1_5 with SHA2-512",
    0x0106: "ECDSA with SHA2-512",
    0x0201: "RSASSA-PSS with SHA2-256 (v3.1)",
    0x0202: "RSASSA-PSS with SHA2-512 (v3.1)",
    0x0203: "ECDSA with SHA2-256 (v3.1)",
}


def _parse_v2(block_value: bytes, apk: APKFile) -> V2V3Result:
    res = V2V3Result(scheme="v2", present=True)
    try:
        # 块值即 length-prefixed signers 序列：u32(len) + signers...
        signers_seq = _SeqReader(block_value)
        content = apk.content_before_sig_block()
        while signers_seq.remaining() > 0:
            signer_block = _SeqReader(signers_seq.length_prefixed())
            signed_data_seq = _SeqReader(signer_block.length_prefixed())

            # signed data: digests, certificates, additional-attributes
            digests_seq = _SeqReader(signed_data_seq.length_prefixed())
            while digests_seq.remaining() > 0:
                item = _SeqReader(digests_seq.length_prefixed())
                algo_id = item.u32()
                digest = item.length_prefixed()
                name, factory = _DIGEST_ALGO_MAP.get(
                    algo_id, (f"0x{algo_id:x}", None)
                )
                res.digest_algorithms.append(name)
                if factory is not None:
                    calc = _chunked_digest(content, factory)
                    if calc != digest:
                        res.digest_matches_apk = False
                        res.digest_mismatch_algos.append(name)
            res.signers += 1
        if res.digest_matches_apk is None and res.digest_algorithms:
            res.digest_matches_apk = True
    except (ValueError, struct.error) as exc:
        res.parse_error = str(exc)
    return res


def _parse_v3(block_value: bytes, apk: APKFile, scheme: str = "v3") -> V2V3Result:
    res = V2V3Result(scheme=scheme, present=True)
    try:
        outer = _SeqReader(block_value)
        # v3: minSdk(uint32), maxSdk(uint32), 然后才是 length-prefixed signers
        if scheme == "v3":
            res.min_sdk = outer.u32()
            res.max_sdk = outer.u32()
        signers_seq = _SeqReader(outer.length_prefixed())
        content = apk.content_before_sig_block()
        while signers_seq.remaining() > 0:
            signer_block = _SeqReader(signers_seq.length_prefixed())
            signed_data_seq = _SeqReader(signer_block.length_prefixed())
            digests_seq = _SeqReader(signed_data_seq.length_prefixed())
            while digests_seq.remaining() > 0:
                item = _SeqReader(digests_seq.length_prefixed())
                algo_id = item.u32()
                digest = item.length_prefixed()
                name, factory = _DIGEST_ALGO_MAP.get(
                    algo_id, (f"0x{algo_id:x}", None)
                )
                res.digest_algorithms.append(name)
                if factory is not None:
                    calc = _chunked_digest(content, factory)
                    if calc != digest:
                        res.digest_matches_apk = False
                        res.digest_mismatch_algos.append(name)
            res.signers += 1
        if res.digest_matches_apk is None and res.digest_algorithms:
            res.digest_matches_apk = True
    except (ValueError, struct.error) as exc:
        res.parse_error = str(exc)
    return res


def analyze_signatures(apk: APKFile) -> dict:
    """汇总四个方案的分析结果。"""
    out: dict = {
        "v1": _verify_v1(apk),
        "v2": V2V3Result(scheme="v2", present=False),
        "v3": V2V3Result(scheme="v3", present=False),
        "v3.1": V2V3Result(scheme="v3.1", present=False),
    }
    schemes = apk.signing_schemes()
    if "v2" in schemes:
        out["v2"] = _parse_v2(schemes["v2"], apk)
    if "v3" in schemes:
        out["v3"] = _parse_v3(schemes["v3"], apk, "v3")
    if "v3.1" in schemes:
        # v3.1 结构与 v3 同构（带 min/maxSdk 包装）
        out["v3.1"] = _parse_v3(schemes["v3.1"], apk, "v3.1")
    return out
