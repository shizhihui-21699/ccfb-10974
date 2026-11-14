"""APK signature analysis: JAR (v1), APK Signature Scheme v2 and v3.

Detection follows AOSP packages/apps/apksig (constants cross-checked against
platform/tools/apksig):

* v1: META-INF/MANIFEST.MF + a signature file (.SF) + a PKCS#7 block (.RSA/.DSA/.EC)
* v2: APK Signing Block pair ID 0x7109871a
* v3: pair ID 0xf05368c0 (v3.1: 0x1b93ad61, handled as v3-family)

Verification uses the openssl CLI (RSA/ECDSA/DSA) so no third-party Python
crypto dependency is required.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .binary import BinaryReader

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61

# SignatureAlgorithm enum values from apksig SignatureAlgorithm.java
ALGO = {
    0x0101: ("RSA", "sha256", "pss"),
    0x0102: ("RSA", "sha512", "pss"),
    0x0103: ("RSA", "sha256", "pkcs1"),
    0x0104: ("RSA", "sha512", "pkcs1"),
    0x0201: ("EC", "sha256", "ecdsa"),
    0x0202: ("EC", "sha512", "ecdsa"),
    0x0301: ("DSA", "sha256", "dsa"),
    0x0421: ("RSA", "sha256", "pkcs1"),  # fsverity
    0x0423: ("EC", "sha256", "ecdsa"),
    0x0425: ("DSA", "sha256", "dsa"),
}

CHUNK_SIZE = 1024 * 1024


@dataclass
class SigCheck:
    scheme: str            # "v1" | "v2" | "v3"
    present: bool
    structural_ok: bool = False
    verified: bool = False
    digest_match: Optional[bool] = None
    algorithms: List[str] = field(default_factory=list)
    signer_subjects: List[str] = field(default_factory=list)
    weak_hash: bool = False
    errors: List[str] = field(default_factory=list)
    details: Dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------- ZIP IO
def find_eocd(data: bytes) -> Tuple[int, int]:
    """Locate the End Of Central Directory record.

    Returns (eocd_offset, central_dir_offset).
    """
    # EOCD has a 22-byte fixed header plus a variable comment (max 65535).
    max_back = min(len(data), 22 + 65535)
    tail = data[-max_back:]
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0:
        raise ValueError("not a ZIP/APK: EOCD record not found")
    eocd = len(data) - max_back + idx
    if len(data) < eocd + 22:
        raise ValueError("truncated EOCD record")
    (
        _disk,
        _cd_disk,
        _disk_entries,
        _total_entries,
        _cd_size,
        cd_offset,
        _comment_len,
    ) = struct.unpack_from("<HHHHIIH", data, eocd + 4)
    return eocd, cd_offset


def parse_signing_block(data: bytes) -> Optional[Tuple[int, int, List[Tuple[int, bytes]]]]:
    """Parse the APK Signing Block if present.

    Returns (block_start, block_size, pairs) or None. Block layout::

        size of block (uint64, excludes this field)
        repeated: pair-size (uint64), ID (uint32), value
        size of block (uint64, repeated)
        magic "APK Sig Block 42" (16 bytes)
    """
    try:
        eocd, cd_offset = find_eocd(data)
    except ValueError:
        return None
    magic_pos = cd_offset - 16
    if magic_pos < 24 or data[magic_pos:cd_offset] != APK_SIG_BLOCK_MAGIC:
        return None
    footer_size = struct.unpack_from("<Q", data, magic_pos - 8)[0]
    block_start = cd_offset - footer_size - 8
    if block_start < 0:
        return None
    # Sanity: header size-of-block must equal footer size-of-block.
    header_size = struct.unpack_from("<Q", data, block_start)[0]
    if header_size != footer_size:
        return None
    pairs: List[Tuple[int, bytes]] = []
    r = BinaryReader(data, block_start + 8)
    end = magic_pos - 8
    while r.pos < end:
        pair_len = struct.unpack_from("<Q", data, r.pos)[0]
        r.pos += 8
        if pair_len < 4 or r.pos + pair_len > end:
            raise ValueError("malformed APK Signing Block pair")
        pair_id = r.u32()
        value = r.read(pair_len - 4)
        pairs.append((pair_id, value))
    return block_start, footer_size + 8, pairs


# ------------------------------------------------------- chunked content digest
def chunked_digest(segments: List[bytes], hash_name: str) -> bytes:
    """Compute the v2/v3 content digest over the given segments.

    Each segment is split into 1 MiB chunks. Per AOSP:
      chunk_digest = H(0xa5 || uint32_le(len) || chunk)
      output       = H(0x5a || uint32_le(num_chunks) || concat(chunk_digests))
    Empty segments produce no chunks.
    """
    h = hashlib.new(hash_name)
    chunk_count = 0
    chunk_digests = bytearray()
    for segment in segments:
        off = 0
        n = len(segment)
        while off < n:
            chunk = segment[off : off + CHUNK_SIZE]
            off += len(chunk)
            ch = hashlib.new(hash_name)
            ch.update(b"\xa5" + struct.pack("<I", len(chunk)) + chunk)
            chunk_digests += ch.digest()
            chunk_count += 1
    h.update(b"\x5a" + struct.pack("<I", chunk_count) + bytes(chunk_digests))
    return h.digest()


# --------------------------------------------------------------- v2/v3 parse
# All integers inside an APK Signature Scheme v2/v3 block value are encoded
# big-endian (the surrounding APK Signing Block container is little-endian).
def _parse_signers(value: bytes, is_v3: bool) -> List[dict]:
    """Parse the signers block.

    Per AOSP V2SchemeVerifier.parseSigners: the pair value is itself a
    length-prefixed sequence of length-prefixed signers.
    """
    sr = BinaryReader(value)
    signers: List[dict] = []
    while sr.remaining():
        signer = sr.be_len_prefixed_u32()
        signers.append(_parse_signer(signer, is_v3))
    if not signers:
        raise ValueError("signer 序列为空")
    return signers


def _parse_signer(blob: bytes, is_v3: bool) -> dict:
    r = BinaryReader(blob)
    signed_data = r.be_len_prefixed_u32()
    min_sdk = max_sdk = None
    if is_v3:
        min_sdk = r.be_u32()
        max_sdk = r.be_u32()
    signatures_blob = r.be_len_prefixed_u32()
    public_key = r.be_len_prefixed_u32()

    sigr = BinaryReader(signatures_blob)
    signatures = []
    # The signatures field body holds records directly: algoId(u32 BE)
    # followed by a length-prefixed signature byte array.
    while sigr.remaining():
        algo_id = sigr.be_u32()
        sig_bytes = sigr.be_len_prefixed_u32()
        signatures.append((algo_id, sig_bytes))

    sdr = BinaryReader(signed_data)
    digests_blob = sdr.be_len_prefixed_u32()
    certs_blob = sdr.be_len_prefixed_u32()
    if is_v3:
        sd_min_sdk = sdr.be_u32()
        sd_max_sdk = sdr.be_u32()
        _additional_attrs = sdr.be_len_prefixed_u32()
    else:
        sd_min_sdk = sd_max_sdk = None

    dr = BinaryReader(digests_blob)
    digests = []
    # digests field body holds records directly: algoId + prefixed digest.
    while dr.remaining():
        algo_id = dr.be_u32()
        digest = dr.be_len_prefixed_u32()
        digests.append((algo_id, digest))

    cr = BinaryReader(certs_blob)
    certs = []
    while cr.remaining():
        certs.append(cr.be_len_prefixed_u32())

    return {
        "signed_data": signed_data,
        "min_sdk": min_sdk,
        "max_sdk": max_sdk,
        "signed_min_sdk": sd_min_sdk,
        "signed_max_sdk": sd_max_sdk,
        "signatures": signatures,
        "public_key": public_key,
        "digests": digests,
        "certificates": certs,
    }


# ------------------------------------------------------------- openssl verify
def _have_openssl() -> bool:
    return shutil.which("openssl") is not None


def _run_openssl(args: List[str], stdin: bytes) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["openssl", *args],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    ok = proc.returncode == 0
    msg = (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()
    return ok, msg


def verify_signature(
    algo_id: int, signed_data: bytes, sig_bytes: bytes, cert_der: bytes
) -> Tuple[bool, str]:
    """Verify one v2/v3 signature with openssl.

    The certificate is converted to a PEM SubjectPublicKeyInfo first, because
    ``openssl dgst -verify`` expects a public key rather than an X.509 cert.
    """
    info = ALGO.get(algo_id)
    if info is None:
        return False, f"unsupported algorithm id 0x{algo_id:04x}"
    key_type, hash_name, mode = info
    with tempfile.TemporaryDirectory() as td:
        cert_der_path = os.path.join(td, "cert.der")
        pubkey_pem_path = os.path.join(td, "pubkey.pem")
        sig_path = os.path.join(td, "sig.bin")
        data_path = os.path.join(td, "data.bin")
        with open(cert_der_path, "wb") as fh:
            fh.write(cert_der)
        with open(data_path, "wb") as fh:
            fh.write(signed_data)

        # cert.der -> public key PEM.
        ok, msg = _run_openssl(
            ["x509", "-inform", "DER", "-in", cert_der_path,
             "-pubkey", "-noout"],
            b"",
        )
        if not ok:
            return False, f"提取公钥失败: {msg}"
        # Re-run capturing stdout to a file (the helper only returns text).
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", cert_der_path,
             "-pubkey", "-noout"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        if proc.returncode != 0:
            return False, "提取公钥失败"
        with open(pubkey_pem_path, "wb") as fh:
            fh.write(proc.stdout)

        signature_bytes = sig_bytes
        if key_type in ("EC", "DSA"):
            # apksig stores raw r||s; openssl wants a DER INTEGER pair.
            signature_bytes = _ecdsa_raw_to_der(sig_bytes)
        with open(sig_path, "wb") as fh:
            fh.write(signature_bytes)

        args = ["dgst", f"-{hash_name}", "-verify", pubkey_pem_path,
                "-signature", sig_path]
        if key_type == "RSA" and mode == "pss":
            salt = 32 if hash_name == "sha256" else 64
            args += ["-sigopt", "rsa_padding_mode:pss",
                     "-sigopt", f"rsa_pss_saltlen:{salt}"]
        args.append(data_path)
        return _run_openssl(args, b"")


def _ecdsa_raw_to_der(raw: bytes) -> bytes:
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")

    def enc_int(v: int) -> bytes:
        body = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body

    payload = enc_int(r) + enc_int(s)
    return b"\x30" + bytes([len(payload)]) + payload


def cert_subject(cert_der: bytes) -> str:
    ok, msg = _run_openssl(
        ["x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "RFC2253"],
        cert_der,
    )
    if not ok:
        return "(unparseable certificate)"
    return msg.replace("subject=", "").strip() or "(empty subject)"


def cert_fingerprint(cert_der: bytes) -> str:
    ok, msg = _run_openssl(
        ["x509", "-inform", "DER", "-noout", "-fingerprint", "-sha256"],
        cert_der,
    )
    if not ok:
        return ""
    return msg.strip()


# ---------------------------------------------------------------- v2/v3 main
def analyze_v2_v3(data: bytes, segments: List[bytes]) -> Dict[str, SigCheck]:
    result = {
        "v2": SigCheck("v2", present=False),
        "v3": SigCheck("v3", present=False),
    }
    parsed = parse_signing_block(data)
    if parsed is None:
        return result
    _start, _size, pairs = parsed
    by_id = {pid: val for pid, val in pairs}

    for scheme, block_id, is_v3 in (
        ("v2", V2_BLOCK_ID, False),
        ("v3", V3_BLOCK_ID, True),
    ):
        check = result[scheme]
        if block_id not in by_id and not (
            scheme == "v3" and V31_BLOCK_ID in by_id
        ):
            continue
        check.present = True
        value = by_id.get(block_id) or by_id.get(V31_BLOCK_ID)
        try:
            signers = _parse_signers(value, is_v3)
            check.structural_ok = True
        except Exception as exc:  # noqa: BLE001 - report every malformed case
            check.errors.append(f"结构解析失败: {exc}")
            continue
        any_verified = False
        any_digest = False
        for signer in signers:
            certs = signer["certificates"]
            if certs:
                check.signer_subjects.append(cert_subject(certs[0]))
            for algo_id, sig_bytes in signer["signatures"]:
                info = ALGO.get(algo_id)
                label = (
                    f"0x{algo_id:04x} "
                    f"{info[0]}-{info[1].upper()}-{info[2].upper()}"
                    if info
                    else f"0x{algo_id:04x} 未知算法"
                )
                check.algorithms.append(label)
                if info and info[1] == "sha256" and info[2] in ("dsa",):
                    pass
                if certs and info and _have_openssl():
                    ok, msg = verify_signature(
                        algo_id, signer["signed_data"], sig_bytes, certs[0]
                    )
                    if ok:
                        any_verified = True
                    else:
                        check.errors.append(f"签名验签失败 ({label}): {msg}")
            for algo_id, digest in signer["digests"]:
                info = ALGO.get(algo_id)
                if not info:
                    continue
                hash_name = info[1]
                actual = chunked_digest(segments, hash_name)
                if actual == digest:
                    any_digest = True
                else:
                    check.digest_match = False
                    check.errors.append(
                        f"内容摘要不匹配 ({hash_name})：APK 内容与签名块记录不一致"
                    )
        check.verified = any_verified
        check.digest_match = any_digest if check.digest_match is None else False
        if is_v3 and signers:
            s0 = signers[0]
            check.details["minSdk"] = s0["min_sdk"]
            check.details["maxSdk"] = s0["max_sdk"]
    return result


# ----------------------------------------------------------------------- v1
_NAME_RE = re.compile(rb"^Name:\s*(.+?)\s*$")


def _parse_manifest_sections(raw: bytes) -> List[Dict[bytes, bytes]]:
    text = raw.replace(b"\r\n", b"\n")
    sections: List[Dict[bytes, bytes]] = []
    current: Dict[bytes, bytes] = {}
    for line in text.split(b"\n"):
        if line == b"":
            if current:
                sections.append(current)
                current = {}
            continue
        if b":" in line:
            k, v = line.split(b":", 1)
            current[k.strip().lower()] = v.strip()
    if current:
        sections.append(current)
    return sections


def analyze_v1(zf: zipfile.ZipFile) -> SigCheck:
    check = SigCheck("v1", present=False)
    names = zf.namelist()
    meta = [n for n in names if n.upper().startswith("META-INF/")]
    has_manifest = "META-INF/MANIFEST.MF" in names
    sf_files = [n for n in meta if n.upper().endswith(".SF")]
    block_files = [
        n
        for n in meta
        if n.upper().endswith((".RSA", ".DSA", ".EC"))
        or ("/SIG-" in n.upper())
    ]
    if not (has_manifest and sf_files and block_files):
        return check
    check.present = True

    try:
        manifest_raw = zf.read("META-INF/MANIFEST.MF")
        sections = _parse_manifest_sections(manifest_raw)
    except KeyError:
        check.errors.append("缺少 META-INF/MANIFEST.MF")
        return check
    check.structural_ok = True

    # Main section first, then per-entry digests. JAR tools emit either
    # "SHA-256-Digest" / "SHA-1-Digest" (hyphenated) or the older
    # "SHA1-Digest" spelling; the section parser lowercases keys.
    digest_keys = (b"sha-256-digest", b"sha-1-digest", b"sha1-digest",
                   b"sha-512-digest")
    entry_digests: Dict[str, str] = {}
    for sec in sections[1:]:
        name = sec.get(b"name")
        digest = next((sec[k] for k in digest_keys if k in sec), None)
        if name and digest:
            entry_digests[name.decode()] = digest.decode()
    weak = any(
        (b"sha-1-digest" in s or b"sha1-digest" in s) for s in sections
    )
    check.weak_hash = weak

    # Verify each entry against MANIFEST.MF.
    digest_failures: List[str] = []
    for entry_name, expected_b64 in entry_digests.items():
        if entry_name not in names:
            digest_failures.append(f"{entry_name}: 清单引用但 APK 中不存在")
            continue
        algo = "sha1" if len(expected_b64) <= 28 else "sha256"
        import base64

        try:
            content = zf.read(entry_name)
        except Exception as exc:  # noqa: BLE001 - CRC/decompression failure
            digest_failures.append(
                f"{entry_name}: 条目无法读取（CRC/解压失败，疑似被篡改）: {exc.__class__.__name__}"
            )
            continue
        actual = hashlib.new(algo, content).digest()

        if base64.b64encode(actual).decode() != expected_b64:
            digest_failures.append(f"{entry_name}: 内容摘要不匹配")
    check.digest_match = not digest_failures
    check.errors.extend(digest_failures)

    # Verify the .SF over MANIFEST.MF and the PKCS#7 block over the .SF.
    import base64

    for sf_name in sf_files:
        stem = sf_name.rsplit(".", 1)[0]
        block = next(
            (n for n in block_files if n.rsplit(".", 1)[0].upper() == stem.upper()),
            None,
        )
        if block is None:
            check.errors.append(f"{sf_name}: 找不到对应的 PKCS#7 签名块")
            continue
        sf_raw = zf.read(sf_name)
        sf_sections = _parse_manifest_sections(sf_raw)
        # Whole-manifest digest field. Section keys are lowercased by the
        # section parser. Real tools emit either
        # "<algo>-Digest-Manifest" (over the whole MANIFEST.MF) or
        # "<algo>-Digest-Manifest-Main-Attributes" (over the main section only).
        main_sf = sf_sections[0] if sf_sections else {}
        main_section_raw = manifest_raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
        sf_ok = False
        for key, algo, target in (
            (b"sha-256-digest-manifest", "sha256", manifest_raw),
            (b"sha-256-digest-manifest-main-attributes", "sha256", main_section_raw),
            (b"sha-1-digest-manifest", "sha1", manifest_raw),
            (b"sha-1-digest-manifest-main-attributes", "sha1", main_section_raw),
            (b"sha1-digest-manifest", "sha1", manifest_raw),
            (b"sha1-digest-manifest-main-attributes", "sha1", main_section_raw),
        ):
            if key in main_sf:
                want = base64.b64decode(main_sf[key])
                got = hashlib.new(algo, target).digest()
                sf_ok = want == got
                if algo == "sha1":
                    check.weak_hash = True
                break
        if not sf_ok:
            check.errors.append(f"{sf_name}: 对 MANIFEST.MF 的摘要校验失败")
        block_raw = zf.read(block)
        ok, msg = _openssl_pkcs7_verify(block_raw, sf_raw)
        if ok:
            check.verified = True
            check.algorithms.append(
                "SHA1withRSA (弱)" if check.weak_hash else "JAR v1 PKCS#7"
            )
            # Extract signer certificate subject from the PKCS#7 block.
            subj = _pkcs7_subject(block_raw)
            if subj:
                check.signer_subjects.append(subj)
        else:
            check.errors.append(f"{block}: PKCS#7 验签失败: {msg}")

    # Entries not covered by MANIFEST.MF (excluding META-INF signature files
    # themselves, which are intentionally unsigned).
    signed_meta = {
        n.upper()
        for n in names
        if n.upper().startswith("META-INF/")
        and n.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))
    }
    uncovered = [
        n
        for n in names
        if n not in entry_digests
        and n != "META-INF/MANIFEST.MF"
        and n.upper() not in signed_meta
    ]
    if uncovered:
        check.errors.append(
            "存在未纳入 v1 签名的条目: " + ", ".join(uncovered[:5])
            + (" ..." if len(uncovered) > 5 else "")
        )
    return check


def _openssl_pkcs7_verify(p7: bytes, content: bytes) -> Tuple[bool, str]:
    if not _have_openssl():
        return False, "openssl 不可用"
    with tempfile.TemporaryDirectory() as td:
        p7_path = os.path.join(td, "CERT.RSA")
        content_path = os.path.join(td, "CERT.SF")
        with open(p7_path, "wb") as fh:
            fh.write(p7)
        with open(content_path, "wb") as fh:
            fh.write(content)
        ok, msg = _run_openssl(
            [
                "smime",
                "-verify",
                "-inform",
                "DER",
                "-in",
                p7_path,
                "-content",
                content_path,
                "-noverify",
            ],
            b"",
        )
        return ok, msg


def _pkcs7_subject(p7: bytes) -> str:
    if not _have_openssl():
        return ""
    with tempfile.TemporaryDirectory() as td:
        p7_path = os.path.join(td, "CERT.RSA")
        with open(p7_path, "wb") as fh:
            fh.write(p7)
        ok, msg = _run_openssl(
            [
                "pkcs7",
                "-inform",
                "DER",
                "-in",
                p7_path,
                "-print_certs",
                "-noout",
            ],
            b"",
        )
        if not ok:
            return ""
        subject = ""
        for line in msg.splitlines():
            if line.startswith("subject="):
                subject = line.split("subject=", 1)[1].strip()
                break
        return subject


def signing_block_segments(data: bytes) -> List[bytes]:
    """Return the two content segments protected by v2/v3 digests:
    everything before the signing block and the central directory + EOCD."""
    parsed = parse_signing_block(data)
    if parsed is None:
        _eocd, cd_offset = find_eocd(data)
        return [data[:cd_offset], data[cd_offset:]]
    block_start, block_size, _pairs = parsed
    _eocd, cd_offset = find_eocd(data)
    return [data[:block_start], data[block_start + block_size :]]
