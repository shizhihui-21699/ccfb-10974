"""JAR (v1) signature implementation.

Writes META-INF/MANIFEST.MF, CERT.SF and a DER PKCS#7/CMS CERT.RSA using
openssl cms. Digest algorithm is selectable so the SHA-1 sample exercises the
weak-hash rule.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
import zipfile
from typing import Dict, List, Tuple


def _wrap(line: str, limit: int = 70) -> bytes:
    """RFC 7230-style manifest folding: continuation lines start with a space."""
    raw = line.encode("utf-8")
    if len(raw) <= limit:
        return raw + b"\r\n"
    out = []
    first = True
    while raw:
        if first:
            out.append(raw[:limit])
            raw = raw[limit:]
            first = False
        else:
            out.append(b" " + raw[: limit - 1])
            raw = raw[limit - 1 :]
    return b"\r\n".join(out) + b"\r\n"


def _b64_digest(data: bytes, algo: str) -> str:
    return base64.b64encode(hashlib.new(algo, data).digest()).decode("ascii")


def build_manifest_mf(entries: List[Tuple[str, bytes]], algo: str = "sha256") -> bytes:
    digest_header = f"{algo.upper().replace('SHA', 'SHA-')}-Digest"
    parts = [
        _wrap("Manifest-Version: 1.0"),
        _wrap("Created-By: apk-audit-test-generifier"),
        b"\r\n",
    ]
    for name, content in entries:
        parts.append(_wrap(f"Name: {name}"))
        parts.append(_wrap(f"{digest_header}: {_b64_digest(content, algo)}"))
        parts.append(b"\r\n")
    return b"".join(parts)


def build_cert_sf(manifest_mf: bytes, algo: str = "sha256") -> bytes:
    hash_name = algo.upper().replace("SHA", "SHA-")
    whole = base64.b64encode(hashlib.new(algo, manifest_mf).digest()).decode("ascii")
    # Per-section digests are computed per section bytes (including trailing
    # CRLF) by real tools; the whole-manifest digest alone is sufficient for
    # openssl cms verification, and our auditor checks the whole-manifest one.
    parts = [
        _wrap("Signature-Version: 1.0"),
        _wrap("Created-By: apk-audit-test-generifier"),
        _wrap(f"{hash_name}-Digest-Manifest-Main-Attributes: {whole}"),
        _wrap(f"{hash_name}-Digest-Manifest: {whole}"),
        b"\r\n",
    ]
    return b"".join(parts)


def build_pkcs7(cert_sf: bytes, key_pem: str, cert_pem: str, algo: str) -> bytes:
    """Sign CERT.SF producing a DER SignedData (CERT.RSA equivalent)."""
    with tempfile.TemporaryDirectory() as td:
        sf_path = os.path.join(td, "CERT.SF")
        out_path = os.path.join(td, "CERT.RSA")
        with open(sf_path, "wb") as fh:
            fh.write(cert_sf)
        cmd = [
            "openssl", "cms", "-sign",
            "-binary",
            "-in", sf_path,
            "-signer", cert_pem,
            "-inkey", key_pem,
            "-outform", "DER",
            "-out", out_path,
            "-md", algo,
            "-noattr",
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        with open(out_path, "rb") as fh:
            return fh.read()


def sign_v1(
    apk_path: str,
    key_pem: str,
    cert_pem: str,
    algo: str = "sha256",
) -> None:
    """Add v1 signature files to an existing unsigned APK in place."""
    with zipfile.ZipFile(apk_path, "r") as zf:
        names = [
            n
            for n in zf.namelist()
            if not n.upper().startswith("META-INF/")
        ]
        entries = [(n, zf.read(n)) for n in names]

    manifest_mf = build_manifest_mf(entries, algo)
    cert_sf = build_cert_sf(manifest_mf, algo)
    cert_rsa = build_pkcs7(cert_sf, key_pem, cert_pem, algo)

    # Rewrite: original entries first, META-INF signature files last, no
    # compression surprises for the signing block logic.
    with zipfile.ZipFile(apk_path, "r") as zin:
        infos = {i.filename: i for i in zin.infolist()}
        with zipfile.ZipFile(
            apk_path + ".tmp", "w", zipfile.ZIP_DEFLATED
        ) as zout:
            for name, content in entries:
                info = infos[name]
                new_info = zipfile.ZipInfo(name, date_time=info.date_time)
                new_info.compress_type = info.compress_type
                new_info.external_attr = info.external_attr
                zout.writestr(new_info, content)
            for meta, content in (
                ("META-INF/MANIFEST.MF", manifest_mf),
                ("META-INF/CERT.SF", cert_sf),
                ("META-INF/CERT.RSA", cert_rsa),
            ):
                zout.writestr(meta, content, compress_type=zipfile.ZIP_DEFLATED)
    os.replace(apk_path + ".tmp", apk_path)
