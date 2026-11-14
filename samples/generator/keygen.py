"""RSA key pair and self-signed X.509 certificate generation via openssl CLI.

Produces PEM private key and DER certificate files on disk; v1 needs the
PKCS#7/CMS wrapper and v2/v3 need the DER certificate embedded as-is.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


@dataclass
class SigningKey:
    key_pem: str
    cert_der: str
    cert_pem: str


def generate_rsa_key(out_dir: str, name: str = "testkey", bits: int = 2048) -> SigningKey:
    os.makedirs(out_dir, exist_ok=True)
    key_pem = os.path.join(out_dir, f"{name}.pem")
    cert_pem = os.path.join(out_dir, f"{name}.crt.pem")
    cert_der = os.path.join(out_dir, f"{name}.crt.der")

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", f"rsa:{bits}",
            "-keyout", key_pem, "-out", cert_pem,
            "-days", "3650", "-nodes", "-sha256",
            "-subj", "/C=CN/O=APK Auditor Test/CN=apk-audit-test",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert_der],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return SigningKey(key_pem=key_pem, cert_der=cert_der, cert_pem=cert_pem)


def generate_weak_sha1_key(out_dir: str, name: str = "weakkey") -> SigningKey:
    """Separate key for the SHA-1 sample so the bad hash is unmistakable."""
    os.makedirs(out_dir, exist_ok=True)
    key_pem = os.path.join(out_dir, f"{name}.pem")
    cert_pem = os.path.join(out_dir, f"{name}.crt.pem")
    cert_der = os.path.join(out_dir, f"{name}.crt.der")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_pem, "-out", cert_pem,
            "-days", "3650", "-nodes", "-sha1",
            "-subj", "/C=CN/O=APK Auditor Test/CN=weak-sha1-test",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert_der],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return SigningKey(key_pem=key_pem, cert_der=cert_der, cert_pem=cert_pem)
