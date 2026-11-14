"""Test-APK builder: synthesizes structurally valid APKs (ZIP + binary AXML)
with v1/v2/v3 signatures implemented from scratch, so the auditor can be
exercised without the Android SDK or apksigner.

Layout:
    keygen.py    - RSA key + self-signed certificate via the openssl CLI
    v1_sign.py   - JAR signature (MANIFEST.MF / CERT.SF / CERT.RSA)
    v2v3_sign.py - APK Signing Block writer (v2 0x7109871a / v3 0xf05368c0)
    build_samples.py - manifest scenarios and sample assembly
"""
