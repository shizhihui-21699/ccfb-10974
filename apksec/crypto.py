"""Pure-stdlib public-key signature verification.

APK signature verification needs RSA PKCS#1 v1.5 and ECDSA over the NIST
P-256/P-384/P-521 curves.  Python's standard library can hash but cannot do
public-key math, so the small amount required is implemented here.  This is
verification only: private keys never enter this module.

The code is deliberately strict (fully padded PKCS#1 v1.5 blocks, low-S ECDSA
accepted both ways, DER-encoded ECDSA signatures only) so that padding oracles
and malleability tricks do not pass verification.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from . import der


class CryptoError(ValueError):
    pass


HASHES = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

# DigestInfo prefixes for PKCS#1 v1.5 (RFC 8017 section 9.2 note 1).
DIGEST_INFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def digest(name: str, data: bytes) -> bytes:
    try:
        return HASHES[name.lower()](data).digest()
    except KeyError as exc:
        raise CryptoError(f"unsupported hash {name!r}") from exc


@dataclass(frozen=True)
class RsaPublicKey:
    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class EcCurve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int
    size_bytes: int


CURVES: dict[str, EcCurve] = {
    # secp256r1 / prime256v1
    "1.2.840.10045.3.1.7": EcCurve(
        "P-256",
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        size_bytes=32,
    ),
    # secp384r1
    "1.3.132.0.34": EcCurve(
        "P-384",
        p=int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            "FFFFFFFF0000000000000000FFFFFFFF",
            16,
        ),
        a=int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            "FFFFFFFF0000000000000000FFFFFFFC",
            16,
        ),
        b=int(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
            "C656398D8A2ED19D2A85C8EDD3EC2AEF",
            16,
        ),
        gx=int(
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
            "5502F25DBF55296C3A545E3872760AB7",
            16,
        ),
        gy=int(
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
            "0A60B1CE1D7E819D7A431D7C90EA0E5F",
            16,
        ),
        n=int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
            "581A0DB248B0A77AECEC196ACCC52973",
            16,
        ),
        size_bytes=48,
    ),
    # secp521r1
    "1.3.132.0.35": EcCurve(
        "P-521",
        p=2**521 - 1,
        a=2**521 - 4,
        b=int(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
            "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
            "3F00",
            16,
        ),
        gx=int(
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
            "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5"
            "BD66",
            16,
        ),
        gy=int(
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
            "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD1"
            "6650",
            16,
        ),
        n=int(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E913864"
            "09",
            16,
        ),
        size_bytes=66,
    ),
}

_SIG_ALG_RSA_PSS = {
    "1.2.840.113549.1.1.10": "sha256",
}
_SIG_ALG_RSA = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.14": "sha224",
}
_SIG_ALG_ECDSA = {
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"


def parse_rsa_public_key(spki_value: bytes) -> RsaPublicKey:
    """Parse a SubjectPublicKeyInfo ::= SEQUENCE { alg, BIT STRING }."""
    info = der.read_tlv(spki_value, 0)
    if info.tag != 0x30:
        raise CryptoError("SubjectPublicKeyInfo is not a SEQUENCE")
    parts = info.children()
    if len(parts) < 2:
        raise CryptoError("truncated SubjectPublicKeyInfo")
    alg = parts[0].children()
    if not alg or alg[0].oid() != OID_RSA_ENCRYPTION:
        raise CryptoError("not an RSA key")
    bits = parts[1].as_octets()
    rsa_seq = der.read_tlv(bits, 0)
    if rsa_seq.tag != 0x30:
        raise CryptoError("RSAPublicKey is not a SEQUENCE")
    vals = rsa_seq.children()
    if len(vals) < 2:
        raise CryptoError("truncated RSAPublicKey")
    n = vals[0].as_int()
    e = vals[1].as_int()
    if n <= 0 or e <= 1:
        raise CryptoError("invalid RSA key values")
    return RsaPublicKey(n=n, e=e)


def parse_ec_public_key(spki_value: bytes) -> tuple[EcCurve, tuple[int, int]]:
    info = der.read_tlv(spki_value, 0)
    parts = info.children()
    if len(parts) < 2:
        raise CryptoError("truncated SubjectPublicKeyInfo")
    alg = parts[0].children()
    if not alg or alg[0].oid() != OID_EC_PUBLIC_KEY:
        raise CryptoError("not an EC key")
    if len(alg) < 2 or alg[1].tag != 0x06:
        raise CryptoError("EC key without named curve")
    curve_oid = alg[1].oid()
    curve = CURVES.get(curve_oid)
    if curve is None:
        raise CryptoError(f"unsupported EC curve {curve_oid}")
    point = parts[1].as_octets()
    if not point or point[0] != 0x04:
        raise CryptoError("only uncompressed EC points are supported")
    if len(point) != 1 + 2 * curve.size_bytes:
        raise CryptoError("EC point has wrong length")
    x = int.from_bytes(point[1 : 1 + curve.size_bytes], "big")
    y = int.from_bytes(point[1 + curve.size_bytes :], "big")
    if not _ec_on_curve(curve, (x, y)):
        raise CryptoError("EC point is not on the curve")
    return curve, (x, y)


def _ec_on_curve(curve: EcCurve, pt: tuple[int, int]) -> bool:
    x, y = pt
    if not (0 <= x < curve.p and 0 <= y < curve.p):
        return False
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def _ec_add(
    curve: EcCurve,
    p1: Optional[tuple[int, int]],
    p2: Optional[tuple[int, int]],
) -> Optional[tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    p = curve.p
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if p1 == p2:
        if y1 == 0:
            return None
        lam = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def _ec_mul(curve: EcCurve, k: int, pt: tuple[int, int]) -> Optional[tuple[int, int]]:
    result: Optional[tuple[int, int]] = None
    addend: Optional[tuple[int, int]] = pt
    while k:
        if k & 1:
            result = _ec_add(curve, result, addend)
        addend = _ec_add(curve, addend, addend)
        k >>= 1
    return result


def _ecdsa_verify(
    curve: EcCurve, pub: tuple[int, int], hash_name: str, sig: bytes, data: bytes
) -> bool:
    try:
        sig_seq = der.read_tlv(sig, 0)
        if sig_seq.tag != 0x30 or sig_seq.end != len(sig):
            return False
        parts = sig_seq.children()
        if len(parts) != 2:
            return False
        r = parts[0].as_int()
        s = parts[1].as_int()
    except der.DerError:
        return False
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    z = int.from_bytes(digest(hash_name, data), "big")
    excess = len(digest(hash_name, data)) * 8 - curve.n.bit_length()
    if excess > 0:
        z >>= excess
    w = pow(s, -1, curve.n)
    u1 = z * w % curve.n
    u2 = r * w % curve.n
    pt = _ec_add(
        curve,
        _ec_mul(curve, u1, (curve.gx, curve.gy)),
        _ec_mul(curve, u2, pub),
    )
    if pt is None:
        return False
    return pt[0] % curve.n == r


def _rsa_pkcs1v15_verify(
    key: RsaPublicKey, hash_name: str, sig: bytes, data: bytes
) -> bool:
    k = key.size_bytes
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= key.n:
        return False
    em = pow(s, key.e, key.n).to_bytes(k, "big")
    t = DIGEST_INFO_PREFIX[hash_name] + digest(hash_name, data)
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return _constant_time_equals(em, expected)


def _mgf1(hash_name: str, seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(digest(hash_name, seed + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(out[:length])


def _rsa_pss_verify(
    key: RsaPublicKey,
    hash_name: str,
    sig: bytes,
    data: bytes,
    salt_len: Optional[int] = None,
) -> bool:
    """RSASSA-PSS-VERIFY (RFC 8017 8.1.2) with MGF1 and the same hash."""
    h_len = len(digest(hash_name, b""))
    em_bits = key.n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    if len(sig) != key.size_bytes or em_len < h_len + 2:
        return False
    s = int.from_bytes(sig, "big")
    if s >= key.n:
        return False
    em = pow(s, key.e, key.n).to_bytes(em_len, "big")
    if em[-1] != 0xBC:
        return False
    masked_db = em[: em_len - h_len - 1]
    h = em[em_len - h_len - 1 : em_len - 1]
    unused_bits = 8 * em_len - em_bits
    if unused_bits and masked_db[0] >> (8 - unused_bits):
        return False
    db = bytes(
        a ^ b for a, b in zip(masked_db, _mgf1(hash_name, h, em_len - h_len - 1))
    )
    if unused_bits:
        db = bytes([db[0] & (0xFF >> unused_bits)]) + db[1:]
    m_hash = digest(hash_name, data)

    def check(s_len: int) -> bool:
        ps_len = em_len - h_len - s_len - 2
        if ps_len < 0:
            return False
        if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
            return False
        salt = db[ps_len + 1 :]
        if len(salt) != s_len:
            return False
        return _constant_time_equals(
            digest(hash_name, b"\x00" * 8 + m_hash + salt), h
        )

    if salt_len is not None:
        return check(salt_len)
    return check(h_len) or check(em_len - h_len - 2)


def _constant_time_equals(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


@dataclass(frozen=True)
class PublicKey:
    kind: str  # "rsa" | "ec" | "dsa" | "unknown"
    spki: bytes
    rsa: Optional[RsaPublicKey] = None
    ec: Optional[tuple[EcCurve, tuple[int, int]]] = None
    algorithm_oid: str = ""

    @property
    def description(self) -> str:
        if self.kind == "rsa" and self.rsa is not None:
            return f"RSA-{self.rsa.n.bit_length()}"
        if self.kind == "ec" and self.ec is not None:
            return f"ECDSA {self.ec[0].name}"
        return self.kind.upper()


def parse_public_key(spki: bytes) -> PublicKey:
    info = der.read_tlv(spki, 0)
    if info.tag != 0x30:
        raise CryptoError("SubjectPublicKeyInfo is not a SEQUENCE")
    parts = info.children()
    if not parts:
        raise CryptoError("empty SubjectPublicKeyInfo")
    alg = parts[0].children()
    alg_oid = alg[0].oid() if alg else ""
    if alg_oid == OID_RSA_ENCRYPTION:
        return PublicKey(
            kind="rsa",
            spki=spki,
            rsa=parse_rsa_public_key(spki),
            algorithm_oid=alg_oid,
        )
    if alg_oid == OID_EC_PUBLIC_KEY:
        return PublicKey(
            kind="ec",
            spki=spki,
            ec=parse_ec_public_key(spki),
            algorithm_oid=alg_oid,
        )
    if alg_oid == "1.2.840.10040.4.1":
        return PublicKey(kind="dsa", spki=spki, algorithm_oid=alg_oid)
    return PublicKey(kind="unknown", spki=spki, algorithm_oid=alg_oid)


def algorithm_digest(sig_algorithm_oid: str) -> Optional[tuple[str, str]]:
    """Map a signature AlgorithmIdentifier OID to (scheme, hash)."""
    if sig_algorithm_oid in _SIG_ALG_RSA_PSS:
        return "rsa-pss", _SIG_ALG_RSA_PSS[sig_algorithm_oid]
    if sig_algorithm_oid in _SIG_ALG_RSA:
        return "rsa", _SIG_ALG_RSA[sig_algorithm_oid]
    if sig_algorithm_oid in _SIG_ALG_ECDSA:
        return "ecdsa", _SIG_ALG_ECDSA[sig_algorithm_oid]
    return None


def verify_signature(
    key: PublicKey, sig_algorithm_oid: str, signature: bytes, data: bytes
) -> bool:
    """Verify ``signature`` over ``data`` with an AlgorithmIdentifier OID."""
    alg = algorithm_digest(sig_algorithm_oid)
    if alg is None:
        raise CryptoError(f"unsupported signature algorithm {sig_algorithm_oid}")
    scheme, hash_name = alg
    if scheme == "rsa-pss":
        if key.rsa is None:
            raise CryptoError("RSA signature with non-RSA key")
        return _rsa_pss_verify(key.rsa, hash_name, signature, data)
    if scheme == "rsa":
        if key.rsa is None:
            raise CryptoError("RSA signature with non-RSA key")
        return _rsa_pkcs1v15_verify(key.rsa, hash_name, signature, data)
    if key.ec is None:
        raise CryptoError("ECDSA signature with non-EC key")
    curve, point = key.ec
    return _ecdsa_verify(curve, point, hash_name, signature, data)
