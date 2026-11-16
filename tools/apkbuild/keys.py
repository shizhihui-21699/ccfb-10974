"""Deterministic key and certificate generation for the test fixtures.

Only test fixtures use this module: real APKs are signed with real tooling.
Keys are derived from a fixed seed so fixture builds are reproducible; the
generated private keys are throw-away test material and are never written to
disk by the auditor.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac

from apksec import crypto, der

# ---------------------------------------------------------------------------
# Deterministic byte stream (HMAC-SHA256 in counter mode)
# ---------------------------------------------------------------------------


class Drbg:
    def __init__(self, seed: bytes, personalization: bytes = b""):
        self._key = hashlib.sha256(b"apksec-fixture-drbg" + seed + personalization).digest()
        self._counter = 0
        self._buffer = b""

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if not self._buffer:
                block = hmac.new(
                    self._key, self._counter.to_bytes(8, "big"), hashlib.sha256
                ).digest()
                self._counter += 1
                self._buffer = block
            take = min(n - len(out), len(self._buffer))
            out.extend(self._buffer[:take])
            self._buffer = self._buffer[take:]
        return bytes(out)

    def int_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("bound must be positive")
        bits = n.bit_length()
        nbytes = (bits + 7) // 8
        while True:
            candidate = int.from_bytes(self.bytes(nbytes), "big") >> (nbytes * 8 - bits)
            if candidate < n:
                return candidate


_SMALL_PRIMES = [
    p
    for p in range(3, 2000)
    if all(p % q for q in range(2, int(p**0.5) + 1))
]


def _is_probable_prime(n: int, rng: Drbg, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng.int_below(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int, rng: Drbg, e: int) -> int:
    while True:
        candidate = rng.int_below(1 << bits) | (1 << (bits - 1)) | 1
        if (candidate - 1) % e == 0:
            continue
        if _is_probable_prime(candidate, rng):
            return candidate


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


class PrivateKey:
    kind = ""

    def sign(self, hash_name: str, data: bytes) -> bytes:
        raise NotImplementedError

    def public_spki(self) -> bytes:
        raise NotImplementedError

    @property
    def public_key(self) -> crypto.PublicKey:
        return crypto.parse_public_key(self.public_spki())

    def signature_algorithm(self, hash_name: str) -> str:
        raise NotImplementedError

    def apk_sig_algorithm(self, hash_name: str) -> int:
        raise NotImplementedError


class RsaPrivateKey(PrivateKey):
    kind = "rsa"

    def __init__(self, n: int, e: int, d: int, p: int, q: int):
        self.n, self.e, self.d, self.p, self.q = n, e, d, p, q

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def public_spki(self) -> bytes:
        rsa = der.seq(der.integer(self.n), der.integer(self.e))
        alg = der.seq(der.oid("1.2.840.113549.1.1.1"), der.null())
        return der.seq(alg, der.bit_string(rsa))

    def sign(self, hash_name: str, data: bytes) -> bytes:
        k = self.size_bytes
        t = crypto.DIGEST_INFO_PREFIX[hash_name] + crypto.digest(hash_name, data)
        if k < len(t) + 11:
            raise ValueError("RSA key too small for digest")
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        sig = pow(int.from_bytes(em, "big"), self.d, self.n)
        return sig.to_bytes(k, "big")

    def signature_algorithm(self, hash_name: str) -> str:
        return {
            "sha1": "1.2.840.113549.1.1.5",
            "sha256": "1.2.840.113549.1.1.11",
            "sha384": "1.2.840.113549.1.1.12",
            "sha512": "1.2.840.113549.1.1.13",
        }[hash_name]

    def apk_sig_algorithm(self, hash_name: str) -> int:
        return {"sha256": 0x0103, "sha512": 0x0104}[hash_name]


class EcPrivateKey(PrivateKey):
    kind = "ec"

    def __init__(self, curve: crypto.EcCurve, d: int):
        self.curve = curve
        self.d = d
        self.public_point = crypto._ec_mul(curve, d, (curve.gx, curve.gy))
        assert self.public_point is not None

    def public_spki(self) -> bytes:
        c = self.curve
        x, y = self.public_point
        point = b"\x04" + x.to_bytes(c.size_bytes, "big") + y.to_bytes(c.size_bytes, "big")
        alg = der.seq(
            der.oid("1.2.840.10045.2.1"),
            der.oid({256: "1.2.840.10045.3.1.7", 384: "1.3.132.0.34", 521: "1.3.132.0.35"}[c.n.bit_length()]),
        )
        return der.seq(alg, der.bit_string(point))

    def sign(self, hash_name: str, data: bytes) -> bytes:
        c = self.curve
        z = int.from_bytes(crypto.digest(hash_name, data), "big")
        excess = len(crypto.digest(hash_name, data)) * 8 - c.n.bit_length()
        if excess > 0:
            z >>= excess
        rng = Drbg(b"ecdsa-nonce" + self.d.to_bytes(c.size_bytes, "big"))
        while True:
            k = rng.int_below(c.n - 1) + 1
            pt = crypto._ec_mul(c, k, (c.gx, c.gy))
            if pt is None:
                continue
            r = pt[0] % c.n
            if r == 0:
                continue
            s = pow(k, -1, c.n) * (z + r * self.d) % c.n
            if s == 0:
                continue
            if s > c.n // 2:  # normalise to low-S
                s = c.n - s
            return der.seq(der.integer(r), der.integer(s))

    def signature_algorithm(self, hash_name: str) -> str:
        return {
            "sha256": "1.2.840.10045.4.3.2",
            "sha384": "1.2.840.10045.4.3.3",
            "sha512": "1.2.840.10045.4.3.4",
        }[hash_name]

    def apk_sig_algorithm(self, hash_name: str) -> int:
        return {"sha256": 0x0201, "sha512": 0x0202}[hash_name]


def generate_rsa_key(seed: str, bits: int = 2048) -> RsaPrivateKey:
    rng = Drbg(seed.encode())
    e = 65537
    while True:
        p = _random_prime(bits // 2, rng, e)
        q = _random_prime(bits // 2, rng, e)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        if d.bit_length() < bits // 2:
            continue
        return RsaPrivateKey(n=n, e=e, d=d, p=p, q=q)


def generate_ec_key(seed: str, bits: int = 256) -> EcPrivateKey:
    curve = {256: "1.2.840.10045.3.1.7", 384: "1.3.132.0.34"}[bits]
    c = crypto.CURVES[curve]
    rng = Drbg(seed.encode(), b"ec")
    d = rng.int_below(c.n - 1) + 1
    return EcPrivateKey(c, d)


# ---------------------------------------------------------------------------
# X.509
# ---------------------------------------------------------------------------


def _name(cn: str, org: str = "", country: str = "") -> bytes:
    rdns = []
    if country:
        rdns.append(der.set_of(der.seq(der.oid("2.5.4.6"), der.utf8(country))))
    if org:
        rdns.append(der.set_of(der.seq(der.oid("2.5.4.10"), der.utf8(org))))
    rdns.append(der.set_of(der.seq(der.oid("2.5.4.3"), der.utf8(cn))))
    return der.seq(*rdns)


def _utc_time(when: _dt.datetime) -> bytes:
    if 1950 <= when.year < 2050:
        body = when.strftime("%y%m%d%H%M%SZ").encode()
        return der.tlv(0x17, body)
    return der.tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode())


def make_certificate(
    key: PrivateKey,
    subject_cn: str,
    *,
    org: str = "",
    country: str = "",
    days_valid: int = 3650,
    not_before: _dt.datetime | None = None,
    serial: int = 1,
    is_ca: bool = False,
) -> tuple[bytes, dict]:
    """Create a self-signed certificate.  Returns (DER bytes, metadata)."""
    now = not_before or _dt.datetime(2023, 1, 1, tzinfo=_dt.timezone.utc)
    nb = now
    na = now + _dt.timedelta(days=days_valid)
    sig_oid = key.signature_algorithm("sha256")
    sig_alg = (
        der.seq(der.oid(sig_oid), der.null())
        if key.kind == "rsa"
        else der.seq(der.oid(sig_oid))
    )
    name = _name(subject_cn, org, country)
    extensions = []
    extensions.append(
        der.seq(
            der.oid("2.5.29.19"),
            der.tlv(0x01, b"\xff" if is_ca else b"\x00"),
            der.octets(der.seq(*([der.tlv(0x01, b"\xff")] if is_ca else []))),
        )
    )
    if key.kind == "rsa":
        # KeyUsage bits, MSB first: digitalSignature(0), keyEncipherment(2),
        # keyCertSign(5); the two trailing bits are the BIT STRING padding.
        key_usage_bits = 0b10100100
    else:
        # digitalSignature(0) + keyCertSign(5)
        key_usage_bits = 0b10000100
    unused = 2
    extensions.append(
        der.seq(
            der.oid("2.5.29.15"),
            der.tlv(0x01, b"\xff"),
            der.octets(der.bit_string(bytes([key_usage_bits]), unused)),
        )
    )
    tbs = der.seq(
        der.ctx(0, der.integer(2)),
        der.integer(serial),
        sig_alg,
        name,
        der.seq(_utc_time(nb), _utc_time(na)),
        name,
        key.public_spki(),
        der.ctx(3, der.seq(*extensions)),
    )
    signature = key.sign("sha256", tbs)
    cert = der.seq(tbs, sig_alg, der.bit_string(signature))
    meta = {
        "subject_cn": subject_cn,
        "not_before": nb,
        "not_after": na,
        "serial": serial,
        "sha256": hashlib.sha256(cert).hexdigest(),
    }
    return cert, meta


def build_pkcs7(
    key: PrivateKey, cert: bytes, content: bytes, hash_name: str = "sha256"
) -> bytes:
    """Build a PKCS#7 SignedData blob encapsulating ``content`` (for v1)."""
    digest_oid = {
        "sha1": "1.3.14.3.2.26",
        "sha256": "2.16.840.1.101.3.4.2.1",
        "sha384": "2.16.840.1.101.3.4.2.2",
        "sha512": "2.16.840.1.101.3.4.2.3",
    }[hash_name]
    digest_alg = der.seq(der.oid(digest_oid), der.null())
    sig_oid = key.signature_algorithm(hash_name)
    sig_alg = (
        der.seq(der.oid(sig_oid), der.null())
        if key.kind == "rsa"
        else der.seq(der.oid(sig_oid))
    )
    cert_tlv = der.read_tlv(cert, 0)
    cert_fields = cert_tlv.children()
    issuer = cert_fields[0].children()[3].raw()
    serial = cert_fields[0].children()[1].raw()

    # Authenticated attributes: contentType + messageDigest
    message_digest = crypto.digest(hash_name, content)
    attrs = [
        der.seq(
            der.oid("1.2.840.113549.1.9.3"),
            der.set_of(der.oid("1.2.840.113549.1.7.1")),
        ),
        der.seq(
            der.oid("1.2.840.113549.1.9.4"),
            der.set_of(der.octets(message_digest)),
        ),
    ]
    # DER SET OF sorts elements by encoding for the signature input.
    encoded = sorted(der.read_tlv(a, 0).raw() for a in attrs)
    attrs_body = b"".join(encoded)
    attrs_sorted = der.tlv(0x31, attrs_body)
    signature = key.sign(hash_name, attrs_sorted)
    signer_info = der.seq(
        der.integer(1),
        der.seq(issuer, serial),
        digest_alg,
        der.tlv(0xA0, attrs_body),
        sig_alg,
        der.octets(signature),
    )
    return _wrap_signed_data(signer_info, cert, content, detached=True)


def _wrap_signed_data(signer_info: bytes, cert: bytes, content: bytes, detached: bool) -> bytes:
    digest_oid = der.read_tlv(signer_info, 0).children()[2].children()[0].oid()
    digest_alg = der.seq(der.oid(digest_oid), der.null())
    if detached:
        econtent = der.seq(der.oid("1.2.840.113549.1.7.1"))
    else:
        econtent = der.seq(der.oid("1.2.840.113549.1.7.1"), der.ctx(0, der.octets(content)))
    signed_data = der.seq(
        der.integer(1),
        der.set_of(digest_alg),
        econtent,
        der.ctx(0, cert),
        der.set_of(signer_info),
    )
    return der.seq(der.oid("1.2.840.113549.1.7.2"), der.ctx(0, signed_data))


def build_pkcs7_unsigned_attrs(
    key: PrivateKey, cert: bytes, content: bytes, hash_name: str = "sha256"
) -> bytes:
    """Build a PKCS#7 SignedData *without* authenticated attributes.

    Android only accepts signed attributes on API 19+, so a v1 signature that
    must work on older platforms is produced this way (which is also what
    apksigner does when signing for API < 19).
    """
    digest_oid = {
        "sha1": "1.3.14.3.2.26",
        "sha256": "2.16.840.1.101.3.4.2.1",
        "sha384": "2.16.840.1.101.3.4.2.2",
        "sha512": "2.16.840.1.101.3.4.2.3",
    }[hash_name]
    digest_alg = der.seq(der.oid(digest_oid), der.null())
    sig_oid = key.signature_algorithm(hash_name)
    sig_alg = (
        der.seq(der.oid(sig_oid), der.null())
        if key.kind == "rsa"
        else der.seq(der.oid(sig_oid))
    )
    cert_fields = der.read_tlv(cert, 0).children()[0].children()
    issuer = cert_fields[3].raw()
    serial = cert_fields[1].raw()
    signature = key.sign(hash_name, content)
    signer_info = der.seq(
        der.integer(1),
        der.seq(issuer, serial),
        digest_alg,
        sig_alg,
        der.octets(signature),
    )
    return _wrap_signed_data(signer_info, cert, content, detached=True)

