"""APK signature verification for JAR signing (v1) and APK Signature
Scheme v2 / v3 / v3.1.

The implementation follows the verification steps of Google's apksig library:

* v2/v3: the signer's public key (as carried in the block) must equal the
  signer certificate's key, every signature must verify over the exact
  signed-data bytes, and the content digest over the ZIP's three sections is
  recomputed and compared.
* v1: MANIFEST.MF entry digests are recomputed over the raw archive content,
  CERT.SF digests are recomputed over the raw MANIFEST.MF bytes, and the
  PKCS#7 signature over CERT.SF is verified.

No trust anchors are involved: Android uses the signing certificate itself as
the app identity, so these checks are exactly what decides installability and
signing identity.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

from . import apkfile, crypto, der, x509

V1 = 1
V2 = 2
V3 = 3
V31 = 31

CHUNK_SIZE = 1024 * 1024

# apksig SignatureAlgorithm IDs
SIG_ALGORITHMS: dict[int, tuple[str, str]] = {
    0x0101: ("rsa-pss", "sha256"),
    0x0102: ("rsa-pss", "sha512"),
    0x0103: ("rsa", "sha256"),
    0x0104: ("rsa", "sha512"),
    0x0201: ("ecdsa", "sha256"),
    0x0202: ("ecdsa", "sha512"),
    0x0301: ("dsa", "sha256"),
    0x0421: ("verity-rsa", "sha256"),
    0x0423: ("verity-ecdsa", "sha256"),
    0x0425: ("verity-dsa", "sha256"),
}

SIG_ALG_NAMES = {
    0x0101: "RSASSA-PSS-SHA256",
    0x0102: "RSASSA-PSS-SHA512",
    0x0103: "RSASSA-PKCS1-v1_5-SHA256",
    0x0104: "RSASSA-PKCS1-v1_5-SHA512",
    0x0201: "ECDSA-SHA256",
    0x0202: "ECDSA-SHA512",
    0x0301: "DSA-SHA256",
    0x0421: "VERITY-RSA-PKCS1-v1_5-SHA256",
    0x0423: "VERITY-ECDSA-SHA256",
    0x0425: "VERITY-DSA-SHA256",
}

ROTATION_ATTR_ID = 0x3BA06F8C
STRIPPING_PROTECTION_ATTR_ID = 0xBEEFF00D

# SignerInfo signatureAlgorithm may name only the key type; map it to the
# PKCS#1 / ECDSA OID for each digest.
_GENERIC_SIG_OIDS = {
    "1.2.840.113549.1.1.1": {
        "sha1": "1.2.840.113549.1.1.5",
        "sha256": "1.2.840.113549.1.1.11",
        "sha384": "1.2.840.113549.1.1.12",
        "sha512": "1.2.840.113549.1.1.13",
        "sha224": "1.2.840.113549.1.1.14",
    },
    "1.2.840.10045.2.1": {
        "sha1": "1.2.840.10045.4.1",
        "sha256": "1.2.840.10045.4.3.2",
        "sha384": "1.2.840.10045.4.3.3",
        "sha512": "1.2.840.10045.4.3.4",
        "sha224": "1.2.840.10045.4.3.1",
    },
}

V1_DIGEST_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
}


class SignatureError(ValueError):
    pass


@dataclass
class Signer:
    scheme: int
    certificates: list[x509.Certificate] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    digests: dict[int, bytes] = field(default_factory=dict)
    verified: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    min_sdk: Optional[int] = None
    max_sdk: Optional[int] = None
    rotation_min_sdk: Optional[int] = None
    lineage: list[x509.Certificate] = field(default_factory=list)

    @property
    def certificate(self) -> Optional[x509.Certificate]:
        return self.certificates[0] if self.certificates else None


@dataclass
class SchemeResult:
    scheme: int
    present: bool = False
    verified: bool = False
    signers: list[Signer] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    uncovered_entries: list[str] = field(default_factory=list)
    protected_schemes: list[int] = field(default_factory=list)


@dataclass
class SignatureReport:
    v1: SchemeResult
    v2: SchemeResult
    v3: SchemeResult
    v31: Optional[SchemeResult] = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def schemes_present(self) -> list[int]:
        out = []
        for label, scheme, res in (
            ("v1", 1, self.v1),
            ("v2", 2, self.v2),
            ("v3", 3, self.v3),
            ("v3.1", 31, self.v31),
        ):
            if res is not None and res.present:
                out.append(scheme)
        return out

    def all_signers(self) -> list[Signer]:
        signers = []
        for res in (self.v1, self.v2, self.v3, self.v31):
            if res is not None:
                signers.extend(res.signers)
        return signers

    def cert_digests(self) -> dict[str, set[str]]:
        """Map SHA-256 fingerprint -> schemes that use that certificate."""
        out: dict[str, set[str]] = {}
        for label, res in (
            ("v1", self.v1),
            ("v2", self.v2),
            ("v3", self.v3),
            ("v3.1", self.v31),
        ):
            if res is None:
                continue
            for signer in res.signers:
                if signer.certificates:
                    out.setdefault(signer.certificates[0].sha256, set()).add(label)
        return out


# ---------------------------------------------------------------------------
# APK Signature Scheme v2 / v3 / v3.1
# ---------------------------------------------------------------------------


class _Parser:
    """Little-endian length-prefixed reader used by the v2+ blocks."""

    def __init__(self, data: bytes):
        self.data = data
        self.off = 0

    def u32(self) -> int:
        if self.off + 4 > len(self.data):
            raise SignatureError("truncated length-prefixed field")
        v = struct.unpack_from("<I", self.data, self.off)[0]
        self.off += 4
        return v

    def bytes(self) -> bytes:
        return self.slice()[0]

    def slice(self) -> tuple[bytes, bytes]:
        """Read a length-prefixed value and return (value, raw-with-prefix)."""
        n = self.u32()
        if self.off + n > len(self.data):
            raise SignatureError("length-prefixed field exceeds block")
        raw = self.data[self.off - 4 : self.off + n]
        v = self.data[self.off : self.off + n]
        self.off += n
        return v, raw

    def remaining(self) -> int:
        return len(self.data) - self.off


def _top_level_sequence(data: bytes, label: str) -> list[tuple[bytes, bytes]]:
    """Unwrap a length-prefixed sequence of length-prefixed elements.

    Every v2+ block value is ``uint32 length`` followed by that many bytes of
    concatenated length-prefixed records.
    """
    if len(data) < 4:
        raise SignatureError(f"truncated {label}")
    outer_len = struct.unpack_from("<I", data, 0)[0]
    if outer_len + 4 != len(data):
        raise SignatureError(
            f"{label} length prefix ({outer_len}) does not match block size ({len(data)})"
        )
    p = _Parser(data[4:])
    items = []
    while p.remaining() > 0:
        if p.remaining() < 4:
            raise SignatureError(f"trailing bytes in {label}")
        items.append(p.slice())
    return items


def compute_content_digest(apk: apkfile.ApkFile, hash_name: str) -> bytes:
    """Compute the v2/v3 content digest over the APK's three sections."""
    block = apk.signing_block
    if block is None:
        raise SignatureError("no APK Signing Block")
    h = getattr(hashlib, hash_name)

    def digest_chunk(chunk: bytes) -> bytes:
        d = h()
        d.update(b"\xa5")
        d.update(struct.pack("<I", len(chunk)))
        d.update(chunk)
        return d.digest()

    chunk_digests: list[bytes] = []
    sections = [
        (0, block.offset),
        (apk.cd_offset, apk.cd_offset + apk.cd_size),
    ]
    for start, end in sections:
        if start < 0 or end > apk.size or end < start:
            raise SignatureError("invalid section bounds")
        off = start
        while off < end:
            take = min(CHUNK_SIZE, end - off)
            chunk_digests.append(digest_chunk(bytes(apk.data[off : off + take])))
            off += take

    # Third section: the EOCD, with the central directory offset replaced by
    # the offset of the APK Signing Block.
    eocd = bytearray(apk.data[apk.eocd_offset : apk.size])
    if len(eocd) < 22:
        raise SignatureError("truncated EOCD")
    struct.pack_into("<I", eocd, 16, block.offset)
    off = 0
    while off < len(eocd):
        take = min(CHUNK_SIZE, len(eocd) - off)
        chunk_digests.append(digest_chunk(bytes(eocd[off : off + take])))
        off += take

    d = h()
    d.update(b"\x5a")
    d.update(struct.pack("<I", len(chunk_digests)))
    for cd in chunk_digests:
        d.update(cd)
    return d.digest()


def _verify_with_public_key(
    key: crypto.PublicKey, alg: int, signature: bytes, data: bytes
) -> Optional[bool]:
    """Verify one signature record.  Returns None when unsupported."""
    info = SIG_ALGORITHMS.get(alg)
    if info is None:
        return None
    scheme_name, hash_name = info
    if scheme_name.startswith("verity"):
        return None
    try:
        if scheme_name in ("rsa", "rsa-pss"):
            if key.rsa is None:
                raise SignatureError("RSA signature with non-RSA key")
            if scheme_name == "rsa-pss":
                return crypto._rsa_pss_verify(key.rsa, hash_name, signature, data)
            return crypto._rsa_pkcs1v15_verify(key.rsa, hash_name, signature, data)
        if scheme_name == "ecdsa":
            if key.ec is None:
                raise SignatureError("ECDSA signature with non-EC key")
            curve, point = key.ec
            return crypto._ecdsa_verify(curve, point, hash_name, signature, data)
        if scheme_name == "dsa":
            raise SignatureError("DSA signatures are not supported")
    except crypto.CryptoError as exc:
        raise SignatureError(str(exc)) from exc
    return None


def _parse_signers(block_value: bytes, scheme: int) -> list[Signer]:
    signers: list[Signer] = []
    for signer_raw, _ in _top_level_sequence(block_value, "signers"):
        p = _Parser(signer_raw)
        signed_data, signed_data_raw = p.slice()
        # v2/v3 signs the *contents* of the length-prefixed signed data
        # field, not the length prefix itself.
        signed_data_raw = signed_data
        signer = Signer(scheme=scheme)
        if scheme in (V3, V31):
            # v3 repeats minSdkVersion/maxSdkVersion outside the signed data so
            # that verifiers can select a signer without verifying signatures.
            if p.remaining() < 8:
                raise SignatureError(f"v{scheme} signer lacks min/max SDK")
            signer.min_sdk = struct.unpack_from("<I", signer_raw, p.off)[0]
            signer.max_sdk = struct.unpack_from("<I", signer_raw, p.off + 4)[0]
            p.off += 8
        signatures_raw, _ = p.slice()
        public_key_raw, _ = p.slice()

        sp = _Parser(signed_data)
        digests_raw, _ = sp.slice()
        certs_raw, _ = sp.slice()
        if scheme in (V3, V31):
            if sp.remaining() < 8:
                raise SignatureError(f"v{scheme} signed data lacks min/max SDK")
            sdk_min = struct.unpack_from("<I", signed_data, sp.off)[0]
            sdk_max = struct.unpack_from("<I", signed_data, sp.off + 4)[0]
            if (sdk_min, sdk_max) != (signer.min_sdk, signer.max_sdk):
                signer.warnings.append(
                    "min/max SDK inside signed data disagrees with the signer block"
                )
            sp.off += 8
            # v3.1 keeps rotation-min-SDK in an additional attribute, which is
            # parsed from the lineage below.
        attrs_raw, _ = sp.slice()
        # v2's signed data ends with one further length-prefixed (empty)
        # element; v3 ends right after the attributes.  Anything beyond that is
        # tolerated for forward compatibility.

        dp = _Parser(digests_raw)
        while dp.remaining() > 0:
            item, _ = dp.slice()
            ip = _Parser(item)
            alg = ip.u32()
            signer.digests[alg] = ip.bytes()
        signer.signature_algorithms = list(signer.digests)

        cp = _Parser(certs_raw)
        while cp.remaining() > 0:
            cert_raw = cp.bytes()
            try:
                signer.certificates.append(x509.parse_certificate(cert_raw))
            except x509.CertificateError as exc:
                signer.errors.append(f"unparsable certificate: {exc}")

        # Additional attributes: a length-prefixed sequence of
        # length-prefixed records, each record being uint32 id + value bytes.
        ap = _Parser(attrs_raw)
        while ap.remaining() > 0:
            record, _ = ap.slice()
            rp = _Parser(record)
            attr_id = rp.u32()
            if attr_id == ROTATION_ATTR_ID:
                signer.lineage = _parse_lineage(rp.data[rp.off:], signer)

        records: list[tuple[int, bytes]] = []
        sigs = _Parser(signatures_raw)
        while sigs.remaining() > 0:
            item, _ = sigs.slice()
            ip = _Parser(item)
            records.append((ip.u32(), ip.bytes()))

        # --- key / certificate binding ---
        if not signer.certificates:
            signer.errors.append("signer has no certificates")
        else:
            try:
                key = crypto.parse_public_key(public_key_raw)
                if key.spki != signer.certificates[0].public_key.spki:
                    signer.errors.append(
                        "signer public key does not match its certificate"
                    )
            except crypto.CryptoError as exc:
                signer.errors.append(f"cannot parse signer public key: {exc}")
                key = None
            if not records:
                signer.errors.append("signer has no signatures")
            if key is not None:
                verified_any = False
                for alg, signature in records:
                    try:
                        ok = _verify_with_public_key(
                            key, alg, signature, signed_data_raw
                        )
                    except SignatureError as exc:
                        signer.warnings.append(str(exc))
                        continue
                    if ok is None:
                        signer.warnings.append(
                            f"unsupported signature algorithm 0x{alg:04x}; skipped"
                        )
                    elif ok:
                        verified_any = True
                    else:
                        signer.errors.append(
                            f"signature verification failed for "
                            f"{SIG_ALG_NAMES.get(alg, hex(alg))}"
                        )
                if not verified_any and not signer.errors:
                    signer.errors.append("no supported signature could be verified")
                signer.verified = verified_any and not signer.errors
        signers.append(signer)
    return signers


def _parse_lineage(value: bytes, signer: Signer) -> list[x509.Certificate]:
    """Parse the proof-of-rotation structure, tolerating unknown attributes."""
    out: list[x509.Certificate] = []
    try:
        p = _Parser(value)
        p.u32()  # version
        while p.remaining() > 0:
            node_raw, _ = p.slice()
            np_ = _Parser(node_raw)
            signed_data, _ = np_.slice()
            flags = np_.u32()
            np_.u32()  # signature algorithm
            np_.bytes()  # signature
            sdp = _Parser(signed_data)
            cert_raw = sdp.bytes()
            sdp.u32()  # signedData signature algorithm
            if sdp.remaining() >= 4:
                signer.rotation_min_sdk = sdp.u32()
            try:
                out.append(x509.parse_certificate(cert_raw))
            except x509.CertificateError as exc:
                signer.warnings.append(f"lineage certificate unparsable: {exc}")
            if flags & 0x1:  # last node
                break
        return out
    except (SignatureError, struct.error) as exc:
        signer.warnings.append(f"could not parse rotation lineage: {exc}")
        return out


def verify_scheme_block(apk: apkfile.ApkFile, scheme: int) -> SchemeResult:
    result = SchemeResult(scheme=scheme)
    block = apk.signing_block
    if block is None:
        return result
    block_id = {
        V2: apkfile.V2_BLOCK_ID,
        V3: apkfile.V3_BLOCK_ID,
        V31: apkfile.V31_BLOCK_ID,
    }[scheme]
    value = block.pairs.get(block_id)
    if value is None:
        return result
    result.present = True
    try:
        signers = _parse_signers(value, scheme)
    except (SignatureError, struct.error) as exc:
        result.errors.append(f"malformed v{scheme} signing block: {exc}")
        return result
    if not signers:
        result.errors.append(f"v{scheme} block contains no signers")
        return result
    result.signers = signers

    digest_cache: dict[str, bytes] = {}
    for signer in signers:
        if not signer.certificates:
            result.errors.append("signer without certificate")
            continue
        digest_matched = False
        supported = 0
        for alg, expected in signer.digests.items():
            info = SIG_ALGORITHMS.get(alg)
            if info is None or info[0].startswith("verity"):
                continue
            hash_name = info[1]
            supported += 1
            try:
                if hash_name not in digest_cache:
                    digest_cache[hash_name] = compute_content_digest(apk, hash_name)
            except SignatureError as exc:
                result.errors.append(str(exc))
                break
            if digest_cache[hash_name] == expected:
                digest_matched = True
            else:
                signer.errors.append(
                    f"content digest mismatch for {SIG_ALG_NAMES.get(alg, hex(alg))}"
                )
        if supported == 0:
            signer.errors.append("signer has no supported content digest")
        signer.verified = signer.verified and digest_matched
        result.errors.extend(signer.errors)
        result.warnings.extend(signer.warnings)
    result.verified = all(s.verified for s in signers)
    if not result.verified and not result.errors:
        result.errors.append(f"v{scheme} signature verification failed")
    return result


# ---------------------------------------------------------------------------
# v1 (JAR) signing
# ---------------------------------------------------------------------------


@dataclass
class _Section:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    raw: bytes = b""


_SECTION_SEPARATOR = re.compile(rb"(\r\n\r\n|\n\n|\r\n\n|\n\r\n)")


def _parse_manifest_file(data: bytes) -> tuple[dict[str, str], dict[str, _Section]]:
    """Split a MANIFEST.MF / CERT.SF into main attributes and named sections.

    ``raw`` holds the exact bytes of each section including its terminating
    blank line, because JAR digests are computed over the original bytes (line
    endings included), never over a re-serialisation.
    """
    main: dict[str, str] = {}
    sections: dict[str, _Section] = {}
    parts = _SECTION_SEPARATOR.split(data)
    chunks: list[bytes] = []
    for index in range(0, len(parts), 2):
        body = parts[index]
        separator = parts[index + 1] if index + 1 < len(parts) else b""
        if not body.strip() and not separator:
            continue
        chunks.append(body + separator)
    for chunk in chunks:
        attrs = _parse_section_attributes(chunk)
        if not attrs:
            continue
        name = attrs.get("Name")
        if name is not None:
            sections[name] = _Section(name=name, attrs=attrs, raw=chunk)
        else:
            main.update(attrs)
    return main, sections


def _parse_section_attributes(chunk: bytes) -> dict[str, str]:
    attrs: dict[str, str] = {}
    last_key: Optional[str] = None
    for line in chunk.split(b"\n"):
        line = line.rstrip(b"\r")
        if not line:
            continue
        if line.startswith(b" ") and last_key is not None:
            attrs[last_key] += line[1:].decode("utf-8", errors="replace")
            continue
        if b":" in line:
            key_raw, _, value_raw = line.partition(b":")
            key = key_raw.strip().decode("utf-8", errors="replace")
            attrs[key] = value_raw.strip().decode("utf-8", errors="replace")
            last_key = key
    return attrs


def _digest_attr(attr: str) -> Optional[str]:
    """Extract the hash name from a ``SHA-256-Digest`` style attribute."""
    low = attr.lower()
    if not low.endswith("-digest"):
        return None
    algo = low[: -len("-digest")]
    if algo in ("sha", "sha1"):
        return "sha1"
    if algo in ("sha-1",):
        return "sha1"
    if algo in ("sha-256", "sha256"):
        return "sha256"
    if algo in ("sha-384", "sha384"):
        return "sha384"
    if algo in ("sha-512", "sha512"):
        return "sha512"
    if algo in ("sha-224", "sha224"):
        return "sha224"
    return None


def _b64(value: str) -> Optional[bytes]:
    try:
        return base64.b64decode("".join(value.split()), validate=True)
    except Exception:  # noqa: BLE001
        return None


def _verify_pkcs7_signed_data(
    blob: bytes, content: bytes
) -> tuple[bool, list[x509.Certificate], list[str]]:
    errors: list[str] = []
    try:
        ci = der.read_tlv(blob, 0)
        if ci.tag != 0x30:
            return False, [], ["PKCS#7 ContentInfo is not a SEQUENCE"]
        ci_parts = ci.children()
        if len(ci_parts) < 2:
            return False, [], ["truncated PKCS#7 ContentInfo"]
        if ci_parts[0].oid() != "1.2.840.113549.1.7.2":
            return False, [], ["PKCS#7 content is not SignedData"]
        sd = ci_parts[1].lone()
        sd_parts = sd.children()
        if len(sd_parts) < 4:
            return False, [], ["truncated SignedData"]
        econtent = sd_parts[2]
        if econtent.tag != 0x30:
            return False, [], ["SignedData contentInfo is not a SEQUENCE"]
        encap = None
        for child in econtent.children():
            inner = child
            if inner.tag == 0xA0:  # [0] EXPLICIT OCTET STRING
                try:
                    inner = inner.lone()
                except der.DerError:
                    continue
            if inner.tag in (0x04, 0x03):
                encap = inner.as_octets()
                break
        # The content type is either data (embedded, compare it) or detached
        # (JAR signing tools commonly strip it).  Both are acceptable: the
        # signature is checked over the .SF file either way.
        if encap is not None and encap != content:
            errors.append("PKCS#7 encapsulated content differs from the .SF file")
        idx = 3
        certs: list[x509.Certificate] = []
        if idx < len(sd_parts) and sd_parts[idx].tag == 0xA0:
            for c in sd_parts[idx].children():
                try:
                    certs.append(x509.parse_certificate(c.raw()))
                except x509.CertificateError as exc:
                    errors.append(f"certificate in PKCS#7 unparsable: {exc}")
            idx += 1
        if idx < len(sd_parts) and sd_parts[idx].tag == 0xA1:
            idx += 1
        if idx >= len(sd_parts):
            return False, certs, errors + ["SignedData has no signerInfos"]
        signer_infos = sd_parts[idx].children()
        if not signer_infos:
            return False, certs, errors + ["SignedData has no signerInfos"]
        any_ok = False
        for si in signer_infos:
            ok = _verify_signer_info(si, certs, content, errors)
            any_ok = any_ok or ok
        return any_ok, certs, errors
    except der.DerError as exc:
        return False, [], [f"malformed PKCS#7: {exc}"]


def _verify_signer_info(
    si: der.Tlv,
    certs: list[x509.Certificate],
    content: bytes,
    errors: list[str],
) -> bool:
    try:
        parts = si.children()
        if len(parts) < 5:
            errors.append("truncated v1 SignerInfo")
            return False
        i = 1  # skip version
        sid = parts[i]
        i += 1
        digest_alg = parts[i]
        i += 1
        auth_attrs = None
        if i < len(parts) and parts[i].tag == 0xA0:
            auth_attrs = parts[i]
            i += 1
        if i + 1 >= len(parts):
            errors.append("truncated v1 SignerInfo")
            return False
        sig_alg = parts[i]
        i += 1
        signature = parts[i].as_octets()
        digest_oid = digest_alg.children()[0].oid()
        hash_name = V1_DIGEST_OIDS.get(digest_oid)
        if hash_name is None:
            errors.append(f"unsupported v1 digest algorithm {digest_oid}")
            return False
        cert = _match_certificate(sid, certs)
        if cert is None:
            errors.append("no certificate matches the v1 SignerInfo")
            return False
        data_to_verify = content
        if auth_attrs is not None:
            md = None
            for attr in auth_attrs.children():
                ap = attr.children()
                if len(ap) >= 2 and ap[0].oid() == "1.2.840.113549.1.9.4":
                    values = ap[1].children()
                    if values:
                        md = values[0].as_octets()
            if md is None:
                errors.append("authenticated attributes lack messageDigest")
                return False
            if md != crypto.digest(hash_name, content):
                errors.append("v1 messageDigest does not match the .SF content")
                return False
            inner = auth_attrs.value
            data_to_verify = b"\x31" + der.encode_length(len(inner)) + inner
        sig_oid = sig_alg.children()[0].oid()
        if sig_oid in _GENERIC_SIG_OIDS:
            # Tools such as jarsigner/Android's apksigner write the *key*
            # algorithm (rsaEncryption / id-ecPublicKey) instead of a combined
            # signature OID; the digest comes from digestAlgorithm.
            sig_oid = _GENERIC_SIG_OIDS[sig_oid][hash_name]
        if not crypto.verify_signature(
            cert.public_key, sig_oid, signature, data_to_verify
        ):
            errors.append("v1 PKCS#7 signature does not verify")
            return False
        return True
    except (der.DerError, crypto.CryptoError, IndexError, ValueError) as exc:
        errors.append(f"malformed v1 SignerInfo: {exc}")
        return False


def _match_certificate(
    sid: der.Tlv, certs: list[x509.Certificate]
) -> Optional[x509.Certificate]:
    if sid.tag == 0x30:
        parts = sid.children()
        if len(parts) >= 2:
            try:
                issuer = x509.format_name(parts[0])
                serial = parts[1].as_int()
            except (der.DerError, IndexError):
                serial = None
                issuer = ""
            for c in certs:
                try:
                    cert_serial = int(c.serial.split(" ")[0])
                except (ValueError, IndexError):
                    continue
                if c.issuer == issuer and cert_serial == serial:
                    return c
    return certs[0] if len(certs) == 1 else None


def _find_first_separator(data: bytes) -> bytes:
    match = _SECTION_SEPARATOR.search(data)
    return match.group(0) if match else b""


def _sf_verified(
    sf_main: dict[str, str],
    sf_sections: dict[str, _Section],
    manifest_data: bytes,
    manifest_sections: dict[str, _Section],
    signer: Signer,
) -> bool:
    whole_ok = False
    whole_checked = False
    main_section_ok = False
    main_section_checked = False
    separator_len = len(_find_first_separator(manifest_data))
    main_attrs_bytes = manifest_data[: separator_len] if separator_len else manifest_data
    for attr, value in sf_main.items():
        hash_name = _digest_attr(attr)
        if hash_name is None:
            continue
        expected = _b64(value)
        if expected is None:
            continue
        lowered = attr.lower()
        if "main-attributes" in lowered:
            main_section_checked = True
            if expected == hashlib.new(hash_name, main_attrs_bytes).digest():
                main_section_ok = True
        elif "manifest" in lowered:
            whole_checked = True
            if expected == hashlib.new(hash_name, manifest_data).digest():
                whole_ok = True
    if whole_ok:
        return True
    if main_section_checked and not main_section_ok and not any(
        "manifest" in attr.lower() and "main-attributes" not in attr.lower()
        for attr in sf_main
    ):
        signer.errors.append(
            "CERT.SF manifest-main-attributes digest does not match MANIFEST.MF"
        )
        return False

    checked = 0
    failed = 0
    for name, section in sf_sections.items():
        manifest_section = manifest_sections.get(name)
        if manifest_section is None:
            signer.errors.append(
                f"signature file references a missing MANIFEST.MF section {name!r}"
            )
            failed += 1
            continue
        for attr, value in section.attrs.items():
            hash_name = _digest_attr(attr)
            if hash_name is None:
                continue
            expected = _b64(value)
            if expected is None:
                failed += 1
                continue
            actual = hashlib.new(hash_name, manifest_section.raw).digest()
            checked += 1
            if actual != expected:
                signer.errors.append(
                    f"CERT.SF digest mismatch for MANIFEST.MF section {name!r}"
                )
                failed += 1
    if checked == 0:
        if whole_checked:
            signer.errors.append("CERT.SF manifest digest does not match MANIFEST.MF")
        else:
            signer.errors.append("signature file has no usable manifest digests")
        return False
    return failed == 0


def verify_v1(apk: apkfile.ApkFile) -> SchemeResult:
    result = SchemeResult(scheme=V1)
    meta = [
        e
        for e in apk.iter_entries()
        if e.name.startswith("META-INF/") and "/" not in e.name[len("META-INF/") :]
    ]
    sf_entries = [e for e in meta if e.name.upper().endswith(".SF")]
    block_entries = [
        e for e in meta if e.name.upper().endswith((".RSA", ".DSA", ".EC"))
    ]
    if not sf_entries and not block_entries:
        return result
    result.present = True
    if not sf_entries:
        result.errors.append("META-INF signature block present without a .SF file")
        return result
    if not block_entries:
        result.errors.append(".SF file present without a PKCS#7 signature block")

    manifest_data = apk.read_entry_safe("META-INF/MANIFEST.MF")
    if manifest_data is None:
        result.errors.append("v1 signature present but META-INF/MANIFEST.MF is missing")
        return result
    _manifest_main, manifest_sections = _parse_manifest_file(manifest_data)

    seen_certs: set[str] = set()
    for sf_entry in sf_entries:
        try:
            sf_data = sf_entry.read()
        except apkfile.ApkFormatError as exc:
            result.errors.append(f"cannot read {sf_entry.name}: {exc}")
            continue
        signer = Signer(scheme=V1)
        base = sf_entry.name.rsplit(".", 1)[0].lower()
        block_entry = next(
            (b for b in block_entries if b.name.rsplit(".", 1)[0].lower() == base),
            None,
        )
        if block_entry is None and len(block_entries) == 1:
            block_entry = block_entries[0]
        if block_entry is None:
            signer.errors.append(f"no signature block for {sf_entry.name}")
            result.signers.append(signer)
            result.errors.extend(signer.errors)
            continue
        try:
            pkcs7 = block_entry.read()
        except apkfile.ApkFormatError as exc:
            signer.errors.append(f"cannot read {block_entry.name}: {exc}")
            result.signers.append(signer)
            result.errors.extend(signer.errors)
            continue

        pkcs7_ok, certs, pkcs7_errors = _verify_pkcs7_signed_data(pkcs7, sf_data)
        signer.certificates = certs
        signer.errors.extend(pkcs7_errors)

        sf_main, sf_sections = _parse_manifest_file(sf_data)
        for key, value in sf_main.items():
            if key.lower() == "x-android-apk-signed":
                for part in value.split(","):
                    part = part.strip()
                    if part.isdigit():
                        result.protected_schemes.append(int(part))
        sf_ok = _sf_verified(
            sf_main, sf_sections, manifest_data, manifest_sections, signer
        )
        signer.verified = pkcs7_ok and sf_ok and not signer.errors
        if not signer.verified and not signer.errors:
            signer.errors.append("v1 signature did not verify")
        for c in certs:
            if c.sha256 in seen_certs:
                signer.warnings.append("duplicate signing certificate across .SF files")
            seen_certs.add(c.sha256)
        result.signers.append(signer)
        result.errors.extend(signer.errors)
        result.warnings.extend(signer.warnings)
    result.verified = bool(result.signers) and all(s.verified for s in result.signers)

    missing, extra = _manifest_coverage(apk, manifest_sections)
    if missing:
        result.uncovered_entries = missing
        # Android (and apksig) treat an unprotected entry as a v1 failure: the
        # JAR signature is supposed to cover every non-META-INF file, so an
        # entry without a digest is exactly what a post-signing injection looks
        # like.  Record it as an error on the scheme, and keep the list so the
        # rule engine can explain what it means.
        result.errors.append(
            f"{len(missing)} archive entries are not covered by MANIFEST.MF "
            f"(e.g. {', '.join(missing[:3])})"
        )
        result.verified = False
        for signer in result.signers:
            signer.verified = False
            signer.errors.append(
                "APK contains entries with no digest in META-INF/MANIFEST.MF"
            )
    if extra:
        result.warnings.append(
            f"MANIFEST.MF references {len(extra)} entries that are absent from the APK"
        )
    return result


def _manifest_coverage(
    apk: apkfile.ApkFile, manifest_sections: dict[str, _Section]
) -> tuple[list[str], list[str]]:
    declared = set(manifest_sections.keys())
    actual: set[str] = set()
    for e in apk.iter_entries():
        if e.is_directory or e.name.upper().startswith("META-INF/"):
            continue
        actual.add(e.name)
    return sorted(actual - declared), sorted(declared - actual)


def verify_entry_digests(apk: apkfile.ApkFile, report: SignatureReport) -> list[str]:
    """Recompute MANIFEST.MF per-entry digests against archive contents.

    This is the check that catches repackaging: a modified file whose digest in
    MANIFEST.MF was not recomputed.
    """
    errors: list[str] = []
    manifest_data = apk.read_entry_safe("META-INF/MANIFEST.MF")
    if manifest_data is None:
        return errors
    _main, sections = _parse_manifest_file(manifest_data)
    for name, section in sections.items():
        digests = []
        for attr, value in section.attrs.items():
            hash_name = _digest_attr(attr)
            if hash_name is None:
                continue
            expected = _b64(value)
            if expected is not None:
                digests.append((hash_name, expected))
        if not digests:
            continue
        entry = apk.get_entry(name)
        if entry is None:
            errors.append(f"MANIFEST.MF references an entry missing from the APK: {name!r}")
            continue
        try:
            content = entry.read()
        except apkfile.ApkFormatError as exc:
            errors.append(f"cannot read {name!r} for v1 digest check: {exc}")
            continue
        for hash_name, expected in digests:
            if hashlib.new(hash_name, content).digest() != expected:
                errors.append(f"v1 entry digest mismatch for {name!r}")
    return errors


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def analyze_signatures(apk: apkfile.ApkFile) -> SignatureReport:
    v31 = verify_scheme_block(apk, V31)
    report = SignatureReport(
        v1=verify_v1(apk),
        v2=verify_scheme_block(apk, V2),
        v3=verify_scheme_block(apk, V3),
        v31=v31 if v31.present else None,
    )
    if report.v1.present:
        report.errors.extend(verify_entry_digests(apk, report))
    return report
