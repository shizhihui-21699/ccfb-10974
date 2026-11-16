"""X.509 certificate parsing and self-signature checking."""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from . import crypto, der


class CertificateError(ValueError):
    pass


_NAME_OIDS = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}

MAX_CERT_BYTES = 64 * 1024


def format_name(tlv: der.Tlv) -> str:
    """Render a Name (RDNSequence) as ``CN=..., O=...``."""
    parts: list[str] = []
    try:
        for rdn in tlv.children():
            for atv in rdn.children():
                vals = atv.children()
                if len(vals) < 2:
                    continue
                key = _NAME_OIDS.get(vals[0].oid(), vals[0].oid())
                parts.append(f"{key}={vals[1].as_text()}")
    except der.DerError:
        return "<malformed name>"
    return ", ".join(parts)


def _parse_time(tlv: der.Tlv) -> Optional[_dt.datetime]:
    raw = tlv.value.decode("ascii", errors="replace")
    try:
        if tlv.tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
            if len(raw) < 12:
                return None
            year = int(raw[0:2])
            year += 2000 if year < 50 else 1900
            rest = raw[2:]
        elif tlv.tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
            year = int(raw[0:4])
            rest = raw[4:]
        else:
            return None
        month, day, hour, minute = (int(rest[i : i + 2]) for i in (0, 2, 4, 6))
        second = int(rest[8:10]) if len(rest) >= 10 else 0
        return _dt.datetime(
            year, month, day, hour, minute, second, tzinfo=_dt.timezone.utc
        )
    except (ValueError, IndexError):
        return None


@dataclass
class Certificate:
    raw: bytes
    subject: str
    issuer: str
    serial: str
    not_before: Optional[_dt.datetime]
    not_after: Optional[_dt.datetime]
    signature_algorithm: str
    public_key: crypto.PublicKey
    is_ca: bool = False
    self_signed: bool = False
    self_signed_valid: Optional[bool] = None
    sha256: str = field(default="")
    sha1: str = field(default="")

    @property
    def expired(self) -> Optional[bool]:
        if self.not_after is None:
            return None
        return self.not_after < _dt.datetime.now(_dt.timezone.utc)

    @property
    def subject_cn(self) -> str:
        for part in self.subject.split(", "):
            if part.startswith("CN="):
                return part[3:]
        return self.subject or "<empty subject>"

    def summary(self) -> dict:
        out = {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "expired": self.expired,
            "public_key": self.public_key.description,
            "signature_algorithm": self.signature_algorithm,
            "self_signed": self.self_signed,
            "self_signed_valid": self.self_signed_valid,
            "sha256": self.sha256,
            "sha1": self.sha1,
        }
        return out


def parse_certificate(raw: bytes) -> Certificate:
    if len(raw) > MAX_CERT_BYTES:
        raise CertificateError("certificate too large")
    try:
        cert = der.read_tlv(raw, 0)
        if cert.tag != 0x30 or cert.end != len(raw):
            raise CertificateError("certificate is not a single SEQUENCE")
        parts = cert.children()
        if len(parts) != 3:
            raise CertificateError("certificate must have 3 fields")
        tbs, sig_alg_tlv, sig_value_tlv = parts
        tbs_fields = tbs.children()
        idx = 0
        if tbs_fields and tbs_fields[0].tag == 0xA0:
            idx = 1
        # serialNumber, signature, issuer, validity, subject, spki
        if len(tbs_fields) < idx + 6:
            raise CertificateError("truncated TBSCertificate")
        serial_tlv = tbs_fields[idx]
        issuer_tlv = tbs_fields[idx + 2]
        validity_tlv = tbs_fields[idx + 3]
        subject_tlv = tbs_fields[idx + 4]
        spki_tlv = tbs_fields[idx + 5]
        validity = validity_tlv.children()
        if len(validity) < 2:
            raise CertificateError("truncated validity")
        not_before = _parse_time(validity[0])
        not_after = _parse_time(validity[1])
        sig_alg_parts = sig_alg_tlv.children()
        if not sig_alg_parts:
            raise CertificateError("missing signature algorithm")
        sig_oid = sig_alg_parts[0].oid()
        spki_raw = spki_tlv.raw()
        public_key = crypto.parse_public_key(spki_raw)
        serial = serial_tlv.value
        serial_hex = serial.hex() if serial else "00"
        try:
            serial_int = serial_tlv.as_int()
            serial_str = f"{serial_int} (0x{serial_int:x})"
        except der.DerError:
            serial_str = serial_hex

        cert_obj = Certificate(
            raw=raw,
            subject=format_name(subject_tlv),
            issuer=format_name(issuer_tlv),
            serial=serial_str,
            not_before=not_before,
            not_after=not_after,
            signature_algorithm=sig_oid,
            public_key=public_key,
        )
        cert_obj.sha256 = hashlib.sha256(raw).hexdigest()
        cert_obj.sha1 = hashlib.sha1(raw).hexdigest()
        cert_obj.self_signed = cert_obj.subject == cert_obj.issuer
        # Basic constraints CA flag
        try:
            for extra in tbs_fields[idx + 6 :]:
                if extra.tag == 0xA3:  # extensions [3]
                    for ext in extra.lone().children():
                        ext_parts = ext.children()
                        if len(ext_parts) >= 3 and ext_parts[0].oid() == "2.5.29.19":
                            bc = der.read_tlv(ext_parts[2].as_octets(), 0)
                            for f in bc.children():
                                if f.tag == 0x01 and f.value:
                                    cert_obj.is_ca = bool(f.value[0])
        except (der.DerError, IndexError):
            pass
        if cert_obj.self_signed:
            try:
                cert_obj.self_signed_valid = crypto.verify_signature(
                    public_key,
                    sig_oid,
                    sig_value_tlv.as_octets(),
                    tbs.raw(),
                )
            except crypto.CryptoError:
                cert_obj.self_signed_valid = None
        return cert_obj
    except der.DerError as exc:
        raise CertificateError(f"malformed certificate: {exc}") from exc
    except crypto.CryptoError as exc:
        raise CertificateError(f"unsupported certificate key: {exc}") from exc
