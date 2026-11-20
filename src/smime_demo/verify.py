"""Check that an issued certificate is the one that was ordered.

verify_certificate() returns a list of human-readable failures (empty means
everything checked out) instead of raising, so a test can report every problem
at once.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


def verify_certificate(
    certificate_pem: str,
    csr_pem: str,
    expected_email: str,
    chain_pems: list[str] | tuple[str, ...] = (),
    *,
    now: datetime | None = None,
) -> list[str]:
    failures: list[str] = []
    now = now or datetime.now(UTC)
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    except ValueError as exc:
        return [f"certificate does not parse: {exc}"]
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except ValueError as exc:
        return [f"CSR does not parse: {exc}"]

    # Public key matches the CSR.
    if _spki(cert.public_key()) != _spki(csr.public_key()):
        failures.append("certificate public key does not match the CSR")

    # SAN holds exactly the expected mailbox.
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.RFC822Name)
        others = [n for n in san if not isinstance(n, x509.RFC822Name)]
        if [n.lower() for n in names] != [expected_email.lower()]:
            failures.append(f"SAN rfc822Name is {names}, expected exactly [{expected_email!r}]")
        if others:
            failures.append(f"SAN has unexpected non-email names: {others}")
    except x509.ExtensionNotFound:
        failures.append("certificate has no subjectAltName")

    # Extended key usage includes email protection.
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.EMAIL_PROTECTION not in eku:
            failures.append("extended key usage does not include emailProtection")
    except x509.ExtensionNotFound:
        failures.append("certificate has no extended key usage")

    # Key usage fits the key type.
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.digital_signature:
            failures.append("key usage lacks digitalSignature")
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey) and not ku.key_encipherment:
            failures.append("RSA certificate lacks keyEncipherment, so it cannot encrypt")
        if isinstance(key, ec.EllipticCurvePublicKey) and ku.key_encipherment:
            failures.append("ECC certificate unexpectedly allows keyEncipherment")
    except x509.ExtensionNotFound:
        failures.append("certificate has no key usage")

    # Currently valid.
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        failures.append(
            f"certificate is not valid now (valid {cert.not_valid_before_utc:%Y-%m-%d} "
            f"to {cert.not_valid_after_utc:%Y-%m-%d})"
        )

    failures += verify_chain(cert, chain_pems)
    return failures


def verify_chain(cert: x509.Certificate, chain_pems: list[str] | tuple[str, ...]) -> list[str]:
    """Each certificate must be signed by the next one in the list."""
    if not chain_pems:
        return ["no issuing chain was returned"]
    try:
        chain = [x509.load_pem_x509_certificate(p.encode()) for p in chain_pems]
    except ValueError as exc:
        return [f"chain certificate does not parse: {exc}"]
    failures = []
    child = cert
    for parent in chain:
        try:
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature) as exc:
            failures.append(
                f"{_cn(child)} is not issued by {_cn(parent)}: {type(exc).__name__} {exc}".strip()
            )
            break
        child = parent
    return failures


def _spki(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _cn(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else cert.subject.rfc4514_string()
