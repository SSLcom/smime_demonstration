"""A throwaway root -> intermediate -> leaf PKI for offline tests.

Issued leaves mimic what the sandbox issues (see docs/API_GUIDE.md):
subject emailAddress=<mailbox>, one rfc822Name SAN, EKU emailProtection +
clientAuth, key usage by key type. Every property can be overridden to build
bad certificates.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _ca(name: str, key, issuer_name: x509.Name | None = None, issuer_key=None) -> x509.Certificate:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(issuer_name or _name(name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA256())
    )


@dataclass
class DemoPki:
    root_key: ec.EllipticCurvePrivateKey
    root: x509.Certificate
    intermediate_key: ec.EllipticCurvePrivateKey
    intermediate: x509.Certificate

    @classmethod
    def create(cls) -> DemoPki:
        root_key = ec.generate_private_key(ec.SECP256R1())
        root = _ca("Test Root", root_key)
        int_key = ec.generate_private_key(ec.SECP256R1())
        intermediate = _ca("Test Intermediate", int_key, root.subject, root_key)
        return cls(root_key, root, int_key, intermediate)

    @property
    def chain_pems(self) -> list[str]:
        return [pem(self.intermediate), pem(self.root)]

    def issue(
        self,
        csr: x509.CertificateSigningRequest,
        email: str,
        *,
        san_emails: list[str] | None = None,
        extra_san: list[x509.GeneralName] | None = None,
        eku: list | None = None,
        digital_signature: bool = True,
        key_encipherment: bool | None = None,
        days_valid: int = 365,
        starts: datetime | None = None,
        public_key=None,
    ) -> x509.Certificate:
        key = public_key or csr.public_key()
        if key_encipherment is None:
            key_encipherment = isinstance(key, rsa.RSAPublicKey)
        start = starts or datetime.now(UTC) - timedelta(minutes=5)
        names = [x509.RFC822Name(e) for e in (san_emails if san_emails is not None else [email])]
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)]))
            .issuer_name(self.intermediate.subject)
            .public_key(key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + timedelta(days=days_valid))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=digital_signature,
                    content_commitment=False,
                    key_encipherment=key_encipherment,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        if names or extra_san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(names + (extra_san or [])), critical=False
            )
        usages = (
            eku
            if eku is not None
            else [
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]
        )
        if usages:
            builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
        return builder.sign(self.intermediate_key, hashes.SHA384())
