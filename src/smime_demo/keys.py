"""Key pairs, CSRs, and PKCS#12 files.

In a real deployment the private key is created on the end user's device or
hardware token, and only the CSR reaches the partner's backend. Everything that
submits a CSR therefore also accepts one read from a file (load_csr).

Key types:
- ECC P-256: signing-only certificates (key usage digitalSignature).
- RSA (3072 by default, at least 2048): signing and encryption
  (digitalSignature + keyEncipherment). SSL.com does not issue
  encryption-only certificates.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey

MIN_RSA_BITS = 2048
DEFAULT_RSA_BITS = 3072


def generate_ecc_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def generate_rsa_key(bits: int = DEFAULT_RSA_BITS) -> rsa.RSAPrivateKey:
    if bits < MIN_RSA_BITS:
        raise ValueError(f"RSA keys must be at least {MIN_RSA_BITS} bits")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_key(kind: str, rsa_bits: int = DEFAULT_RSA_BITS) -> PrivateKey:
    if kind == "ecc":
        return generate_ecc_key()
    if kind == "rsa":
        return generate_rsa_key(rsa_bits)
    raise ValueError("key kind must be 'ecc' or 'rsa'")


def build_csr(key: PrivateKey, email: str) -> x509.CertificateSigningRequest:
    """CSR with the mailbox as the CN and as an rfc822Name SAN.

    The CA decides the final subject: in the sandbox the issued certificate's
    subject is emailAddress=<mailbox> only and the CN is dropped. The SAN is what
    mail clients match against.
    """
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, email)]))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .sign(key, hashes.SHA256())
    )


def csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def load_csr(path: str | Path) -> str:
    """Read a CSR made elsewhere (device, token, openssl) and return it as PEM."""
    data = Path(path).read_bytes()
    try:
        csr = x509.load_pem_x509_csr(data)
    except ValueError:
        csr = x509.load_der_x509_csr(data)
    return csr_to_pem(csr)


def write_private_key(key: PrivateKey, path: str | Path) -> Path:
    """Write an unencrypted PKCS#8 PEM readable only by the current user (0600)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    os.chmod(path, 0o600)  # in case the file already existed with wider permissions
    return path


def export_pkcs12(
    key: PrivateKey,
    certificate_pem: str,
    chain_pems: list[str] | tuple[str, ...],
    password: str,
    friendly_name: str = "S/MIME",
) -> bytes:
    """Password-protected PKCS#12 with the key, its certificate, and the chain,
    for importing the same key on several devices."""
    if not password:
        raise ValueError("a PKCS#12 password is required")
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    cas = [x509.load_pem_x509_certificate(p.encode()) for p in chain_pems]
    return pkcs12.serialize_key_and_certificates(
        friendly_name.encode(),
        key,
        cert,
        cas or None,
        serialization.BestAvailableEncryption(password.encode()),
    )
