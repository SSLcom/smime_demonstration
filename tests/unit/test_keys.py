import stat
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from smime_demo.keys import (
    build_csr,
    csr_to_pem,
    export_pkcs12,
    generate_key,
    generate_rsa_key,
    load_csr,
    write_private_key,
)
from tests.unit.pki import pem


@pytest.mark.parametrize(
    ("kind", "key_type"), [("ecc", ec.EllipticCurvePrivateKey), ("rsa", rsa.RSAPrivateKey)]
)
def test_csr_carries_mailbox_in_cn_and_san(kind, key_type):
    key = generate_key(kind, rsa_bits=2048)
    assert isinstance(key, key_type)
    csr = build_csr(key, "a@example.com")
    assert csr.is_signature_valid
    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert cn == "a@example.com"
    assert san.get_values_for_type(x509.RFC822Name) == ["a@example.com"]


def test_rsa_defaults_to_3072_and_refuses_small_keys():
    assert generate_rsa_key().key_size == 3072
    with pytest.raises(ValueError, match="2048"):
        generate_rsa_key(1024)


def test_private_key_file_is_owner_only(tmp_path):
    path = tmp_path / "keys" / "device.key.pem"
    path.parent.mkdir()
    path.write_text("old")
    path.chmod(0o644)
    write_private_key(generate_key("ecc"), path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert b"PRIVATE KEY" in path.read_bytes()


def test_load_csr_accepts_pem_and_der(tmp_path):
    csr = build_csr(generate_key("ecc"), "a@example.com")
    (tmp_path / "c.pem").write_text(csr_to_pem(csr))
    (tmp_path / "c.der").write_bytes(csr.public_bytes(serialization.Encoding.DER))
    assert load_csr(tmp_path / "c.pem") == load_csr(tmp_path / "c.der") == csr_to_pem(csr)


def test_load_csr_made_by_openssl(tmp_path):
    """A CSR generated outside this code, as a device or token would."""
    key, csr = tmp_path / "k.pem", tmp_path / "r.pem"
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            "/CN=a@example.com",
            "-addext",
            "subjectAltName=email:a@example.com",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("openssl with -addext not available")
    loaded = x509.load_pem_x509_csr(load_csr(csr).encode())
    assert loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_pkcs12_round_trip(pki):
    key = generate_key("rsa", rsa_bits=2048)
    cert = pki.issue(build_csr(key, "a@example.com"), "a@example.com")
    blob = export_pkcs12(key, pem(cert), pki.chain_pems, "correct horse")
    loaded = pkcs12.load_pkcs12(blob, b"correct horse")
    assert loaded.cert.certificate == cert
    assert loaded.key.private_numbers() == key.private_numbers()
    assert len(loaded.additional_certs) == 2
    with pytest.raises(ValueError):
        pkcs12.load_pkcs12(blob, b"wrong")
    with pytest.raises(ValueError, match="password"):
        export_pkcs12(key, pem(cert), [], "")
