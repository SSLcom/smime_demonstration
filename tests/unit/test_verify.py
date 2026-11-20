from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from smime_demo.keys import build_csr, csr_to_pem, generate_key
from smime_demo.models import CertificateBundle
from smime_demo.verify import verify_certificate
from tests.unit.pki import DemoPki, pem
from tests.unit.test_models import DOMAIN_RUN, domain_fixture

EMAIL = "a@example.com"


def issue(pki, kind="ecc", **overrides):
    key = generate_key(kind, rsa_bits=2048)
    csr = build_csr(key, EMAIL)
    return pem(pki.issue(csr, EMAIL, **overrides)), csr_to_pem(csr)


def test_real_sandbox_certificate_passes():
    """A certificate the sandbox actually issued, checked against its own CSR."""
    body = domain_fixture("16_generate_employee3.json")
    bundle = CertificateBundle.from_pem_chain(body["cert_results"])
    csr = (DOMAIN_RUN / "employee3.csr.pem").read_text()
    during_validity = datetime(2027, 1, 1, tzinfo=UTC)
    failures = verify_certificate(
        bundle.leaf_pem,
        csr,
        "employee3@smimedemo.sslcom.link",
        bundle.chain_pems,
        now=during_validity,
    )
    assert failures == []


def test_good_ecc_and_rsa(pki):
    for kind in ("ecc", "rsa"):
        cert, csr = issue(pki, kind)
        assert verify_certificate(cert, csr, EMAIL, pki.chain_pems) == []


def test_reports_every_problem_at_once(pki):
    other_key = generate_key("ecc").public_key()
    cert, csr = issue(
        pki,
        public_key=other_key,
        san_emails=["someone@else.example"],
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
        starts=datetime.now(UTC) - timedelta(days=400),
        days_valid=30,
    )
    failures = verify_certificate(cert, csr, EMAIL, pki.chain_pems)
    text = "\n".join(failures)
    assert "public key does not match" in text
    assert "SAN rfc822Name" in text
    assert "emailProtection" in text
    assert "not valid now" in text
    assert len(failures) == 4


def test_key_usage_must_fit_key_type(pki):
    cert, csr = issue(pki, "rsa", key_encipherment=False)
    assert any("keyEncipherment" in f for f in verify_certificate(cert, csr, EMAIL, pki.chain_pems))
    cert, csr = issue(pki, "ecc", key_encipherment=True)
    assert any("ECC" in f for f in verify_certificate(cert, csr, EMAIL, pki.chain_pems))


def test_extra_san_names_are_reported(pki):
    cert, csr = issue(pki, extra_san=[x509.DNSName("example.com")])
    assert any("non-email" in f for f in verify_certificate(cert, csr, EMAIL, pki.chain_pems))


def test_chain_must_link_up(pki):
    cert, csr = issue(pki)
    stranger = DemoPki.create()
    assert verify_certificate(cert, csr, EMAIL, []) == ["no issuing chain was returned"]
    failures = verify_certificate(cert, csr, EMAIL, stranger.chain_pems)
    assert len(failures) == 1 and "is not issued by Test Intermediate" in failures[0]


def test_unparseable_input():
    assert verify_certificate("nope", "nope", EMAIL)[0].startswith("certificate does not parse")
