import json

from smime_demo.models import (
    STATUS_AWAITING_MAILBOX,
    STATUS_NO_RECIPIENT,
    CertificateBundle,
    CnameRecord,
    Order,
    split_pem_certificates,
)
from tests.unit.conftest import FIXTURES

DOMAIN_RUN = FIXTURES / "sandbox" / "domain-20261120-190645-2c58"


def domain_fixture(name: str) -> dict:
    return json.loads((DOMAIN_RUN / name).read_text())["response"]["body"]


def test_order_without_recipient_is_flagged(fixture):
    order = Order.from_api(fixture("05")["response"]["body"])
    assert order.ref == "co-041lg0thnaa"
    assert order.order_status == STATUS_NO_RECIPIENT
    assert order.needs_recipient and not order.can_issue


def test_order_with_recipient_awaits_mailbox(fixture):
    order = Order.from_api(fixture("25")["response"]["body"])
    assert order.order_status == STATUS_AWAITING_MAILBOX
    assert order.awaiting_mailbox_confirmation and not order.needs_recipient


def test_multi_certificate_order(fixture):
    order = Order.from_api(fixture("24")["response"]["body"], ref="co-041lg0thnaa")
    assert order.ref == "co-041lg0thnaa"  # GET responses do not repeat the ref
    assert order.can_issue
    assert [e.serial for e in order.end_entity_certificates] == [
        "7ae9d9ea9baea76be6dec6b87de14c97",
        "554fe3606ea85426782dc3c694f4bb05",
    ]
    assert order.issued_serials == [e.serial for e in order.end_entity_certificates]


def test_revoked_order(fixture):
    order = Order.from_api(fixture("52")["response"]["body"], ref="co-041lg0thnaa")
    assert order.order_status == "revoked"
    assert order.issued_serials == []


def test_cname_record_from_validation_methods():
    body = domain_fixture("02_methods_employee1.json")
    rec = CnameRecord.from_methods(body, "smimedemo.sslcom.link")
    assert rec.name == "_C636DB9505C34E23333008083701584A.smimedemo.sslcom.link"
    assert rec.value.endswith(".20261120.ssl.com")
    assert CnameRecord.from_methods(body, "other.example") is None


def test_bundle_from_generate_certificate_response():
    body = domain_fixture("16_generate_employee3.json")
    bundle = CertificateBundle.from_pem_chain(body["cert_results"])
    assert bundle is not None
    assert len(bundle.chain_pems) == 2  # intermediate, root
    assert bundle.full_chain_pem.count("BEGIN CERTIFICATE") == 3


def test_split_pem_ignores_redaction_placeholders():
    text = (
        "<end-entity certificate redacted, serial 1a>\n"
        "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
    )
    assert len(split_pem_certificates(text)) == 1
    assert split_pem_certificates(None) == []
