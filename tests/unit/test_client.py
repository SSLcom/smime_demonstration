"""SwsClient against mocked HTTP, using bodies recorded from the sandbox."""

import json
import logging

import pytest
import requests
import responses
from responses import matchers

from smime_demo.client import USER_AGENT, SwsClient
from smime_demo.errors import SwsError
from tests.unit.test_models import domain_fixture

BASE = "https://sws-test.sslpki.com"
CREDS = {"account_key": "test-account-key", "secret_key": "test-secret-key"}


@pytest.fixture
def client(settings):
    return SwsClient(settings, backoff=0)


@responses.activate
def test_create_order_sends_recipient_and_credentials(client, fixture):
    responses.post(
        f"{BASE}/certificates",
        json=fixture("25")["response"]["body"],
        match=[
            matchers.query_param_matcher(CREDS),
            matchers.json_params_matcher(
                {
                    "product": 300,
                    "period": 365,
                    "email_address": "a@example.com",
                    "recipient": {"email": "a@example.com"},
                    "external_order_number": "cust-1-emp-1",
                }
            ),
            matchers.header_matcher({"User-Agent": USER_AGENT}),
        ],
    )
    order = client.create_order(email="a@example.com", external_order_number="cust-1-emp-1")
    assert order.ref == "co-671lg0u8oaf"
    assert order.awaiting_mailbox_confirmation


@responses.activate
def test_create_order_for_domain_path_includes_csr_and_address(client, fixture):
    responses.post(f"{BASE}/certificates", json=fixture("25")["response"]["body"])
    client.create_order(
        email="a@example.com",
        external_order_number="x",
        csr_pem="CSR",
        locality="Houston",
        state_or_province="Texas",
    )
    sent = json.loads(responses.calls[0].request.body)
    assert sent["csr"] == "CSR"
    assert sent["locality"] == "Houston"
    assert sent["state_or_province"] == "Texas"
    assert "state_or_providence" not in sent


@responses.activate
def test_post_is_never_retried(client):
    responses.post(f"{BASE}/certificates", status=503, body="unavailable")
    with pytest.raises(SwsError) as exc:
        client.create_order(email="a@example.com", external_order_number="x")
    assert exc.value.status == 503
    assert len(responses.calls) == 1


@responses.activate
def test_get_is_retried_on_5xx_then_succeeds(client, fixture):
    responses.get(f"{BASE}/certificate/co-1", status=502, body="bad gateway")
    responses.get(f"{BASE}/certificate/co-1", json=fixture("24")["response"]["body"])
    order = client.get_certificate("co-1")
    assert len(responses.calls) == 2
    assert order.ref == "co-1" and len(order.end_entity_certificates) == 2


@responses.activate
def test_get_is_retried_on_connection_error_then_gives_up(client):
    responses.get(f"{BASE}/certificate/co-1", body=requests.ConnectionError("refused"))
    with pytest.raises(SwsError, match="ConnectionError"):
        client.get_certificate("co-1")
    assert len(responses.calls) == 3


@responses.activate
def test_error_body_with_http_200_raises(client):
    responses.get(
        f"{BASE}/certificates",
        json={"errors": {"login": ["account_key not found or wrong secret_key"]}},
    )
    with pytest.raises(SwsError, match="login: account_key not found"):
        client.list_certificates()


@responses.activate
def test_generate_certificate_returns_bundle(client):
    body = domain_fixture("16_generate_employee3.json")
    responses.post(
        f"{BASE}/generate_certificate",
        json=body,
        match=[matchers.json_params_matcher({"ref": "co-651lg171vc4", "csr": "CSR"})],
    )
    bundle = client.generate_certificate("co-651lg171vc4", "CSR")
    assert bundle.leaf_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert len(bundle.chain_pems) == 2


@responses.activate
def test_generate_certificate_empty_success_is_an_error(client):
    # Observed on the domain path: HTTP 200, no certificate, no error message.
    responses.post(
        f"{BASE}/generate_certificate",
        json=domain_fixture("12_generate_employee2.json"),
    )
    with pytest.raises(SwsError, match="no certificate in the response"):
        client.generate_certificate("co-c01lg16oi18", "CSR")


@responses.activate
def test_domain_validation_calls(client):
    responses.get(
        f"{BASE}/certificate/co-ce1lg16i624/validations/methods",
        json=domain_fixture("02_methods_employee1.json"),
    )
    responses.put(
        f"{BASE}/certificate/co-ce1lg16i624",
        json=domain_fixture("03_set_dcv_employee1.json"),
        match=[
            matchers.json_params_matcher(
                {"domains": {"smimedemo.sslcom.link": {"dcv": "cname_csr_hash"}}}
            )
        ],
    )
    responses.get(
        f"{BASE}/certificate/co-ce1lg16i624/validations/status",
        json=domain_fixture("05_dcv_status_employee1.json"),
    )
    methods = client.get_validation_methods("co-ce1lg16i624")
    assert "cname_csr_hash" in methods["dcv_methods"]["smimedemo.sslcom.link"]
    order = client.set_domain_validation("co-ce1lg16i624", "smimedemo.sslcom.link")
    assert order.ref == "co-ce1lg16i624"
    status = client.get_validation_status("co-ce1lg16i624")
    assert status["smimedemo.sslcom.link"]["status"] == "satisfied"


@responses.activate
def test_revoke_whole_order_and_single_serial(client):
    responses.delete(
        f"{BASE}/certificate/co-1",
        json={"status": "revoked"},
        match=[matchers.query_param_matcher({"reason": "CESSATIONOFOPERATION", **CREDS})],
    )
    responses.delete(
        f"{BASE}/certificate/co-1",
        json={"status": "revoked"},
        match=[
            matchers.query_param_matcher(
                {"reason": "SUPERSEDED", "serials": "554fe3606ea8", **CREDS}
            )
        ],
    )
    client.revoke("co-1", "CESSATIONOFOPERATION")
    client.revoke("co-1", "SUPERSEDED", serial="55:4F:E3:60:6E:A8")
    assert len(responses.calls) == 2


def test_revoke_rejects_unknown_reason(client):
    with pytest.raises(ValueError, match="CESSATIONOFOPERATION"):
        client.revoke("co-1", "mistake")


@responses.activate
def test_logs_never_contain_credentials(client, caplog):
    responses.get(f"{BASE}/certificates", json=[])
    with caplog.at_level(logging.DEBUG, logger="smime_demo.sws"):
        client.list_certificates()
    assert "test-secret-key" not in caplog.text
    assert "test-account-key" not in caplog.text
    assert "secret_key=REDACTED" in caplog.text


@responses.activate
def test_recorder_writes_publishable_examples(settings, tmp_path, fixture):
    from smime_demo.recording import Recorder

    responses.post(f"{BASE}/certificates", json=fixture("25")["response"]["body"])
    rec = Recorder(tmp_path, replace={"person@private.example": "jane.doe@example.com"})
    c = SwsClient(settings, backoff=0, recorder=rec)
    c.create_order(email="person@private.example", external_order_number="x")
    (path,) = tmp_path.glob("*.json")
    text = path.read_text()
    assert path.name == "001_post_certificates.json"
    assert "YOUR_SECRET_KEY" in text and "test-secret-key" not in text
    assert "person@private.example" not in text and "jane.doe@example.com" in text
