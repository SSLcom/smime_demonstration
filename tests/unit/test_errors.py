"""SwsError must recognise every error body the sandbox produced, whatever the status."""

import pytest

from smime_demo.errors import SwsError, error_from_response


def test_invalid_product_response_type_error(fixture):
    resp = fixture("03")["response"]  # POST /certificates with product 0
    err = error_from_response(resp["status"], resp["body"], method="POST", path="/certificates")
    assert err is not None
    assert err.status == 400
    assert err.code == 400
    assert any(m.startswith("product: is invalid") for m in err.field_messages)


def test_errors_object_with_http_200(fixture):
    resp = fixture("34")["response"]  # DELETE with reason=mistake
    assert resp["status"] == 200
    err = error_from_response(resp["status"], resp["body"])
    assert err is not None
    assert "reason" in err.messages


def test_bad_credentials_on_get_with_http_200():
    body = {"errors": {"login": ["account_key not found or wrong secret_key"]}}
    err = error_from_response(200, body, method="GET", path="/certificates")
    assert err is not None
    assert str(err) == (
        "SWS error (GET /certificates HTTP 200): login: account_key not found or wrong secret_key"
    )


def test_single_error_string_with_404(fixture):
    resp = fixture("49")["response"]  # revoke with a colon-separated serial
    err = error_from_response(resp["status"], resp["body"])
    assert err is not None
    assert err.messages == {"": ["This order has no issued certificate."]}


def test_generate_certificate_error_message(fixture):
    import json
    from pathlib import Path

    run = (
        Path(__file__).resolve().parent.parent
        / "fixtures"
        / "sandbox"
        / "domain-20261120-190645-2c58"
    )
    body = json.loads((run / "06_generate_employee1.json").read_text())["response"]["body"]
    err = error_from_response(200, body)
    assert err is not None
    assert "City can't be blank" in str(err)


def test_errors_array_shape():
    err = error_from_response(500, {"errors": ["something broke"]})
    assert err is not None and err.messages == {"": ["something broke"]}


@pytest.mark.parametrize(
    "body",
    [
        [{"ref": "co-1"}],
        {"ref": "co-1", "order_status": "issued"},
        {"cert_results": "PEM", "cert_common_name": "x.crt", "error_message": None},
        {"status": "revoked"},
    ],
)
def test_success_bodies_are_not_errors(body):
    assert error_from_response(200, body) is None


def test_non_2xx_without_body_is_an_error():
    err = error_from_response(502, "Bad Gateway")
    assert err is not None and err.status == 502 and "Bad Gateway" in str(err)


def test_raw_body_is_redacted():
    body = {"errors": {"login": ["nope"]}, "parameters": {"secret_key": "s3cret"}}
    err = error_from_response(200, body)
    assert err.raw["parameters"]["secret_key"] == "REDACTED"
    assert isinstance(err, SwsError)
