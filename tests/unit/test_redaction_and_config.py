import pytest

from smime_demo.config import ConfigError, load_settings
from smime_demo.redaction import redact, redact_text


def test_redacts_credentials_in_urls():
    url = (
        "https://sws-test.sslpki.com/certificates?per_page=1&account_key=abc123&secret_key=x%2By%3D"
    )
    assert redact_text(url) == (
        "https://sws-test.sslpki.com/certificates?per_page=1&account_key=REDACTED&secret_key=REDACTED"
    )


def test_redacts_credentials_in_json_text_and_bodies(fixture):
    assert '"secret_key":"REDACTED"' in redact_text('{"account_key":"a","secret_key":"b"}')
    # api_parameters responses echo the credentials back
    body = {"parameters": {"account_key": "a", "secret_key": "b", "product": "300"}}
    assert redact(body) == {
        "parameters": {"account_key": "REDACTED", "secret_key": "REDACTED", "product": "300"}
    }


def test_redacts_activation_link_tokens():
    link = "https://sandbox.ssl.com/certificate_order_token/19925bb576318e6e1lg0/generate_cert"
    assert (
        redact_text(link)
        == "https://sandbox.ssl.com/certificate_order_token/REDACTED/generate_cert"
    )


def test_defaults_to_sandbox(monkeypatch):
    monkeypatch.setenv("SSLCOM_ACCOUNT_KEY", "KEY-123")
    monkeypatch.setenv("SSLCOM_SECRET_KEY", "SECRET-456")
    monkeypatch.setenv("SSLCOM_TEST_DOMAIN", "Example.COM.")
    s = load_settings()
    assert s.is_sandbox and s.base_url == "https://sws-test.sslpki.com"
    assert s.test_domain == "example.com"
    assert "KEY-123" not in repr(s) and "SECRET-456" not in repr(s)


def test_production_requires_explicit_permission(monkeypatch):
    monkeypatch.setenv("SSLCOM_ENV", "production")
    monkeypatch.setenv("SSLCOM_ACCOUNT_KEY", "k")
    monkeypatch.setenv("SSLCOM_SECRET_KEY", "s")
    with pytest.raises(ConfigError, match="spends-money"):
        load_settings()
    assert load_settings(allow_production=True).base_url == "https://sws.sslpki.com"


def test_rejects_unknown_environment_and_missing_keys(monkeypatch):
    monkeypatch.setenv("SSLCOM_ENV", "staging")
    with pytest.raises(ConfigError, match="sandbox"):
        load_settings()
    monkeypatch.delenv("SSLCOM_ENV")
    with pytest.raises(ConfigError, match="SSLCOM_ACCOUNT_KEY, SSLCOM_SECRET_KEY"):
        load_settings()
