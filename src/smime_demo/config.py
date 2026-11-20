"""Settings from environment variables (and an optional .env file).

The demo talks to the SSL.com sandbox unless told otherwise. Production is
reachable only when SSLCOM_ENV=production AND the caller passes
allow_production=True (the CLI's --i-understand-this-spends-money flag),
because every POST /certificates in production is charged to the account.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

SANDBOX = "sandbox"
PRODUCTION = "production"

BASE_URLS = {
    SANDBOX: "https://sws-test.sslpki.com",
    PRODUCTION: "https://sws.sslpki.com",
}


class ConfigError(Exception):
    """A required setting is missing, invalid, or not allowed."""


@dataclass(frozen=True)
class Settings:
    environment: str
    account_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    test_email: str | None = None
    test_domain: str | None = None  # an email domain the partner validates once for a customer

    @property
    def base_url(self) -> str:
        return BASE_URLS[self.environment]

    @property
    def is_sandbox(self) -> bool:
        return self.environment == SANDBOX


def load_settings(*, allow_production: bool = False, require_credentials: bool = True) -> Settings:
    """Read SSLCOM_* settings, applying the environment guard."""
    load_dotenv()
    environment = (os.environ.get("SSLCOM_ENV") or SANDBOX).strip().lower()
    if environment not in BASE_URLS:
        raise ConfigError(f"SSLCOM_ENV must be 'sandbox' or 'production', not {environment!r}.")
    if environment == PRODUCTION and not allow_production:
        raise ConfigError(
            "SSLCOM_ENV=production orders real, charged certificates. "
            "Pass --i-understand-this-spends-money to continue."
        )

    account_key = os.environ.get("SSLCOM_ACCOUNT_KEY", "").strip()
    secret_key = os.environ.get("SSLCOM_SECRET_KEY", "").strip()
    if require_credentials:
        missing = [
            name
            for name, value in (
                ("SSLCOM_ACCOUNT_KEY", account_key),
                ("SSLCOM_SECRET_KEY", secret_key),
            )
            if not value
        ]
        if missing:
            raise ConfigError(f"Missing {', '.join(missing)}. Set them in .env (see .env.example).")

    test_email = os.environ.get("SSLCOM_TEST_EMAIL", "").strip() or None
    test_domain = os.environ.get("SSLCOM_TEST_DOMAIN", "").strip().lower().rstrip(".") or None
    return Settings(environment, account_key, secret_key, test_email, test_domain)
