"""SwsClient: one method per SWS endpoint the demo uses, and nothing else.

Every call here has been observed in the sandbox; see docs/API_GUIDE.md for
the exact requests and responses.

- Credentials go in the query string on every call (accepted for all verbs).
- Responses are checked for error bodies even on HTTP 200, and raised as SwsError.
- Only GET requests are retried (on 5xx and connection errors). POST and DELETE
  are never retried: in production POST /certificates charges the account.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

import requests

from smime_demo import __version__
from smime_demo.config import Settings
from smime_demo.errors import SwsError, error_from_response
from smime_demo.models import (
    PRODUCT_MAILBOX_SMIME,
    REVOKE_REASONS,
    CertificateBundle,
    Order,
)
from smime_demo.redaction import redact, redact_text

log = logging.getLogger("smime_demo.sws")

USER_AGENT = f"sslcom-smime-demo/{__version__}"
TIMEOUT_SECONDS = 30
GET_ATTEMPTS = 3
GET_BACKOFF_SECONDS = 1.0


class SwsClient:
    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
        *,
        timeout: float = TIMEOUT_SECONDS,
        backoff: float = GET_BACKOFF_SECONDS,
        recorder: Callable[..., Any] | None = None,
    ) -> None:
        self.recorder = recorder  # optional: smime_demo.recording.Recorder
        self.settings = settings
        self.base_url = settings.base_url
        self.timeout = timeout
        self.backoff = backoff
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.session.headers["Accept"] = "application/json"

    # -- endpoints -----------------------------------------------------------

    def list_certificates(self, *, page: int = 1, per_page: int = 10) -> list[dict[str, Any]]:
        """GET /certificates — the account's orders, a page at a time."""
        body = self._request("GET", "/certificates", params={"page": page, "per_page": per_page})
        return body if isinstance(body, list) else []

    def create_order(
        self,
        *,
        email: str,
        external_order_number: str,
        period: int = 365,
        product: int = PRODUCT_MAILBOX_SMIME,
        csr_pem: str | None = None,
        locality: str | None = None,
        state_or_province: str | None = None,
    ) -> Order:
        """POST /certificates — order a mailbox-validated S/MIME certificate.

        `recipient.email` is what makes SSL.com email the activation link to the
        mailbox. Without it the order is created but stuck, and the API cannot add
        a recipient afterwards. A CSR sent here is not issued until
        generate_certificate() is called after validation.

        Domain-validated orders (no mailbox click) only issued when the order
        carried the CSR plus `locality` and `state_or_province`; those two never
        appear in the certificate. See docs/API_GUIDE.md.

        NEVER retried. Call this at most once per external_order_number.
        """
        payload: dict[str, Any] = {
            "product": product,
            "period": period,
            "email_address": email,
            "recipient": {"email": email},
            "external_order_number": external_order_number,
        }
        if csr_pem:
            payload["csr"] = csr_pem
        if locality:
            payload["locality"] = locality
        if state_or_province:
            payload["state_or_province"] = state_or_province  # not "state_or_providence"
        body = self._request("POST", "/certificates", json=payload)
        return Order.from_api(body)

    def get_certificate(self, ref: str) -> Order:
        """GET /certificate/{ref} — order status and every certificate on it."""
        body = self._request(
            "GET",
            f"/certificate/{ref}",
            params={"response_type": "individually", "response_encoding": "base64"},
        )
        return Order.from_api(body, ref=ref)

    def set_registrant_address(self, ref: str, locality: str, state_or_province: str) -> Order:
        """PUT /certificate/{ref} — set the registrant's city and state on an
        existing order. Needed before a second certificate on any order that has a
        registrant (one created with `recipient`); the values never appear in the
        certificate, so placeholders work. See docs/API_GUIDE.md."""
        body = self._request(
            "PUT",
            f"/certificate/{ref}",
            json={"locality": locality, "state_or_province": state_or_province},
        )
        return Order.from_api(body, ref=ref)

    def get_validation_methods(self, ref: str) -> dict[str, Any]:
        """GET /certificate/{ref}/validations/methods — how each name on the order
        can be validated, including the `cname_csr_hash` record for the mailbox's
        domain (needs a CSR on the order). See CnameRecord.from_methods."""
        return self._request("GET", f"/certificate/{ref}/validations/methods")

    def set_domain_validation(self, ref: str, domain: str, method: str = "cname_csr_hash") -> Order:
        """PUT /certificate/{ref} — choose how `domain` is validated. With the CNAME
        already published, the domain was validated immediately. The account keeps
        the validation for later orders on the same domain."""
        body = self._request(
            "PUT", f"/certificate/{ref}", json={"domains": {domain: {"dcv": method}}}
        )
        return Order.from_api(body, ref=ref)

    def get_validation_status(self, ref: str) -> dict[str, dict[str, Any]]:
        """GET /certificate/{ref}/validations/status — per name: method, status
        ("satisfied" once validated), validated_at."""
        body = self._request("GET", f"/certificate/{ref}/validations/status")
        return body.get("validation_status") or {} if isinstance(body, dict) else {}

    def generate_certificate(self, ref: str, csr_pem: str) -> CertificateBundle:
        """POST /generate_certificate — issue a certificate for `csr_pem` on a
        validated order. Calling it again with another CSR adds another
        certificate to the same order without a new mailbox validation."""
        body = self._request("POST", "/generate_certificate", json={"ref": ref, "csr": csr_pem})
        bundle = CertificateBundle.from_pem_chain(body.get("cert_results"))
        if bundle is None:
            raise SwsError(
                200,
                {"": ["no certificate in the response"]},
                raw=body,
                method="POST",
                path="/generate_certificate",
            )
        return bundle

    def revoke(self, ref: str, reason: str, serial: str | None = None) -> None:
        """DELETE /certificate/{ref} — revoke every certificate on the order, or
        only the one with `serial`.

        `serial` is lowercase hex without colons, as end_entity_certificates[].serial
        returns it. Revoking one certificate leaves order_status at "issued"; check
        end_entity_certificates[].status instead.
        """
        if reason not in REVOKE_REASONS:
            raise ValueError(f"reason must be one of {', '.join(REVOKE_REASONS)}")
        params = {"reason": reason}
        if serial:
            params["serials"] = serial.replace(":", "").lower()
        self._request("DELETE", f"/certificate/{ref}", params=params)

    # -- transport -------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        query = {
            **(params or {}),
            "account_key": self.settings.account_key,
            "secret_key": self.settings.secret_key,
        }
        url = self.base_url + path
        shown_url = redact_text(f"{url}?{urlencode(query)}")
        attempts = GET_ATTEMPTS if method == "GET" else 1

        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            try:
                resp = self.session.request(
                    method, url, params=query, json=json, timeout=self.timeout
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                log.warning(
                    "%s %s -> %s (attempt %d/%d)",
                    method,
                    shown_url,
                    type(exc).__name__,
                    attempt,
                    attempts,
                )
                if attempt < attempts:
                    time.sleep(self.backoff * 2 ** (attempt - 1))
                    continue
                raise SwsError(
                    0,
                    {"": [f"{type(exc).__name__}: {redact_text(str(exc))}"]},
                    method=method,
                    path=path,
                ) from exc

            elapsed = time.monotonic() - started
            log.info("%s %s -> HTTP %d (%.2fs)", method, shown_url, resp.status_code, elapsed)
            if json is not None:
                log.debug("request body: %s", redact(json))
            body = _parse(resp)
            log.debug("response body: %s", redact(body))
            if self.recorder:
                self.recorder(method, path, query, json, resp.status_code, body, elapsed)

            if resp.status_code >= 500 and attempt < attempts:
                time.sleep(self.backoff * 2 ** (attempt - 1))
                continue
            error = error_from_response(resp.status_code, body, method=method, path=path)
            if error:
                raise error
            return body
        raise AssertionError("unreachable")  # pragma: no cover


def _parse(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text
