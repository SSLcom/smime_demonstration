"""Remove credentials from anything that might be logged or saved.

GET requests carry account_key and secret_key in the query string, and some
responses echo them back (GET /certificate/{ref}/api_parameters/...), so both
URLs and bodies are redacted.
"""

from __future__ import annotations

import re
from typing import Any

SECRET_FIELDS = frozenset({"account_key", "secret_key", "password"})
REDACTED = "REDACTED"

_SECRET_IN_TEXT = re.compile(
    r"""((?:account_key|secret_key|password)(?:=|"\s*:\s*"|'\s*:\s*'))[^&\s"']+""",
    re.IGNORECASE,
)
# Validation links: https://<host>/certificate_order_token/<token>/generate_cert
_ORDER_TOKEN = re.compile(r"(/certificate_order_token/)[^/\s\"']+")


def redact_text(text: str) -> str:
    text = _SECRET_IN_TEXT.sub(rf"\1{REDACTED}", text)
    return _ORDER_TOKEN.sub(rf"\1{REDACTED}", text)


def redact(value: Any) -> Any:
    """Return a copy of a JSON-like value with secrets replaced."""
    if isinstance(value, dict):
        return {k: (REDACTED if k in SECRET_FIELDS else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
