"""SwsError: one exception type for every way the SWS API reports a failure.

The API signals errors in several body shapes, often with HTTP 200, so a
response is only a success when its status is 2xx AND its body is not one of
these (see docs/API_GUIDE.md):

    {"errors": {"field": ["message", ...]}}            e.g. bad credentials (200 on GET)
    {"errors": ["message", ...]}                        documented in the Swagger spec
    {"response_type": "ERROR", "response_code": 400,
     "message": {"field": ["message", ...]}}            e.g. invalid product on create (400)
    {"error": "message"}                                e.g. revoke with nothing issued (404)
    {"cert_results": null, "error_message": "message"}  POST /generate_certificate refusals (200)
"""

from __future__ import annotations

from typing import Any

from smime_demo.redaction import redact


class SwsError(Exception):
    def __init__(
        self,
        status: int,
        messages: dict[str, list[str]],
        *,
        code: int | None = None,
        raw: Any = None,
        method: str = "",
        path: str = "",
    ) -> None:
        self.status = status
        self.code = code
        self.messages = messages
        self.raw = redact(raw)
        self.method = method
        self.path = path
        super().__init__(str(self))

    @property
    def field_messages(self) -> list[str]:
        """Every message, each prefixed with its field name when there is one."""
        out = []
        for field_name, msgs in self.messages.items():
            for msg in msgs:
                out.append(f"{field_name}: {msg}" if field_name else msg)
        return out

    def __str__(self) -> str:
        where = f"{self.method} {self.path} " if self.method else ""
        detail = "; ".join(self.field_messages) or "no error details in the response"
        return f"SWS error ({where}HTTP {self.status}): {detail}"


def error_from_response(
    status: int, body: Any, *, method: str = "", path: str = ""
) -> SwsError | None:
    """Return an SwsError if the response is a failure, else None."""
    messages: dict[str, list[str]] = {}
    code: int | None = None

    if isinstance(body, dict):
        if body.get("errors"):
            messages = _normalize(body["errors"])
        elif body.get("response_type") == "ERROR":
            code = body.get("response_code")
            messages = _normalize(body.get("message") or {})
        elif body.get("error"):
            messages = _normalize(body["error"])
        elif body.get("error_message"):
            messages = _normalize(body["error_message"])

    if messages or not 200 <= status < 300:
        if not messages and isinstance(body, str) and body.strip():
            messages = {"": [body.strip()[:300]]}
        return SwsError(status, messages, code=code, raw=body, method=method, path=path)
    return None


def _normalize(value: Any) -> dict[str, list[str]]:
    if isinstance(value, dict):
        return {
            str(k): [str(m) for m in (v if isinstance(v, list) else [v])] for k, v in value.items()
        }
    if isinstance(value, list):
        return {"": [str(m) for m in value]}
    return {"": [str(value)]}
