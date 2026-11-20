"""Check whether a CNAME record has been published.

Uses a public DNS-over-HTTPS resolver so that no DNS library is needed. Only
the record name is sent, and it is a public DNS name anyway. Callers can pass
their own lookup function instead (tests do).
"""

from __future__ import annotations

from collections.abc import Callable

import requests

DOH_URL = "https://cloudflare-dns.com/dns-query"

CnameLookup = Callable[[str], str | None]


def lookup_cname(name: str, *, timeout: float = 10) -> str | None:
    """The CNAME target of `name`, without the trailing dot, or None."""
    resp = requests.get(
        DOH_URL,
        params={"name": name, "type": "CNAME"},
        headers={"Accept": "application/dns-json"},
        timeout=timeout,
    )
    resp.raise_for_status()
    for answer in resp.json().get("Answer") or []:
        if answer.get("type") == 5:  # CNAME
            return str(answer.get("data", "")).rstrip(".").lower()
    return None


def cname_matches(lookup: CnameLookup, name: str, value: str) -> bool:
    try:
        found = lookup(name)
    except requests.RequestException:
        return False
    return found is not None and found.rstrip(".").lower() == value.rstrip(".").lower()
