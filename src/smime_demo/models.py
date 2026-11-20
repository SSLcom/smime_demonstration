"""Typed views of the SWS responses the demo uses.

Only fields observed in the sandbox are modelled (see docs/API_GUIDE.md);
everything else stays available in `raw`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PRODUCT_MAILBOX_SMIME = 300  # "Personal Basic": mailbox-validated S/MIME

# order_status values observed for product 300, in the order they occur.
STATUS_NO_RECIPIENT = "waiting on registrant information from customer"
STATUS_AWAITING_MAILBOX = "validating, please wait"
STATUS_VALIDATED = "validated"
STATUS_ISSUED = "issued"
STATUS_REVOKED = "revoked"

# DELETE /certificate/{ref} only accepts these reason codes.
REVOKE_REASONS = (
    "UNSPECIFIED",
    "CESSATIONOFOPERATION",
    "AFFILIATIONCHANGED",
    "SUPERSEDED",
    "KEYCOMPROMISE",
)

_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def split_pem_certificates(text: str | None) -> list[str]:
    """All PEM certificates in a string, in order, each ending with a newline."""
    return [m.group(0) + "\n" for m in _PEM_CERT.finditer(text or "")]


@dataclass(frozen=True)
class CertificateBundle:
    """An issued end-entity certificate and the chain that came with it."""

    leaf_pem: str
    chain_pems: tuple[str, ...]  # intermediate(s) first, then the root

    @classmethod
    def from_pem_chain(cls, text: str | None) -> CertificateBundle | None:
        """SWS returns the leaf first, then intermediate, then root."""
        pems = split_pem_certificates(text)
        if not pems:
            return None
        return cls(leaf_pem=pems[0], chain_pems=tuple(pems[1:]))

    @property
    def full_chain_pem(self) -> str:
        return self.leaf_pem + "".join(self.chain_pems)


@dataclass(frozen=True)
class CnameRecord:
    """The DNS record that proves control of a domain (`cname_csr_hash`).

    Derived from the CSR on the order, and the value includes the date, so it
    is specific to the order it was read from."""

    domain: str
    name: str  # e.g. _<md5>.example.com
    value: str  # e.g. <sha256 split>.<yyyymmdd>.ssl.com

    @classmethod
    def from_methods(cls, body: dict[str, Any], domain: str) -> CnameRecord | None:
        """From a GET /certificate/{ref}/validations/methods response."""
        cname = ((body.get("dcv_methods") or {}).get(domain) or {}).get("cname_csr_hash") or {}
        if not cname.get("name") or not cname.get("value"):
            return None
        return cls(domain=domain, name=cname["name"].rstrip("."), value=cname["value"].rstrip("."))


DCV_SATISFIED = "satisfied"


@dataclass(frozen=True)
class EndEntityCertificate:
    """One entry of `end_entity_certificates` on an order."""

    serial: str  # lowercase hex, no colons, as the API returns it
    status: str  # "issued" or "revoked"
    pem: str | None


@dataclass(frozen=True)
class Order:
    ref: str
    order_status: str
    external_order_number: str | None = None
    recipient_notice: str | None = None
    expiration_date: str | None = None
    latest_certificate: CertificateBundle | None = None
    end_entity_certificates: tuple[EndEntityCertificate, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, body: dict[str, Any], ref: str | None = None) -> Order:
        """Build from a POST /certificates or GET /certificate/{ref} response.
        GET responses do not repeat the ref, so the caller passes it."""
        entries = tuple(
            EndEntityCertificate(
                serial=str(e.get("serial") or "").lower(),
                status=str(e.get("status") or ""),
                pem=(split_pem_certificates(e.get("certificate")) or [None])[0],
            )
            for e in body.get("end_entity_certificates") or []
        )
        return cls(
            ref=body.get("ref") or ref or "",
            order_status=body.get("order_status") or "",
            external_order_number=body.get("external_order_number"),
            recipient_notice=body.get("recipient_notice"),
            expiration_date=body.get("expiration_date"),
            latest_certificate=CertificateBundle.from_pem_chain(body.get("certificates")),
            end_entity_certificates=entries,
            raw=body,
        )

    @property
    def awaiting_mailbox_confirmation(self) -> bool:
        return self.order_status == STATUS_AWAITING_MAILBOX

    @property
    def needs_recipient(self) -> bool:
        return self.order_status == STATUS_NO_RECIPIENT or bool(self.recipient_notice)

    @property
    def can_issue(self) -> bool:
        """Mailbox confirmed, so POST /generate_certificate will be accepted."""
        return self.order_status in (STATUS_VALIDATED, STATUS_ISSUED)

    @property
    def issued_serials(self) -> list[str]:
        return [e.serial for e in self.end_entity_certificates if e.status == STATUS_ISSUED]
