"""An in-memory stand-in for SwsClient that behaves like the sandbox did.

- Orders start "validating, please wait". `confirm_mailbox(ref)` plays the
  person pressing confirm. A domain validated on any order covers later orders
  for that domain, as observed.
- generate_certificate issues a real certificate from the test PKI, and
  refuses (like the sandbox) when the order is not validated, when a
  domain-path order lacks its CSR or city/state, or when a second certificate
  is requested on an order whose registrant has no city/state.
"""

from __future__ import annotations

import itertools

from cryptography import x509

from smime_demo.errors import SwsError
from smime_demo.models import (
    STATUS_AWAITING_MAILBOX,
    STATUS_ISSUED,
    STATUS_REVOKED,
    STATUS_VALIDATED,
    CertificateBundle,
    EndEntityCertificate,
    Order,
)
from tests.unit.pki import pem


class FakeSws:
    def __init__(self, pki) -> None:
        self.pki = pki
        self.orders: dict[str, dict] = {}
        self.validated_domains: set[str] = set()
        self.published: set[str] = set()  # CNAME names "in DNS"
        self.calls: list[tuple] = []
        self._ids = itertools.count(1)

    # -- test controls --
    def confirm_mailbox(self, ref: str) -> None:
        self.orders[ref]["mailbox_confirmed"] = True

    def generate_in_browser(self, ref: str) -> str:
        """The end user generates a certificate on the activation page."""
        from smime_demo.keys import build_csr, generate_key

        o = self.orders[ref]
        cert = self.pki.issue(build_csr(generate_key("rsa", 2048), o["email"]), o["email"])
        serial = self._add_cert(o, cert)
        return serial

    # -- SwsClient interface --
    def create_order(
        self,
        *,
        email,
        external_order_number,
        csr_pem=None,
        locality=None,
        state_or_province=None,
        **_,
    ):
        self.calls.append(("create_order", email, external_order_number))
        ref = f"co-fake{next(self._ids)}"
        self.orders[ref] = dict(
            email=email,
            ext=external_order_number,
            csr=csr_pem,
            locality=locality,
            state=state_or_province,
            mailbox_confirmed=False,
            certs=[],
            revoked=False,
        )
        return self.get_certificate(ref)

    def get_certificate(self, ref: str) -> Order:
        o = self._order(ref)
        domain = o["email"].split("@")[1]
        if o["revoked"]:
            status = STATUS_REVOKED
        elif o["certs"]:
            status = STATUS_ISSUED
        elif o["mailbox_confirmed"] or domain in self.validated_domains:
            status = STATUS_VALIDATED
        else:
            status = STATUS_AWAITING_MAILBOX
        latest = (
            CertificateBundle(o["certs"][-1]["pem"], tuple(self.pki.chain_pems))
            if o["certs"]
            else None
        )
        return Order(
            ref=ref,
            order_status=status,
            external_order_number=o["ext"],
            latest_certificate=latest,
            end_entity_certificates=tuple(
                EndEntityCertificate(c["serial"], c["status"], c["pem"]) for c in o["certs"]
            ),
            raw={
                "registrant": {
                    "email": o["email"],
                    "locality": o["locality"],
                    "state_or_province": o["state"],
                }
            },
        )

    def set_registrant_address(self, ref: str, locality: str, state_or_province: str) -> Order:
        self.calls.append(("set_registrant_address", ref))
        o = self._order(ref)
        o["locality"], o["state"] = locality, state_or_province
        return self.get_certificate(ref)

    def get_validation_methods(self, ref: str) -> dict:
        o = self._order(ref)
        if not o["csr"]:
            return {"dcv_methods": {}}
        domain = o["email"].split("@")[1]
        return {
            "dcv_methods": {
                domain: {
                    "cname_csr_hash": {
                        "name": f"_abc123.{domain}",
                        "value": "def456.20261120.ssl.com",
                    }
                }
            }
        }

    def set_domain_validation(self, ref: str, domain: str, method: str = "cname_csr_hash") -> Order:
        self.calls.append(("set_domain_validation", ref, domain))
        if f"_abc123.{domain}" in self.published:
            self.validated_domains.add(domain)
        return self.get_certificate(ref)

    def get_validation_status(self, ref: str) -> dict:
        domain = self._order(ref)["email"].split("@")[1]
        ok = domain in self.validated_domains
        return {
            domain: {
                "method": "cname_csr_hash" if ok else None,
                "status": "satisfied" if ok else "not yet started",
                "validated_at": "2026-11-20T13:08:49.000-06:00" if ok else None,
            }
        }

    def generate_certificate(self, ref: str, csr_pem: str) -> CertificateBundle:
        self.calls.append(("generate_certificate", ref))
        o = self._order(ref)
        order = self.get_certificate(ref)
        if not order.can_issue:
            raise SwsError(200, {"": ["Email address validation is not complete."]})
        if not o["mailbox_confirmed"]:  # domain path rules seen in the sandbox
            if not o["csr"]:
                raise SwsError(200, {"": ["no certificate in the response"]})
            if not (o["locality"] and o["state"]):
                raise SwsError(200, {"": ["City can't be blank and State can't be blank"]})
        if o["certs"] and not (o["locality"] and o["state"]):
            raise SwsError(200, {"": ["City can't be blank and State can't be blank"]})
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        cert = self.pki.issue(csr, o["email"])
        self._add_cert(o, cert)
        return CertificateBundle(pem(cert), tuple(self.pki.chain_pems))

    def revoke(self, ref: str, reason: str, serial: str | None = None) -> None:
        self.calls.append(("revoke", ref, serial))
        o = self._order(ref)
        for c in o["certs"]:
            if serial is None or c["serial"].lstrip("0") == serial.lstrip("0"):
                c["status"] = "revoked"
        if serial is None:
            o["revoked"] = True

    # -- helpers --
    def _order(self, ref: str) -> dict:
        if ref not in self.orders:
            raise SwsError(200, {"ref": ["doesn't exist"]})
        return self.orders[ref]

    def _add_cert(self, o: dict, cert) -> str:
        text = f"{cert.serial_number:x}"
        serial = text.zfill(len(text) + len(text) % 2)
        o["certs"].append({"serial": serial, "status": "issued", "pem": pem(cert)})
        return serial
