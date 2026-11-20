"""Workflow B: one person, several devices, one order, one mailbox confirmation.

Default devices:
    phone   ECC P-256  signing only
    laptop  ECC P-256  signing only
    shared  RSA        signing and encryption; its key goes on both devices, so it is
                       also exported as a password-protected PKCS#12

ECC certificates are signing-only. SSL.com does not issue encryption-only
certificates, so the shared RSA certificate can sign as well.

Each certificate gets its own validity period from its own issue time
(observed: 365 days for the first certificate on an order, 364 for later ones);
they do not share the order's expiry.
Earlier certificates stay valid when later ones are issued.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509

from smime_demo.roster import Device
from smime_demo.workflows.enterprise import EmployeeOutcome
from smime_demo.workflows.single import issue_for_devices

DEFAULT_DEVICES = (
    Device("phone", "ecc"),
    Device("laptop", "ecc"),
    Device("shared", "rsa"),
)

MIN_DAYS, MAX_DAYS = 360, 366


def issue_multi_device(
    client, store, *, email, external_id, out_dir, devices=DEFAULT_DEVICES, **kwargs
) -> EmployeeOutcome:
    return issue_for_devices(
        client,
        store,
        email=email,
        external_id=external_id,
        devices=devices,
        out_dir=out_dir,
        **kwargs,
    )


def check_multi_device(client, outcome: EmployeeOutcome) -> list[str]:
    """After issuing: every requested certificate is still on the order and
    'issued', and each is valid for about a year from its own issue time."""
    problems = []
    if not outcome.ref:
        return ["no order"]
    on_order = {
        c.serial.lstrip("0"): c.status
        for c in client.get_certificate(outcome.ref).end_entity_certificates
    }
    for dev in outcome.devices:
        key = (dev.serial or "").lstrip("0")
        if on_order.get(key) != "issued":
            problems.append(
                f"{dev.name}: certificate {dev.serial} is {on_order.get(key, 'missing')}"
            )
        cert_file = dev.files.get("certificate")
        if cert_file:
            cert = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
            days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
            if not MIN_DAYS <= days <= MAX_DAYS:
                problems.append(f"{dev.name}: valid for {days} days, expected about a year")
    return problems
