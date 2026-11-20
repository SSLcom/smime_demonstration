"""Per-employee steps shared by every workflow.

    device_csr()          make a key + CSR for a device, or load the device's own CSR
    ensure_order()        create the employee's order exactly once (store-guarded)
    wait_until_issuable() poll until the mailbox owner has confirmed (mailbox path)
    issue_device()        POST /generate_certificate, verify, save files

Two ways an order becomes issuable (see docs/API_GUIDE.md):

- "mailbox": SSL.com emails the employee an activation link; they press confirm.
  The order is created without a CSR.
- "domain":  the customer's domain was validated once. The order must carry the
  first device's CSR plus locality and state_or_province (never put in the
  certificate), and issues immediately.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from smime_demo.client import SwsClient
from smime_demo.keys import (
    build_csr,
    csr_to_pem,
    export_pkcs12,
    generate_key,
    load_csr,
    write_private_key,
)
from smime_demo.models import CertificateBundle, Order
from smime_demo.roster import Device, Employee
from smime_demo.store import Store
from smime_demo.verify import verify_certificate

MAILBOX = "mailbox"
DOMAIN = "domain"


class MissingRegistrantAddress(Exception):
    """A second certificate is being requested on an order whose registrant has no
    city/state, and none was supplied."""


class OrderNeedsReconciliation(Exception):
    """A create call was attempted but no ref was recorded. Creating another
    order could double-charge in production, so a person must check first."""


@dataclass
class Polling:
    """How long and how often to poll. `sleep` and `clock` are injectable for tests."""

    timeout: float = 30 * 60
    interval: float = 10
    max_interval: float = 60
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic


@dataclass
class DeviceResult:
    name: str
    serial: str | None = None
    not_after: str | None = None
    files: dict[str, str] = field(default_factory=dict)
    verify_failures: list[str] = field(default_factory=list)
    skipped: bool = False  # already issued in an earlier run
    error: str | None = None


def employee_dir(out_dir: Path, customer_id: str, employee_id: str) -> Path:
    return out_dir / "customers" / customer_id / employee_id


# -- step: CSR -------------------------------------------------------------------


def device_csr(device: Device, email: str, folder: Path, rsa_bits: int = 3072) -> str:
    """CSR for a device. Generated keys are kept (mode 0600) and reused on re-runs,
    so a re-run issues for the same key rather than a new one."""
    if device.kind == "csr":
        return load_csr(device.csr_path)
    csr_path = folder / f"{device.name}.csr.pem"
    if csr_path.exists():
        return csr_path.read_text()
    key = generate_key(device.kind, rsa_bits)
    write_private_key(key, folder / f"{device.name}.key.pem")
    csr = csr_to_pem(build_csr(key, email))
    csr_path.write_text(csr)
    return csr


# -- step: order -----------------------------------------------------------------


def ensure_order(
    client: SwsClient,
    store: Store,
    customer_id: str,
    employee: Employee,
    *,
    path: str,
    first_csr: str | None = None,
    locality: str | None = None,
    state_or_province: str | None = None,
) -> Order:
    """The employee's order: fetched if it exists, created once if it does not."""
    record = store.employee(customer_id, employee.employee_id, employee.email)
    order_rec = record.get("order")
    if order_rec and order_rec.get("ref"):
        return client.get_certificate(order_rec["ref"])
    if order_rec and order_rec.get("attempted_at"):
        raise OrderNeedsReconciliation(
            f"An order for {employee.email} ({order_rec['external_order_number']}) was "
            f"attempted at {order_rec['attempted_at']} but no ref was recorded. Check "
            "GET /certificates for it before creating another."
        )
    if path == DOMAIN and not (first_csr and locality and state_or_province):
        raise ValueError("domain-validated orders need the first CSR, locality and state")

    ext = store.mark_order_attempted(customer_id, employee.employee_id, path)
    order = client.create_order(
        email=employee.email,
        external_order_number=ext,
        csr_pem=first_csr if path == DOMAIN else None,
        locality=locality if path == DOMAIN else None,
        state_or_province=state_or_province if path == DOMAIN else None,
    )
    store.set_order_ref(customer_id, employee.employee_id, order.ref)
    return order


# -- step: wait for the mailbox owner --------------------------------------------


def wait_until_issuable(
    client: SwsClient,
    refs: list[str],
    polling: Polling,
    on_tick: Callable[[dict[str, Order]], None] | None = None,
) -> dict[str, Order]:
    """Poll orders until each can be issued or the timeout passes.
    Returns the latest Order for every ref; callers check `.can_issue`."""
    latest: dict[str, Order] = {}
    pending = list(refs)
    deadline = polling.clock() + polling.timeout
    interval = polling.interval
    while True:
        for ref in list(pending):
            latest[ref] = client.get_certificate(ref)
            if latest[ref].can_issue:
                pending.remove(ref)
        if on_tick:
            on_tick(latest)
        if not pending or polling.clock() >= deadline:
            return latest
        polling.sleep(interval)
        interval = min(interval * 1.5, polling.max_interval)


# -- step: registrant address ------------------------------------------------------


def ensure_registrant_address(
    client: SwsClient, ref: str, locality: str | None, state_or_province: str | None
) -> None:
    """Every certificate after the first on an order with a registrant (any order
    created with `recipient`) failed with "City can't be blank and State can't be
    blank" until the registrant had a city and state. Set them once if missing.
    The values never appear in the certificate, so placeholders are fine."""
    registrant = client.get_certificate(ref).raw.get("registrant") or {}
    if not registrant or (registrant.get("locality") and registrant.get("state_or_province")):
        return
    if not (locality and state_or_province):
        raise MissingRegistrantAddress(
            f"Order {ref} needs a registrant city and state before another certificate can be "
            "issued on it. Pass --locality and --state (placeholders are fine; they are not "
            "put in the certificate)."
        )
    client.set_registrant_address(ref, locality, state_or_province)


# -- step: issue -------------------------------------------------------------------


def issue_device(
    client: SwsClient,
    store: Store,
    customer_id: str,
    employee: Employee,
    device: Device,
    ref: str,
    folder: Path,
    *,
    p12_password: str | None = None,
) -> DeviceResult:
    """Issue one device's certificate on the employee's order, verify it, save it."""
    dev_rec = store.device(customer_id, employee.employee_id, device.name)
    if dev_rec.get("serial") and dev_rec.get("status") == "issued":
        return DeviceResult(
            device.name,
            dev_rec["serial"],
            dev_rec.get("not_after"),
            dev_rec.get("files", {}),
            skipped=True,
        )

    csr = device_csr(device, employee.email, folder)
    bundle = client.generate_certificate(ref, csr)
    result = save_certificate(device, bundle, folder, p12_password)
    result.verify_failures = verify_certificate(
        bundle.leaf_pem, csr, employee.email, bundle.chain_pems
    )
    dev_rec.update(
        kind=device.kind,
        serial=result.serial,
        status="issued",
        not_after=result.not_after,
        files=result.files,
        verify_failures=result.verify_failures,
        issued_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    store.save()
    return result


def serial_hex(serial_number: int) -> str:
    """Lowercase hex padded to whole bytes, as the API reports serials
    (e.g. "08df…", not "8df…")."""
    text = f"{serial_number:x}"
    return text.zfill(len(text) + len(text) % 2)


def save_certificate(
    device: Device, bundle: CertificateBundle, folder: Path, p12_password: str | None
) -> DeviceResult:
    cert = x509.load_pem_x509_certificate(bundle.leaf_pem.encode())
    files = {
        "certificate": folder / f"{device.name}.cert.pem",
        "chain": folder / f"{device.name}.chain.pem",
    }
    files["certificate"].write_text(bundle.leaf_pem)
    files["chain"].write_text("".join(bundle.chain_pems))

    key_path = folder / f"{device.name}.key.pem"
    if device.kind == "rsa" and key_path.exists():
        # The shared signing+encryption key goes on several devices: package it.
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        password = p12_password or secrets.token_urlsafe(16)
        files["pkcs12"] = folder / f"{device.name}.p12"
        files["pkcs12"].write_bytes(
            export_pkcs12(key, bundle.leaf_pem, bundle.chain_pems, password, device.name)
        )
        if not p12_password:
            pw_path = folder / f"{device.name}.p12.password"
            pw_path.write_text(password + "\n")
            pw_path.chmod(0o600)
            files["pkcs12_password"] = pw_path

    return DeviceResult(
        device.name,
        serial=serial_hex(cert.serial_number),
        not_after=cert.not_valid_after_utc.isoformat(timespec="seconds"),
        files={k: str(v) for k, v in files.items()},
    )
