"""Workflow C, steps 2 and 3: issue certificates for a customer's employees,
revoke them when no longer needed, and report what exists.

    onboard_customer()  one order per employee, then one certificate per device
                        - path "domain":  domain validated in step 1; issues at once
                        - path "mailbox": each employee confirms their activation link
    offboard()          revoke one device (by serial), one employee, or the customer
    inventory()         every certificate on the customer's orders, including any the
                        partner did not request (e.g. generated on the activation page)

Re-running onboard_customer is safe: orders and certificates already recorded in
the store are not created again.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509

from smime_demo.client import SwsClient
from smime_demo.errors import SwsError
from smime_demo.models import DCV_SATISFIED, Order
from smime_demo.roster import Employee
from smime_demo.store import Store
from smime_demo.workflows.issuance import (
    DOMAIN,
    MAILBOX,
    DeviceResult,
    MissingRegistrantAddress,
    OrderNeedsReconciliation,
    Polling,
    device_csr,
    employee_dir,
    ensure_order,
    ensure_registrant_address,
    issue_device,
    wait_until_issuable,
)


class DomainNotValidated(Exception):
    pass


@dataclass
class EmployeeOutcome:
    employee_id: str
    email: str
    ref: str | None = None
    order_status: str | None = None
    devices: list[DeviceResult] = field(default_factory=list)
    waiting_for_mailbox: bool = False
    error: str | None = None


def onboard_customer(
    client: SwsClient,
    store: Store,
    customer_id: str,
    employees: list[Employee],
    *,
    path: str,
    out_dir: Path,
    polling: Polling | None = None,
    p12_password: str | None = None,
    on_awaiting_mailbox: Callable[[list[tuple[Employee, Order]]], None] | None = None,
    on_tick: Callable[[dict[str, Order]], None] | None = None,
    locality: str | None = None,
    state_or_province: str | None = None,
) -> list[EmployeeOutcome]:
    """`locality` / `state_or_province` (mailbox path): placeholders used if an
    employee gets more than one certificate on their order. The domain path takes
    them from step 1."""
    if path == DOMAIN:
        return _onboard_domain(client, store, customer_id, employees, out_dir, p12_password)
    address = (locality, state_or_province)
    if path == MAILBOX:
        return _onboard_mailbox(
            client,
            store,
            customer_id,
            employees,
            out_dir,
            polling or Polling(),
            p12_password,
            on_awaiting_mailbox,
            on_tick,
            address,
        )
    raise ValueError("path must be 'domain' or 'mailbox'")


def _onboard_domain(client, store, customer_id, employees, out_dir, p12_password):
    customer = store.customer(customer_id)
    dv = customer.get("domain_validation") or {}
    domain = customer.get("domain")
    if not domain or dv.get("domain") != domain or dv.get("status") != DCV_SATISFIED:
        raise DomainNotValidated(
            f"{customer_id}: validate the domain first (smime-demo domain validate)."
        )
    outcomes = []
    for emp in employees:
        outcome = EmployeeOutcome(emp.employee_id, emp.email)
        outcomes.append(outcome)
        if emp.domain != domain:
            outcome.error = f"{emp.email} is not on the validated domain {domain}"
            continue
        folder = employee_dir(out_dir, customer_id, emp.employee_id)
        folder.mkdir(parents=True, exist_ok=True)
        try:
            # The first device's CSR travels with the order (required on this path).
            first_csr = device_csr(emp.devices[0], emp.email, folder)
            order = ensure_order(
                client,
                store,
                customer_id,
                emp,
                path=DOMAIN,
                first_csr=first_csr,
                locality=customer["locality"],
                state_or_province=customer["state_or_province"],
            )
            outcome.ref = order.ref
            address = (customer["locality"], customer["state_or_province"])
            _issue_all(
                client, store, customer_id, emp, order.ref, folder, p12_password, outcome, address
            )
            outcome.order_status = client.get_certificate(order.ref).order_status
        except (SwsError, OrderNeedsReconciliation, MissingRegistrantAddress) as exc:
            outcome.error = str(exc)
    return outcomes


def _onboard_mailbox(
    client,
    store,
    customer_id,
    employees,
    out_dir,
    polling,
    p12_password,
    on_awaiting_mailbox,
    on_tick,
    address,
):
    store.customer(customer_id, create=True)
    outcomes: dict[str, EmployeeOutcome] = {}
    orders: dict[str, Order] = {}
    for emp in employees:
        outcome = outcomes[emp.employee_id] = EmployeeOutcome(emp.employee_id, emp.email)
        try:
            order = ensure_order(client, store, customer_id, emp, path=MAILBOX)
            outcome.ref, orders[emp.employee_id] = order.ref, order
        except (SwsError, OrderNeedsReconciliation) as exc:
            outcome.error = str(exc)

    awaiting = [
        (e, orders[e.employee_id])
        for e in employees
        if e.employee_id in orders and not orders[e.employee_id].can_issue
    ]
    if awaiting and on_awaiting_mailbox:
        on_awaiting_mailbox(awaiting)
    latest = wait_until_issuable(client, [o.ref for o in orders.values()], polling, on_tick)

    for emp in employees:
        outcome = outcomes[emp.employee_id]
        order = latest.get(outcome.ref) if outcome.ref else None
        if order is None:
            continue
        outcome.order_status = order.order_status
        if not order.can_issue:
            outcome.waiting_for_mailbox = True
            continue
        folder = employee_dir(out_dir, customer_id, emp.employee_id)
        folder.mkdir(parents=True, exist_ok=True)
        try:
            _issue_all(
                client, store, customer_id, emp, order.ref, folder, p12_password, outcome, address
            )
        except (SwsError, MissingRegistrantAddress) as exc:
            outcome.error = str(exc)
    return list(outcomes.values())


def _issue_all(client, store, customer_id, emp, ref, folder, p12_password, outcome, address):
    """Issue every device. If the order will hold more than one certificate, make
    sure its registrant has a city and state first (see ensure_registrant_address)."""
    already = [
        d
        for d in store.employee(customer_id, emp.employee_id)["devices"].values()
        if d.get("status") == "issued"
    ]
    if len(emp.devices) > 1 or already:
        ensure_registrant_address(client, ref, *address)
    for device in emp.devices:
        outcome.devices.append(
            issue_device(
                client, store, customer_id, emp, device, ref, folder, p12_password=p12_password
            )
        )


# -- step 3: revoke -------------------------------------------------------------------


def offboard(
    client: SwsClient,
    store: Store,
    customer_id: str,
    *,
    reason: str,
    employee_id: str | None = None,
    serial: str | None = None,
) -> list[str]:
    """Revoke one certificate (serial), one employee's certificates, or the whole
    customer's. Returns a line per action taken."""
    customer = store.customer(customer_id)
    actions = []
    if serial:
        found = store.find_serial(customer_id, serial)
        if not found:
            raise KeyError(
                f"serial {serial} is not a certificate this partner issued for {customer_id}"
            )
        emp_id, device_name = found
        ref = customer["employees"][emp_id]["order"]["ref"]
        stored_serial = customer["employees"][emp_id]["devices"][device_name]["serial"]
        client.revoke(ref, reason, serial=stored_serial)
        actions.append(f"revoked {emp_id}/{device_name} ({stored_serial}) on {ref}")
    else:
        targets = [employee_id] if employee_id else list(customer["employees"])
        for emp_id in targets:
            order = (customer["employees"].get(emp_id) or {}).get("order") or {}
            ref = order.get("ref")
            if not ref:
                actions.append(f"{emp_id}: no order")
                continue
            if not client.get_certificate(ref).issued_serials:
                actions.append(f"{emp_id}: nothing left to revoke on {ref}")
                continue
            client.revoke(ref, reason)
            actions.append(f"revoked every certificate of {emp_id} on {ref}")
    refresh_statuses(client, store, customer_id)
    return actions


# -- inventory ----------------------------------------------------------------------------


@dataclass
class InventoryRow:
    employee_id: str
    email: str
    ref: str | None
    order_status: str | None
    device: str | None  # None: on the order, but not requested by the partner
    serial: str | None
    status: str | None
    not_after: str | None


def inventory(client: SwsClient, store: Store, customer_id: str) -> list[InventoryRow]:
    customer = store.customer(customer_id)
    rows = []
    for emp_id, emp in sorted(customer["employees"].items()):
        ref = (emp.get("order") or {}).get("ref")
        if not ref:
            rows.append(InventoryRow(emp_id, emp["email"], None, None, None, None, None, None))
            continue
        order = client.get_certificate(ref)
        requested = {
            (d.get("serial") or "").lstrip("0"): name for name, d in emp["devices"].items()
        }
        if not order.end_entity_certificates:
            rows.append(
                InventoryRow(emp_id, emp["email"], ref, order.order_status, None, None, None, None)
            )
        for cert in order.end_entity_certificates:
            device = requested.get(cert.serial.lstrip("0"))
            not_after = emp["devices"][device].get("not_after") if device else _not_after(cert.pem)
            rows.append(
                InventoryRow(
                    emp_id,
                    emp["email"],
                    ref,
                    order.order_status,
                    device,
                    cert.serial,
                    cert.status,
                    not_after,
                )
            )
    return rows


def refresh_statuses(client: SwsClient, store: Store, customer_id: str) -> None:
    """Copy each certificate's status from SSL.com into the store."""
    for emp in store.customer(customer_id)["employees"].values():
        ref = (emp.get("order") or {}).get("ref")
        if not ref:
            continue
        status = {
            c.serial.lstrip("0"): c.status
            for c in client.get_certificate(ref).end_entity_certificates
        }
        for dev in emp["devices"].values():
            key = (dev.get("serial") or "").lstrip("0")
            if key in status:
                dev["status"] = status[key]
    store.save()


def _not_after(pem: str | None) -> str | None:
    if not pem:
        return None
    cert = x509.load_pem_x509_certificate(pem.encode())
    return cert.not_valid_after_utc.isoformat(timespec="seconds")
