"""Workflow A: one mailbox, one certificate, confirmed through the activation link.

    order (with recipient)  ->  mailbox owner presses confirm  ->  poll until "validated"
    ->  POST /generate_certificate with the device's CSR  ->  verify  ->  save PEM files

It is the enterprise onboarding (enterprise.py) for a single person, recorded
under the customer ID "individual" with the partner's ID as the employee ID.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from smime_demo.client import SwsClient
from smime_demo.models import Order
from smime_demo.roster import Device, Employee
from smime_demo.store import Store
from smime_demo.workflows.enterprise import EmployeeOutcome, onboard_customer
from smime_demo.workflows.issuance import MAILBOX, Polling

INDIVIDUAL = "individual"


def issue_mailbox_certificate(
    client: SwsClient,
    store: Store,
    *,
    email: str,
    external_id: str,
    device: Device,
    out_dir: Path,
    polling: Polling | None = None,
    on_awaiting_validation: Callable[[Order], None] | None = None,
    on_tick: Callable[[dict[str, Order]], None] | None = None,
) -> EmployeeOutcome:
    return issue_for_devices(
        client,
        store,
        email=email,
        external_id=external_id,
        devices=(device,),
        out_dir=out_dir,
        polling=polling,
        on_awaiting_validation=on_awaiting_validation,
        on_tick=on_tick,
    )


def issue_for_devices(
    client: SwsClient,
    store: Store,
    *,
    email: str,
    external_id: str,
    devices: tuple[Device, ...],
    out_dir: Path,
    polling: Polling | None = None,
    p12_password: str | None = None,
    on_awaiting_validation: Callable[[Order], None] | None = None,
    on_tick: Callable[[dict[str, Order]], None] | None = None,
    locality: str | None = None,
    state_or_province: str | None = None,
) -> EmployeeOutcome:
    """`locality` / `state_or_province` are needed only when the order holds more
    than one certificate; they never appear in the certificate."""
    employee = Employee(external_id, email.lower(), devices)

    def awaiting(pairs: list[tuple[Employee, Order]]) -> None:
        if on_awaiting_validation:
            on_awaiting_validation(pairs[0][1])

    (outcome,) = onboard_customer(
        client,
        store,
        INDIVIDUAL,
        [employee],
        path=MAILBOX,
        out_dir=out_dir,
        polling=polling,
        p12_password=p12_password,
        on_awaiting_mailbox=awaiting,
        on_tick=on_tick,
        locality=locality,
        state_or_province=state_or_province,
    )
    return outcome
