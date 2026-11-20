"""Workflow C, step 1: validate a customer's email domain once.

The SWS API has no domain-only validation call, so the domain is validated on
the order for the customer's first employee (a real order; nothing is issued in
this step):

    1. Order for the first employee, carrying their first device's CSR plus
       locality and state_or_province.
           POST /certificates
    2. Read the DNS record SSL.com expects.
           GET /certificate/{ref}/validations/methods
    3. The customer's DNS admin publishes the CNAME (a person; the demo only
       checks DNS).
    4. Ask SSL.com to check it.
           PUT /certificate/{ref}  {"domains": {D: {"dcv": "cname_csr_hash"}}}
    5. Poll until the domain is "satisfied".
           GET /certificate/{ref}/validations/status

The account keeps the validation: later orders for any mailbox on the domain
issue without a confirmation, and the DNS record is no longer needed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from smime_demo.client import SwsClient
from smime_demo.dns_check import CnameLookup, cname_matches, lookup_cname
from smime_demo.models import DCV_SATISFIED, CnameRecord
from smime_demo.roster import Employee
from smime_demo.store import Store, now_iso
from smime_demo.workflows.issuance import (
    DOMAIN,
    Polling,
    device_csr,
    employee_dir,
    ensure_order,
)

WAITING_FOR_DNS = "waiting_for_dns"
WAITING_FOR_SSLCOM = "waiting_for_sslcom"


class DomainValidationError(Exception):
    pass


@dataclass
class DomainValidation:
    customer_id: str
    domain: str
    status: str  # waiting_for_dns, waiting_for_sslcom, or satisfied
    ref: str | None = None
    record: CnameRecord | None = None
    validated_at: str | None = None
    already_validated: bool = False


def validate_domain(
    client: SwsClient,
    store: Store,
    customer_id: str,
    first_employee: Employee,
    *,
    domain: str,
    locality: str,
    state_or_province: str,
    out_dir: Path,
    polling: Polling | None = None,
    dns_lookup: CnameLookup = lookup_cname,
    on_record: Callable[[CnameRecord], None] | None = None,
    on_dns_wait: Callable[[], None] | None = None,
) -> DomainValidation:
    polling = polling or Polling()
    domain = domain.lower().rstrip(".")
    if first_employee.domain != domain:
        raise DomainValidationError(f"{first_employee.email} is not on {domain}")

    customer = store.customer(customer_id, create=True)
    previous = customer.get("domain_validation") or {}
    if previous.get("domain") == domain and previous.get("status") == DCV_SATISFIED:
        return DomainValidation(
            customer_id,
            domain,
            DCV_SATISFIED,
            previous.get("ref"),
            validated_at=previous.get("validated_at"),
            already_validated=True,
        )
    customer.update(domain=domain, locality=locality, state_or_province=state_or_province)
    store.save()

    # 1. The first employee's order carries the domain validation.
    folder = employee_dir(out_dir, customer_id, first_employee.employee_id)
    folder.mkdir(parents=True, exist_ok=True)
    first_csr = device_csr(first_employee.devices[0], first_employee.email, folder)
    order = ensure_order(
        client,
        store,
        customer_id,
        first_employee,
        path=DOMAIN,
        first_csr=first_csr,
        locality=locality,
        state_or_province=state_or_province,
    )

    # 2. The record SSL.com expects (derived from that order's CSR).
    record = CnameRecord.from_methods(client.get_validation_methods(order.ref), domain)
    if record is None:
        raise DomainValidationError(f"SSL.com offered no cname_csr_hash record for {domain}")
    customer["domain_validation"] = {
        "domain": domain,
        "employee_id": first_employee.employee_id,
        "ref": order.ref,
        "record": {"name": record.name, "value": record.value},
        "status": WAITING_FOR_DNS,
        "validated_at": None,
    }
    store.save()
    result = DomainValidation(customer_id, domain, WAITING_FOR_DNS, order.ref, record)
    if on_record:
        on_record(record)

    # 3. Wait for the customer's DNS admin to publish it.
    if not _wait(
        lambda: cname_matches(dns_lookup, record.name, record.value), polling, on_dns_wait
    ):
        return result  # re-run the command once the record is published

    # 4-5. Ask SSL.com to check, then poll until it is satisfied.
    client.set_domain_validation(order.ref, domain)
    result.status = WAITING_FOR_SSLCOM
    customer["domain_validation"]["status"] = WAITING_FOR_SSLCOM
    store.save()

    def satisfied() -> bool:
        entry = client.get_validation_status(order.ref).get(domain) or {}
        if entry.get("status") == DCV_SATISFIED:
            result.validated_at = entry.get("validated_at") or now_iso()
            return True
        return False

    if _wait(satisfied, polling):
        result.status = DCV_SATISFIED
        customer["domain_validation"].update(status=DCV_SATISFIED, validated_at=result.validated_at)
        store.save()
    return result


def _wait(
    check: Callable[[], bool], polling: Polling, on_tick: Callable[[], None] | None = None
) -> bool:
    deadline = polling.clock() + polling.timeout
    interval = polling.interval
    while True:
        if check():
            return True
        if polling.clock() >= deadline:
            return False
        if on_tick:
            on_tick()
        polling.sleep(interval)
        interval = min(interval * 1.5, polling.max_interval)
