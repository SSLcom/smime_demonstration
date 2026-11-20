"""Local state: a stand-in for the partner's own database.

The sandbox cannot look orders up by external_order_number, so the partner
must remember which order it created for which employee. This module keeps
that record as one JSON file:

    customers/<customer_id>
        domain, locality, state_or_province
        domain_validation: ref, employee_id, record {name, value}, status, validated_at
        employees/<employee_id>
            email
            order: external_order_number, ref, attempted_at, path ("domain" | "mailbox")
            devices/<name>: kind, serial, status, not_after, files, verify_failures

An order is marked as attempted BEFORE the create call and gets its ref after
it. If a create call fails in a way that leaves no ref (a timeout, say), the
order is left "attempted" and is never created again automatically: in
production a second POST /certificates would be charged again.

Writes go to a temporary file that replaces the real one, so a crash never
leaves half-written state.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_PATH = Path("out") / "state.json"
_SAFE = re.compile(r"[^A-Za-z0-9-]+")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def external_order_number(customer_id: str, employee_id: str) -> str:
    """The partner's ID for an employee's order: letters, digits and hyphens."""
    return "-".join(_SAFE.sub("-", part).strip("-") for part in (customer_id, employee_id))


class Store:
    def __init__(self, path: str | Path = DEFAULT_PATH) -> None:
        self.path = Path(path)
        self.data: dict[str, Any] = {"version": 1, "customers": {}}
        if self.path.exists():
            self.data = json.loads(self.path.read_text())

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.path)

    # -- customers -------------------------------------------------------------

    def customer_ids(self) -> list[str]:
        return sorted(self.data["customers"])

    def customer(self, customer_id: str, *, create: bool = False) -> dict[str, Any]:
        customers = self.data["customers"]
        if customer_id not in customers:
            if not create:
                raise KeyError(f"unknown customer {customer_id!r}")
            customers[customer_id] = {"employees": {}, "domain_validation": None}
        return customers[customer_id]

    # -- employees ---------------------------------------------------------------

    def employee(
        self, customer_id: str, employee_id: str, email: str | None = None
    ) -> dict[str, Any]:
        """The employee's record, created on first use (needs `email` then)."""
        employees = self.customer(customer_id, create=email is not None)["employees"]
        if employee_id not in employees:
            if email is None:
                raise KeyError(f"unknown employee {employee_id!r} at {customer_id!r}")
            employees[employee_id] = {"email": email.lower(), "order": None, "devices": {}}
        record = employees[employee_id]
        if email is not None and record["email"] != email.lower():
            raise ValueError(
                f"employee {employee_id!r} is recorded with {record['email']}, not {email}"
            )
        return record

    def mark_order_attempted(self, customer_id: str, employee_id: str, path: str) -> str:
        record = self.employee(customer_id, employee_id)
        ext = external_order_number(customer_id, employee_id)
        record["order"] = {
            "external_order_number": ext,
            "ref": None,
            "attempted_at": now_iso(),
            "path": path,
        }
        self.save()
        return ext

    def set_order_ref(self, customer_id: str, employee_id: str, ref: str) -> None:
        self.employee(customer_id, employee_id)["order"]["ref"] = ref
        self.save()

    def device(self, customer_id: str, employee_id: str, name: str) -> dict[str, Any]:
        devices = self.employee(customer_id, employee_id)["devices"]
        return devices.setdefault(name, {"serial": None, "status": None})

    def find_serial(self, customer_id: str, serial: str) -> tuple[str, str] | None:
        """(employee_id, device name) that holds `serial`, if the partner requested it."""
        wanted = serial.replace(":", "").lower().lstrip("0")
        for employee_id, emp in self.customer(customer_id)["employees"].items():
            for name, dev in emp["devices"].items():
                if (dev.get("serial") or "").lstrip("0") == wanted:
                    return employee_id, name
        return None
