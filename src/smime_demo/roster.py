"""Employees and their devices, as the partner would supply them.

CSV columns: employee_id, email, devices. `devices` is a semicolon-separated
list of name:source pairs, where source is

    ecc         generate an ECC P-256 key here (signing only)
    rsa         generate an RSA key here (signing and encryption)
    csr=<path>  use a CSR made on the device or token; the key never leaves it

Example row:  alice,alice@example.com,phone:ecc;laptop:ecc;shared:rsa
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

KINDS = ("ecc", "rsa")


@dataclass(frozen=True)
class Device:
    name: str
    kind: str  # "ecc", "rsa", or "csr"
    csr_path: Path | None = None


@dataclass(frozen=True)
class Employee:
    employee_id: str
    email: str
    devices: tuple[Device, ...]

    @property
    def domain(self) -> str:
        return self.email.rsplit("@", 1)[-1].lower()


def parse_devices(text: str, base: Path | None = None) -> tuple[Device, ...]:
    devices = []
    for item in filter(None, (part.strip() for part in text.split(";"))):
        name, _, source = item.partition(":")
        name, source = name.strip(), source.strip()
        if not name or not source:
            raise ValueError(f"device {item!r} must look like name:ecc, name:rsa or name:csr=path")
        if source in KINDS:
            devices.append(Device(name, source))
        elif source.startswith("csr="):
            path = Path(source[4:])
            devices.append(
                Device(name, "csr", path if path.is_absolute() or base is None else base / path)
            )
        else:
            raise ValueError(f"device {item!r}: source must be ecc, rsa or csr=<path>")
    if not devices:
        raise ValueError("each employee needs at least one device")
    names = [d.name for d in devices]
    if len(set(names)) != len(names):
        raise ValueError(f"duplicate device names in {text!r}")
    return tuple(devices)


def read_roster(path: str | Path) -> list[Employee]:
    path = Path(path)
    employees = []
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            employee_id = (row.get("employee_id") or "").strip()
            email = (row.get("email") or "").strip().lower()
            if not employee_id or "@" not in email:
                raise ValueError(f"row {row} needs employee_id and email")
            employees.append(
                Employee(employee_id, email, parse_devices(row.get("devices") or "", path.parent))
            )
    ids = [e.employee_id for e in employees]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate employee_id in roster")
    return employees
