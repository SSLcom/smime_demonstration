#!/usr/bin/env python3
"""Probe: can an organization validate its email domain once and then have
certificates issued for any mailbox on that domain without per-mailbox clicks?

Step-by-step and attended. Each subcommand makes one or two SWS calls,
records them (redacted) under tests/fixtures/sandbox/domain-<run_id>/, and
prints what it found. State (refs, keys) lives in out/probe/domain-<run_id>/.

    python scripts/probe_domain_validation.py order EMAIL           # new order (+ CSR, recipient)
    python scripts/probe_domain_validation.py methods KEY           # DCV methods for the order
    python scripts/probe_domain_validation.py set-dcv KEY DOMAIN METHOD
    python scripts/probe_domain_validation.py status KEY            # order + DCV status
    python scripts/probe_domain_validation.py generate KEY          # POST /generate_certificate
    python scripts/probe_domain_validation.py revoke KEY

KEY is the short name the `order` command prints (e.g. employee1). Pass
--run RUN_ID to continue a run; without it the latest run is used.

Sandbox only. Never retries an order: `order` refuses if KEY already exists.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dotenv import load_dotenv  # noqa: E402
from probe_contract import FIXTURE_ROOT, OUT_ROOT, REPO, Redactor, Sws, make_csr, ok  # noqa: E402


def load_state(run_id: str | None) -> tuple[str, Path, dict]:
    runs = sorted(OUT_ROOT.glob("domain-*")) if OUT_ROOT.exists() else []
    if run_id:
        out = OUT_ROOT / f"domain-{run_id}"
    elif runs:
        out = runs[-1]
    else:
        out = OUT_ROOT / (
            "domain-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
        )
    out.mkdir(parents=True, exist_ok=True)
    state_path = out / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"orders": {}}
    return out.name, out, state


def show(data) -> None:
    print(json.dumps(data, indent=2)[:3000])


def main() -> int:
    load_dotenv(REPO / ".env")
    if (os.environ.get("SSLCOM_ENV") or "sandbox").strip().lower() != "sandbox":
        print("Sandbox only.")
        return 2
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--run")
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("order")
    o.add_argument("email")
    o.add_argument("--key")
    o.add_argument("--no-recipient", action="store_true")
    o.add_argument("--no-csr", action="store_true", help="Do not send the CSR with the order")
    o.add_argument("--locality", help="Registrant city (API field: locality)")
    o.add_argument("--state", help="Registrant state (API field: state_or_province)")
    for name in ("methods", "status", "generate", "revoke"):
        sub.add_parser(name).add_argument("key")
    s = sub.add_parser("set-dcv")
    s.add_argument("key")
    s.add_argument("domain")
    s.add_argument("method")
    args = p.parse_args()

    name, out, state = load_state(args.run)
    test_email = os.environ.get("SSLCOM_TEST_EMAIL", "")
    sws = Sws(
        os.environ["SSLCOM_ACCOUNT_KEY"],
        os.environ["SSLCOM_SECRET_KEY"],
        FIXTURE_ROOT / name,
        Redactor([test_email]),
    )
    save = lambda: (out / "state.json").write_text(json.dumps(state, indent=2) + "\n")  # noqa: E731
    print(f"run {name}")

    if args.cmd == "order":
        key = args.key or args.email.split("@")[0]
        if key in state["orders"]:
            print(
                f"{key} already ordered ({state['orders'][key].get('ref')}); not creating another."
            )
            return 1
        csr = make_csr(args.email, "ecc", out / "keys", key)
        ext = f"probe-{name}-{key}"
        state["orders"][key] = {"email": args.email, "external_order_number": ext, "ref": None}
        save()
        body = {
            "product": 300,
            "period": 365,
            "email_address": args.email,
            "external_order_number": ext,
        }
        if not args.no_csr:
            body["csr"] = csr
        if args.locality:
            body["locality"] = args.locality
        if args.state:
            body["state_or_province"] = args.state
        if not args.no_recipient:
            body["recipient"] = {"email": args.email}
        status, data = sws.call(f"order_{key}", "POST", "/certificates", body=body)
        show(sws.redact(data))
        if ok(status, data) and isinstance(data, dict) and data.get("ref"):
            state["orders"][key]["ref"] = data["ref"]
            save()
            print(f"\n{key} -> {data['ref']}")
        return 0

    entry = state["orders"][args.key]
    ref = entry["ref"]
    if args.cmd == "methods":
        _, data = sws.call(f"methods_{args.key}", "GET", f"/certificate/{ref}/validations/methods")
        show(sws.redact(data))
    elif args.cmd == "set-dcv":
        _, data = sws.call(
            f"set_dcv_{args.key}",
            "PUT",
            f"/certificate/{ref}",
            body={"domains": {args.domain: {"dcv": args.method}}},
        )
        show(sws.redact(data))
    elif args.cmd == "status":
        _, data = sws.call(f"status_{args.key}", "GET", f"/certificate/{ref}")
        keep = (
            "order_status",
            "validations",
            "domains",
            "recipient_notice",
            "end_entity_certificates",
        )
        show(sws.redact({k: data.get(k) for k in keep} if isinstance(data, dict) else data))
        _, data = sws.call(
            f"dcv_status_{args.key}", "GET", f"/certificate/{ref}/validations/status"
        )
        show(sws.redact(data))
    elif args.cmd == "generate":
        csr = (out / "keys" / f"{args.key}.csr.pem").read_text()
        status, data = sws.call(
            f"generate_{args.key}", "POST", "/generate_certificate", body={"ref": ref, "csr": csr}
        )
        show(sws.redact(data))
        issued = ok(status, data) and isinstance(data, dict) and bool(data.get("cert_results"))
        print("issued" if issued else "NOT issued")
    elif args.cmd == "revoke":
        _, data = sws.call(
            f"revoke_{args.key}",
            "DELETE",
            f"/certificate/{ref}",
            params={"reason": "CESSATIONOFOPERATION"},
        )
        show(sws.redact(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
