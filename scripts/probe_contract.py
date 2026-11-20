#!/usr/bin/env python3
"""Probe the SSL.com SWS sandbox to find out how mailbox-validated S/MIME orders
actually behave.

Attended: a person must click the validation link SSL.com emails to the test
mailbox. The probe never reads the mailbox or follows links itself; it waits
for the order status to change after you click.

Every request and response is saved, redacted, to tests/fixtures/sandbox/<run_id>/.
Keys, unredacted certificates, and run state go to out/probe/<run_id>/.

The probe is resumable. Steps whose results are already in the run's state
file are not repeated, so an order is never created twice for the same step:

    python scripts/probe_contract.py                  # start a new run
    python scripts/probe_contract.py --resume RUN_ID  # continue after a failure

Sandbox only. It refuses to run if SSLCOM_ENV is set to anything but 'sandbox'.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv

SANDBOX_URL = "https://sws-test.sslpki.com"
REPO = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = REPO / "tests" / "fixtures" / "sandbox"
OUT_ROOT = REPO / "out" / "probe"
USER_AGENT = "sslcom-smime-demo-probe/0.1.0"
TIMEOUT = 30
SECRET_FIELDS = {"account_key", "secret_key", "password"}
PLACEHOLDER_EMAIL = "mailbox@example.com"
URL_SECRET = re.compile(r"((?:account_key|secret_key|password|token)=)[^&\s\"']+", re.IGNORECASE)

# Candidate calls for submitting a CSR to an existing order. Only the PUT is
# in the public Swagger spec; the others have been described elsewhere and
# are tried to find out whether they exist.
CSR_SUBMIT_METHODS = [
    ("POST /generate_certificate", "POST", "/generate_certificate", True),
    ("PUT /certificate/{ref}/replace", "PUT", "/certificate/{ref}/replace", False),
    ("PUT /certificate/{ref}", "PUT", "/certificate/{ref}", False),
]


# --------------------------------------------------------------------------
# Keys and CSRs (simplified; the demo's keys.py will replace this)
# --------------------------------------------------------------------------


def make_csr(email: str, kind: str, key_dir: Path, name: str) -> str:
    if kind == "ecc":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, email)]))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / f"{name}.key.pem"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    (key_dir / f"{name}.csr.pem").write_text(pem)
    return pem


# --------------------------------------------------------------------------
# Certificates in responses
# --------------------------------------------------------------------------

PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s\\n]+?-----END CERTIFICATE-----")
B64_BLOB = re.compile(r"^[A-Za-z0-9+/=\s]{400,}$")


def _load_cert(text: str) -> x509.Certificate | None:
    try:
        if "BEGIN CERTIFICATE" in text:
            return x509.load_pem_x509_certificate(text.replace("\\n", "\n").encode())
        return x509.load_der_x509_certificate(base64.b64decode(re.sub(r"\s", "", text)))
    except Exception:  # noqa: BLE001 - anything unparseable is simply not a certificate
        return None


def find_certificates(obj: Any) -> list[x509.Certificate]:
    """Every certificate anywhere in a JSON response, as PEM or bare base64 DER."""
    found: list[x509.Certificate] = []
    if isinstance(obj, dict):
        for v in obj.values():
            found += find_certificates(v)
    elif isinstance(obj, list):
        for v in obj:
            found += find_certificates(v)
    elif isinstance(obj, str):
        blocks = PEM_CERT.findall(obj) or ([obj] if B64_BLOB.match(obj) else [])
        for block in blocks:
            cert = _load_cert(block)
            if cert is not None:
                found.append(cert)
    return found


def serial_hex(cert: x509.Certificate) -> str:
    h = f"{cert.serial_number:x}"
    h = h if len(h) % 2 == 0 else "0" + h
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


def mentions(cert: x509.Certificate, email: str) -> bool:
    text = cert.subject.rfc4514_string().lower()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        text += " " + " ".join(n.lower() for n in san.get_values_for_type(x509.RFC822Name))
    except x509.ExtensionNotFound:
        pass
    return email.lower() in text


def describe(cert: x509.Certificate) -> dict[str, Any]:
    try:
        eku = [
            o.dotted_string
            for o in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ]
    except x509.ExtensionNotFound:
        eku = []
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": serial_hex(cert),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "eku": eku,
        "key": type(cert.public_key()).__name__,
    }


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


class Redactor:
    def __init__(self, emails: list[str]) -> None:
        self.emails = [e for e in emails if e]

    def text(self, s: str) -> str:
        s = URL_SECRET.sub(r"\1REDACTED", s)
        if "BEGIN CERTIFICATE REQUEST" in s:
            return "<CSR redacted>"
        for block in PEM_CERT.findall(s):
            cert = _load_cert(block)
            if cert is not None and any(mentions(cert, e) for e in self.emails):
                s = s.replace(
                    block, f"<end-entity certificate redacted, serial {serial_hex(cert)}>"
                )
        if B64_BLOB.match(s):
            cert = _load_cert(s)
            if cert is not None and any(mentions(cert, e) for e in self.emails):
                return f"<end-entity certificate redacted, serial {serial_hex(cert)}>"
        for e in self.emails:
            s = re.sub(re.escape(e), PLACEHOLDER_EMAIL, s, flags=re.IGNORECASE)
        # Portal URLs in responses carry the account's team identifier.
        s = re.sub(r"/team/[A-Za-z0-9-]+/", "/team/TEAM/", s)
        # The API also lists the mailbox's domain on its own (in "domains" and
        # "validations"), so redact that too.
        for e in self.emails:
            domain = e.rsplit("@", 1)[-1]
            s = re.sub(
                rf"(?<![\w.-]){re.escape(domain)}(?![\w-])", "example.com", s, flags=re.IGNORECASE
            )
        return s

    def __call__(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            # Keys too: the API uses the mailbox as a key under "validations".
            return {
                self.text(k): ("REDACTED" if k in SECRET_FIELDS else self(v))
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [self(v) for v in obj]
        if isinstance(obj, str):
            return self.text(obj)
        return obj


# --------------------------------------------------------------------------
# HTTP with recording
# --------------------------------------------------------------------------


class Sws:
    def __init__(self, account_key: str, secret_key: str, fixtures: Path, redact: Redactor):
        self.creds = {"account_key": account_key, "secret_key": secret_key}
        self.fixtures = fixtures
        self.redact = redact
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.seq = len(list(fixtures.glob("*.json"))) if fixtures.exists() else 0

    def call(
        self,
        step: str,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        auth: str = "query",
        record: bool = True,
    ) -> tuple[int, Any]:
        """auth: 'query' (credentials as query parameters), 'body' (in the
        JSON body), or 'none'. Never retried."""
        params = dict(params or {})
        if auth == "query":
            params.update(self.creds)
        if auth == "body":
            body = {**(body or {}), **self.creds}
        started = time.monotonic()
        try:
            resp = self.session.request(
                method,
                SANDBOX_URL + path,
                params=params or None,
                json=body,
                timeout=TIMEOUT,
            )
        except requests.RequestException as exc:
            print(f"  {method} {path} -> network error: {self.redact.text(str(exc))}")
            return 0, None
        elapsed = time.monotonic() - started
        try:
            data: Any = resp.json()
        except ValueError:
            data = resp.text[:4000]
        print(f"  {method} {path} -> HTTP {resp.status_code} ({elapsed:.1f}s)")
        if record:
            self.seq += 1
            self.fixtures.mkdir(parents=True, exist_ok=True)
            safe_step = re.sub(r"[^a-z0-9_]+", "_", step.lower()).strip("_")
            fixture = {
                "step": step,
                "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "request": {
                    "method": method,
                    "path": path,
                    "auth_placement": auth,
                    "query": self.redact(params),
                    "json": self.redact(body),
                },
                "response": {
                    "status": resp.status_code,
                    "content_type": resp.headers.get("Content-Type"),
                    "body": self.redact(data),
                },
            }
            path_out = self.fixtures / f"{self.seq:02d}_{safe_step}.json"
            path_out.write_text(json.dumps(fixture, indent=2) + "\n")
        return resp.status_code, data


def ok(status: int, data: Any = None) -> bool:
    """Success means a 2xx status AND no error body. The sandbox returns
    HTTP 200 with {"errors": ...} for some failures (for example bad
    credentials on GET), so the status alone is not enough."""
    if not 200 <= status < 300:
        return False
    # Error bodies seen: {"errors": ...} (often with HTTP 200), {"error": "..."},
    # {"response_type": "ERROR", ...}, and /generate_certificate's 200 with a
    # non-empty "error_message".
    is_error_body = isinstance(data, dict) and bool(
        data.get("errors")
        or data.get("error")
        or data.get("error_message")
        or data.get("response_type") == "ERROR"
    )
    return not is_error_body


def short(data: Any, redact: Redactor, limit: int = 600) -> str:
    text = json.dumps(redact(data)) if not isinstance(data, str) else redact.text(data)
    return text if len(text) <= limit else text[:limit] + " …"


# --------------------------------------------------------------------------
# The probe
# --------------------------------------------------------------------------


class Probe:
    def __init__(self, args: argparse.Namespace, account_key: str, secret_key: str):
        self.args = args
        self.run_id = args.resume or (
            datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
        )
        self.out = OUT_ROOT / self.run_id
        self.out.mkdir(parents=True, exist_ok=True)
        self.state_path = self.out / "state.json"
        self.state: dict[str, Any] = (
            json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        )
        self.state.setdefault("run_id", self.run_id)
        self.state.setdefault("email_a", args.email)
        self.state.setdefault("email_b", args.email_b or args.email)
        self.state.setdefault("findings", {})
        self.redact = Redactor([self.state["email_a"], self.state["email_b"]])
        self.sws = Sws(account_key, secret_key, FIXTURE_ROOT / self.run_id, self.redact)
        self.state.setdefault("write_auth", args.write_auth)
        self.write_auth = self.state["write_auth"]

    # -- state helpers -----------------------------------------------------

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state, indent=2) + "\n")

    def note(self, key: str, value: Any) -> None:
        self.state["findings"][key] = value
        self.save()
        print(f"  => {key}: {json.dumps(self.redact(value))[:300]}")

    def heading(self, text: str) -> None:
        print(f"\n=== {text}")

    # -- polling -------------------------------------------------------------

    def get_order(self, ref: str, step: str, record: bool = True) -> tuple[int, Any]:
        return self.sws.call(
            step,
            "GET",
            f"/certificate/{ref}",
            params={"response_type": "individually", "response_encoding": "base64"},
            record=record,
        )

    def snapshot(self, data: Any) -> str:
        if not isinstance(data, dict):
            return json.dumps(data)
        keys = ("order_status", "validations", "certificates", "certificate_status")
        return json.dumps({k: data.get(k) for k in keys}, sort_keys=True, default=str)

    def wait_for_change(self, ref: str, label: str, minutes: float) -> Any:
        """Poll the order until its status, validations, or certificates change."""
        skip = self.out / "skip"
        skip.unlink(missing_ok=True)
        _, first = self.get_order(ref, f"{label}_before")
        baseline = self.snapshot(first)
        deadline = time.monotonic() + minutes * 60
        print(f"  Waiting up to {minutes:g} min for order {ref} to change.")
        print(f"  To stop waiting early: touch {skip}")
        while time.monotonic() < deadline:
            time.sleep(self.args.poll_seconds)
            if skip.exists():
                print("  Skip requested.")
                break
            status, data = self.get_order(ref, f"{label}_poll", record=False)
            current = data.get("order_status") if isinstance(data, dict) else None
            print(f"  {datetime.now():%H:%M:%S} HTTP {status} order_status={current!r}")
            if ok(status, data) and self.snapshot(data) != baseline:
                print("  Order changed.")
                self.get_order(ref, f"{label}_after")
                return data
        else:
            print("  Timed out without a change.")
        self.get_order(ref, f"{label}_after")
        return None

    def wait_for_certs(self, ref: str, label: str, at_least: int) -> list[x509.Certificate]:
        deadline = time.monotonic() + self.args.issue_minutes * 60
        certs: list[x509.Certificate] = []
        print(f"  Waiting up to {self.args.issue_minutes:g} min for {at_least} certificate(s).")
        while True:
            status, data = self.get_order(ref, f"{label}_poll", record=False)
            certs = [c for c in find_certificates(data) if self.is_leaf(c)]
            current = data.get("order_status") if isinstance(data, dict) else None
            print(
                f"  {datetime.now():%H:%M:%S} HTTP {status} order_status={current!r} "
                f"end-entity certificates={len(certs)}"
            )
            if len(certs) >= at_least or time.monotonic() > deadline:
                break
            time.sleep(self.args.poll_seconds)
        self.get_order(ref, f"{label}_result")
        return certs

    def is_leaf(self, cert: x509.Certificate) -> bool:
        return any(mentions(cert, e) for e in (self.state["email_a"], self.state["email_b"]))

    def save_certs(self, data: Any, name: str) -> list[dict[str, Any]]:
        certs = find_certificates(data)
        d = self.out / "certs"
        d.mkdir(exist_ok=True)
        described = []
        for i, cert in enumerate(certs):
            (d / f"{name}_{i}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            info = describe(cert)
            info["end_entity"] = self.is_leaf(cert)
            described.append(info)
        return described

    def ask_for_click(self, email: str, ref: str) -> None:
        print(
            f"\n  >>> ACTION: SSL.com should now email {email} about order {ref}.\n"
            "  >>> Open that email and click the validation link, and complete any page it opens.\n"
            "  >>> Note the sender, subject, and link host, and every other email you receive.\n"
        )

    # -- steps ---------------------------------------------------------------

    def step_credentials(self) -> bool:
        self.heading("1. Credentials (GET /certificates?per_page=1, credentials in query)")
        status, data = self.sws.call("credentials", "GET", "/certificates", params={"per_page": 1})
        self.note("credentials_ok", ok(status, data))
        if not ok(status, data):
            print("  " + short(data, self.redact))
        return ok(status, data)

    def step_auth_placement(self) -> None:
        if "auth_placement" in self.state["findings"]:
            return
        self.heading("2. Auth placement for POST (product 0 is invalid, so nothing is ordered)")
        results = {}
        for placement in ("none", "query", "body"):
            status, data = self.sws.call(
                f"auth_post_{placement}",
                "POST",
                "/certificates",
                body={"product": 0},
                auth=placement,
            )
            results[placement] = {"status": status, "body": self.redact(data)}
            print("    " + short(data, self.redact, 300))
        self.note("auth_placement", results)
        print("  Compare: 'none' should fail on credentials; an accepted placement should")
        print(f"  fail on the product instead. Using {self.write_auth!r} placement for POST/PUT.")

    def create_order(self, key: str, email: str, csr: str | None) -> str | None:
        """Create an order once. Its ref is stored, so a resumed run never re-creates it."""
        if self.state.get(f"{key}_ref"):
            print(f"  Order {key} already exists: {self.state[f'{key}_ref']} (not re-created)")
            return self.state[f"{key}_ref"]
        if self.state.get(f"{key}_attempted") and not self.args.retry_create:
            print(f"  A previous create for {key} failed. Re-run with --retry-create to try again.")
            return None
        external_id = f"probe-{self.run_id}-{key}"
        body: dict[str, Any] = {
            "product": self.args.product,
            "period": self.args.period,
            "external_order_number": external_id,
        }
        if self.args.email_field == "email_address":
            body["email_address"] = email
        elif self.args.email_field == "domains":
            body["domains"] = [email]
        if not self.args.no_recipient:
            # Without a recipient, S/MIME orders are created but no validation
            # email is sent, and the API cannot add a recipient later.
            body["recipient"] = {"email": email}
        if csr:
            body["csr"] = csr
        if self.args.contacts:
            body["contacts"] = {
                "all": {
                    "first_name": "Test",
                    "last_name": "Mailbox",
                    "email": email,
                    "phone": "+1-555-0100",
                    "country": "US",
                }
            }
        self.state[f"{key}_attempted"] = True
        self.state[f"{key}_external_id"] = external_id
        self.save()
        status, data = self.sws.call(
            f"create_{key}", "POST", "/certificates", body=body, auth=self.write_auth
        )
        print("    " + short(data, self.redact))
        ref = data.get("ref") if isinstance(data, dict) else None
        if ok(status, data) and ref:
            self.state[f"{key}_ref"] = ref
            self.save()
            self.note(f"create_{key}", {"status": status, "response": data})
            return ref
        self.note(
            f"create_{key}_failed",
            {
                "status": status,
                "response": data,
                "email_field": self.args.email_field,
                "with_csr": bool(csr),
                "contacts": self.args.contacts,
            },
        )
        return None

    def step_lookups(self, ref: str) -> None:
        if self.state["findings"].get("lookups_done"):
            return
        self.heading("Lookups: order details, search by external_order_number, api_parameters")
        self.get_order(ref, "order_a_initial")
        ext = self.state["order_a_external_id"]
        found = {}
        for search in (ext, f"external_order_number:{ext}"):
            status, data = self.sws.call(
                "search_external_id",
                "GET",
                "/certificates",
                params={"search": search, "per_page": 5},
            )
            found[search] = {"status": status, "contains_ref": ref in json.dumps(data)}
        self.note("search_by_external_order_number", found)
        for action in ("create", "create_w_csr", "update", "show"):
            self.sws.call(
                f"api_parameters_{action}", "GET", f"/certificate/{ref}/api_parameters/{action}"
            )
        self.state["findings"]["lookups_done"] = True
        self.save()

    def submit_csr(self, key: str, ref: str, csr: str, label: str) -> str | None:
        """Try each candidate CSR-submission call until one succeeds."""
        done = self.state.get(f"{label}_method")
        if done:
            print(f"  CSR for {label} already submitted with {done}")
            return done
        tried = {}
        for name, method, path, ref_in_body in CSR_SUBMIT_METHODS:
            body: dict[str, Any] = {"csr": csr}
            if ref_in_body:
                body["ref"] = ref
            status, data = self.sws.call(
                f"{label}_{name}", method, path.format(ref=ref), body=body, auth=self.write_auth
            )
            print("    " + short(data, self.redact, 400))
            tried[name] = {"status": status, "response": data}
            if ok(status, data):
                self.state[f"{label}_method"] = name
                self.note(f"{label}_submit", tried)
                return name
        self.note(f"{label}_submit_failed", tried)
        return None

    def run(self) -> int:
        a, b = self.state["email_a"], self.state["email_b"]
        print(f"Run {self.run_id}  (state: {self.state_path})")
        print(f"Fixtures: {self.sws.fixtures}")
        print(
            "\nThis probe creates up to 2 S/MIME orders in the sandbox:\n"
            f"  order A for {a}, with a CSR sent in the order\n"
            f"  order B for {b}, without a CSR (CSR submitted after validation)\n"
            "Expect up to 2 validation emails; you will be asked to click each link."
        )
        if not self.step_credentials():
            return 1
        self.step_auth_placement()
        keys = self.out / "keys"

        # ---- Order A: CSR sent with the order --------------------------------
        self.heading("3. Order A: create with CSR")
        csr_a1 = (
            (keys / "a1_ecc.csr.pem").read_text()
            if (keys / "a1_ecc.csr.pem").exists()
            else make_csr(a, "ecc", keys, "a1_ecc")
        )
        ref_a = self.create_order("order_a", a, csr_a1)
        if not ref_a:
            print(
                "\nOrder A could not be created. See the response above; adjust "
                "--email-field/--contacts and re-run with --resume " + self.run_id
            )
            return 2
        self.step_lookups(ref_a)

        if not self.state.get("order_a_validated"):
            self.heading("4. Order A: mailbox validation")
            self.ask_for_click(a, ref_a)
            changed = self.wait_for_change(ref_a, "order_a_validation", self.args.wait_minutes)
            self.state["order_a_validated"] = True
            self.note("order_a_after_click", changed)

        self.heading("5. Order A: issuance of the CSR sent with the order")
        certs = self.wait_for_certs(ref_a, "order_a_issue", 1)
        if not certs:
            print("  Nothing issued from the CSR in the order; trying to submit it separately.")
            self.submit_csr("order_a", ref_a, csr_a1, "order_a_first_csr")
            certs = self.wait_for_certs(ref_a, "order_a_issue_after_submit", 1)
        _, data = self.get_order(ref_a, "order_a_download_individually")
        self.note("order_a_certificates", self.save_certs(data, "order_a_first"))
        self.sws.call(
            "order_a_download_pkcs7",
            "GET",
            f"/certificate/{ref_a}",
            params={"response_type": "pkcs7", "response_encoding": "base64"},
        )
        first_count = len(certs)

        # ---- Order A: second certificate on the same order -------------------
        if first_count:
            self.heading("6. Order A: second certificate (RSA) on the same order")
            csr_a2 = (
                (keys / "a2_rsa.csr.pem").read_text()
                if (keys / "a2_rsa.csr.pem").exists()
                else make_csr(a, "rsa", keys, "a2_rsa")
            )
            if self.submit_csr("order_a", ref_a, csr_a2, "order_a_second_cert"):
                certs = self.wait_for_certs(ref_a, "order_a_second_issue", first_count + 1)
                _, data = self.get_order(ref_a, "order_a_after_second")
                self.note(
                    "order_a_certificates_after_second", self.save_certs(data, "order_a_second")
                )
                print("  Check whether the first certificate is still listed and not revoked.")

        # ---- Order B: same address, no CSR -----------------------------------
        self.heading("7. Order B: same mailbox, no CSR (voucher)")
        ref_b = self.create_order("order_b", b, None)
        if ref_b:
            self.get_order(ref_b, "order_b_initial")
            if not self.state.get("order_b_validated"):
                self.ask_for_click(b, ref_b)
                print("  (No email for a voucher? Touch the skip file once the wait starts.)")
                changed = self.wait_for_change(ref_b, "order_b_validation", self.args.wait_minutes)
                self.state["order_b_validated"] = True
                self.note("order_b_after_click", changed)
            self.heading("8. Order B: submit CSR after validation")
            csr_b = (
                (keys / "b1_ecc.csr.pem").read_text()
                if (keys / "b1_ecc.csr.pem").exists()
                else make_csr(b, "ecc", keys, "b1_ecc")
            )
            if self.submit_csr("order_b", ref_b, csr_b, "order_b_csr"):
                self.wait_for_certs(ref_b, "order_b_issue", 1)
                _, data = self.get_order(ref_b, "order_b_download")
                self.note("order_b_certificates", self.save_certs(data, "order_b"))

        # ---- Revoke everything -----------------------------------------------
        if self.args.no_revoke:
            print("\nSkipping revocation (--no-revoke).")
        else:
            self.revoke_all([r for r in (ref_a, ref_b) if r])

        self.heading("Done")
        print(f"State and findings: {self.state_path}")
        print(f"Redacted fixtures:  {self.sws.fixtures}")
        print(
            "Now report the emails you received (sender, subject, link host, what the "
            "link did) so they can go into docs/API_GUIDE.md."
        )
        return 0

    def revoke_all(self, refs: list[str]) -> None:
        self.heading(f"9. Revoke (reason={self.args.revoke_reason!r})")
        for ref in refs:
            if self.state.get(f"revoked_{ref}"):
                continue
            _, data = self.get_order(ref, f"revoke_{ref}_before", record=False)
            serials = [serial_hex(c) for c in find_certificates(data) if self.is_leaf(c)]
            if len(serials) > 1:
                # One certificate by serial first, to see whether per-serial revocation works.
                status, resp = self.sws.call(
                    "revoke_one_serial",
                    "DELETE",
                    f"/certificate/{ref}",
                    params={"reason": self.args.revoke_reason, "serials": json.dumps(serials[:1])},
                )
                print("    " + short(resp, self.redact, 300))
                self.get_order(ref, "after_revoke_one_serial")
            status, resp = self.sws.call(
                "revoke_all",
                "DELETE",
                f"/certificate/{ref}",
                params={"reason": self.args.revoke_reason},
            )
            print("    " + short(resp, self.redact, 300))
            self.get_order(ref, "after_revoke_all")
            self.state[f"revoked_{ref}"] = ok(status, resp)
            self.note(f"revoke_{ref}", {"status": status, "response": resp})


def main() -> int:
    load_dotenv(REPO / ".env")
    env = os.environ.get("SSLCOM_ENV", "sandbox").strip() or "sandbox"
    if env != "sandbox":
        print(f"Refusing to run: SSLCOM_ENV={env!r}. The probe only runs against the sandbox.")
        return 2
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--email",
        default=os.environ.get("SSLCOM_TEST_EMAIL", ""),
        help="Mailbox for order A (default: SSLCOM_TEST_EMAIL)",
    )
    p.add_argument("--email-b", default="", help="Mailbox for order B (default: same as --email)")
    p.add_argument("--resume", metavar="RUN_ID", help="Continue an earlier run")
    p.add_argument("--product", type=int, default=300)
    p.add_argument("--period", type=int, default=365)
    p.add_argument(
        "--email-field",
        choices=["email_address", "domains", "none"],
        default="email_address",
        help="How to send the mailbox in POST /certificates (default: email_address)",
    )
    p.add_argument("--contacts", action="store_true", help="Send contacts.all with the order")
    p.add_argument(
        "--no-recipient",
        action="store_true",
        help="Do not send recipient.email with the order (shows the stranded-order case)",
    )
    p.add_argument(
        "--write-auth",
        choices=["query", "body"],
        default="query",
        help="Where to put credentials for POST/PUT (default: query, as in the spec)",
    )
    p.add_argument(
        "--retry-create",
        action="store_true",
        help="Try again to create an order whose previous create failed",
    )
    p.add_argument("--wait-minutes", type=float, default=20, help="Wait for each validation click")
    p.add_argument("--issue-minutes", type=float, default=10, help="Wait for each issuance")
    p.add_argument("--poll-seconds", type=float, default=15)
    p.add_argument("--revoke-reason", default="mistake")
    p.add_argument("--no-revoke", action="store_true")
    args = p.parse_args()

    account_key = os.environ.get("SSLCOM_ACCOUNT_KEY", "").strip()
    secret_key = os.environ.get("SSLCOM_SECRET_KEY", "").strip()
    missing = [
        n
        for n, v in (
            ("SSLCOM_ACCOUNT_KEY", account_key),
            ("SSLCOM_SECRET_KEY", secret_key),
            ("SSLCOM_TEST_EMAIL or --email", args.email),
        )
        if not v
    ]
    if args.resume and not args.email:
        args.email = "resumed"  # replaced by the address stored in the run's state
        missing = [m for m in missing if not m.startswith("SSLCOM_TEST_EMAIL")]
    if missing:
        print("Missing: " + ", ".join(missing) + ". Fill in .env (see .env.example).")
        return 2
    return Probe(args, account_key, secret_key).run()


if __name__ == "__main__":
    sys.exit(main())
