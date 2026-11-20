"""The smime-demo command line.

Enterprise customer, domain validated once (no mailbox clicks):
    smime-demo domain validate   CUSTOMER --employees FILE [--domain D] --locality L --state S
    smime-demo customer onboard  CUSTOMER --employees FILE
    smime-demo customer offboard CUSTOMER [--employee E | --serial S] --reason R
    smime-demo customer status   CUSTOMER

Each employee confirms their own activation link instead:
    smime-demo customer onboard  CUSTOMER --employees FILE --mailbox-links

One person:
    smime-demo issue        --email E --external-id X (--generate ecc|rsa | --csr FILE)
    smime-demo multi-device --email E --external-id X

Single calls:
    smime-demo check | status REF | download REF | revoke REF --reason R [--serial S]
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

import typer

from smime_demo.client import SwsClient
from smime_demo.config import ConfigError, Settings, load_settings
from smime_demo.errors import SwsError
from smime_demo.models import REVOKE_REASONS, CnameRecord, Order
from smime_demo.recording import Recorder
from smime_demo.roster import Device, Employee, read_roster
from smime_demo.store import DEFAULT_PATH, Store
from smime_demo.workflows.domain import DomainValidationError, validate_domain
from smime_demo.workflows.enterprise import (
    DomainNotValidated,
    EmployeeOutcome,
    InventoryRow,
    inventory,
    offboard,
    onboard_customer,
)
from smime_demo.workflows.issuance import (
    DOMAIN,
    MAILBOX,
    MissingRegistrantAddress,
    OrderNeedsReconciliation,
    Polling,
)
from smime_demo.workflows.multi_device import check_multi_device, issue_multi_device
from smime_demo.workflows.single import issue_mailbox_certificate

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Order and issue mailbox-validated S/MIME certificates through the SSL.com SWS API.",
)
domain_app = typer.Typer(no_args_is_help=True, help="Step 1: validate a customer's email domain.")
customer_app = typer.Typer(no_args_is_help=True, help="Steps 2-3: onboard, offboard, inventory.")
app.add_typer(domain_app, name="domain")
app.add_typer(customer_app, name="customer")

REASON_HELP = "One of " + ", ".join(REVOKE_REASONS)
LOCALITY_HELP = "Registrant city; a placeholder is fine (never put in the certificate)."
STATE_HELP = "Registrant state/province; a placeholder is fine (never put in the certificate)."


@dataclass
class Context:
    settings: Settings
    client: SwsClient
    store: Store
    out_dir: Path


def _ctx(ctx: typer.Context) -> Context:
    return ctx.obj


@app.callback()
def main(
    ctx: typer.Context,
    state_file: Path = typer.Option(
        DEFAULT_PATH, help="Local state (stand-in for the partner database)."
    ),
    out: Path = typer.Option(
        Path("out"), help="Where keys, certificates and PKCS#12 files are written."
    ),
    i_understand_this_spends_money: bool = typer.Option(
        False, "--i-understand-this-spends-money", help="Required with SSLCOM_ENV=production."
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose", help="Log every API call (credentials redacted)."
    ),
    record: Path = typer.Option(
        None, help="Save every request and response (credentials replaced) to this directory."
    ),
    record_replace: list[str] = typer.Option(
        [], help="With --record: OLD=NEW text to substitute, e.g. a personal test address."
    ),
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING, format="  %(message)s")
    if verbose:
        logging.getLogger("smime_demo.sws").setLevel(logging.INFO)
    try:
        settings = load_settings(allow_production=i_understand_this_spends_money)
    except ConfigError as exc:
        _fail(str(exc), code=2)
    if not settings.is_sandbox:
        typer.secho(
            "PRODUCTION: every new order is charged to the account.", fg=typer.colors.RED, err=True
        )
    recorder = None
    if record:
        replace = dict(item.split("=", 1) for item in record_replace if "=" in item)
        recorder = Recorder(record, replace)
    ctx.obj = Context(settings, SwsClient(settings, recorder=recorder), Store(state_file), out)


# -- single calls ------------------------------------------------------------------


@app.command()
def check(ctx: typer.Context) -> None:
    """Check credentials and environment."""
    c = _ctx(ctx)
    _call(c.client.list_certificates, per_page=1)
    typer.echo(f"OK: credentials accepted by {c.settings.base_url} ({c.settings.environment})")


@app.command()
def status(ctx: typer.Context, ref: str) -> None:
    """Show an order's status and every certificate on it."""
    order = _call(_ctx(ctx).client.get_certificate, ref)
    _print_order(order)


@app.command()
def download(
    ctx: typer.Context, ref: str, out: Path = typer.Option(None, help="Directory")
) -> None:
    """Save the most recent certificate on an order, and its chain."""
    c = _ctx(ctx)
    order = _call(c.client.get_certificate, ref)
    if not order.latest_certificate:
        _fail(f"{ref}: no certificate yet (order_status: {order.order_status})")
    folder = out or c.out_dir / "downloads" / ref
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "certificate.pem").write_text(order.latest_certificate.leaf_pem)
    (folder / "chain.pem").write_text("".join(order.latest_certificate.chain_pems))
    _print_order(order)
    typer.echo(f"wrote {folder / 'certificate.pem'} and {folder / 'chain.pem'}")


@app.command()
def revoke(
    ctx: typer.Context,
    ref: str,
    reason: str = typer.Option(..., help=REASON_HELP),
    serial: str = typer.Option(None, help="Revoke only this certificate (hex serial)."),
) -> None:
    """Revoke every certificate on an order, or one by serial."""
    c = _ctx(ctx)
    _call(c.client.revoke, ref, reason, serial=serial)
    _print_order(_call(c.client.get_certificate, ref))


# -- one person ------------------------------------------------------------------------


@app.command()
def issue(
    ctx: typer.Context,
    email: str = typer.Option(None, help="Mailbox (default: SSLCOM_TEST_EMAIL)."),
    external_id: str = typer.Option(..., help="Your own ID for this order."),
    generate: str = typer.Option(None, help="Generate a key here: ecc or rsa."),
    csr: Path = typer.Option(None, exists=True, help="Use a CSR made on the device instead."),
    timeout_minutes: float = typer.Option(30, help="How long to wait for the mailbox owner."),
) -> None:
    """Workflow A: one certificate, confirmed through the activation link."""
    c = _ctx(ctx)
    if bool(generate) == bool(csr):
        _fail("give exactly one of --generate ecc|rsa or --csr FILE")
    device = Device("device", "csr", csr) if csr else Device("device", generate)
    outcome = _run(
        issue_mailbox_certificate,
        c.client,
        c.store,
        email=_email(c, email),
        external_id=external_id,
        device=device,
        out_dir=c.out_dir,
        polling=Polling(timeout=timeout_minutes * 60),
        on_awaiting_validation=_say_check_mailbox,
        on_tick=_tick,
    )
    _print_outcomes([outcome])


@app.command("multi-device")
def multi_device(
    ctx: typer.Context,
    email: str = typer.Option(None, help="Mailbox (default: SSLCOM_TEST_EMAIL)."),
    external_id: str = typer.Option(..., help="Your own ID for this order."),
    p12_password: str = typer.Option(
        None,
        envvar="SSLCOM_P12_PASSWORD",
        help="PKCS#12 password (default: generated, saved 0600).",
    ),
    timeout_minutes: float = typer.Option(30),
    locality: str = typer.Option(..., envvar="SSLCOM_REGISTRANT_LOCALITY", help=LOCALITY_HELP),
    state: str = typer.Option(..., envvar="SSLCOM_REGISTRANT_STATE", help=STATE_HELP),
) -> None:
    """Workflow B: phone + laptop (ECC, signing) and a shared RSA certificate, one order."""
    c = _ctx(ctx)
    outcome = _run(
        issue_multi_device,
        c.client,
        c.store,
        email=_email(c, email),
        external_id=external_id,
        out_dir=c.out_dir,
        p12_password=p12_password,
        polling=Polling(timeout=timeout_minutes * 60),
        on_awaiting_validation=_say_check_mailbox,
        on_tick=_tick,
        locality=locality,
        state_or_province=state,
    )
    _print_outcomes([outcome])
    for problem in check_multi_device(c.client, outcome):
        typer.secho(f"  CHECK FAILED: {problem}", fg=typer.colors.RED)


# -- enterprise customer -----------------------------------------------------------------


@domain_app.command("validate")
def domain_validate(
    ctx: typer.Context,
    customer: str,
    employees: Path = typer.Option(
        ..., exists=True, help="Roster CSV; its first employee carries the validation."
    ),
    domain: str = typer.Option(None, help="Email domain (default: SSLCOM_TEST_DOMAIN)."),
    locality: str = typer.Option(
        ..., envvar="SSLCOM_REGISTRANT_LOCALITY", help="City; required, not in the certificate."
    ),
    state: str = typer.Option(
        ...,
        envvar="SSLCOM_REGISTRANT_STATE",
        help="State/province; required, not in the certificate.",
    ),
    timeout_minutes: float = typer.Option(30, help="How long to wait for DNS and for SSL.com."),
) -> None:
    """Step 1: validate the customer's domain once, on the first employee's order."""
    c = _ctx(ctx)
    domain = (domain or c.settings.test_domain or "").lower()
    if not domain:
        _fail("give --domain or set SSLCOM_TEST_DOMAIN")
    roster = _roster(employees)
    first = next((e for e in roster if e.domain == domain), None)
    if first is None:
        _fail(f"no employee in {employees} has an address on {domain}")
    typer.echo(
        f"Validating {domain} for {customer} on the order for {first.email} "
        "(nothing is issued yet)."
    )
    result = _run(
        validate_domain,
        c.client,
        c.store,
        customer,
        first,
        domain=domain,
        locality=locality,
        state_or_province=state,
        out_dir=c.out_dir,
        polling=Polling(timeout=timeout_minutes * 60, interval=15),
        on_record=_say_publish_record,
        on_dns_wait=lambda: typer.echo("  waiting for DNS…"),
    )
    if result.already_validated:
        typer.echo(f"{domain} is already validated for {customer} ({result.validated_at}).")
    elif result.status == "satisfied":
        typer.secho(
            f"{domain} validated ({result.validated_at}) on order {result.ref}.",
            fg=typer.colors.GREEN,
        )
        typer.echo("The DNS record can now be removed. Next: smime-demo customer onboard")
    else:
        _fail(
            f"{domain}: still {result.status} on order {result.ref}. "
            "Re-run this command to continue.",
            code=3,
        )


@customer_app.command("onboard")
def customer_onboard(
    ctx: typer.Context,
    customer: str,
    employees: Path = typer.Option(..., exists=True, help="Roster CSV: employee_id,email,devices"),
    mailbox_links: bool = typer.Option(
        False, help="Each employee confirms an activation link instead."
    ),
    p12_password: str = typer.Option(None, envvar="SSLCOM_P12_PASSWORD"),
    timeout_minutes: float = typer.Option(
        30, help="Mailbox path: how long to wait for confirmations."
    ),
    locality: str = typer.Option(
        None, envvar="SSLCOM_REGISTRANT_LOCALITY", help="Mailbox path: " + LOCALITY_HELP
    ),
    state: str = typer.Option(
        None, envvar="SSLCOM_REGISTRANT_STATE", help="Mailbox path: " + STATE_HELP
    ),
) -> None:
    """Step 2: order and issue certificates for every employee and device."""
    c = _ctx(ctx)
    path = MAILBOX if mailbox_links else DOMAIN
    outcomes = _run(
        onboard_customer,
        c.client,
        c.store,
        customer,
        _roster(employees),
        path=path,
        out_dir=c.out_dir,
        polling=Polling(timeout=timeout_minutes * 60),
        p12_password=p12_password,
        on_awaiting_mailbox=_say_check_mailboxes,
        on_tick=_tick,
        locality=locality,
        state_or_province=state,
    )
    _print_outcomes(outcomes)
    if any(o.error for o in outcomes):
        raise typer.Exit(1)


@customer_app.command("offboard")
def customer_offboard(
    ctx: typer.Context,
    customer: str,
    reason: str = typer.Option(..., help=REASON_HELP),
    employee: str = typer.Option(None, help="Only this employee."),
    serial: str = typer.Option(None, help="Only this certificate."),
) -> None:
    """Step 3: revoke one certificate, one employee's, or the whole customer's."""
    c = _ctx(ctx)
    if employee and serial:
        _fail("give --employee or --serial, not both")
    for line in _run(
        offboard, c.client, c.store, customer, reason=reason, employee_id=employee, serial=serial
    ):
        typer.echo(line)
    _print_inventory(_run(inventory, c.client, c.store, customer))


@customer_app.command("status")
def customer_status(ctx: typer.Context, customer: str) -> None:
    """Every certificate on the customer's orders, including any not requested by you."""
    c = _ctx(ctx)
    dv = c.store.customer(customer).get("domain_validation") or {}
    if dv:
        typer.echo(f"domain {dv.get('domain')}: {dv.get('status')} (order {dv.get('ref')})")
    _print_inventory(_run(inventory, c.client, c.store, customer))


# -- output ----------------------------------------------------------------------------------


def _say_publish_record(record: CnameRecord) -> None:
    typer.echo(
        "\nAsk the customer's DNS admin to publish this record (it can be removed afterwards):\n"
    )
    typer.secho(f"  {record.name}.  CNAME  {record.value}.\n", bold=True)


def _say_check_mailbox(order: Order) -> None:
    _say_check_mailboxes([(None, order)])


def _say_check_mailboxes(pairs: list[tuple[Employee | None, Order]]) -> None:
    typer.echo("\nSSL.com has emailed an activation link to:")
    for emp, order in pairs:
        who = emp.email if emp else "the mailbox"
        typer.echo(f"  {who}  (order {order.ref})")
    typer.echo("Each person opens the link, presses Confirm, then closes the page.")
    typer.echo("They should NOT generate a certificate there. Waiting for confirmation…\n")


def _tick(latest: dict[str, Order]) -> None:
    waiting = [ref for ref, o in latest.items() if not o.can_issue]
    if waiting:
        typer.echo(
            f"  {len(latest) - len(waiting)}/{len(latest)} confirmed; "
            f"waiting on {', '.join(waiting)}"
        )


def _print_order(order: Order) -> None:
    typer.echo(f"{order.ref}: {order.order_status}")
    if order.recipient_notice:
        typer.secho(f"  {order.recipient_notice}", fg=typer.colors.YELLOW)
    for cert in order.end_entity_certificates:
        typer.echo(f"  {cert.serial}  {cert.status}")


def _print_outcomes(outcomes: list[EmployeeOutcome]) -> None:
    for o in outcomes:
        typer.echo(f"\n{o.employee_id} <{o.email}>  order {o.ref or '-'}  {o.order_status or ''}")
        if o.waiting_for_mailbox:
            typer.secho(
                "  still waiting for the mailbox owner to confirm; re-run later",
                fg=typer.colors.YELLOW,
            )
        if o.error:
            typer.secho(f"  ERROR: {o.error}", fg=typer.colors.RED)
        for d in o.devices:
            note = "already issued" if d.skipped else "issued"
            typer.echo(f"  {d.name:<8} {note:<15} serial {d.serial}  expires {d.not_after}")
            for path in d.files.values():
                typer.echo(f"           {path}")
            for failure in d.verify_failures:
                typer.secho(f"           VERIFY FAILED: {failure}", fg=typer.colors.RED)


def _print_inventory(rows: list[InventoryRow]) -> None:
    typer.echo(f"\n{'employee':<14}{'order':<17}{'device':<10}{'serial':<36}{'status':<9}expires")
    for r in rows:
        device = r.device or ("-" if not r.serial else "NOT REQUESTED")
        typer.echo(
            f"{r.employee_id:<14}{(r.ref or '-'):<17}{device:<10}{(r.serial or '-'):<36}"
            f"{(r.status or r.order_status or '-'):<9}{(r.not_after or '')[:10]}"
        )


# -- helpers ---------------------------------------------------------------------------------


def _email(c: Context, email: str | None) -> str:
    email = email or c.settings.test_email
    if not email:
        _fail("give --email or set SSLCOM_TEST_EMAIL")
    return email


def _roster(path: Path) -> list[Employee]:
    try:
        return read_roster(path)
    except (OSError, ValueError) as exc:
        _fail(f"{path}: {exc}", code=2)


def _call(fn, *args, **kwargs):
    return _run(fn, *args, **kwargs)


def _run(fn, *args, **kwargs):
    """Run a step and turn expected failures into a one-line message."""
    try:
        return fn(*args, **kwargs)
    except SwsError as exc:
        _fail(str(exc))
    except (
        DomainNotValidated,
        DomainValidationError,
        OrderNeedsReconciliation,
        MissingRegistrantAddress,
        KeyError,
        ValueError,
    ) as exc:
        _fail(str(exc).strip("'\""))


def _fail(message: str, code: int = 1):
    typer.secho(message, fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


if __name__ == "__main__":  # pragma: no cover
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    app()
