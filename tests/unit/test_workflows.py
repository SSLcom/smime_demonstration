"""The three-step enterprise flow, the mailbox path, and Workflows A/B, offline."""

import stat

import pytest

from smime_demo.roster import Device, Employee, parse_devices, read_roster
from smime_demo.store import Store, external_order_number
from smime_demo.workflows.domain import WAITING_FOR_DNS, validate_domain
from smime_demo.workflows.enterprise import (
    DomainNotValidated,
    inventory,
    offboard,
    onboard_customer,
)
from smime_demo.workflows.issuance import (
    DOMAIN,
    MAILBOX,
    OrderNeedsReconciliation,
    Polling,
    serial_hex,
)
from smime_demo.workflows.multi_device import check_multi_device, issue_multi_device
from tests.unit.fake_sws import FakeSws

DOMAIN_NAME = "globex.example"
ALICE = Employee("alice", f"alice@{DOMAIN_NAME}", parse_devices("phone:ecc;laptop:ecc;shared:rsa"))
BOB = Employee("bob", f"bob@{DOMAIN_NAME}", parse_devices("laptop:ecc"))


class Clock:
    """Fake time for polling loops."""

    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += s

    def __call__(self):
        return self.t


def polling(timeout=60):
    clock = Clock()
    return Polling(timeout=timeout, interval=10, sleep=clock.sleep, clock=clock)


@pytest.fixture
def sws(pki):
    return FakeSws(pki)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state.json")


def dns_from(sws):
    return lambda name: "def456.20261120.ssl.com" if name in sws.published else None


def validate(sws, store, tmp_path, **kw):
    return validate_domain(
        sws,
        store,
        "globex",
        ALICE,
        domain=DOMAIN_NAME,
        locality="Springfield",
        state_or_province="Oregon",
        out_dir=tmp_path,
        polling=polling(),
        dns_lookup=dns_from(sws),
        **kw,
    )


# -- step 1 ---------------------------------------------------------------------------------


def test_domain_validation_waits_for_dns_then_validates(sws, store, tmp_path):
    shown = []
    result = validate(sws, store, tmp_path, on_record=shown.append)
    assert result.status == WAITING_FOR_DNS  # nobody published the record yet
    assert shown[0].name == f"_abc123.{DOMAIN_NAME}"
    assert not any(c[0] == "generate_certificate" for c in sws.calls)  # nothing issued in step 1

    sws.published.add(f"_abc123.{DOMAIN_NAME}")  # the customer's DNS admin acts
    result = validate(sws, store, tmp_path)
    assert result.status == "satisfied"
    assert [c[0] for c in sws.calls].count("create_order") == 1  # the re-run reused the order
    order = sws.orders[result.ref]
    assert order["csr"] and order["locality"] == "Springfield" and order["state"] == "Oregon"

    again = validate(sws, store, tmp_path)
    assert again.already_validated


def test_domain_must_match_first_employee(sws, store, tmp_path):
    with pytest.raises(Exception, match="not on other.example"):
        validate_domain(
            sws,
            store,
            "globex",
            ALICE,
            domain="other.example",
            locality="x",
            state_or_province="y",
            out_dir=tmp_path,
            polling=polling(),
            dns_lookup=dns_from(sws),
        )


# -- step 2: domain path ------------------------------------------------------------------------


def test_onboarding_requires_a_validated_domain(sws, store, tmp_path):
    store.customer("globex", create=True)["domain"] = DOMAIN_NAME
    with pytest.raises(DomainNotValidated):
        onboard_customer(sws, store, "globex", [ALICE], path=DOMAIN, out_dir=tmp_path)


def test_domain_path_issues_every_device_without_clicks(sws, store, tmp_path):
    sws.published.add(f"_abc123.{DOMAIN_NAME}")
    validate(sws, store, tmp_path)

    outcomes = onboard_customer(
        sws, store, "globex", [ALICE, BOB], path=DOMAIN, out_dir=tmp_path, p12_password="pw"
    )
    assert [o.error for o in outcomes] == [None, None]
    assert [len(o.devices) for o in outcomes] == [3, 1]
    assert all(not d.verify_failures for o in outcomes for d in o.devices)
    # Alice's order is the one from step 1; Bob got a new one.
    assert [c[0] for c in sws.calls].count("create_order") == 2
    alice_dir = tmp_path / "customers" / "globex" / "alice"
    assert (alice_dir / "shared.p12").exists()
    assert stat.S_IMODE((alice_dir / "phone.key.pem").stat().st_mode) == 0o600

    # Re-running issues nothing new.
    again = onboard_customer(sws, store, "globex", [ALICE, BOB], path=DOMAIN, out_dir=tmp_path)
    assert all(d.skipped for o in again for d in o.devices)
    assert [c[0] for c in sws.calls].count("generate_certificate") == 4


def test_employee_off_the_domain_is_reported(sws, store, tmp_path):
    sws.published.add(f"_abc123.{DOMAIN_NAME}")
    validate(sws, store, tmp_path)
    stranger = Employee("eve", "eve@elsewhere.example", parse_devices("p:ecc"))
    (outcome,) = onboard_customer(sws, store, "globex", [stranger], path=DOMAIN, out_dir=tmp_path)
    assert "not on the validated domain" in outcome.error


# -- step 3 --------------------------------------------------------------------------------------


@pytest.fixture
def onboarded(sws, store, tmp_path):
    sws.published.add(f"_abc123.{DOMAIN_NAME}")
    validate(sws, store, tmp_path)
    onboard_customer(
        sws, store, "globex", [ALICE, BOB], path=DOMAIN, out_dir=tmp_path, p12_password="pw"
    )
    return sws, store


def test_offboard_one_device(onboarded):
    sws, store = onboarded
    laptop = store.employee("globex", "alice")["devices"]["laptop"]["serial"]
    offboard(sws, store, "globex", reason="SUPERSEDED", serial=laptop)
    rows = {(r.employee_id, r.device): r.status for r in inventory(sws, store, "globex")}
    assert rows[("alice", "laptop")] == "revoked"
    assert rows[("alice", "phone")] == "issued"
    assert rows[("bob", "laptop")] == "issued"


def test_offboard_one_employee_then_customer(onboarded):
    sws, store = onboarded
    offboard(sws, store, "globex", reason="CESSATIONOFOPERATION", employee_id="alice")
    statuses = {(r.employee_id, r.device): r.status for r in inventory(sws, store, "globex")}
    assert {v for k, v in statuses.items() if k[0] == "alice"} == {"revoked"}
    assert statuses[("bob", "laptop")] == "issued"
    lines = offboard(sws, store, "globex", reason="CESSATIONOFOPERATION")
    assert any("nothing left to revoke" in line or "revoked" in line for line in lines)
    assert {r.status for r in inventory(sws, store, "globex")} == {"revoked"}


def test_offboard_unknown_serial(onboarded):
    sws, store = onboarded
    with pytest.raises(KeyError, match="not a certificate this partner issued"):
        offboard(sws, store, "globex", reason="SUPERSEDED", serial="deadbeef")


def test_inventory_flags_certificates_the_partner_did_not_request(onboarded):
    sws, store = onboarded
    bob_ref = store.employee("globex", "bob")["order"]["ref"]
    extra = sws.generate_in_browser(bob_ref)
    rows = inventory(sws, store, "globex")
    unrequested = [r for r in rows if r.serial == extra]
    assert len(unrequested) == 1 and unrequested[0].device is None
    assert unrequested[0].not_after


# -- mailbox path --------------------------------------------------------------------------------


def test_mailbox_path_issues_as_people_confirm(sws, store, tmp_path):
    asked = []
    confirmed_after_first_poll = []

    def on_tick(latest):
        if not confirmed_after_first_poll:  # Alice confirms while we wait; Bob never does
            sws.confirm_mailbox(store.employee("globex", "alice")["order"]["ref"])
            confirmed_after_first_poll.append(True)

    outcomes = onboard_customer(
        sws,
        store,
        "globex",
        [ALICE, BOB],
        path=MAILBOX,
        out_dir=tmp_path,
        polling=polling(timeout=60),
        p12_password="pw",
        on_awaiting_mailbox=asked.append,
        on_tick=on_tick,
        locality="Placeholder City",
        state_or_province="Placeholder",
    )
    alice, bob = outcomes
    assert len(asked[0]) == 2
    assert len(alice.devices) == 3 and not alice.waiting_for_mailbox
    assert bob.waiting_for_mailbox and not bob.devices
    assert sws.orders[alice.ref]["csr"] is None  # mailbox path sends no CSR with the order


def test_order_is_never_created_twice(sws, store, tmp_path):
    store.employee("globex", "bob", BOB.email)
    store.mark_order_attempted("globex", "bob", MAILBOX)  # e.g. a timeout after the POST
    (outcome,) = onboard_customer(
        sws, store, "globex", [BOB], path=MAILBOX, out_dir=tmp_path, polling=polling()
    )
    assert "no ref was recorded" in outcome.error
    assert not any(c[0] == "create_order" for c in sws.calls)
    assert issubclass(OrderNeedsReconciliation, Exception)


def test_multi_device_checks(sws, store, tmp_path):
    def confirm(order):
        sws.confirm_mailbox(order.ref)

    outcome = issue_multi_device(
        sws,
        store,
        email="pat@example.com",
        external_id="pat-1",
        out_dir=tmp_path,
        polling=polling(),
        p12_password="pw",
        on_awaiting_validation=confirm,
        locality="Placeholder City",
        state_or_province="Placeholder",
    )
    assert [d.name for d in outcome.devices] == ["phone", "laptop", "shared"]
    assert check_multi_device(sws, outcome) == []


# -- small pieces ---------------------------------------------------------------------------------


def test_roster_parsing(tmp_path):
    (tmp_path / "dev.csr").write_text("x")
    path = tmp_path / "roster.csv"
    path.write_text(
        "employee_id,email,devices\nalice,Alice@Globex.example,phone:ecc;token:csr=dev.csr\n"
    )
    (emp,) = read_roster(path)
    assert emp.email == "alice@globex.example" and emp.domain == "globex.example"
    assert emp.devices[1] == Device("token", "csr", tmp_path / "dev.csr")
    for bad in ("", "phone", "phone:dsa", "a:ecc;a:rsa"):
        with pytest.raises(ValueError):
            parse_devices(bad)


def test_external_order_number_is_safe():
    assert external_order_number("Globex Corp", "alice@globex") == "Globex-Corp-alice-globex"


def test_serial_hex_pads_to_whole_bytes():
    assert serial_hex(0x8DF90516) == "8df90516"  # 8 digits: unchanged
    assert serial_hex(0x8DF9051) == "08df9051"  # 7 digits: leading zero, as the API shows


def test_second_certificate_needs_a_registrant_address(sws, store, tmp_path):
    def confirm(order):
        sws.confirm_mailbox(order.ref)

    # Without a city/state the order cannot take a second certificate: refuse up front.
    outcome = issue_multi_device(
        sws,
        store,
        email="pat@example.com",
        external_id="pat-2",
        out_dir=tmp_path,
        polling=polling(),
        on_awaiting_validation=confirm,
    )
    assert "needs a registrant city and state" in outcome.error
    assert not any(c[0] == "generate_certificate" for c in sws.calls)

    # With placeholders, the address is set once (PUT) and every device issues.
    outcome = issue_multi_device(
        sws,
        store,
        email="pat@example.com",
        external_id="pat-2",
        out_dir=tmp_path,
        polling=polling(),
        on_awaiting_validation=confirm,
        locality="Placeholder City",
        state_or_province="Placeholder",
    )
    assert outcome.error is None and len(outcome.devices) == 3
    assert [c[0] for c in sws.calls].count("set_registrant_address") == 1

    # A single-device order never needs it.
    from smime_demo.workflows.single import issue_mailbox_certificate

    single = issue_mailbox_certificate(
        sws,
        store,
        email="sam@example.com",
        external_id="sam-1",
        device=Device("phone", "ecc"),
        out_dir=tmp_path,
        polling=polling(),
        on_awaiting_validation=confirm,
    )
    assert single.error is None and len(single.devices) == 1
    assert [c[0] for c in sws.calls].count("set_registrant_address") == 1
