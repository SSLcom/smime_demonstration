#!/usr/bin/env python3
"""Build the worked examples in docs/API_GUIDE.md from real recorded calls.

    python scripts/build_api_guide.py --import out/guide   # copy + sanitize recordings
    python scripts/build_api_guide.py                      # regenerate the guide sections

Recordings come from `smime-demo --record DIR ...`. Importing copies the ones the
guide uses into docs/examples/, replacing the account's team ID and shortening
every PEM block (certificates and CSRs encode the mailbox address, so they are
never published in full). Building rewrites the text between the
`<!-- example: NAME -->` / `<!-- /example -->` markers in docs/API_GUIDE.md.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / "docs" / "examples"
GUIDE = REPO / "docs" / "API_GUIDE.md"
BASE = "https://sws-test.sslpki.com"

# guide example name -> recording (relative to the import directory)
SELECTION = {
    "domain/01_order_first_employee": "rec-domain/001_post_certificates.json",
    "domain/02_validation_methods": "rec-domain/002_get_certificate_*_validations_methods.json",
    "domain/03_choose_cname_validation": "rec-domain/003_put_certificate_*.json",
    "domain/04_validation_status": "rec-domain/004_get_certificate_*_validations_status.json",
    "domain/05_order_status_before_issuing": "rec-onboard/001_get_certificate_*.json",
    "domain/06_issue_first_device": "rec-onboard/002_post_generate_certificate.json",
    "domain/07_issue_another_device": "rec-onboard/003_post_generate_certificate.json",
    "domain/08_order_next_employee": "rec-onboard/006_post_certificates.json",
    "domain/09_issue_next_employee": "rec-onboard/007_post_generate_certificate.json",
    "domain/10_issue_device_own_csr": "rec-onboard/008_post_generate_certificate.json",
    "domain/11_order_with_three_certificates": "rec-onboard/005_get_certificate_*.json",
    "domain/12_revoke_one_certificate": "rec-revoke-device/001_delete_certificate_*.json",
    "domain/13_after_revoking_one": "rec-revoke-device/002_get_certificate_*.json",
    "domain/14_revoke_employee": "rec-revoke-employee/002_delete_certificate_*.json",
    "domain/15_after_revoking_employee": "rec-revoke-employee/004_get_certificate_*.json",
    "mailbox/01_order": "rec-mailbox/001_post_certificates.json",
    "mailbox/02_waiting_for_confirmation": "rec-mailbox/002_get_certificate_*.json",
    "mailbox/03_confirmed": "rec-mailbox/004_get_certificate_*.json",
    "mailbox/04_issue_first_device": "rec-mailbox/005_post_generate_certificate.json",
    "mailbox/05_second_device_without_address": "rec-mailbox/006_post_generate_certificate.json",
    "mailbox/06_set_placeholder_address": "rec-mailbox-fix/001_put_certificate_*.json",
    "mailbox/07_issue_second_device": "rec-mailbox/010_post_generate_certificate.json",
    "mailbox/08_issue_shared_rsa": "rec-mailbox/011_post_generate_certificate.json",
    "mailbox/09_order_with_three_certificates": "rec-mailbox/012_get_certificate_*.json",
    "other/01_list_orders": "rec-check/001_get_certificates.json",
}

PEM = re.compile(r"-----BEGIN ([A-Z ]+)-----\s*(.*?)\s*-----END \1-----", re.S)
TEAM = re.compile(r"/team/[A-Za-z0-9-]+/")


def shorten_pem(text: str) -> str:
    def repl(m: re.Match) -> str:
        body = m.group(2).split()
        first = body[0][:24] if body else ""
        return f"-----BEGIN {m.group(1)}-----\n{first}...(shortened)\n-----END {m.group(1)}-----"

    return PEM.sub(repl, text)


def sanitize(value):
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        return TEAM.sub("/team/YOUR_TEAM/", shorten_pem(value))
    return value


def import_recordings(source: Path) -> None:
    if EXAMPLES.exists():
        shutil.rmtree(EXAMPLES)
    for name, pattern in SELECTION.items():
        matches = sorted(source.glob(pattern))
        if len(matches) != 1:
            raise SystemExit(f"{pattern}: expected one recording, found {len(matches)}")
        record = sanitize(json.loads(matches[0].read_text()))
        out = EXAMPLES / f"{name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=2) + "\n")
    print(f"imported {len(SELECTION)} examples into {EXAMPLES.relative_to(REPO)}")


def render(name: str) -> str:
    rec = json.loads((EXAMPLES / f"{name}.json").read_text())
    query = "&".join(f"{k}={v}" for k, v in rec["query"].items())
    url = f"{BASE}{rec['path']}?{query}"
    lines = [
        f"`{rec['method']} {rec['path']}` — [{name}.json](examples/{name}.json)",
        "",
        "```bash",
    ]
    if rec["json"] is None:
        lines.append(f'curl -sS -X {rec["method"]} "{url}"')
    else:
        lines += [
            f'curl -sS -X {rec["method"]} "{url}" \\',
            "  -H 'Content-Type: application/json' -d @- <<'JSON'",
            json.dumps(rec["json"], indent=2),
            "JSON",
        ]
    lines += [
        "```",
        "",
        f"Response: HTTP {rec['status']} ({rec['elapsed_seconds']} s)",
        "",
        "```json",
        json.dumps(rec["response"], indent=2),
        "```",
    ]
    return "\n".join(lines)


def build() -> None:
    text = GUIDE.read_text()
    pattern = re.compile(r"(<!-- example: (\S+) -->\n).*?(<!-- /example -->)", re.S)
    count = 0

    def repl(m: re.Match) -> str:
        nonlocal count
        count += 1
        return f"{m.group(1)}{render(m.group(2))}\n{m.group(3)}"

    GUIDE.write_text(pattern.sub(repl, text))
    print(f"rendered {count} examples into {GUIDE.relative_to(REPO)}")


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--import", dest="source", type=Path, help="Directory of recordings to import")
    args = p.parse_args()
    if args.source:
        import_recordings(args.source)
    build()
    return 0


if __name__ == "__main__":
    sys.exit(main())
