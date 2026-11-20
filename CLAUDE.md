# Working on this repository

A reference integration for ordering, issuing and revoking mailbox-validated
S/MIME certificates through the SSL.com SWS API. Partner engineers read this code
as documentation, so prefer clear, small, named steps over cleverness.

## Layout

- `src/smime_demo/client.py`: one method per SWS call. Add a call here only after
  it has been observed in the sandbox and recorded in `docs/API_GUIDE.md`.
- `src/smime_demo/errors.py`: every error shape the API returns. Errors often come
  back with HTTP 200, so never judge a response by its status alone.
- `src/smime_demo/workflows/`: `domain.py` (validate a customer's domain once),
  `enterprise.py` (onboard, offboard, inventory), `single.py`, `multi_device.py`,
  and the shared steps in `issuance.py`.
- `src/smime_demo/store.py`: local JSON state standing in for the partner's database.
- `tests/unit/`: offline tests. They use recorded sandbox responses
  (`tests/fixtures/sandbox/`) and an in-memory stand-in (`fake_sws.py`).
- `scripts/probe_*.py`: attended probes that verify behavior against the sandbox.

## Commands

```bash
pip install -e '.[dev]'
ruff check .
pytest -m "not live"
```

## Rules

1. **Never invent endpoints, parameters or response fields.** The source of truth
   is behavior observed in the sandbox, recorded in `docs/API_GUIDE.md`. When the
   Swagger spec (`docs/openapi.json`) disagrees, the sandbox wins.
2. **Sandbox by default.** Production needs both `SSLCOM_ENV=production` and
   `--i-understand-this-spends-money`. Do not run anything against production.
3. **Never retry `POST /certificates` automatically**; it is charged in production.
   Record each order in the store before creating it. Only GET requests are retried.
4. **Secrets.** Credentials come only from the environment or `.env`. Redact
   `account_key`, `secret_key`, passwords and activation-link tokens everywhere,
   including URLs and response bodies. Never disable TLS verification.
5. **Private keys never leave the device.** Only CSRs are sent, and every path that
   submits a CSR also accepts one generated elsewhere. Key files are written `0600`
   under `out/` (gitignored).
6. **People do the proving.** A mailbox owner presses Confirm on the activation page,
   or a customer's DNS admin publishes the CNAME. The code never reads mailboxes,
   follows validation links, or changes DNS.
7. **Partner-facing.** Everything in this repository is shared with partners: keep
   code, comments, docs and commit messages neutral and self-contained.
