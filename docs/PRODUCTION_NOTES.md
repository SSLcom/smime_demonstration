# Production notes

What this demo deliberately leaves out, and what a production integration needs.
Behavior referred to here is recorded in [`API_GUIDE.md`](API_GUIDE.md).

## Orders and money

- **Every `POST /certificates` is charged** to the account in production. Never
  retry it automatically. Record the order in your own database *before* the call
  and store the returned `ref` after it. If the call fails without a `ref` (a
  timeout, say), reconcile before creating another: page through `GET /certificates`
  and match `external_order_number`. In the sandbox, `search` did not filter by
  `external_order_number`, so the match has to be made on your side.
- **No placeholder orders.** The domain is validated on the first real employee's
  order. An order placed only to validate a domain is charged like any other, and
  `PATCH /certificate/{ref}/cancel` is not enabled on every account (it returned
  HTTP 403 on the test account).
- **Balance monitoring.** Orders draw from the account balance. Alert well before
  it runs out; a failed order in the middle of onboarding leaves employees waiting.
- **Rate limiting.** Onboarding many employees means many calls. Pace them and
  back off on HTTP 429 or 5xx. Only GET requests are safe to retry automatically.

## Errors

- Many failures come back with **HTTP 200** and an error body (`errors`, `error`,
  `error_message`, or `response_type: "ERROR"`). Treat a response as successful
  only if the status is 2xx *and* the body has none of these.
- `POST /generate_certificate` can return HTTP 200 with neither a certificate nor an
  error. Treat a missing `cert_results` as a failure.
- Some responses (`GET /certificate/{ref}/api_parameters/...`) echo the account key
  and secret key. Redact response bodies as well as request URLs before logging.

## Domain validation (organizations)

- **City and state are required, but placeholders work.** On this path,
  issuance only succeeded when the order carried the device's CSR plus `locality`
  and `state_or_province`; the same applies to the second and later certificates
  on *any* order with a recipient (set them with `PUT /certificate/{ref}`). Neither
  value appears in the certificate, so a fixed placeholder is fine; the customer's
  real headquarters is better if you have it. This has been reported to SSL.com;
  check for changes before relying on it. Details:
  [Placeholder city and state](API_GUIDE.md#placeholder-city-and-state).
- **The DNS record is needed once.** After the domain was validated, the CNAME
  could be removed and later orders still issued. How long the validation stays
  valid has not been measured. Track when each customer validated, and be ready to
  validate again (a new order gives a new record).
- **The record is derived from the order's CSR and includes the date.** Read it from
  `GET /certificate/{ref}/validations/methods` every time; do not construct it.
- Validation is per account. Every customer's validated domain sits in the
  partner's account, alongside all their orders.

## Activation links (mailbox path)

- **Tell end users what to expect.** One email per order says the certificate "has
  been validated and approved" and asks them to visit a link "to download the
  certificate". The wording suggests more than it does. What they actually need to
  do is open the link, **press Confirm, and close the page**.
- **The page goes on to offer certificate generation in the browser.** If a user
  generates a certificate there, it is issued on your order with a key you never
  deployed. `customer status` flags such certificates as "NOT REQUESTED". Watch for
  them and revoke them.
- **Link scanners.** Opening the link (GET) does not confirm anything; only the
  Confirm button does. Mail-security products that pre-open links (Microsoft Defender
  Safe Links and similar) therefore cannot confirm on a user's behalf. This demo's
  own tests did not exercise such scanners.
- **Expiry and resend.** The confirmation page has a "send new token" button that
  emails a fresh link. No API call for resending has been verified, and link lifetime
  has not been measured. Plan a support path for users whose link expired.
- **Automated confirmation.** Confirming the link on a customer's behalf (reading
  their mailbox, following the link) would remove the proof that the mailbox owner
  agreed. Whether a partner may ever do this in production is a compliance question
  for SSL.com, not something to decide in code. Automating it against test mailboxes
  is fine for testing.

## Certificates and keys

- **Key custody.** Generate keys on the device or hardware token and submit only
  the CSR (`name:csr=<path>` in the roster). The demo's own key generation and
  unencrypted key files are for demonstration; use an HSM or device keystore in
  production.
- **Shared encryption key.** The PKCS#12 for a shared RSA certificate carries a
  private key that ends up on several devices. Deliver it over a protected channel,
  and treat the password as a secret.
- **Validity.** Each certificate gets its own validity from its own issue time: 365
  days for the first certificate on an order and 364 for each later one. A device
  added months later expires months later. Plan renewals per certificate, not per
  order.
- **Verification.** Check every issued certificate against the CSR it came from and
  the expected mailbox (what `verify.py` does) before installing it.

## Lifecycle

- **Offboarding.** Revoke an employee's certificates when they leave, a device's when
  it is lost (`KEYCOMPROMISE`) or replaced (`SUPERSEDED`), and everything when a
  customer leaves (`CESSATIONOFOPERATION`). Revoking one certificate by serial leaves
  the order's `order_status` at `issued`; read each certificate's status from
  `end_entity_certificates`.
- **Reconciliation.** Periodically compare your database with the orders and
  certificates SSL.com reports. Revoke anything you did not request, and recover
  orders whose `ref` was lost.
- **Webhooks.** The demo polls. Orders accept a `callback` (URL, method,
  authentication) that SSL.com calls on issuance; its behavior for S/MIME has not
  been verified here. If you use it, authenticate the calls and keep polling as a
  fallback.

## Account structure

The demo uses one partner account for all customers. Per-customer SSL.com teams can
be created with the partner's own credentials (`POST /v2/teams`), but ordering into
a team requires **that team's** credentials, and each team has its own balance. That
means N key pairs to store and N balances to fund. One account with your own
customer mapping is simpler.

## Not covered here

- IV, OV and IV+OV S/MIME (identity and organization validation).
- Domain validation by email to admin@ or by HTTP file; only the DNS CNAME method is
  shown.
- TLS products, the CLM API, and per-customer SSL.com accounts.
- Reading mailboxes automatically (IMAP, Microsoft Graph) for testing.
