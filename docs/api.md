# HTTP API guide

What another program needs to know to use an epistle server over HTTP: how to
get a key, what it may do, how to send mail, how to read what became of it,
and what to expect when something goes wrong.

The routes are described machine-readably in
[`src/api/openapi/openapi.yaml`](../src/api/openapi/openapi.yaml) (OpenAPI 3.1).
A running server serves the same document as JSON at
`GET /api/v1/openapi.json`, with a key that has the `read` scope. The tests
fail when a route in the code is missing from it or it lists one the code does
not register, and when an operation names a scope the code does not enforce;
they do not check every field or status code in it. This
guide is the prose around it. How the headers of the mail come out is in
[Message headers](headers.md).

| Prefix | What it is | Needs |
|---|---|---|
| `/api/v1` | Management, mail submission, delivery log | A bearer key with `read`, `write` or `send` |
| `/jmap` and `/.well-known/jmap` | JMAP mail (RFC 8620, 8621, 8887) | A bearer key with `read`, `write` or `send` |
| `/scim/v2` | SCIM 2.0 account provisioning | A bearer key with `scim` |
| `/oauth` | Device and PKCE grants for mail clients | The account's own credentials |
| `/healthz` | Liveness | Nothing |

Not in the API, because they exist only in the CLI: DKIM keys, TLS, evidence,
warm-up, limits, domains (listing excepted), aliases, relays, backups.

The other protocols the server speaks (SMTP, IMAP, POP3, ManageSieve) and the
WebDAV, CardDAV and CalDAV listener are not described here. The mail client
autodiscovery, ACME and metrics listeners are HTTP and are in the OpenAPI
document, with the listener each one is served on.

## Turn it on

The API is closed until a listener and a token hash are configured:

```toml
[[listeners]]
kind = "api"
addr = "127.0.0.1"
port = 8025

[api]
token_hash = "sha256:<64 hex digits>"
```

`epistle token-hash` reads a token on stdin and prints the hash. That token
is the static token: it holds every scope and reaches every domain, so keep
it for the operator and give programs a key (next section). The listener
speaks plain HTTP only. Bind it to loopback, or put a TLS proxy in front of
it, before it carries a key across a network. A browser cannot call it
cross-origin: CORS is denied.

## Keys and scopes

```sh
epistle api-key create billing --scope send --scope read
```

The key is printed once and never stored (only its SHA-256 is). It is 52
lowercase letters and digits. The server reads `api_keys.toml` again within a
few seconds of a change, so a new, rotated or revoked key takes effect
without a restart.

| Flag | Effect |
|---|---|
| `--scope read\|write\|send\|scim` | Required, repeatable. Scopes are independent: `write` does not include `read` |
| `--expires-at EPOCH` | Unix seconds. After it the key is refused with `401`, like an unknown one |
| `--ip-cidr CIDR` | One network the client must come from. A request from elsewhere is `401` |
| `--domain NAME` | Confine the key to a domain (repeat for more). Without it the key reaches every domain |
| `--account NAME` | Bind the key to one account. It then reaches only JMAP, `POST /api/v1/send` and `GET /api/v1/deliveries`, acting as that account, and cannot hold `scim` or `--domain` |
| `--class CLASS` | The mail class `POST /api/v1/send` gives mail sent with the key when the request names none (see [Class and evidence](#class-and-evidence)) |

`epistle api-key rotate LABEL` replaces the secret and keeps everything else,
the class included; `epistle api-key revoke LABEL` removes the key;
`epistle api-key list` shows the label, expiry, network, scopes, domains and
account, never the key.

What each scope reaches:

| Scope | Reaches |
|---|---|
| `read` | Every `GET` of `/api/v1`, `/jmap/session`, `/.well-known/jmap`, `/jmap/download`, `/jmap/ws`, `/jmap/eventsource`, and the JMAP methods that return data (`*/get`, `*/query`, `*/changes`, `*/queryChanges`, `Identity/get`, `Quota/get`, `SieveScript/validate`) |
| `write` | Every other method of `/api/v1` except `send`, `/jmap/upload`, and the JMAP methods that change data (`Mailbox/set`, `Email/set`, `Email/copy`, `PushSubscription/set`, `VacationResponse/set`, `SieveScript/set`) |
| `send` | `POST /api/v1/send` and JMAP `EmailSubmission/set` |
| `scim` | Everything under `/scim/v2` |

A key confined to some domains sees and changes only the accounts that live
entirely inside them. What is outside is answered `404`, as if it did not
exist, so a tenant cannot find out which names the others use. The global
suppression list is refused to it with `403`. The per-route rules are in
[Domain-confined API keys](configuration.md#domain-confined-api-keys-multi-tenancy).

## Authenticating

Every route of the API listener except `/healthz` and `/oauth/*` needs
`Authorization: Bearer <key>`, exactly that spelling with one space. A token
longer than 1024 bytes is not looked at.

```sh
API=http://127.0.0.1:8025
KEY=...   # the 52 characters printed by api-key create
curl -s -H "Authorization: Bearer $KEY" "$API/api/v1/status"
```

| Answer | Cause |
|---|---|
| `401` `unauthenticated` | No header, an unknown or expired key, a key pinned to another network, **or a key whose scopes do not cover the route**. The four look the same |
| `403` `forbidden` | The key is bound to one account and the route is administrative, or the bound account is disabled or gone |
| `403` `forbidden_from` | `POST /api/v1/send` from an address the credential may not act for |
| `429` `rate_limited` | The client address made 20 requests with credentials that did not hold in the last 60 seconds. Every request from it is refused, valid or not, until the window passes. The `Retry-After` header gives the remaining window in seconds, rounded up |

A valid call does not use up the budget, and it does not clear failures already
counted. The limit is per client address (an IPv6 client counts as its /64, and
its /48 has a larger shared budget), and there is a ceiling for failures from
everyone at once that only ever refuses a request that already failed. There is
no limit on the rate of valid calls. The server uses the TCP peer by default. With
[`[api] trusted_proxies`](configuration.md#api), a trusted peer may supply
`X-Forwarded-For`: the whole chain must parse as IP addresses, and the first
untrusted address from right to left is the client. Missing, malformed or wholly
trusted chains fall back to the peer; an untrusted peer cannot override its
address. This applies to OAuth bans and device grant counters too. Configure
only proxies under your control, with forwarding headers appended or replaced
using the actual connecting client's address. Restart after changing the list.
OAuth `429 slow_down` responses carry `Retry-After` for grant expiry or polling;
password bans keep the same response as an incorrect password.

Checks of a password (`POST /api/v1/auth/verify`, and the `/oauth` endpoints)
are counted apart, in the shared ban table: 5 failures in 15 minutes ban the
client or the account for 15 minutes, doubling up to 24 hours, with the same
answer as a wrong password. That table needs `[database]`; see
[Security](security.md).

If the static token's hash in `[api] token_hash` is an old argon2id string
and not `sha256:`, each request that is not a key costs an argon2 check: 2
run at a time, 64 may wait, and the next gets `429`. Use the `sha256:` form.

## Errors

A failure the API decides is JSON:

```json
{"error": {"code": "invalid_input", "message": "At least one recipient is required."}}
```

`code` is for programs and stays; `message` is for people and its wording can
change. A request the HTTP layer cannot read never reaches the handler, and
its answer is **plain text**, with no `error` object:

| Status | When | Body |
|---|---|---|
| `400` | Malformed JSON, a query or path value of the wrong type, a path id that is not a UUID | `Failed to parse the request body as JSON: ...`, `Invalid URL: ...`, `Failed to deserialize query string: ...` |
| `415` | A body without `Content-Type: application/json` | The text "Expected request with `Content-Type: application/json`" |
| `422` | A required field missing or of the wrong type | `Failed to deserialize the JSON body into the target type: ...` naming the field |
| `413` | A request body over the size limit | `Failed to buffer the request body: length limit exceeded` |
| `404` | A path that is not a route | Empty |
| `405` | A route with another method | Empty, with an `allow` header |

Handle both shapes: read `error.code` when the body is JSON, and fall back to
the status. The codes the API itself sends:

| Code | Status | Meaning |
|---|---|---|
| `unauthenticated` | 401 | See above |
| `forbidden`, `forbidden_from` | 403 | See above, and a confined key on the global suppression list |
| `not_found` | 404 | The thing is not there, or is outside the key's reach |
| `invalid_input` | 400 | The message says which field |
| `conflict` | 409 | A limit that waiting will not lift: the tenant is at `max_accounts`, the account at its masked-address cap, a queue entry with evidence still to write |
| `message_too_large` | 413 | The built message is over the size limit |
| `scan_too_large` | 413 | Too large for the content scan, and the server lets nothing pass unscanned. Retrying cannot help |
| `virus_detected`, `attachment_refused`, `too_many_header_fields`, `marketing_refused` | 422 | Refused for its content; sending it again unchanged is refused again. Nothing was sent |
| `rate_limited` | 429 | The authentication limit above, or a sending limit (next section) |
| `internal` | 500 | The server failed. The message never carries details |
| `scan_unavailable`, `evidence_unavailable` | 503 | Nothing was sent; retrying later works |
| `mailbox_full` | 507 | A local recipient's mailbox is full. Nothing was queued for anyone |

New codes can appear within `/api/v1`; treat an unknown one by its status.

## Sending mail

`POST /api/v1/send` builds a message from JSON and submits it the way SMTP
submission does: DKIM-signed for the sender's domain when it leaves the
server, delivered at once to local recipients, queued for the rest. It needs
the `send` scope.

```sh
curl -s -X POST "$API/api/v1/send" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{
    "from": "billing@example.org",
    "from_name": "Example Billing",
    "to": ["customer@example.net"],
    "subject": "Your receipt",
    "text": "Thank you.",
    "html": "<p>Thank you.</p>",
    "extra": {"order": "A-1042"}
  }'
```

```json
{"queued": "01a15026-ff4b-7411-a7e9-9292a7662720", "class": "personal"}
```

`queued` is the queue id. It is also the `spool_id` of every delivery record
and webhook event of the message, so keep it. A message for local recipients
only is delivered at once and also gets an id.

| Field | Type | Notes |
|---|---|---|
| `from` | string, required | A bare address, no display name. Must be one the acting account owns |
| `from_name` | string | The phrase of `From`. Absent uses the account's display name. At most 128 characters |
| `to`, `cc`, `bcc` | arrays of strings | `to` is required but may be empty if `cc` or `bcc` has someone. Together at most 100. `bcc` is envelope only |
| `reply_to`, `sender` | string | `sender` must be an address the account owns, like `from` |
| `subject` | string | Default empty |
| `text`, `html` | string | With both, a `multipart/alternative`, text first |
| `attachments`, `inline` | arrays of `{name, content_type, data, content_id}` | `data` is base64 (standard alphabet, padded). An empty `content_type` is detected. Every `inline` part needs a `content_id`; the HTML refers to it as `cid:<content_id>`. At most 100 parts together |
| `in_reply_to`, `references` | string | `<id@domain>` ids, space separated: one for `in_reply_to`, up to 100 for `references` (in practice about 50, because each header value is at most 1000 bytes) |
| `importance` (or `priority`) | `high`, `normal`, `low` | Writes `Importance` and `X-Priority` |
| `list_unsubscribe` | array of strings | Up to 4 `mailto:` or `https://` URLs |
| `list_unsubscribe_post` | boolean | Adds the RFC 8058 one-click header. Needs an `https://` URL in `list_unsubscribe` |
| `auto_submitted`, `feedback_id` | string | `Auto-Submitted` (`no`, `auto-generated`, `auto-replied`, `auto-notified`) and `Feedback-ID` (printable ASCII, no spaces) |
| `headers` | object | Custom headers: up to 32, name `X-` plus letters, digits and hyphens (at most 76 characters), not `X-Priority` |
| `save_sent` | boolean | Whether a copy goes to the account's Sent folder. Absent follows the account setting. Transactional mail is never copied |
| `extra` | object of strings | Correlation data, up to 10 keys (printable ASCII, no spaces, at most 64 bytes) with values of at most 256 bytes. It comes back on `/api/v1/deliveries` and in the webhook events of the message and is never written into the message |
| `class` | `transactional`, `marketing`, `personal` | See below |

Fields the server does not know are ignored. Every value that ends up on a
header line, attachment names and types included, may not hold a control
character other than a tab and is at most 1000 bytes. Nothing in `headers`
can replace `From`, `To`, `Date`, `Message-ID`, a signature or the MIME
structure, and the server removes `X-Epistle-Attachment-Warning` if you send
it.

**Who may be the sender.** The sender has to be an address the acting account
owns. A key bound to one account acts for that account. Any other key acts
for the account that owns `from`, provided the key reaches it. In every other
case the answer is `403 forbidden_from`, the same whether the address belongs
to another account or to nobody, so it says nothing about which addresses
exist. The envelope sender is the `from` as written; its letter case is kept.

### Class and evidence

Every message has a class, decided by the server and never by the message.
The class bound to the key, else to the account, is a floor, and `class` in
the request may ask for a stricter one (personal, then marketing, then
transactional), never a looser one. A key made with `--class transactional`
keeps its mail transactional whatever the request says; the response's
`class` is the one granted.

- `transactional`: an evidence record is written before the message is
  accepted, and when it cannot be, the request is refused with `503
  evidence_unavailable`. Never copied to Sent. See [Evidence of sending](evidence.md).
- `marketing`: refused with `422 marketing_refused` unless it has a
  `List-Unsubscribe` with an `https` URL and a one-click `List-Unsubscribe-Post`
  (set `list_unsubscribe` and `list_unsubscribe_post`). Sent with
  `Precedence: bulk`. Recipients on a suppression list are dropped and listed
  in `suppressed` in the response; if none is left, `marketing_refused`.
- `personal`: the default.

### Limits on sending

| Limit | Value | Answer |
|---|---|---|
| Message size | `[server] max_message_size`, 25 MiB by default | A built message over it: `413 message_too_large`. A request body over it: plain-text `413` |
| Recipients | 100 per message (`to`, `cc`, `bcc` together) | `400 invalid_input` |
| Parts | 100 attachments and inline parts together | `400 invalid_input` |
| Submission rate | `submission_rate_limit_per_min` recipients per minute per account, shared with SMTP and JMAP; per-domain and per-tenant limits too | `429 rate_limited`, "sending rate limit exceeded; retry later". Nothing was sent |
| New recipients | `new_recipients_per_day` first-time recipients per account per rolling 24 hours | `429 rate_limited`, "too many new recipients today; retry tomorrow" |
| Mailbox quota | `quota_bytes` | `507 mailbox_full` |

The message of a `429` tells the sending limits from the authentication one.
When the server has the antivirus on (`clamd_socket`), a message it cannot
scan now is `503 scan_unavailable`, a detection is `422 virus_detected`, and
a message the attachment policy refuses is `422 attachment_refused`.

There is no idempotency key. A request that timed out may or may not have
queued a message; look in `/api/v1/deliveries` or the queue, or send an
`extra` value of your own and search for it, before sending again.

## What happened to a message

`GET /api/v1/deliveries` (scope `read`) is the per-recipient delivery log,
newest day first. It is kept for `[storage] delivery_log_days` (30 by
default); with `0` it answers `404`.

```sh
curl -s -H "Authorization: Bearer $KEY" \
  "$API/api/v1/deliveries?since=24h&outcome=failed&limit=20"
```

```json
{"entries": [{"time": 1792346437, "spool_id": "01a15026-ff4b-7411-a7e9-9292a7662720",
  "account": "billing", "from": "billing@example.org", "recipient": "customer@example.net",
  "outcome": "failed", "remote": "mx.example.net", "reply": "550 5.1.1 no such user",
  "attempt": 3, "extra": {"order": "A-1042"}}]}
```

| Filter | Meaning |
|---|---|
| `recipient` | Exact address |
| `account` | The sending account. Ignored for a key bound to one account, which sees only its own records |
| `since` | `30s`, `15m`, `24h`, `7d` or an RFC 3339 time |
| `outcome` | `delivered`, `deferred`, `failed`, `suppressed`, `canceled` |
| `limit` | 1 to 100, default 50. There is no cursor: narrow with the filters |

`delivered` is a remote server accepting the message; `deferred` a temporary
failure being retried (a record is written again only when the reason
changes); `failed` a permanent refusal or expiry in the queue; `suppressed`
the recipient was on a suppression list; `canceled` an operator removed the
entry through the API or `epistle queue remove`. A key confined to some
domains sees no records, because they carry an account and not a domain.

`GET /api/v1/queue` lists what is still waiting (`limit` 1 to 100, `cursor`
from `next_cursor`), `DELETE /api/v1/queue/{id}` removes an entry and records
each pending recipient as `canceled` in the delivery log, then posts a
`canceled` webhook event when the delivery log is enabled and a webhook is
configured.
`GET /api/v1/suppression` and `DELETE /api/v1/suppression/{address}`
list and clear suppressed recipients, globally or for one sending account with
`?account=`. Pages end when `next_cursor` is absent.

## Accounts and the rest of the management API

All of these use JSON, the `write` scope for changes and `read` for reads.
Names are lowercase letters, digits and hyphens, up to 64 characters.
Passwords are 12 to 64 printable ASCII characters and not in the bundled
breach list.

```sh
# create an account (answers 200 with {"created": "ana"})
curl -s -X POST "$API/api/v1/accounts" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"ana","addresses":["ana@example.org"],"password":"a long password here"}'

# delete it; ?queue=discard|drain is required
curl -s -X DELETE -H "Authorization: Bearer $KEY" "$API/api/v1/accounts/ana?queue=drain"
```

| Route | What it does |
|---|---|
| `GET /api/v1/status` | `version`, `domains`, `accounts` and `queue_size` (left out for a confined key) |
| `GET /api/v1/domains` | The hosted domains in the key's reach and which are `disabled` |
| `GET`, `POST /api/v1/accounts` | List (not paged), create. A duplicate name or address is `400 invalid_input` |
| `DELETE /api/v1/accounts/{name}` | Removes the account and its data. Only accounts made through the API; one declared in the configuration file is `404 no such dynamic account` |
| `PUT /api/v1/accounts/{name}/password` | New password |
| `PUT /api/v1/accounts/{name}/display_name` | `{"display_name": "..."}`; empty clears it |
| `POST`, `DELETE /api/v1/accounts/{name}/totp` | Enrol a fresh secret (returned once, effective at once) or turn two-factor off |
| `GET /api/v1/accounts/{name}/mailboxes` | Mailbox names and a tree |
| `GET`, `POST /api/v1/accounts/{name}/masked` | Masked addresses; create answers `201` |
| `PATCH`, `DELETE /api/v1/accounts/{name}/masked/{address}` | Enable or disable, remove |
| `GET /api/v1/accounts/{name}/archive`, `POST .../archive/{id}/restore` | Expunged messages kept by `deleted_retention_days`, and put one back |
| `POST /api/v1/auth/verify` | Check a login and password; `{"valid": bool, "admin": bool}`. Scope `write` |

Reading and writing the `Created`, `Removed` and other bodies is in the
OpenAPI document, which also has every response code per route.

## Webhooks

The server posts events to the URL in `[webhook]` (`epistle webhook set URL
--secret-stdin`), one JSON object per request with the event name in `event`:

| `event` | When | Fields besides `event` |
|---|---|---|
| `delivered` | A remote server accepted the message for a recipient | `spool_id`, `recipient`, `message_id` (or `null`), `remote` (or `null`), `extra` |
| `delayed` | The first temporary failure of a recipient, once per recipient per message | `spool_id`, `recipient`, `reason`, `remote`, `attempt`, `extra` |
| `delivery_failed` | A recipient failed for good (refused or expired) | `spool_id` (`null` in an entry queued before it was recorded), `recipient`, `reason`, `class` (`invalid_address`, `mailbox_full`, `policy_rejected`, `too_big`, `other`), `remote`, `extra` |
| `suppressed` | The recipient was on a suppression list | `spool_id`, `recipient`, `extra` |
| `canceled` | An operator removed the entry through the API or `epistle queue remove` | `spool_id`, `recipient`, `extra` |
| `message_received` | A message was delivered to a local recipient | `account` (the recipient address), `from` (the envelope sender, empty for a bounce), `subject`, `message_id` (the last two may be `null`) |
| `metric_alert`, `dkim_rotation_failed`, `outbound_virus`, `warmup.ok`, `warmup.held`, `warmup.backoff` | Operator events | See [configuration](configuration.md#webhook) and [warm-up](warmup.md) |
| `test` | Only `epistle webhook test` | `message` |

`extra` is left out when empty; `spool_id` is the `queued` id the send
returned. The name of the event for a permanent failure is `delivery_failed`;
there is no `bounced` event.

```json
{"event":"delivered","spool_id":"01a15026-ff4b-7411-a7e9-9292a7662720","recipient":"customer@example.net","message_id":"<01a15026-ff4a-76d9-bbea-732452399a76@example.org>","remote":"mx.example.net","extra":{"order":"A-1042"}}
```

**Verify the signature.** With a `secret`, the request carries
`X-Webhook-Signature: sha256=<hex>`, the HMAC-SHA256 of the raw request body
with the secret as the key. Compute it over the bytes you received, not over a
re-encoded copy, and compare in constant time:

```sh
printf %s "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex
```

The command prints `SHA2-256(stdin)= <hex>` or just `<hex>`, depending on the
OpenSSL version; compare the hex part with what follows `sha256=` in the header.

The only other headers are `Content-Type: application/json`. There is no
timestamp, event id or nonce, so a replay is yours to detect: the pair
`event` and `spool_id` with `recipient` identifies a delivery event.

**Delivery.** Each event is posted once, with a 15 second timeout and no
retry. A redirect is not followed and counts as a failure. Any other answer,
a `500` included, counts as sent, and a failure to connect is logged and
dropped. Events are posted concurrently, so their order is not the order of
the mail. Treat webhooks as a hint and the delivery log as the record: if you
need every outcome, read `/api/v1/deliveries` as well. `epistle webhook test`
posts a `test` event and reports the status the endpoint answered.

## JMAP

JMAP uses the same keys. `GET /jmap/session` (or `/.well-known/jmap`) returns
the Session resource: the accounts the key reaches (the JMAP account id is the
account name), the capabilities and the limits; its URLs are relative.
`POST /jmap/api` runs method calls. The scope is checked per call: a call the
key does not cover answers a `forbidden` method error inside a `200`.

- Methods: `Core/echo`; `Mailbox/get`, `query`, `changes`, `queryChanges`,
  `set`; `Email/get`, `query`, `changes`, `queryChanges`, `set`, `copy`;
  `Thread/get`, `changes`; `Identity/get`; `Quota/get`; `EmailSubmission/set`;
  `PushSubscription/get`, `set`; `VacationResponse/get`, `set`;
  `SieveScript/get`, `query`, `set`, `validate`. Anything else is
  `unknownMethod`.
- `EmailSubmission/set` accepts `epistle:class`, with the same rule as the
  REST `class`.
- Upload with `POST /jmap/upload/{accountId}` (scope `write`) and download with
  `GET /jmap/download/{accountId}/{blobId}/{name}`.
- `GET /jmap/ws` is JMAP over WebSocket. It accepts the upgrade but does not
  answer the `jmap` subprotocol, and the bearer goes in the `Authorization`
  header of the upgrade, so a browser cannot use it. Push is connection-scoped.
- `GET /jmap/eventsource?types=Email,Mailbox&closeafter=no&ping=30` streams
  `state` and `ping` events for changes made by any protocol; there is no
  replay, so catch up with `/changes`.

Limits, also in the Session: 10,000,000 octets per request, 16 calls, 500
objects per `/get` or `/set`, 4 requests and 4 uploads in flight per
credential, 4 event streams per credential, `maxSizeUpload` equal to the
message size limit. Past the size of a request or its number of calls the answer is
`400` or `413` with a `urn:ietf:params:jmap:error:limit` problem naming the
limit; past the in-flight limits it is a `429` with such a problem; past 500
objects in a `/get` or `/set` it is a `200` whose method response is the error
`requestTooLarge`. A key bound to one account sees only that account.

## SCIM

For an identity provider that provisions mail accounts. Scope `scim`;
responses are `application/scim+json` and errors use the SCIM error object.
`/scim/v2/Users` supports `GET` (with `filter=userName eq "x"`, `startIndex`,
`count` up to 200), `POST`, and on `/Users/{id}` `GET`, `PUT`, `PATCH`
(`replace` or `add` of `active`, `password` or `displayName` only) and
`DELETE` (`204`, queued mail is kept). `id` is the account name. Only
API-managed accounts appear. `totalResults` is the number of users on the
page, not the number that match. `/Groups` answers `501`. A `POST` and `PUT`
need `active`; without it the answer is a plain-text `422`. A SCIM key
cannot be bound to an account.

## OAuth

Present only when `[oauth] signing_key` is set; otherwise every `/oauth/*`
path answers `401` to a request with no bearer (which counts as a failed
authentication for the 20 per minute limit) and `404` to one with a valid
bearer. It issues ES256 access tokens, valid for one hour, for
OAUTHBEARER on IMAP and SMTP submission. The REST API does not accept them as
a bearer. `POST /oauth/device_authorization` starts a device flow,
`POST /oauth/device/approve` approves it with the account's `login` and
`password` (or HTTP Basic), and `POST /oauth/token` polls (no faster than every
5 seconds) or redeems a PKCE code from `POST /oauth/authorize` (`S256` only).
Bodies are form-encoded or JSON; errors are `{"error": "<code>"}` as in
RFC 6749 and 8628. Wrong credentials and a wrong code give the same answer.

## What can go wrong

| Symptom | Likely cause |
|---|---|
| `401` on a route that worked yesterday | The key expired (`--expires-at`), was rotated or revoked, or the client moved outside `--ip-cidr` |
| `401` on one route and `200` on another with the same key | The key lacks the scope of the first. A missing scope is `401`, not `403` |
| `429` with a correct key | Your address made 20 failed attempts in a minute (perhaps another program behind the same NAT). Wait a minute |
| `403` on `/api/v1/accounts` | The key is bound to one account; use a key without `--account` |
| `403 forbidden_from` | `from` or `sender` is not an address of the account the key acts for |
| `422` with text/plain and `missing field` | The body lacks a required field (`from`, `to`; for SCIM, `userName`, `active`) |
| `400` with text/plain | The JSON is malformed, or a UUID in the path is not one |
| `413` JSON vs plain text | JSON `message_too_large`: the message built from your fields is over the limit. Plain text: the request body itself is |
| `422 marketing_refused` | A `marketing` message with no https `list_unsubscribe` and `list_unsubscribe_post`, or every recipient is suppressed |
| `409 conflict` | A cap that waiting will not lift (tenant accounts, masked addresses) |
| `404` on `/api/v1/deliveries` | The delivery log is off (`delivery_log_days = 0`) |
| `401` or `404` on `/oauth/*` | No `[oauth] signing_key`: `401` without a bearer, `404` with a valid one |
| `404 no such dynamic account` | The account is declared in the configuration file; the API manages only API-made accounts |
| The webhook never arrives | The server posts once with a 15 second timeout and does not retry, and a `[webhook]` with `enabled = false` posts nothing |
| Mail accepted (`200`) but never delivered | Look at `/api/v1/deliveries` for `deferred` or `failed` with the remote reply |

## Limits

| What | Value |
|---|---|
| Message size | `[server] max_message_size`, 25 MiB by default, for send, SMTP and JMAP upload alike |
| Recipients per message | 100 |
| Attachments and inline parts | 100 |
| Custom headers | 32; `extra` 10 keys |
| One header value | 1000 bytes |
| Request head | About 64 KiB (a larger one is `431`; the cut is not exact); 30 seconds to send it |
| Page size | 1 to 100 (`limit`), default 50 |
| Failed authentications | 20 per client address per 60 seconds |
| Authenticated request rate | No limit of its own; sending has its own limits |
| JMAP | See [JMAP](#jmap) |
| Webhook | 15 seconds, one try |
| Open connections | Not limited by the HTTP layer |

## Versioning and stability

Everything under `/api/v1` is version 1 of the API. The rule of the project is
that breaking an endpoint means a new version and not a silent change, and
these are stable within `/api/v1`: the paths and methods, the scope each
route needs, the names and types of the fields in this guide and in the
OpenAPI document, the meaning of the status codes and of `error.code`, and the
webhook event names and fields.

These can change without a new version: the wording of `message`, new
optional fields in a response, new `error.code` values and new routes, the
order of keys and of list entries where this guide does not state one, the text
of the plain-text rejections, and the contents of the descriptions in the
OpenAPI document. A client should ignore fields it does not know and treat an
unknown error code by its status.

`/jmap`, `/scim/v2` and `/oauth` follow their RFCs and are as stable as the
parts of them this server implements; the OpenAPI document lists what it
implements. The mail headers are covered in [Message headers](headers.md),
which marks what is planned to change.
