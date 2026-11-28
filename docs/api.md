# HTTP API guide

What another program needs to know to use an epistle server over HTTP: how to
get a key, what it may do, how to send mail, how to read what became of it,
and what to expect when something goes wrong.

The routes are described machine-readably in
[`src/api/openapi/openapi.yaml`](../src/api/openapi/openapi.yaml) (OpenAPI 3.1).
A running server serves the same document as JSON at
`GET /api/v1/openapi.json`, with a key that has the `manage:read` scope. The tests
fail when a route in the code is missing from it or it lists one the code does
not register, and when an operation names a scope the code does not enforce;
they do not check every field or status code in it. This
guide is the prose around it. How the headers of the mail come out is in
[Message headers](headers.md).

| Prefix | What it is | Needs |
|---|---|---|
| `/api/v1` | Management, mail submission, delivery log | A bearer key with `read`, `write` or `send` |
| `/jmap` and `/.well-known/jmap` | JMAP mail (RFC 8620, 8621, 8887) | A bearer key or local OAuth access token with `read`, `write` or `send` |
| `/scim/v2` | SCIM 2.0 account provisioning | A bearer key with `scim` |
| `/oauth` | Device and PKCE grants for mail clients | The account's own credentials |
| `/healthz` | Liveness | Nothing |

Each prefix is a surface, and the listeners say which of them a port serves. A
listener of kind `api` serves management and, unless they have a listener of
their own, JMAP, SCIM and the OAuth grants too, which is what a configuration
from 0.14.0 means. A listener of kind `jmap` (port 8026), `scim` (8027) or
`oauth` (8028) serves that surface and `/healthz` and nothing else, and the
`api` listener stops serving it. A path outside the surfaces a listener serves
is treated like any path nobody serves: `401` without a valid credential, `403`
with a key that may not call that path, and `404` otherwise. `[api] surfaces`
lists the surfaces the `api` listener adds to management (`[]` for none), and
`epistle service enable jmap`, `scim` or `oauth` adds the listener
([`service` in the command reference](cli.md#service-listeners)).

Not in the API, because they exist only in the CLI: DKIM keys, TLS, evidence,
warm-up, global limits, address aliases and lists, relays, backups.

The other protocols the server speaks (SMTP, IMAP, POP3, ManageSieve) and the
WebDAV, CardDAV and CalDAV listener are not described here. The mail client
autodiscovery, ACME and metrics listeners are HTTP and are in the OpenAPI
document, with the listener each one is served on.

## Turn it on

The API needs a listener and an `[api]` section. The static token is optional:

```toml
[[listeners]]
kind = "api"
addr = "127.0.0.1"
port = 8025

[api]
# Optional operator credential:
# token_hash = "sha256:<64 hex digits>"
```

Without `token_hash`, labelled keys in `api_keys.toml` authenticate on
bearer-protected routes; local OAuth access tokens also authenticate JMAP.
Create a key with `epistle api-key create app --account
ACCOUNT --scope send --expires-in 365d`. `epistle init` with `services.api = true`
and `epistle service enable api` create the section without a static token;
`epistle status` reports "no static token configured" as a good state.

No routes become unreachable in this release: every bearer-protected route has
a per-key scope, including SCIM discovery, Users and Groups (`scim`). OAuth's
`POST /oauth/device_authorization`, `/oauth/device/approve`, `/oauth/authorize`
and `/oauth/token` use grant codes or account credentials; `/oauth/revoke` uses
possession of the token to revoke. These work independently of the
static token (and still require an OAuth signing key). A key with every scope
remains a labelled key; it never becomes the configured static identity.
A route reserved to the static token with no per-key scope must refuse keys
with `403 forbidden` when no static token is configured. There are currently
no such routes. Empty bearers and the literal `sha256:` never match an absent
hash. Unknown credentials are still `401`, subject to failure limits.

`epistle token-hash` reads a token on stdin and prints the hash. That token
is the static token: it holds every scope and reaches every domain, so keep
it for the operator and give programs a key (next section). The listener
speaks plain HTTP only. Bind it to loopback, or put a TLS proxy in front of
it, before it carries a key across a network. A browser cannot call it
cross-origin: CORS is denied.

### Exposing the API on a private interface

Keeping the management API on a WireGuard (or any private) network is two
decisions, and they are not the same one. The listener says which address the
server binds. The published port on the host says how much of that host the
bind reaches.

```toml
[[listeners]]
kind = "api"
addr = "10.0.0.1"   # the host's private address
```

`addr` is resolved inside the container, in the network namespace `serve`
runs in, so it has to be an address the container owns. `10.0.0.1` is the
host's address and the container does not have it: the bind fails with
`EADDRNOTAVAIL` and `serve` stops starting, because every address other than
`::` goes straight to `TcpListener::bind` with no other address to fall back
to. What bounds the exposure is therefore the published port, and there the
two forms are not equivalent:

```
10.0.0.1:8025:8025    # the API answers on the private address only
0.0.0.0:8025:8025     # the API answers on every address the host has
```

`epistle init` derives the `ports:` array of the `mail` service from the
listeners: every non-loopback listener is published as `<port>:<port>`, which
the engine publishes on every host address, and a loopback listener gets no
`ports:` entry at all. The three listeners that carry plain HTTP (`api`,
`web-dav` and `autoconfig`) are the exception: the generated map publishes them
on `127.0.0.1` unless it names another address, so `api` arrives as
`127.0.0.1:8025:8025` and not as `8025:8025` on every host address. A private
bind address does not by itself publish the API anywhere, and a wider
publication is the operator's decision, written in the override. The map is
regenerated, by `init` on a rerun and by `stack update`, which takes the
published ports from the listeners in the config, so an edit to `compose.yaml`
does not survive. The supported place for the pinned form is
`<data_dir>/compose/compose.override.yaml`, the file every stack invocation
passes after `compose.yaml`. Its lists are merged with the generated ones, so a
plain `ports:` entry there is added to the generated one, not put in its
place, and the engine refuses to bind both. Replace the list with the `!override` tag and
repeat every port the stack publishes:

```yaml
services:
  mail:
    ports: !override
      - "25:25"
      - "143:143"
      - "465:465"
      - "587:587"
      - "993:993"
      - "10.0.0.1:8025:8025"
```

Set the listener itself to `addr = "0.0.0.0"` (the container side). With this
the API answers on `10.0.0.1:8025` and not on any other host address. `epistle
stack update` and `epistle probe` check the API on the loopback of the host,
so they report `5 of 6 listeners answer` while the stack is running as
intended. See [the container stack](operations/container.md#bringing-up-the-stack) and the
notes on customizations in [`epistle stack`](cli.md).

Two things stay true whichever way the port is published:

- **Cleartext without TLS is a warning, not a refusal.** `api`, `web-dav`,
  `autoconfig` and `metrics` (and `submission`) bind outside loopback with no
  `[tls]` section without being rejected: validation logs `no-TLS listener
  bound externally; configure [tls] or front with a TLS proxy` and the server
  starts. Nothing refuses the configuration, so a private network carries the
  bearer key in clear: put a TLS proxy in front, or accept the exposure only
  inside the tunnel. [Listeners](configuration.md#listeners) has the whole list.
- **The key, not the address, is what an attacker needs.** Pin every key with
  `--ip-cidr` and `--expires-at`, and give each program its own key with only
  the scopes it uses. The allowlist is a second gate, not a replacement for
  the scopes.

### What `--ip-cidr` sees, and what a bridge takes away

`--ip-cidr` is matched against the address the server sees on the socket,
which is the peer of the connection, or the first untrusted address in
`X-Forwarded-For` when the peer is in `[api] trusted_proxies`. That is the one
place where the container network matters directly.

The `mail` service runs with `network_mode: "pasta"`, which is what
`epistle init` writes and what keeps the client's address intact. A bridge
does not: rootless Podman on a bridge funnels every connection through
`rootlessport` and the listener sees one internal address for everyone. A key
pinned to the client's real network then refuses the clients it was meant to
admit, and admits every client the container's own network holds instead.
`epistle api-key create` and `epistle api-key list` print a warning naming
the compose `network_mode` whenever that is the case, and `epistle status`
reports one item per pinned key. None of them changes the exit code, and on
`create --json` the advisory arrives in a `warnings` array that the result
object carries only when there is something to say, the same way `reload` is
optional.
`epistle app-password create --ip-cidr` matches the address the same way and
carries no such warning. Two ways out: keep `network_mode: "pasta"` on
`mail`, or front the API with a proxy, list it in
[`[api] trusted_proxies`](configuration.md#api) and have it set
`X-Forwarded-For` with the real client address.

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
| `--scope manage:read\|manage:write\|mail:read\|mail:write\|send\|scim\|alias\|ban\|health\|key` | Required, repeatable. Scopes are independent: `manage:write` does not include `manage:read`, and a management scope never opens JMAP or the other way round. `read` and `write`, the names before 0.15.0, are still taken and open both the management and the mail scope of their kind, with a warning |
| `--expires-at WHEN` | Unix seconds, a date (`2027-01-31`, midnight UTC), an RFC 3339 instant (`2027-01-31T12:00:00+02:00`) or a duration from now (`90d`). A date or instant already in the past is refused, and a bare number is read as an epoch only between 2001-09-09 and 9999-12-31, so `2027`, `20270131` and a count of milliseconds are refused. After the expiry the key is refused with `401`, like an unknown one |
| `--expires-in DURATION` | A number and a unit from now: `s`, `m`, `h`, `d` or `w`, for example `90d`. `m` is minutes, not months: count months in days. Not combined with `--expires-at` |
| `--ip-cidr CIDR` | One network the client must come from. A request from elsewhere is `401` |
| `--domain NAME` | Confine the key to a domain (repeat for more). Without it the key reaches every domain |
| `--account NAME` | Bind the key to one account. It then reaches only JMAP, `POST /api/v1/send`, `GET /api/v1/deliveries` and that account's suppression list, acting as that account, and cannot hold `manage:read`, `manage:write`, `scim`, `alias`, `ban`, `health`, `key` or `--domain` (`read` and `write` mean `mail:read` and `mail:write` for it) |
| `--class CLASS` | The mail class `POST /api/v1/send` gives mail sent with the key when the request names none (see [Class and evidence](#class-and-evidence)) |
| `--auto-submitted` | Add `Auto-Submitted: auto-generated` to mail sent with this key through `POST /api/v1/send` when the request omits the header. Off by default. A value in the request always wins. Other send paths and server-generated mail, including bounces, are not changed |

`epistle api-key rotate LABEL` replaces the secret and keeps everything else,
the class included; `epistle api-key set LABEL --auto-submitted on|off`
changes the `Auto-Submitted` setting and `epistle api-key set LABEL --scope S
[--scope ...]` replaces the scopes; `epistle api-key revoke LABEL` removes
the key; `epistle api-key list` shows the label, expiry, network, scopes,
domains, account and `auto_submitted` setting, never the key. The expiry is
printed as an RFC 3339 instant, with `(expired)` after one that has passed;
`--json` keeps the epoch and adds `"auto_submitted": true` only when the
setting is enabled, so disabled keys keep their existing JSON shape. The scopes
shown are the names the key was made with (`read` stays `read`), or the new
names once it is narrowed or was made with them. A key made
or changed by 0.15.0 is stored with two fields in `api_keys.toml`: `grants`, the
scopes above, and `scopes`, the narrowest of the old names that covers them
(`read`, `write`, `send`, `scim`, `alias`), so the same file still loads in
0.14.0 after a rollback.

0.14.0 must not give a key more than it holds. It reads only `scopes`, and in
its names: `read` opens the management and the mail reads together, `write`
both writes. So a key keeps working there only when its scopes are exactly what
a name of 0.14.0 opens: `manage:read` with `mail:read`, `manage:write` with
`mail:write`, `send`, `scim`, `alias`, and combinations of those (an account
reaches no management route in either release, so for a key bound to an account
the mail half alone is enough). Every other key, a `mail:write` key that could
change a password there, a `manage:read` key that could read mail, and any key
that holds `ban` or `health`, is written so that 0.14.0 loads the file and
refuses the key from every address: its `ip_cidr` is `held-until-0.15`, which
is no network, and the `ip_cidr` it really has is kept in a `[[rollback_hold]]`
table that 0.14.0 ignores. After a rollback these keys are unusable until
0.15.0 is back, which puts them back as they were. If 0.14.0 wrote
`api_keys.toml` in between, the table is gone and the key stays refused: make it
again.

Keys that an earlier build stored in another form (`scopes = ["read"]` for a key
that holds only `ban`, or one half of `read`) are rewritten the same way when
`epistle serve` starts and again by `stack rollback`, which stops if it cannot,
before it puts the old binary back. `epistle status` names each key that holds
only scopes 0.14.0 has no name for.

### The panel's key

When the stack runs the web panel, `epistle init` and `epistle stack update`
create a key labelled `panel` for it, with the scopes `manage:read`, `manage:write`, `mail:read` and `mail:write` only (its webmail calls JMAP with it),
no `--domain` and no `--account`, and a 365-day expiry. It is an
administrator-grade key: the panel acts for every domain. The secret is written
to `secrets/panel_api_token` beside the data directory with mode `0600` and is
never printed. `stack update` creates the key when it is absent, replaces the
secret when the file was lost, and renews the secret and the expiry when fewer
than 30 days remain. A key labelled `panel` with any other scopes, domains or
account is refused, not rewritten: revoke it and run the command again.

The panel's admin area is served at `/app/{id}`, where `{id}` is a UUID v4 of
this installation. `init` and `stack update` generate it once from the system's
random source and keep it in `secrets/panel_admin_id` beside the data directory
with mode `0600`; the panel reads it through `EPISTLE_PANEL_ADMIN_ID_FILE`. A
later run keeps it, narrows a wider mode to `0600`, and refuses a file that
holds anything but a lower-case UUID v4 (it never overwrites one: a new id
moves the admin area). It is not a cryptographic secret, since the session and
the admin role are the barrier, but it is not public: it appears in no plan, no
report, no `--json` output and no `epistle status`. `epistle panel admin-id`
prints it.

### Expiry is opt-in

No key expires unless it is given an expiry. There is no default lifetime: a
key an outside client depends on should not stop working on a date nobody
picked. Instead, `epistle status` warns, in its `api_keys` area, about
each key that

- has no expiry,
- expires within 14 days, or has already expired,
- holds every scope (a legacy key made before scopes existed),
- holds `read` or `write`, which open both management and mail (it is told to
  split the key, and the release from which `stack update` refuses a stack that
  still has one),
- holds a write scope or `send` with no `--domain`, no `--account` and no
  `--ip-cidr` (an `--ip-cidr` does not count while the server sits behind a
  network that hides the client address), so a leaked copy reaches every domain from any address, or
- holds `scim` or `alias` with no `--domain`, or `ban` or `health` with one (those routes refuse it).

These are warnings only; nothing is refused or revoked. To clear one, give the
key an expiry, narrow it with `--domain`, `--account` or `--ip-cidr`, or
recreate it with an explicit `--scope`. `epistle api-key rotate` keeps the
expiry, so extend a key by creating a new one.

What each scope reaches:

| Scope | Reaches |
|---|---|
| `manage:read` | Every `GET` and `HEAD` of `/api/v1` except the mail routes below |
| `manage:write` | Every other method of `/api/v1` except `send`, `aliases` and the mail routes below; `DELETE /api/v1/send/{id}` |
| `mail:read` | `/jmap/session`, `/.well-known/jmap`, `/jmap/download`, `/jmap/ws`, `/jmap/eventsource`, the JMAP methods that return data (`*/get`, `*/query`, `*/changes`, `*/queryChanges`, `Identity/get`, `Quota/get`, `SieveScript/validate`), and, for a key bound to one account, `GET /api/v1/deliveries` and `GET /api/v1/suppression?account=`; every other key reads those with `manage:read` |
| `mail:write` | `/jmap/upload`, the JMAP methods that change data (`Mailbox/set`, `Email/set`, `Email/copy`, `PushSubscription/set`, `VacationResponse/set`, `SieveScript/set`), and, for a key bound to one account, its own suppression list; every other key changes the suppression lists with `manage:write` |
| `send` | `POST /api/v1/send` and JMAP `EmailSubmission/set` |
| `scim` | Everything under `/scim/v2` |
| `alias` | Everything under `/api/v1/aliases`, reads included. `manage:read`, `manage:write` and the old `read` and `write` do not open it, and the key made before scopes existed (it holds every scope) does |
| `health` | `GET /api/v1/health` and `/api/v1/health/{area}`. No management or mail scope opens them. See [Health](#health) |
| `ban` | Everything under `/api/v1/bans`, reads included. No management or mail scope opens it. See [Bans](#bans) |
| `key` | Everything under `/api/v1/keys`, reads included. No management or mail scope opens it, and a key bound to an account never holds it. See [API keys](#api-keys) |

A key made before 0.15.0 keeps what it reached: `read` holds `manage:read` and
`mail:read`, `write` holds `manage:write` and `mail:write`, and a key with no
scopes holds every scope. OAuth access tokens keep asking for and carrying
`read`, `write` and `send`; they mean `mail:read`, `mail:write` and `send`, and
reach JMAP only. To split a key that holds `read` or `write`, run
`epistle api-key set LABEL --scope manage:read --scope manage:write` (or the two
`mail:` scopes).

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
| `401` `unauthenticated` | No header, an unknown or expired key, or a key pinned to another network. The three look the same. Every `401` carries `WWW-Authenticate: Bearer` |
| `403` `forbidden` | A valid key whose scopes do not cover the route. It does not count towards the authentication failure limit |
| `403` `forbidden` | The key is bound to one account and the route is administrative outside its suppression list, or the bound account is disabled or gone |
| `403` `forbidden_from` | `POST /api/v1/send` from an address the credential may not act for |
| `403` `sending_off` | `POST /api/v1/send` for an account whose sending is switched off (`epistle account set NAME --send off`) |
| `429` `rate_limited` | The client address made 20 requests with credentials that did not hold in the last 60 seconds. Every request from it is refused, valid or not, until the window passes. The `Retry-After` header gives the remaining window in seconds, rounded up. When too many credential checks are already waiting, the answer is the same `429` with `Retry-After: 1` and the request is not counted as a failure. The same code answers a stream refused by the caps of [Live updates](#live-updates) |

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
are counted apart, in the shared ban table: by default 5 failures in 15 minutes
ban the client or the account for 15 minutes, doubling up to 24 hours (`[bans]`
changes the numbers within its floors), with the same
answer as a wrong password. That table needs `[database]`; see
[Security](security.md).

If the static token's hash in `[api] token_hash` is an old argon2id string
and not `sha256:`, each request that is not a key costs an argon2 check: 2
run at a time, 64 may wait, and the next gets `429`. Use the `sha256:` form.

### Limit of `/api/v1/auth/verify` under a confined key

`POST /api/v1/auth/verify` answers `valid: true` only for an account the
bearer could legitimately verify. The configured token and administrative keys
without `account` or `domains` (= `DomainScope::All`), authorized for this route,
skip the post-auth membership check: the mail listeners accept any account the
directory knows, including SQL and LDAP ones, and the verify route must agree.
Account-bound keys cannot access `/api/v1/auth/verify`, even without `domains`.

A key confined to some domains narrows the post-auth check to the
`accounts()` listing (static + dynamic accounts). An account the listing
cannot resolve, such as a SQL or LDAP row without a static or dynamic shadow,
is answered `valid: false`, even with the correct password, and the
password is never tried: the password would have answered "the other
tenant exists with that password". The fail-closed answer is identical
to a wrong password, so a confined key cannot enumerate another
tenant's account names through this route.

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
the status.

### Problem details

A client that sends `Accept: application/problem+json` gets every error the
API decides as an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem.
Any other `Accept` (none, `application/json`, `*/*`, or the problem type with
`q=0`) gets the `error` object above, unchanged. The problem form is only for
errors the API itself decides; the plain-text rejections of the HTTP layer
stay as they are.

```json
{
  "type": "urn:epistle:problem:field_missing",
  "title": "A required field is missing",
  "status": 400,
  "detail": "At least one recipient is required.",
  "code": "field_missing",
  "instance": "urn:uuid:019e5c3a-7a40-7c10-9d6e-3f1b8f6a2c11",
  "request_id": "019e5c3a-7a40-7c10-9d6e-3f1b8f6a2c11",
  "errors": [{"field": "to", "detail": "At least one recipient is required."}]
}
```

`type` is `urn:epistle:problem:` followed by `code`, so it is stable and names
no host. `title` is the same for every occurrence of a type; `detail` is for
people and its wording can change. `request_id` is a fresh identifier for the
answer, and the server logs it (level `info`) with the status, the code, the
method and the path, so an operator given the id finds the line. `errors`
appears for an input error whose field is known.

In the problem, an `invalid_input` carries its cause as `code`:

| `code` | Meaning |
|---|---|
| `field_missing` | A field the request needs is absent or empty |
| `field_out_of_range` | A length or a count over or under what the field accepts |
| `value_not_allowed` | A value the field does not accept |
| `invalid_input` | Anything else; the field is not named |

The `error` object keeps `invalid_input` for all of them, so nothing that
reads it breaks. A `401` carries `WWW-Authenticate: Bearer` and a `429` carries
`Retry-After` in both forms.

The codes the API itself sends:

| Code | Status | Meaning |
|---|---|---|
| `unauthenticated` | 401 | See above |
| `forbidden`, `forbidden_from`, `sending_off` | 403 | See above, and a confined key on the global suppression list |
| `not_found` | 404 | The thing is not there, or is outside the key's reach |
| `invalid_input` | 400 | The message says which field |
| `conflict` | 409 | A limit that waiting will not lift: the tenant is at `max_accounts`, the account at its masked-address cap, a queue entry with evidence still to write |
| `already_sent` | 409 | `DELETE /api/v1/send/{id}` for a message the send delay already handed on. Nothing can take it back |
| `limit_reached` | 409 | A configured cap stopped the request (addresses per account at `POST /api/v1/accounts`). The message says which limit, its value, the scope that set it and how to make room |
| `message_too_large` | 413 | The built message is over the size limit of the server, or of the sending account (`[[limit_scope]] max_message_size`) |
| `scan_too_large` | 413 | Too large for the content scan, and the server lets nothing pass unscanned. Retrying cannot help |
| `virus_detected`, `attachment_refused`, `too_many_header_fields`, `marketing_refused` | 422 | Refused for its content; sending it again unchanged is refused again. Nothing was sent |
| `rate_limited` | 429 | The authentication limit above, or a sending limit (next section). Always with `Retry-After` in seconds |
| `internal` | 500 | The server failed. The message never carries details |
| `scan_unavailable`, `evidence_unavailable` | 503 | Nothing was sent; retrying later works |
| `unavailable` | 503 | Something the server needs cannot be reached now, such as the system resolver behind `/api/v1/dns/verify` |
| `timeout` | 504 | A check did not finish in the time its route allows (`/api/v1/dns/verify`: 45 seconds) |
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
{"queued": "01a15026-ff4b-7411-a7e9-9292a7662720", "message_id": "<01a15026-ff4b-7411-a7e9-9292a7662721@example.org>", "class": "personal"}
```

`queued` is the queue id. It is also the `spool_id` of every delivery record
and webhook event of the message, so keep it. A message for local recipients
only is delivered at once and also gets an id.

`message_id` is the `Message-ID` header the server wrote, with its angle
brackets. It is what a later request puts in `in_reply_to` and `references` to
continue the thread, and what a recipient's mail client shows. The server
makes it, so it cannot be chosen in the request; every message gets a new one.
Its domain is the domain of `from`.

A recipient in `to`, `cc` or `reply_to` can carry a display name, which is
written in front of the address in the `To`, `Cc` and `Reply-To` headers:

```json
{"to": [{"name": "Ana Pérez", "address": "ana@example.org"}, "bob@example.org"]}
```

A plain string keeps its meaning: the address alone. A string of the form
`Ana Pérez <ana@example.org>` is refused; use the object. The name follows
the rules of `from_name`: at most 128 characters and no control character or
line break. It is written as a quoted string when it holds a comma, a quote,
a backslash, parentheses, angle brackets or an at sign, and as RFC 2047
encoded-words when it holds non-ASCII text. A name that cannot be written
safely is refused with `400 invalid_input` and the field `to[2].name`
(`reply_to.name` for a single reply address, `reply_to[1].name` inside a list);
it is never dropped or altered.
Names in `bcc` are checked but appear in no header. The envelope, the
delivery records and the webhook events identify a recipient by its address
only. An address given more than once is one recipient, and the first name
given for it is the one written in the header.

| Field | Type | Notes |
|---|---|---|
| `from` | string, required | A bare address, no display name. Must be one the acting account owns |
| `from_name` | string | The phrase of `From`. Absent uses the account's display name. At most 128 characters |
| `to`, `cc`, `bcc` | arrays of recipients | A recipient is a bare address or `{"name": "Ana Pérez", "address": "ana@example.org"}`; see below. `to` is required but may be empty if `cc` or `bcc` has someone. Together at most 100 distinct addresses by default (`max_recipients`). `bcc` is envelope only. With `to` and `cc` both empty the message carries `To: undisclosed-recipients:;`, an empty group, so no header names a recipient |
| `reply_to` | recipient or array of recipients | A bare address or the same object, or a list of them (at most 10), written as one `Reply-To` header. An empty list or `null` writes none |
| `sender` | string | A bare address; it must be one the account owns, like `from` |
| `envelope_from` | string | The address bounces and delivery reports go back to (`MAIL FROM`), where `from` is what the reader sees. A bare address the account owns, like `from`; absent is `from`. An empty string is refused: the null sender is not offered here. The `From` header, the DKIM signature and the `Message-ID` keep following `from`; see below for what else follows which address |
| `subject` | string | Default empty. A request with no subject, no `text`, no `html`, no `attachments` and no `inline` is an empty message and is refused with `400 invalid_input` on `text` |
| `text`, `html` | string | With both, a `multipart/alternative`, text first |
| `attachments`, `inline` | arrays of `{name, content_type, data, content_id}` | `data` is base64 (standard alphabet, padded). An empty `content_type` is detected. Every `inline` part needs a `content_id`; the HTML refers to it as `cid:<content_id>`. At most 100 parts together |
| `in_reply_to`, `references` | string | `<id@domain>` ids, space separated: one for `in_reply_to`, up to 100 for `references` (in practice about 50, because each header value is at most 1000 bytes) |
| `importance` (or `priority`) | `high`, `normal`, `low` | Writes `Importance` and `X-Priority` |
| `list_unsubscribe` | array of strings | Up to 4 `mailto:` or `https://` URLs |
| `list_unsubscribe_post` | boolean | Adds the RFC 8058 one-click header. Needs an `https://` URL in `list_unsubscribe` |
| `auto_submitted`, `feedback_id` | string | `Auto-Submitted` (`no`, `auto-generated`, `auto-replied`, `auto-notified`) and `Feedback-ID` (printable ASCII, no spaces). A value in the request always wins. When `auto_submitted` is absent and the API key has the per-key setting enabled, the server writes `Auto-Submitted: auto-generated` |
| `auto_response_suppress` | boolean | Default `false`: writes `X-Auto-Response-Suppress: DR, NDR, RN, NRN, OOF, AutoReply` when true, independently of the server mail setting and `auto_submitted`. |
| `headers` | object | Custom headers: up to 32, name `X-` plus letters, digits and hyphens (at most 76 characters), neither `X-Priority` nor `X-Auto-Response-Suppress` |
| `save_sent` | boolean | Whether a copy goes to the account's Sent folder. Absent follows the account setting. Transactional mail is never copied |
| `extra` | object of strings | Correlation data, up to 10 keys (printable ASCII, no spaces, at most 64 bytes) with values of at most 256 bytes. It comes back on `/api/v1/deliveries` and in the webhook events of the message and is never written into the message |
| `class` | `transactional`, `marketing`, `personal` | See below |
| `dry_run` | boolean | Default `false`, also for `null`. Runs every check of a send and answers what would happen, without sending; see below |

A refusal for a limit names the limit: `Too many recipients; the maximum is 100.`, the same for attachments, custom headers, `reply_to`, `list_unsubscribe`, `references` and the `extra` map.

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
exist. The envelope sender is `envelope_from` when the request has it and the `from` as written otherwise; the same rule and the same `403 forbidden_from` hold for `sender` and `envelope_from`.

**Which address counts for what.** `from`, `sender` and `envelope_from` may be three different addresses, and each is held to the account and to the key: a key confined to some domains is refused (`403 forbidden_from`) when any of the three is outside them, even when the account owns it as a member of a list in another domain. The sending rate limit of every tenant that owns one of the three is checked and charged. The suppression lists, which are kept per sender, are asked about the envelope sender and about the address in `From`, and the queue asks again before delivering. The evidence tenant and its retention follow the `From` address, not the envelope sender.

**An account that does not send.** An account whose `send` switch is off
(`epistle account set NAME --send off`) sends nothing through the API: a key
bound to it, or any other key whose `from` names one of its addresses, gets
`403 sending_off`, whatever the sender, before any rate limit is spent. The
refusal names the account's own state and tells nothing about other addresses.
Signing in and reading mail are not affected. The same switch is what SMTP
submission, JMAP and the account's own forwarding and auto-replies follow.

### Dry run

`"dry_run": true` runs the whole request through the checks of a real send and
queues nothing:

```json
{"dry_run": true, "class": "marketing", "recipients": 1, "size": 2314, "suppressed": ["gone@example.net"]}
```

The answer has the `class` the server would grant, the number of envelope
`recipients` left after suppression, the `size` in bytes of the message as it
would be queued (about: the `Date` and `Message-ID` it will get are not fixed
yet), and `suppressed` when a marketing message would drop recipients. It has
no `queued` and no `message_id`: nothing was queued and no identifier is
reserved. The checks are the ones of the real request: the scope and the
credential's reach, sender ownership, `sending_off`, the address, header and
size rules, the account, tenant and domain size caps, the full-mailbox check,
the class rules, the sending rate limit and the cap on first-time recipients.
A request refused for one of them is refused with the same status and body
with or without `dry_run`, but for the mailbox checks below.

A dry run is a question that costs a send nothing, so it has limits of its
own, per account: one unit per recipient, at most 600 recipients a minute,
and at most 1000 addresses a day that the account never wrote to. Past
either, the answer is `429 rate_limited` with `Retry-After`, and what it
asked is not counted again once refused. It measures only the mailboxes of
the local recipients the key reaches: for any other address it does not
check the mailbox, so it cannot be used to ask whether someone else's
mailbox is full.

A dry run of a marketing message reads the suppression lists, the one every
tenant shares among them, and would tell which addresses are on them. It is
therefore for an unconfined credential that holds `manage:read`: any other is
refused `403` before a list is looked at, with the same answer whatever the
lists hold. A confined credential keeps the real send and the personal and
transactional dry runs. For a confined credential a dry run does not measure
aliases, whoever their members are, since what it would measure depends on
accounts the credential does not reach. The sending limits are asked for as
many units as the real send charges, the recipients left after the suppressed
ones.

It spends nothing from the sending limits: no rate limit unit is charged, no recipient counts as
written to for the first-time cap, no evidence record is written, no Sent
copy is saved and nothing reaches the spool or a mailbox. It does not run
what happens after queueing, so it does not tell that the antivirus will
refuse an attachment, that the content scan is up, or that the evidence log
can take a record.

### Taking a send back

When the server holds what accounts send for a few seconds (`[queue.undo_send]`
in the [configuration](configuration.md#queueundo_send), off by default), the
answer to `POST /api/v1/send` also carries `cancel_until`, an RFC 3339 instant:

```json
{"queued": "01a15026-ff4b-7411-a7e9-9292a7662720", "message_id": "<01a15026-ff4b-7411-a7e9-9292a7662721@example.org>", "class": "personal", "cancel_until": "2026-11-16T10:00:30Z"}
```

Until then, and before anything of the message is delivered or queued,
`DELETE /api/v1/send/{id}` (the `queued` id) takes it back:

```json
{"canceled": "01a15026-ff4b-7411-a7e9-9292a7662720"}
```

It needs the `send` or the `manage:write` scope. A key bound to one account cancels
that account's messages; a key confined to some domains cancels those of the
accounts it reaches; an unconfined key cancels any. An id that is unknown,
that belongs to an account the key does not reach, or that was never held
(the delay is off, or the message is not one the account sent) answers the
same `404 not_found`, so the answer says nothing about other accounts'
messages. A message the delay already handed on answers `409 already_sent`
to the account that sent it: from that moment it is in the queue or in
mailboxes and cannot be taken back (an operator can still remove the queue
entry). The id is a UUID and is not a secret: the answer depends on who asks,
not on knowing it. The same cancel is `EmailSubmission/set` with
`undoStatus: "canceled"` over JMAP and `epistle queue undo cancel ID` for the
operator.

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
| Message size | `max_message_size`, 25 MiB by default, and below it the cap of the account, its domain or its tenant (`[[limit_scope]]`) | A built message over it: `413 message_too_large`, naming the cap and the scope that set it. A request body over the server's: plain-text `413` |
| Recipients | 100 per message (`to`, `cc`, `bcc` together) | `400 invalid_input` |
| Parts | 100 attachments and inline parts together | `400 invalid_input` |
| Submission rate | `submission_rate_limit_per_min` recipients per minute per account, shared with SMTP and JMAP; per-domain and per-tenant limits too | `429 rate_limited`, "sending rate limit exceeded; retry later", with `Retry-After: 60`. Nothing was sent |
| New recipients | `new_recipients_per_day` first-time recipients per account per rolling 24 hours | `429 rate_limited`, "too many new recipients today; retry tomorrow", with `Retry-After: 86400`. `503 unavailable` while the cap cannot be checked; nothing was sent |
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
configured. The removal writes one `queue.removed` on `epistle::api::audit`,
with the id of the message, the account that sent it when the envelope knows
it (the pseudonym the logs use, never the name), the label of the key that
asked and the client address. The recipients and the subject of the message
are not in it, and the key itself never is.

The cursor of a page is opaque: carry it back as it is. It is the id of an
entry the key reaches, or, when the page ended on an entry of another tenant,
a sealed marker that names no entry at all, so a key confined to some domains
never learns the id of an entry it cannot see. A cursor the server did not
issue is refused with `400`.

One entry in detail, and its schedule. `GET /api/v1/queue/{id}` prints what
`epistle queue show --json` prints: the envelope and its retry state
(`attempts`, `next_attempt`, `held`, `last_error`), never the message. With
`?headers=true` it also returns the header fields of the message, in order,
folding undone, up to 200 of them with a value cut at 1000 characters
(`headers_truncated` says when something was left out); the body is never
read past the blank line. `POST /api/v1/queue/{id}/retry`, `/hold` and
`/release` do what `epistle queue retry`, `hold` and `release` do to one
entry, with the `manage:write` scope, and answer `{"changed", "id", "held"}`:
`changed` is false when the entry already was as asked, and then no audit line
is written. Each change writes one (`queue.retried`, `queue.held`,
`queue.released`) with the label of the key. A key confined to some domains
reaches the entries whose sender is inside them, and an entry of another
tenant and one that is not there are the same `404 no such queue entry`.
An entry belongs to the hosted domain the server decided when it queued it (the
domain of the account that sent it, of the local recipient that forwarded it, or
of the delivery that produced a report), never to the sender the message names:
anyone can write a tenant's domain in `MAIL FROM`. So a forward, with or without
SRS, and a return are the tenant's whatever their reverse-path says, an entry
with no owner is reached by a key with no confinement only, and the same rule
decides the list, the removal and these routes. A release is refused with `409`
for an entry whose removal began (it stays on hold until it is gone, and the
worker does not attempt it), and a confined key lifts only a hold put by a key
confined inside its own domains: the operator's, or one put by a key outside its
reach, is `403` and stays. `DELETE /api/v1/queue/{id}` follows the same rule for a hold: a confined key does
not remove mail the operator, or a key outside its reach, put on hold (`403`, the
entry stays), decided on the entry as it is under the spool's lock before anything is written,
so a hold put between the check and the removal counts, and so does one put on an
entry a removal is already holding (the hold a removal puts on an entry is only a
marker, and no one's hold). `--all` stays with the command. `GET /api/v1/queue/destinations` lists the
destinations the queue holds off and the receiver groups at their warm-up cap,
as `epistle queue destinations --json` does (at most 1000 rows, `truncated`
says more); the holds are shared by every tenant, so a confined key is
refused with `403`.

`GET /api/v1/suppression` lists suppressed recipients,
`POST /api/v1/suppression` adds one and `DELETE /api/v1/suppression/{address}`
clears one. The POST body is `{"address": "recipient@example.net"}` with an
optional `reason` (at most 512 characters, no control or invisible formatting
characters). The reason is stored with the entry; the suppression listing
returns addresses only. The address is validated by the server, and adding an
address already on the list succeeds without replacing its first reason or
timestamp.
`?account=` selects one account name or sending address's list instead of the
global one. `?tenant=NAME` selects a tenant's list (`GET` and `DELETE`, not both with
`account`); like the global list it is refused to a confined key. A key confined to an account or domain may use only the list of an
account it can act for; the global list needs an unconfined key.
Pages end when `next_cursor` is absent.

## Live updates

`GET /api/v1/events` (scope `read`) is a `text/event-stream` for dashboards
that would otherwise poll. It carries notifications, not data: each event
names a topic that changed and nothing more, so the client fetches the detail
from the route it already uses and every authorization check stays where it is.

```sh
curl -sN -H "Authorization: Bearer $KEY" "$API/api/v1/events"
```

```text
id: 1792346437.12
event: queue
data: {"topic":"queue"}
```

| Topic | Something changed in |
|---|---|
| `queue` | The outbound queue: a message entered or left it |
| `deliveries` | The delivery log (only while `delivery_log_days` is above `0`) |
| `suppression` | A suppression list, the shared one or an account's |
| `status` | What `GET /api/v1/status` counts |
| `accounts` | An account was added, removed or changed |
| `domains` | A hosted domain was added, removed, switched or changed |

No address, subject, message content or credential is ever in an event. The
`data` is `{"topic": "<name>"}` and the `id` is opaque: keep it, and send it
back as `Last-Event-ID` when you reconnect.

- **Coalescing.** Changes are looked for once a second, so a burst of queue
  activity is one `queue` event, and a reader that was slow gets one event per
  topic with the id of the last change.
- **Resuming.** The last 256 notifications are kept in memory. A reconnect with
  `Last-Event-ID` is sent what came after that id. If the server cannot replay
  from it (the ring moved past it, the server restarted, or nobody was
  connected for a while, because nothing is watched without a stream) it sends
  one event for each topic the key may be told about, which means "fetch
  everything again". A new connection without the header is told only what
  happens from then on.
- **What a key sees.** An unconfined key gets every topic. A key confined to
  some domains gets only `status`, `accounts` and `domains`, and only when the
  change touched a domain or an account it reaches (an account that moves
  between tenants is told to both). It gets no `queue`, `deliveries` or
  `suppression` event, because the data behind them is shared and cannot be
  filtered without reading every entry. A key bound to one account is refused
  with `403`, as on every administrative route. A missing, unknown or expired
  key is `401`, a key without `read` is `403`, and both are problem details like
  every other refusal.
- **Limits.** A key may hold 4 streams and the server 64; the next is refused
  with `429` and `Retry-After` (`[api] event_streams_per_key`,
  `event_streams_per_server`). A comment line (`:heartbeat`) is sent every 15
  seconds so a proxy does not close an idle stream. A stream lives one hour
  (`event_stream_max_secs`) and is closed, and the client reconnects. The key
  is checked again twice a second: a stream whose key was revoked, expired,
  narrowed or lost `read` is closed. A client that stops reading is closed when
  the ring moves past it; nothing is queued for it.
- **Cost.** One task samples the server while at least one stream is open, and
  none runs otherwise. It lists the queue directory once a second, so a very
  large queue makes that listing the cost of each open server, not of each
  stream.

Behind a reverse proxy, turn response buffering off for this path; the answer
carries `X-Accel-Buffering: no` for nginx.

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
| `GET /api/v1/dns/records` | The records the hosted domains need, as `epistle dns-records --json` prints them; `read`. See [DNS](#dns) |
| `GET /api/v1/dns/verify` | A check of the live DNS against them, as `epistle verify-dns --json` prints it; `read`. See [DNS](#dns) |
| `GET /api/v1/health`, `GET /api/v1/health/{area}` | What `epistle status --json` and `epistle check <area> --json` print; scope `health`. See [Health](#health) |
| `GET /api/v1/domains` | The hosted domains in the key's reach, which are `disabled`, and under `details` the rows `epistle domain list --json` prints |
| `GET /api/v1/domains/{domain}` | What `epistle domain show <domain> --json` prints. A domain outside a confined key's reach is `404` like an unknown one |
| `POST /api/v1/domains` | Host a new domain; unconfined `write` key only; answers `201` |
| `DELETE /api/v1/domains/{domain}` | Stop hosting an unused domain; `write`, confined to the path domain. The `409` names what still uses it for an unconfined key; a confined key gets only `domain is still in use`. An account created through the API at the same moment can still land on the domain being removed (the in-use check reads `accounts.toml` while account creation checks the running snapshot), as with `epistle domain remove` |
| `PUT /api/v1/domains/{domain}` | Set `role`, `quota` (bytes), `submission_rate` (recipients/minute) atomically; `write`; `quota` and `submission_rate` need an unconfined key (`403` for a confined one) |
| `POST /api/v1/domains/{domain}/enable` | Enable, keeping the stored role; `write` |
| `POST /api/v1/domains/{domain}/disable` | Disable, keeping the stored role; `write`; refuses the last enabled domain with listeners |
| `POST /api/v1/domains/{domain}/aliases` | Add `{"alias":"example.net"}` targeting the path domain; `write`; answers `201` |
| `DELETE /api/v1/domains/{domain}/aliases/{alias}` | Remove an alias currently pointing to the path domain; `write` |
| `GET`, `POST /api/v1/aliases` | List the address aliases (paged, filtered by `domain` and `account`), make one; scope `alias`; create answers `201`. See [Address aliases](#address-aliases) |
| `DELETE /api/v1/aliases/{alias}` | Remove an address alias; scope `alias` |
| `GET`, `POST /api/v1/bans`, `DELETE /api/v1/bans/{subject}`, `GET`, `POST /api/v1/bans/allow`, `DELETE /api/v1/bans/allow/{cidr}` | The bans in force, banning, lifting, and the allow list; scope `ban`. See [Bans](#bans) |
| `GET`, `POST /api/v1/keys`, `DELETE /api/v1/keys/{label}` | List, make and revoke API keys, never reaching further than the key that asks; scope `key`. See [API keys](#api-keys) |
| `GET`, `POST /api/v1/accounts` | List (not paged), create. A duplicate name or address is `400 invalid_input` |
| `DELETE /api/v1/accounts/{name}` | Removes the account and its data. Only accounts made through the API; one declared in the configuration file is `404 no such dynamic account`. The removal runs to its end even if the client goes away. A removal that finishes writes `account.removed` on `epistle::api::audit`. One that stops after it began to clear the account writes `account.removal_incomplete` instead: the account may still exist, and running the removal again takes it over. |
| `PUT /api/v1/accounts/{name}/password` | New password. The change writes `account.password_reset` on `epistle::api::audit`, with the account and the client address; the password and its hash are never in it |
| `PUT /api/v1/accounts/{name}/display_name` | `{"display_name": "..."}`; empty clears it |
| `PUT`, `DELETE /api/v1/accounts/{name}/quota` | Set the storage quota (`{"quota":"10G"}`; `none` for the default) or clear it, as `epistle account quota` does; `manage:write`, and only for a key confined to no account and no domain. See [Account quota](#account-quota) |
| `POST`, `DELETE /api/v1/accounts/{name}/totp` | Enrol a fresh secret (returned once, effective at once) or turn two-factor off |
| `GET /api/v1/accounts/{name}/mailboxes` | Mailbox names and a tree |
| `GET`, `POST /api/v1/accounts/{name}/masked` | Masked addresses; create answers `201` |
| `PATCH`, `DELETE /api/v1/accounts/{name}/masked/{address}` | Enable or disable, remove |
| `GET /api/v1/accounts/{name}/archive`, `POST .../archive/{id}/restore` | Expunged messages kept by `deleted_retention_days`, and put one back |
| `POST /api/v1/auth/verify` | Check a login and password; `{"valid": bool, "admin": bool}`. Scope `write` |

Reading and writing the `Created`, `Removed` and other bodies is in the
OpenAPI document, which also has every response code per route.

### DNS

`GET /api/v1/dns/records` answers `{"records": [...], "skipped": [...],
"complete": true}`. `records` holds the rows `epistle dns-records --json`
prints (`name`, `ttl`, `type`, `value`, a TXT value unsplit), computed by the
same code. `skipped` names the groups the configuration does not publish
(`[dns_publish] skip`) and how many records each holds: they are not missing.
`complete` is false when an input could not be read, such as a DKIM key or the
certificate; the list may then lack a record, and the server's log names the
input. The answer never names a file.

`GET /api/v1/dns/verify` answers what `epistle verify-dns --json` prints,
`{"ok": false, "groups": [{"name": "example.org", "checks": [...]}]}`, with
each check `ok`, `missing`, `error` (a lookup that failed, inconclusive) or
`skipped`. Drift is a normal `200` with `ok: false`. The server asks its own
resolver, built for each check, so it reuses no answer an earlier check cached;
the name servers it asks may still hold a cached answer of their own.

Both take `?domain=example.org` to cover one hosted domain, and both are
reads: scope `read`.

- A key with no domain or account restriction gets the mail host as well: the address
  records of the hostname and its TLSA record in the list, and the hostname's
  addresses and reverse DNS as the first group of the check. Naming a `domain`
  leaves the host out.
- A key confined to some domains gets those domains and never the host. A
  `domain` outside its reach and one the server does not host are both
  `404 no such domain`. A key bound to one account is refused with `403`.
- Bounds. A listing covers at most 200 domains and a check at most 20, because
  each domain is about a dozen lookups; past that the answer is `400` and
  names `?domain=`. Two checks run at once on a server; the third is `429`
  with `Retry-After`. A check not finished in 45 seconds is `504 timeout`, and
  a resolver that cannot start is `503 unavailable`. The two places for a check
  belong to the whole server, not to a key, so one key can hold both. The caps
  on domains belong to the routes: the commands have none. The routes write no
  audit line, since they change nothing.

### Changing hosted domains

Domain writes share the commit and refusal rules of `epistle domain`. They
write `<data_dir>/domains.toml` under its cross-process lock, with an atomic
owner-only rename. Adding a domain also makes its SRS secret and, when DKIM
is configured, a key under `<data_dir>/keys/dkim/`. The API container needs
write access to data_dir; `/etc/epistle` can remain read-only. The running
server applies changes through its file watcher, asynchronously. A successful
write does not mean every listener has already observed it.

`POST /api/v1/domains` takes `{"domain":"example.net","role":"full"}`;
`role` defaults to `full`, and also accepts `send-only` or `receive-only`.
`shared_dkim_key: true` opts into the configured shared DKIM key. The default
makes a key of its own, like the CLI. Secrets are never returned.

All mutations need `write`. A new hosted domain requires an unconfined key,
even when its name appears in a confined key's allowed domains. Other domain
writes require the path domain in the key's reach. Alias writes additionally
require the alias name in that reach: a tenant cannot claim or remove another
tenant's name. A foreign domain or alias answers `404 no such domain`, before
looking up whether it exists. An unconfined key gets the CLI's precise
unknown-domain or unknown-alias message.

Names are validated on the server with the CLI's ASCII DNS-name rules,
trimmed and lowercased. Unicode names must be supplied as ASCII A-labels.
A trailing dot, empty label, control character or path component is refused.
Unknown fields and mistyped JSON fields are rejected by the HTTP extractor.

`PUT /api/v1/domains/example.net` takes any subset of `role`, `quota` and
`submission_rate`. Omitted fields stay unchanged. A null quota or rate clears
the domain override (the server default then applies); quota 0 is explicitly
unlimited, and rate must be 1 through 4294967295. Quota is an integer byte
count, at most 9223372036854775807. CLI unit strings such as `1G` are not JSON
numbers. Role null also leaves it unchanged. Role and limits commit together,
so an invalid limit cannot leave a changed role behind. Limits are the
operator's: a key confined to some domains may change the `role` of its
domains but any request naming `quota` or `submission_rate`, even a null that
clears one, is `403 forbidden`; an empty body is `400 invalid_input`.

Every successful mutation returns `{"changed":true,"domain":"example.net",
"reload":"watcher"}` (the target domain for alias routes). A no-op returns
`changed: false` and `reload: "none"`, succeeds with `200`, and does not create
or replace the state file. Already-hosted domains and existing aliases are
CLI refusals, `409 conflict`, rather than no-ops. Domain-in-use and
last-enabled-domain refusals are also `409`, preserving the CLI message;
malformed names or invalid limits are `400 invalid_input`, unknown names
are `404 not_found`, and storage failures are `500 internal`.

Each durable change emits one structured event on `epistle::api::audit`, written by the same thread that makes the change, so a client that drops the connection after the write still leaves the line:
`domain.added`, `domain.removed`, `domain.enabled`, `domain.disabled`,
`domain.updated`, `domain.alias_added` or `domain.alias_removed`, with `domain`
(the alias name for alias events) and `client_ip`. Refusals and no-ops emit no
change event. Bearer tokens, private keys and SRS secrets are never logged.

### Health

`GET /api/v1/health` answers what `epistle status --json` prints, from the
same code, and `GET /api/v1/health/{area}` what `epistle check <area> --json`
prints: one object keyed by the name of the area (`config`, `ports`, `tls`,
`dns`, `db`, `api_keys`, `antivirus`, `antispam`, `queue`, `disk`, `spool`,
`storage_keys`, `subid`, `boot`, `warmup`, `resources`, `clock`, `evidence`,
`deliverability`), each with `status` (`ok`, `warn` or `fail`), a `detail` and
its `items`. The answer is `200` whatever the areas find; a failing area is in
the body, and the command's exit code has no HTTP counterpart. A name that is
not an area is `404 no such area`.

The scope is `health`, and only that: `read` does not open it. The answer
names the listeners, the certificate, the disk, the key labels and the state of
the stack, which belong to the server and not to a tenant. A key confined with
`--domain` or bound to an account is refused with `403`, before the name of the
area is looked at, so the status says nothing of which areas exist;
`epistle api-key create` makes neither, and `epistle status` warns about one it
finds in `api_keys.toml`.

The areas run against the configuration the server runs with now, with the
state files laid over it, and the `config` area names the file the server was
started with. They run inside the server, so an area that reads the host or the
stack's tools (`boot`, `resources`, `clock`) reports what it can see from
there, which is not always what the command sees on the host. Every area is cut off after 60 seconds, as in the
command, and at most two runs are in progress on a server, however many API
listeners it has: the third is `429` with `Retry-After`. The places are the
server's, so one key can hold both. A run is a task of its own: a client that
leaves neither stops it nor frees its place, which is given back when the last
thread the run started has returned. The programs a check runs (`systemctl`,
`podman` and the like) are killed, with whatever they started, when the area's
time is over. The same time holds the collection of what they print: a program
that ends and leaves something running that keeps its output open does not hold
the run past it, the process group is killed when the program ends, at most 4 MiB
of output is kept (the rest is read and dropped, so a program is never stopped by
a full pipe), and the checks that ask the mail container, and `podup ps`, run on
the thread that keeps the run's place and are killed at the same time.
The routes write nothing and write no audit line.

### Bans

`/api/v1/bans` is `epistle ban` over HTTP, through the same code: the bans in
force, banning an address or a network, lifting a ban, and the allow list of
the addresses that are never banned. The bans live in PostgreSQL, so a server
without `[database]` answers `404` (`bans are not manageable`), as the command
says so and exits 1.

| Route | What it does |
|---|---|
| `GET /api/v1/bans` | The bans in force, as `epistle ban list --json` prints them (`subject`, `reason`, `until`), ordered by subject and paged: `limit` (100 by default, 500 at most) and `cursor` (the `next_cursor` of the page before) |
| `POST /api/v1/bans` | `{"target":"203.0.113.9","for":"90m"}` bans an address or a network; `for` is a number and a unit (`s`, `m`, `h`, `d`, `w`), a day when absent. Answers `201` with `target` and `until` |
| `DELETE /api/v1/bans/{subject}` | Lifts a ban and clears its failure records. Name the subject as the listing prints it, percent-encoded: `203.0.113.9`, `cidr:203.0.113.0%2F24`, `pair:alice@example.org\|203.0.113.9`, `account:alice@example.org`. A subject with no ban and no failure record is `404` |
| `GET /api/v1/bans/allow` | The allow list, as `epistle ban allow list --json` prints it |
| `POST /api/v1/bans/allow` | `{"cidr":"10.1.0.0/16"}` adds a block; `201`, or `200` with `changed: false` when it was there |
| `DELETE /api/v1/bans/allow/{cidr}` | Takes a block off the list, percent-encoded (`10.1.0.0%2F16`); `404` when it is not there |

All of it needs the `ban` scope, and only that one: `read` and `write` do not
open it, and neither does the key made before scopes existed. A ban locks
clients out and the allow list exempts them from every ban, so a leaked key of
this kind is a way to shut out the panel or to switch the bans off. The bans
belong to the server and not to a tenant, so a key confined with `--domain` is
refused with `403` and so is one bound to an account; `epistle api-key create`
does not make either, and `epistle status` warns about one found in
`api_keys.toml`.

A key is held to a narrower reach than the operator at a terminal, in the
shape of the alias routes:

- no network wider than a /16 of IPv4 or a /32 of IPv6 may be banned or
  allowed (`400`); the command takes any block but the whole internet to ban
  and any block at all to allow;
- an address on the allow list cannot be banned (`409`, as the command says);
- a key may leave at most 10000 manual bans in force (the bans the listeners
  raise on their own are not counted, so they cannot use up its room), at
  most 100 banned networks and 100 allowed networks (a block, not one
  address), and 1000 allow-list entries (`409`). A few hundred networks of a
  middling size would cover more than any one of them does, so the networks
  have a count of their own. The command has no count;
- a key may lift or remove only what it could have made: a network ban or an
  allow-list block wider than a /16 of IPv4 or a /32 of IPv6, which the
  operator may have set, stays until the operator lifts it (`400`);
- a body is at most 4 KiB and carries only the fields above.

Every change writes one audit line (`ban.added`, `ban.removed`,
`ban.allow_added`, `ban.allow_removed`) with the label of the key and the
client address; an account named by a subject is written as the pseudonym the
logs use. The change and its line are made together on a task the request does
not own, so a client that goes away leaves both or neither. The counts above are
made and written in one step by the store (one transaction under a lock), so
requests that arrive together at the edge take no more than the room left. A refusal and a request that changed nothing write none. A database
that fails is a plain `500`: the answer never carries its message.

### API keys

`/api/v1/keys` is `epistle api-key` over HTTP, through the same rules: a key
that makes keys is the way to every other, so what it makes never reaches
further than it does. The scope is `key`; `read` and `write` do not open it, and
a key bound to an account never holds it (`403`).

| Route | What it does |
| --- | --- |
| `GET /api/v1/keys` | The keys the caller could have made (all of them for the configured token), as `epistle api-key list --json` prints them, ordered by label and paged: `limit` (50 by default, 200 at most) and `cursor`. Neither the secret nor its digest is ever listed |
| `POST /api/v1/keys` | `{"label":"ci","scopes":["manage:read"],"domains":["example.org"],"expires_in":"90d"}`. The scopes are those of the command; `read` and `write` are still taken and open both the management and the mail scope of their kind (only the mail one for a key bound to an account). `account`, `expires_at` (or `expires_in`, not both), `ip_cidr` and `auto_submitted` are the options of the command. Answers `201` with the key as listed plus `key`, its secret, once; the answer is `Cache-Control: no-store` and only a digest is kept |
| `DELETE /api/v1/keys/{label}` | Revokes a key; the running server stops accepting it at once. Answers `{"revoked":"<label>"}` |

A key makes only a key that is inside its own reach (`403` otherwise):

- every scope the new key holds, the caller holds, and the scopes that act on
  the whole server (`ban`, `health`) go only to a key with no domains and no
  account;
- every domain it names is one the caller is confined to (a caller with no
  domains may name any hosted domain, and a domain the server does not host is
  `400` whoever asks), and one with no domains reaches every domain only if the
  caller does;
- an `account` has to be one whose addresses are all inside the caller's domains;
- `ip_cidr` is inside the caller's, and a key pinned to a network makes only
  pinned keys;
- `expires_at` is no later than the caller's own, and a key that expires makes
  only keys that expire.

The same reach limits what a key lists and revokes: the keys it could have
made. A key it cannot reach and one that does not exist are the same `404`, so
a tenant does not learn which labels the others use. A key may revoke itself.

A key may leave at most 500 keys in the file (`409`); the configured token has
no cap. The label is unique (`409`). The key that asks is read again under the
lock of the file when a key is made or revoked, with what it reaches at that
moment, so one revoked or narrowed a moment ago does no more than it may now,
and requests that arrive together for one label make one key. A body is at most
4 KiB and carries only the fields above.

Every change writes one audit line (`key.created`, `key.revoked`) with the
label of the key that asked, the label and the scopes of the key it touched and
the client address, and never a secret or a digest. The change and its line are
made together on a thread a client that goes away does not stop.

### Account quota

`PUT /api/v1/accounts/{name}/quota` with `{"quota":"10G"}` and
`DELETE /api/v1/accounts/{name}/quota` are `epistle account quota` over HTTP,
through the same size parser (`500M`, `10G`, `1T`, any case, or `none` for the
server default) and the same store call, so the answer is the object `--json`
prints: `result`, `action`, `account` and `quota_bytes`. A quota of zero is
refused (`400`): it would refuse all mail, which the command lets an operator do
and a request may not. So is a size above 8191 petabytes (`9000000T`): the account
file keeps a quota as a TOML integer, and a number it cannot hold would leave a
file nothing can read, in which the check that a domain is still in use would find
no accounts. That check now refuses to remove a domain when it cannot read the
file. The command takes the same limit, since it shares the parser.

The scope is `manage:write`, with one more condition: a quota is room on the
server's disk, so only a key that is not confined to domains and not bound to an
account sets or clears one. A tenant's key could otherwise give its accounts any
amount, or put them back on a default larger than what they have. Any other key
is `403` whatever the account, so it learns nothing of which accounts exist.
Setting a quota takes no place of a tenant's `max_accounts`, and an account that
is disabled still counts there, so no cap depends on this route. A body is at
most 4 KiB and carries only `quota`, a string of at most 32 characters. Only an
account made through the API has a quota to change; any other name is `404`.

The key is read again under the lock of the account file, where the quota is
written. One that was revoked, expired, confined, stripped of the scope or
limited to a network the client is not in while the request waited writes
nothing, and the answer is that same `404`.

Every write adds one audit line (`account.quota_set`, or
`account.quota_cleared` when the quota is cleared or set to `none`) with the
label of the key, the account as the pseudonym the logs use, the quota in bytes
(`0` for the default) and the client address; a refusal writes none. The change
and its line are made together on a thread a client that goes away does not stop.

### Address aliases

An address alias fans one address (`team@example.org`) out to several local
accounts. The routes write the same state file as `epistle alias`,
`<data_dir>/address-aliases.toml`, through the same rules, under its
cross-process lock; the running server applies the change through its file
watcher, like a domain change. The `[[alias]]` tables of the configuration
file are the seed: they are copied into the state file at the first write or
the first start of `serve`, and edited there afterwards.

All three routes need the `alias` scope, and only that one; a key that holds
it should also be confined with `--domain`. An account-bound key is refused.

`POST /api/v1/aliases` takes `{"alias":"team@example.org","members":
["ana@example.org","bo@example.org"]}`, or `{"alias":"help@example.org",
"target_account":"ana"}` for one account (the member is its address in the
alias's domain). `"dry_run": true` checks the request as it would be written
and writes nothing. What differs from the command is stricter, not looser:

- every member is the address of an account that exists on this server,
  never an outside address, so a leaked key cannot forward a domain's mail
  to a third party;
- a key confined to some domains needs the alias and every member inside
  them. A domain, a member or an account that does not exist and one that is
  not the key's get the same `400`, and the alias of another tenant is `404
  alias ... not found` like one that is not there;
- the role addresses `postmaster`, `abuse`, `hostmaster`, `webmaster`,
  `security`, `noc`, `admin`, `administrator`, `root`, `ssladmin`, `tlsrpt`
  and `mailer-daemon` are the operator's, with or without a sub-address tag
  (`postmaster+x`): a key may not make an alias on one, and may not remove
  or edit one the operator made (`400`);
- an alias address whose local part carries a sub-address tag (`shop+x@example.org`,
  with the separators the directory strips, today `+`) is refused whether or
  not an account of the base address exists: an alias is looked up before the
  tag is stripped, so it would take that account's mail, now or once the
  account is made. The command keeps the choice;
- a member is an account that lies entirely inside the key's domains: an
  account with one address inside and one outside is as unavailable as one
  that does not exist.

A key's domains are compared as they are written, in ASCII lowercase. A key
made with `--domain bücher.example` does not reach `xn--bcher-kva.example`;
list the domain as punycode. An alias address written in Unicode is stored as
punycode and judged as such.

The rest is the command's: the address is in a hosted domain and no account,
masked address or other alias holds it, the caps of the domain
(`max_aliases_per_domain`, `max_members_per_list`) apply and answer `409
limit_reached`, an alias that exists is `409 conflict` with the command's
text, and at most 100 members and 16 KiB of body are taken. A route makes a
plain private alias: senders, `list_id` and visibility stay with the command.

`GET /api/v1/aliases` lists the aliases ordered by address, with `limit`
(default 50, at most 100) and `cursor`, filtered by `domain` and `account`.
A key confined to some domains sees the aliases whose address, members and
senders all lie in them (and every address of the account of a member or sender), and removes or edits only those; any other is `404`
like one that is not there. `DELETE /api/v1/aliases/{alias}` takes `dry_run=true` as a
query. Each durable change emits `alias.added` or `alias.removed` on
`epistle::api::audit`, with the label of the key (never the key), the domain,
a pseudonym of the alias and `client_ip`.

Mail to an alias is delivered to each member account as before. The copy's
`Delivered-To` names the member's address, not the alias, so a program that
reads the mailbox cannot yet tell by it which alias a message came through.

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
| `metric_alert`, `dkim_rotation_failed`, `own_ip_blocklisted`, `outbound_virus`, `warmup.ok`, `warmup.held`, `warmup.backoff` | Operator events | See [configuration](configuration.md#webhook) and [warm-up](operations/warmup.md) |
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

**Per tenant.** A tenant with a `[tenant.webhook]` receives the events of its
domains, signed with its own secret, and no other tenant's; every other domain
uses `[webhook]`. See [a webhook per
tenant](configuration.md#a-webhook-per-tenant-tenantwebhook).

**Delivery.** Each event is posted once, with a 15 second timeout and no
retry. A redirect is not followed and counts as a failure. Any other answer,
a `500` included, counts as sent, and a failure to connect is logged and
dropped. Events are posted concurrently, so their order is not the order of
the mail. Treat webhooks as a hint and the delivery log as the record: if you
need every outcome, read `/api/v1/deliveries` as well. `epistle webhook test`
posts a `test` event and reports the status the endpoint answered.

## JMAP

JMAP accepts the same keys and local OAuth access tokens (see [OAuth](#oauth)). `GET /jmap/session` (or `/.well-known/jmap`) returns
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
  REST `class`. A created submission says `undoStatus`: `pending` with `sendAt`
  (when the send delay will release it) while `[queue.undo_send]` holds it,
  `final` with `sendAt: null` otherwise. An `update` of `undoStatus:
  "canceled"` takes a pending one back (`updated`), and answers `cannotUnsend`
  in `notUpdated` once it was handed on, `notFound` for a submission of
  another account. No other update is allowed. `maxDelayedSend` stays `0`:
  the client does not choose the delay (`sendAt` on create is not read).
- For an account whose `send` switch is off, `EmailSubmission/set` answers
  `forbiddenToSend` ("sending is turned off for this account") in
  `notCreated`, and `VacationResponse/set` and `SieveScript/set` refuse, with
  `forbidden`, to turn a reply on or to store or activate a script that
  redirects, replies or rejects: those would send for the account. Mail
  already in the account's mailbox and every read are untouched.
- Upload with `POST /jmap/upload/{accountId}` (scope `write`) and download with
  `GET /jmap/download/{accountId}/{blobId}/{name}`.
- `GET /jmap/ws` is JMAP over WebSocket. It accepts the upgrade but does not
  answer the `jmap` subprotocol, and the bearer goes in the `Authorization`
  header of the upgrade, so a browser cannot use it. Push is connection-scoped.
  A credential may hold 4 sockets open; the next upgrade is a `429`. A socket
  that sends no frame (a ping counts) for 300 seconds is closed with 1001.
- `GET /jmap/eventsource?types=Email,Mailbox&closeafter=no&ping=30` streams
  `state` and `ping` events for changes made by any protocol; there is no
  replay, so catch up with `/changes`.

Limits, also in the Session: 10,000,000 octets per request, 16 calls, 500
objects per `/get` or `/set`, 4 requests and 4 uploads in flight per
credential, 4 event streams per credential, 4 WebSockets per credential, `maxSizeUpload`
equal to the message size limit. Past the size of a request or its number of calls the answer is
`400` or `413` with a `urn:ietf:params:jmap:error:limit` problem naming the
limit; past the in-flight limits it is a `429` with such a problem; past 500
objects in a `/get` or `/set` it is a `200` whose method response is the error
`requestTooLarge`. A key bound to one account sees only that account.

## SCIM

For an identity provider that provisions mail accounts. Scope `scim`;
responses are `application/scim+json` and errors use the SCIM error object.
`/scim/v2/Users` supports `GET` (with `filter=userName eq "x"`, a quote inside the
value escaped as `\"`, `startIndex`, `count` up to 200), `POST`, and on
`/Users/{id}` `GET`, `PUT`, `PATCH` (`replace` or `add` of `active`, `password`
or `displayName` only, at most 20 operations and 3 password changes per request, and all of them are
checked before the first is applied) and
`DELETE` (`204`, queued mail is kept). `id` is the account name. Only
API-managed accounts appear. `totalResults` is the number of users on the
page, not the number that match. `/Groups` answers `501`. A `POST` and `PUT`
need `active`; without it the answer is a plain-text `422`. A `PUT` replaces
what SCIM models (`active`, `emails`, `displayName`, `password` when sent) and
leaves the quota, forwards, catch-all and the other account settings as they
were. A SCIM key
cannot be bound to an account.

A credential change leaves the same trace as the management route that makes
it: a password SCIM sets writes `account.password_reset` on
`epistle::api::audit`, with the account and the client address, and an
account it suspends or enables again writes `account.disabled` or
`account.enabled`, with the account, the label of the key that asked and the
client address. The lines are written by the task that made the change, so a
client that drops the connection after the write still leaves them. A request
that changed nothing — a `PATCH` that asks for the `active` flag the account
already has — writes no line, and neither the password nor its hash is ever
written.

## OAuth

Present only when `[oauth] signing_key` is set; otherwise every `/oauth/*`
path answers `401` to a request with no bearer (which counts as a failed
authentication for the failure limit, 20 per minute by default, `[api.limiter]`) and `404` to one with a valid
bearer. It issues ES256 access tokens, valid for one hour unless
`[oauth] access_token_ttl_secs` says otherwise, for
OAUTHBEARER on IMAP and SMTP submission, and bearer authentication on JMAP.
On JMAP the signed `sub` confines the token to its own live account. The token
never authenticates `/api/v1` or SCIM. `POST /oauth/device_authorization` starts a device flow,
`POST /oauth/device/approve` approves it with the account's `login` and
`password` (or HTTP Basic), and `POST /oauth/token` polls (no faster than every
5 seconds) or redeems a PKCE code from `POST /oauth/authorize` (`S256` only; a `code_verifier` is
43 to 128 characters of `A-Z a-z 0-9 - . _ ~`, and a `redirect_uri`, which is never
followed, has to be an absolute URI of a plain scheme and, when the authorization
carried one, the redemption carries the same). The `code_challenge` of that
request is the digest of the verifier, so it is exactly 43 characters of
`A-Z a-z 0-9 - _` (RFC 7636 section 4.2); anything else is
`400 invalid_request`. At most 100 codes may be alive for one account, 50 for
one client address and 10,000 in all; past them the answer is
`429 temporarily_unavailable` with `Retry-After`, and nothing is stored.
Both grant requests accept a space-separated `scope` drawn from `read write send`.
Omitting it grants `read`; an explicit empty or unknown scope is `400 invalid_scope`.
The grant stores the scopes, and the signed access token and token response carry
them. Approval and redemption cannot widen them. `write` and `send` do not imply
`read`. `EmailSubmission/set` requires `send` even on an otherwise writable account.
Tokens without explicit scopes must be reissued. Token responses disable caching.

With `[oauth] refresh_token_ttl_secs` set, every grant also returns a
`refresh_token`, and `POST /oauth/token` accepts `grant_type=refresh_token`
with `refresh_token` and an optional narrower `scope` (a wider one is
`400 invalid_scope` and spends nothing). The answer carries a new access token
and a new refresh token, and the one presented is retired. Presenting a retired
token again, or one of an account that was disabled, locked, removed or had its
password changed or reset since the grant, is `400 invalid_grant`, and for a
retired token the whole family issued from that grant is revoked too. Without
the setting the grant type is `400 unsupported_grant_type`, as before.

`POST /oauth/revoke` takes `token` as form or JSON. Possession permits revoking
that token's signed identifier for JMAP; given a refresh token it revokes the
whole family it belongs to. Invalid, expired and already revoked
tokens get the same empty `200`. Revocations persist in `oauth_revocations.json`
under the data directory, containing identifier hashes and expiries, and survive
restart. Expired entries are pruned on revocation. A write failure gives `503`;
unreadable or corrupt revocations fail closed during OAuth authentication.
Every JMAP request checks signature against the local signing key, issuer,
audience, expiry, revocation and account availability. Failed authentication
uses the same bearer limiter and generic `401` as other bearers. WebSockets
recheck on each frame, and event sources on each poll.

Bodies are form-encoded or JSON; errors are `{"error": "<code>"}` as in
RFC 6749 and 8628. Wrong credentials and a wrong code give the same answer.

## What can go wrong

| Symptom | Likely cause |
|---|---|
| `401` on a route that worked yesterday | The key expired (`--expires-at`), was rotated or revoked, or the client moved outside `--ip-cidr` |
| `401` on one route and `200` on another with the same key | The key lacks the scope of the first; that answer is `403 forbidden` |
| `429` with a correct key | Your address made 20 failed attempts in a minute (perhaps another program behind the same NAT). Wait a minute |
| `403` on `/api/v1/accounts` | The key is bound to one account; use a key without `--account` |
| `403 forbidden_from` | `from` or `sender` is not an address of the account the key acts for |
| `403 sending_off` | The account's `send` switch is off; turn it on with `epistle account set NAME --send on` |
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
| Message size | `max_message_size`, 25 MiB by default, for send, SMTP and JMAP upload alike |
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
| Event streams (`/api/v1/events`) | 4 per key and 64 per server by default, one hour each; see [Live updates](#live-updates) |
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
implements. The mail headers are covered in [Message headers](headers.md).
