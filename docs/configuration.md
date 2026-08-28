# Configuration

`epistle` is configured with a single TOML file, passed to
every command with `--config`:

```sh
epistle serve --config /etc/glyndor/epistle/mail.toml
epistle config-check --config /etc/glyndor/epistle/mail.toml   # validate without starting
```

The file must be owner-only — the server refuses to load a file that is group-
or world-readable:

```sh
chmod 600 /etc/glyndor/epistle/mail.toml
```

Validation is **fail-closed**: an unknown key, an invalid value, insecure
permissions, or an undefined `${VAR}` reference all abort startup rather than
run with a questionable setup.

## Secrets

Keep secrets out of the file. Any `${VAR}` is substituted from the process
environment when the file is loaded, and a referenced variable that is unset
fails the load (never a silent empty value):

```toml
[database]
url = "postgres://mail:${MAIL_DB_PASSWORD}@db/mail"
```

Substitution happens before the TOML is parsed, so a substituted value must not
contain TOML metacharacters (`"`, newlines) — percent-encode such characters in
a connection URL.

## Top-level keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `hostname` | string | — (required) | FQDN the server identifies as (EHLO, TLS, HELO/PTR). One consistent name for all outbound. |
| `data_dir` | path | — (required) | Absolute path where all server state lives (mail, spool, suppression, …). |
| `domains` | list | `[]` | Domains this server accepts mail for. Required once any listener is configured. |
| `domain_aliases` | table | `{}` | `alias → target`: mail to `user@alias` is delivered as `user@target`. |
| `dnsbl_zones` | list | `[]` | DNS blocklist zones (RFC 5782) screened against unauthenticated clients. Empty disables DNSBL. |
| `first_time_sender_delay_secs` | int | `0` | Delay a first-time (no-reputation) unauthenticated sender before accepting. Requires `[database]`. `0` disables. |
| `greylist_delay_secs` | int | `0` | Seconds an unseen (client, sender, recipient) triplet is greylisted (451) before a retry is accepted. `0` disables. |
| `srs_secret` | string | unset | Secret for Sender Rewriting Scheme on forwarded mail (SPF survives the next hop). Absent disables SRS. |
| `quota_bytes` | int | 5 GiB | Default per-account mailbox quota (RFC 9208), used when an account has no per-account or per-domain quota. |
| `domain_quotas` | table | `{}` | `domain → bytes`: default mailbox quota for accounts in a domain (overridden by a per-account `quota_bytes`). |
| `submission_rate_limit_per_min` | int | unset | Max messages an authenticated account may submit per minute (deferred with 450 over the limit). Absent disables it. |
| `max_connections_per_listener` | int | per-protocol | Max concurrent connections per listener; excess are dropped. Absent uses the built-in default (SMTP 1000, IMAP 500, POP3 500, ManageSieve 100). |
| `queue_give_up_secs` | int | 5 days | Outbound give-up window: undelivered mail older than this is bounced. A delay-warning DSN is sent once at ~4h. |
| `scanner_hook_url` | string | unset | External scanner hook (ClamAV/Rspamd behind HTTP) for unauthenticated inbound mail. Absent disables scanning. |
| `antispam_llm` | section | unset | LLM-assisted screening for unauthenticated mail whose Bayesian score lands in an uncertain band. Absent disables the hook. |
| `log_format` | `text`\|`json` | `text` | Log output format. |
| `rules` | array | `[]` | Delivery rules that route or flag locally delivered mail by sender/header. |

## Listeners

Each `[[listeners]]` opens one service. Listeners bind to **loopback by
default** — external exposure is opt-in via `addr`.

```toml
[[listeners]]
kind = "smtp"
addr = "0.0.0.0"   # default: 127.0.0.1
# port = 25        # default: the service's IANA port
```

| `kind` | Default port | Notes |
|---|---|---|
| `smtp` | 25 | Inbound mail from other servers. STARTTLS when `[tls]` is set. |
| `submission` | 587 | Authenticated client submission, STARTTLS. |
| `submissions` | 465 | Authenticated submission over implicit TLS. Requires `[tls]`. |
| `imap` | 143 | IMAP4rev2 with mandatory STARTTLS. Requires `[tls]`. |
| `imaps` | 993 | IMAP4rev2 over implicit TLS. Requires `[tls]`. |
| `pop3s` | 995 | POP3 over implicit TLS (no plaintext POP3). |
| `manage-sieve` | 4190 | ManageSieve (RFC 5804), STARTTLS before auth. Requires `[tls]`. |
| `api` | 8025 | Management HTTP API. Requires `[api]`. |
| `metrics` | 9090 | Prometheus metrics at `GET /metrics`. |
| `acme` | 80 | ACME HTTP-01 challenge responder. |
| `autoconfig` | 8091 | Serves Thunderbird autoconfig + Microsoft Autodiscover. Point `autoconfig.<domain>`/`autodiscover.<domain>` here (behind your TLS proxy). |
| `web-dav` | 8090 | WebDAV (RFC 4918) files + CardDAV (RFC 6352) addressbooks + CalDAV (RFC 4791) calendars. HTTP Basic auth as the mail account; each account is confined to its own tree. Run behind a TLS proxy. |

Plaintext listeners (`submission` 587, `web-dav` 8090, `api` 8025, `autoconfig` 8091, `metrics` 9090) are accepted without a `[tls]` block ONLY when bound to a loopback address. When `addr = 0.0.0.0` (or any non-loopback address) and `[tls]` is unset, a warning is emitted at validate time. Hardening follows in the next release: an opt-in `allow_insecure_no_tls` flag, then a hard rejection when the flag is absent. Operators exposing any of these externally should either configure `[tls]` itself or front the listener with a TLS proxy.

## Sections

### `[tls]`
TLS material, shared by all transports. Required by `submissions`/`imap`/`imaps`/`manage-sieve`; enables STARTTLS on `smtp`/`submission`.

| Key | Meaning |
|---|---|
| `cert_file` | PEM certificate chain. |
| `key_file` | PEM private key. |
| `client_ca` | PEM trust anchor for verifying TLS **client** certificates. When set, a client may authenticate with a certificate via SASL `EXTERNAL` (the account comes from the certificate's verified email SAN); clients without one fall back to password auth. Absent disables client-certificate auth. Requires a static certificate (not available under ACME, like SCRAM-SHA-256-PLUS). |

### `[dkim]`
Outbound DKIM signing. Ed25519 is primary; an RSA selector can be added for receivers that lack Ed25519 support.

| Key | Meaning |
|---|---|
| `selector` | Ed25519 selector (the `s=` tag). |
| `key_file` | Ed25519 private key (PKCS#8 PEM); generate with `epistle dkim-keygen`. |
| `rsa_selector` | Optional RSA selector. |
| `rsa_key_file` | Optional RSA private key. |
| `rotate_days` | Automatic key rotation interval in days. Requires a `[dns]` provider to publish the new selector's TXT. Absent disables rotation. |
| `rotate_overlap_days` | Days the previous selector's TXT stays published after a rotation so in-flight mail still verifies (default `7`). |

### `[api]`
Management API (consumed by `epistle-panel`). Closed by default.

| Key | Meaning |
|---|---|
| `token_hash` | `sha256:<hex>` (from `epistle token-hash`) or an argon2id PHC string. |
| `admins` | Optional list of account names allowed to authenticate to the admin panel (via `POST /api/v1/auth/verify`). Empty (default) means no account can administer the panel. |

### `/scim/v2` (SCIM 2.0 provisioning)
Mounted under `/scim/v2` when the management API listener is enabled.
Authenticates against the same bearer token plus the labeled keys in
`api_keys.toml`, but requires the dedicated `Scim` scope: a `read`- or
`write`-only key cannot enumerate or mutate users here, so an IdP
integration can be scoped tighter than the operator's own panel access.

The implementation is the minimum that Entra ID, Okta and Keycloak
actually use: `ServiceProviderConfig`, `Schemas`, `ResourceTypes` for
discovery; full `Users` lifecycle (list with `userName eq "x"` filter,
create, read, replace, patch, delete). `Groups` returns `501` — the
directory has no group membership yet, so provisioning groups would be
a no-op pretending to be a feature.

`active: false` is honoured: the account stays on disk and keeps its
mailboxes, but `authenticate` rejects every password before any
hashing. `PUT` and `PATCH` refuse to change `userName` (renames are
not supported — the account name is the directory primary key).
`PATCH` accepts only `replace` of `active` and `password`. Every
response carries `Content-Type: application/scim+json`; errors follow
RFC 7644 §3.7 (`{ schemas: [Error URN], status, detail }`).

### `[database]`
PostgreSQL backing for the antispam engine (reputation, Bayes).

| Key | Meaning |
|---|---|
| `url` | Connection URL (keep the password in `${VAR}`). |
| `max_connections` | Pool size. |

### `[acme]`
Automatic TLS certificates for the mail protocols (not the panel's web TLS).

| Key | Meaning |
|---|---|
| `directory_url` | ACME directory (must be `https://`). |
| `contacts` | Account contact URIs. |
| `domains` | Domains to issue for (each must be a configured `domains` entry). |
| `renew_before_days` | Renew this many days before expiry. |

### `[arc]`
ARC sealing of inbound mail (RFC 8617), so authentication survives forwarders.

| Key | Meaning |
|---|---|
| `selector` | ARC selector. |
| `key_file` | Ed25519 sealing key (DKIM format). |

### `[oauth]`
OAuth2/OIDC bearer-token verification (OAUTHBEARER/XOAUTH2) for IMAP/SMTP/JMAP.

| Key | Meaning |
|---|---|
| `issuer` | Expected token issuer. |
| `audience` | Expected audience. |
| `algorithm` | Signing algorithm (e.g. `RS256`). |
| `public_key` | The IdP's public key. |

### `[webhook]`
Outbound event notifications. The URL must be `https://` (or a loopback `http://`).

| Key | Meaning |
|---|---|
| `url` | Endpoint to POST events to. |
| `secret` | Optional HMAC-SHA256 signing secret. |

### `[antispam.llm]`
LLM-assisted screening for the **uncertain band** — the slice of mail where the
local Bayesian classifier is not confident in either direction. Outside the band
the local classifier is trusted and the LLM is not paid for; inside it, the
server POSTs a minimal excerpt of the message (only `From`, `Subject`,
`Reply-To`, plus a truncated body) to a chat-completions endpoint and parses
the reply. Requires `[database]` so the Bayesian score can be computed.

Fails open on any failure (transport, timeout, parse, shape): the message is
accepted, a warning is logged, and `mail_llm_failed_total` increments. The LLM
is never trusted to reject mail outright — its strongest action is quarantine
to the `Rejects` mailbox.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | string | — (required) | Chat-completions URL (any OpenAI-compatible API). |
| `api_key_env` | string | — (required) | Name of the env var that carries the API key; the server reads it at start and refuses to start if unset. |
| `model` | string | — (required) | Model identifier sent in every request body. |
| `uncertain_low` | float | `0.35` | Inclusive lower bound of the uncertain band. Scores below this skip the LLM. |
| `uncertain_high` | float | `0.65` | Inclusive upper bound. Scores above this skip the LLM. |
| `timeout_secs` | int | `10` | Per-request HTTP timeout. |
| `max_body_bytes` | int | `16384` | Cap on the user-side bytes of the request body. The outbound prompt is always `≤` this plus the system prompt and JSON envelope. |

Example:

```toml
[antispam.llm]
endpoint = "https://api.openai.com/v1/chat/completions"
api_key_env = "EPISTLE_LLM_API_KEY"
model = "gpt-4o-mini"
```

### `[privileges]`
Drop OS privileges after binding ports (run the daemon unprivileged).

| Key | Meaning |
|---|---|
| `user` | Unprivileged user to switch to (must exist). |
| `group` | Optional; defaults to the user's primary group. |

### `[storage]`
Optional at-rest encryption of stored message files. Defaults to off (relying on
full-disk encryption). When on, `.eml` bodies, the outbound spool and JMAP blobs
are encrypted with ChaCha20-Poly1305; reads decrypt transparently. The key must
be sourced off the data disk. With `encrypt_at_rest = true` and no usable key the
server refuses to start (fail closed). See the security guide's "Data at rest".

| Key | Meaning |
|---|---|
| `encrypt_at_rest` | Encrypt new message writes at rest (default `false`). |
| `encryption_key_env` | Name of an env var holding the base64 32-byte key. |
| `encryption_key_file` | Path to a file holding the base64 32-byte key (ideally outside `data_dir`); takes precedence over `encryption_key_env`. |

Generate a key with `epistle storage-keygen` (prints a fresh base64 32-byte key
to stdout; place it in the env var or key file). Mirrors `epistle dkim-keygen`.

### `[otel]`
OpenTelemetry trace export. Present enables exporting tracing spans over OTLP/HTTP to a collector.

| Key | Meaning |
|---|---|
| `endpoint` | OTLP/HTTP endpoint of the collector (e.g. `http://localhost:4318`). |
| `service_name` | `service.name` resource attribute (default `epistle`). |

### `[dns]`
DNS provider for record automation (DKIM rotation, MTA-STS, TLS-RPT,
TLSA-on-cert-rotate, …). Records published through a provider are
**re-published on every change** — when this section is configured, epistle
stops asking the operator to add records by hand. Absent or unmatched
`provider` → manual mode (records printed for the operator to add).

| `provider` value | Notes |
|---|---|
| `bunny` | Bunny.net account access key; `AccessKey` header; `?search=` resolves the zone id; see limitations below. |
| `cloudflare` | API token; bearer auth; supports TLSA via structured data. |
| `desec` | deSEC API token; rrset-style bulk PUT; supports TLSA. |
| `digitalocean` | Personal access token; bearer auth; v2 REST API; see specifics below. |
| `gcloud` | Google Cloud DNS service-account JSON; RS256 JWT bearer; supports TLSA. |
| `dnsimple` | DNSimple API token + account id; bearer auth; record-id granularity. |
| `namecheap` | Username + API key in `token`; XML API; **TLSA not supported**; see limitations below. |
| `route53` | AWS access key + secret + hosted zone id; signed with SigV4. |
| `rfc2136` | TSIG-authenticated DNS UPDATE to a local nameserver (`host:port`); A/AAAA/TXT/CNAME/TLSA. |
| `spaceship` | API key + secret; `X-API-Key`/`X-API-Secret` headers; see specifics below. |
| `manual` | Always available; no credentials. |

Common keys (every provider):

| Key | Meaning |
|---|---|
| `provider` | One of `cloudflare`, `desec`, `digitalocean`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `cloudflare`, `desec`, `gcloud`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `cloudflare`, `desec`, `dnsimple`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `bunny`, `cloudflare`, `desec`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `cloudflare`, `desec`, `digitalocean`, `namecheap`, `route53`, `rfc2136`, `spaceship`, `manual`. |
| `zone` | The DNS zone the token is scoped to (least privilege). |
| `token` | Inline API token — discouraged, prefer `token_file` or `token_env`. |
| `token_env` | Name of an env var holding the API token. |
| `token_file` | Path to a `0600` file holding the API token. |

#### `[dns]` — DigitalOcean specifics

```toml
[dns]
provider = "digitalocean"
zone = "example.org"
token = "your_personal_access_token"     # or token_file / token_env
```

- Generate the token at <https://cloud.digitalocean.com/account/api/tokens>
  with **Write** scope and a single domain. DigitalOcean tokens are not
  zone-scoped at the API level, so the zone restriction is enforced by
  epistle (records outside `zone` are rejected before any call).
- **API URL:** production is `https://api.digitalocean.com`. The provider's
  `with_base` constructor swaps to an alternate base for tests; no config
  knob for it yet.
- **TXT values are unquoted.** DigitalOcean adds the DNS wire-format quotes
  at the zone layer, so epistle sends `data: "v=DMARC1; p=none"` rather than
  `data: "\"v=DMARC1; p=none\""`. Quoting them would produce a double-quoted
  TXT record.
- **`upsert` is read-then-write.** epistle `GET`s records matching the name
  and type, then either `PUT`s the existing record's id (replacing) or
  `POST`s a new one. Two TXT records with the same name and type are not
  possible because of the lookup.
- **Pagination is followed.** `list` walks `links.pages.next` until exhausted,
  so a zone with hundreds of records is not silently truncated.
#### `[dns]` — DNSimple specifics

```toml
[dns]
provider = "dnsimple"
zone = "example.org"
account_id = "1010"             # not a secret; visible in the path /v2/{id}/...
token = "your_api_token"        # or token_file / token_env
```

- `account_id` is **required**: every URL is `/v2/{account_id}/zones/{zone}/records`,
  so a missing `account_id` fails the build rather than guessing. The id is
  not a secret; it sits in the config file in clear alongside the zone.
- `token` is a user token (DNSimple's "Account API token" or an OAuth token
  for the same user); the provider sends it as `Authorization: Bearer …`.
- **Upsert is list-then-write.** DNSimple's `POST` returns 400 if a record
  with the same name and type already exists, so every upsert first lists
  the zone (filtered to that `(name, type)`) and either `PATCH`es the
  existing record or `POST`s a new one. Two TXT records for the same name
  therefore cannot be created by mistake.
- **Delete is idempotent.** Deleting a record that does not exist is a no-op
  (no `DELETE` request is sent) — the list comes back empty.
- **List walks pagination.** The records endpoint is paginated; the
  provider requests `per_page=100` (the API maximum) and follows
  `pagination.total_pages`. Records are returned as FQDNs — the relative
  `name` from the API is joined to the configured zone.
- **Unsupported kinds:** MX (priority is not modelled by epistle yet), SRV
  (priority/weight/port), and TLSA (no structured-data field). The provider
  returns `provider does not support writes` for these.
- **API base:** `https://api.dnsimple.com/v2` — overridable through the
  provider's `with_base` for tests.

#### `[dns]` — Namecheap specifics

```toml
[dns]
provider = "namecheap"
zone = "example.org"
token = "your_username:your_api_key"      # or token_file / token_env
```

- The `token` carries **two** values separated by `:` — Namecheap's API
  requires `ApiUser`, `ApiKey`, and `UserName` on every call (the username
  doubles as both `ApiUser` and `UserName`). A missing colon, empty
  username, or empty key disables automation (fail closed).
- **API URL:** production is `https://api.namecheap.com/xml.response`. The
  provider's `with_api_url` constructor swaps to
  `https://api.sandbox.namecheap.com/xml.response` for sandbox credentials;
  no config knob for it yet.
- **IPv4 whitelist is mandatory.** Namecheap rejects API calls from any IP
  not on the account's whitelist at
  <https://www.namecheap.com/support/api/methods/>. The server's egress IP
  must be added there or every call returns an auth-flavoured error.
- **TLSA is not supported** by Namecheap's UI or API. DANE records must be
  published at a different DNS host (or the zone must be split between
  providers) — epistle will return `provider does not support writes` for
  TLSA and skip publishing it.
- **`setHosts` is destructive.** It replaces the entire record set at the
  zone. epistle's upsert/delete is a read-modify-write (`getHosts` → mutate
  → `setHosts`), so if an operator also edits the zone by hand between
  those calls their changes are silently dropped. Pair with periodic drift
  checks (`epistle dns-check`) for zones that are not fully epistle-owned.

#### `[dns]` — RFC 2136 specifics
```toml
[dns]
provider = "rfc2136"
zone = "example.org"
endpoint = "127.0.0.1:5359"   # the nameserver that accepts UPDATE messages
key_name = "epistle-key."
token = "base64-of-shared-secret"
# token_file / token_env also accepted, like every provider
algorithm = "hmac-sha256"     # default; "hmac-sha384" and "hmac-sha512" supported
```
- **No HTTP API.** epistle sends DNS UPDATE messages (opcode 5) over TCP,
  framed with a 2-byte length prefix (RFC 1035 §4.2.4). The endpoint is
  `host:port` of a nameserver that has the zone configured and the TSIG
  key loaded — typically BIND, Knot, NSD, or dnsdist in front of any of
  those.
- **Authentication is TSIG** (RFC 8945). `key_name` is the key's name in
  the nameserver's config; `token` is the shared secret as base64 (the
  format `rndc-confgen` and similar tools print). The MAC is computed
  over the full UPDATE wire format, including the message id, so replays
  are non-viable on top of the time tolerance (`fudge`, 5 minutes by
  default — adjust the nameserver if you need more).
- **Supported algorithms:** `hmac-sha256` (default), `hmac-sha384`,
  `hmac-sha512`. `hmac-sha1`, `hmac-sha224`, and `hmac-md5` are rejected
  at build time — hickory's TSIG implementation does not implement the
  MAC primitives for them, so an attempt to sign would fail in
  non-obvious ways.
- **Upsert is `delete RRset (name,type)` + `add RR` in one message.**
  RFC 2136 §2.5 — the canonical replacement. Guarantees we never end up
  with two TXT records at the same owner name.
- **Delete is the same `delete RRset` with no `add` after it** —
  class NONE, TTL 0, empty RDATA. Idempotent by definition; the server
  answers NOERROR whether the RRset existed or not.
- **`list` is not implemented.** RFC 2136 defines UPDATE only; reading
  the zone back would need AXFR or per-name queries that the provider
  has no way to enumerate. Drift detection (`epistle dns-check`) will
  return `provider does not support writes` against an rfc2136 zone.
- **Supported record kinds:** A, AAAA, TXT, CNAME, TLSA. MX and SRV are
  rejected (`Unsupported`) because they carry extra fields
  (preference, weight, port) that epistle does not currently build.
#### `[dns]` — Google Cloud DNS specifics
provider = "gcloud"
token = "unused"                       # placeholder; auth is signature-based
credentials_file = "/etc/glyndor/epistle/dns/gcloud.json"
- **Auth is signature-based, not bearer-based.** `token` (and friends) is a
  placeholder; Google authenticates the service account with a JWT RS256
  signed with the private key from the credentials file. The bearer
  exchanged at `https://oauth2.googleapis.com/token` is cached in-process
  until one minute before `expires_in`, so the JWT is signed once per cache
  lifetime, not on every DNS API call.
- **`credentials_file`** is a Google service-account JSON (`client_email`,
  `private_key` in PKCS#8 PEM, `project_id`). The service account needs the
  **DNS Administrator** role on the project (scope
  `https://www.googleapis.com/auth/ndev.clouddns.readwrite`) and the
  `private_key` must be reachable by the process; a `0600` file outside
  `data_dir` is the recommended location.
- **Two-phase write.** Every change lists the zone's rrsets and submits one
  `POST .../changes` carrying `additions` (and, when replacing, `deletions`
  of the old rrset). A second upsert with identical value + TTL is a no-op
  (no second change request is submitted), so two TXT records for the same
  name cannot appear.
- **Delete is idempotent.** Deleting an absent rrset is a no-op; the
  provider only submits a change when the rrset exists in the zone.
- **TLSA is supported** via the structured `rrdatas` path. MX/SRV are not
  emitted yet and return `provider does not support writes`.
#### `[dns]` — Bunny specifics

```toml
[dns]
provider = "bunny"
zone = "example.org"
token = "your-bunny-account-key"      # or token_file / token_env
```

- The token is the Bunny.net account **Access Key** (Account → API → API Key
  in the panel). epistle sends it in the `AccessKey` HTTP header — *not*
  `Authorization: Bearer …`. Keep it in `token_file` (`0600`) or `token_env`
  in production.
- **Zone id, not name.** Bunny references a zone by numeric id; on first
  use epistle issues `GET /dnszone?search=<zone>` and picks the entry whose
  `Domain` matches the token's zone exactly (Bunny's search is a prefix
  match, so `example.org` also returns `evilexample.org` and
  `example.org.evil.test` — those are ignored). The id is cached for the
  life of the provider.
- **Create vs update.** Bunny's record fields are numeric types
  (`A=0`, `AAAA=1`, `CNAME=2`, `TXT=3`, `MX=4`, `SRV=8`, `TLSA=15`). epistle
  upserts by first reading the zone's record list, then choosing between
  `PUT /dnszone/{id}/records` (create) and `POST /dnszone/{id}/records/{rid}`
  (update); without that read-modify-write, Bunny rejects a second `TXT`
  at the same name as `400`. Two TXT records at the same name is the
  classic mistake and is covered by a test.
- **Delete is idempotent.** `DELETE` returns `404` for a record that is
  already gone (e.g. removed between our find and delete by another
  caller); epistle swallows the `404` and returns `Ok`.
- **TLSA and SRV are not supported** — Bunny's API takes a `Type` integer
  and the MX/SRV/TLSA wire formats need fields (`Priority`, `Port`,
  `Flags`, `Tag`) epistle does not yet emit. epistle returns
  `provider does not support writes` for those kinds and skips them.

#### `[dns]` — Spaceship specifics

```toml
[dns]
provider = "spaceship"
zone = "example.org"
access_key = "your_api_key"     # or secret_key for inline; secret_key_env is preferred
secret_key_env = "EPISTLE_SPACESHIP_SECRET"
```

- Generate the key pair at
  <https://www.spaceship.com/application/api-manager/> with the
  `dnsrecords:read` and `dnsrecords:write` scopes. The two halves travel as
  `X-API-Key` and `X-API-Secret` headers on every call; they are not
  zone-scoped at the API level, so the zone restriction is enforced by
  epistle (records outside `zone` are rejected before any call).
- **API URL:** production is `https://spaceship.dev/api/v1`. The provider's
  `with_base` constructor swaps to an alternate base for tests; no config
  knob for it yet.
- **No in-place update.** Spaceship's `PUT /dns/records/{zone}` *adds*
  items (with `force: true` to overwrite). epistle implements upsert as
  read-then-delete-then-add: it `DELETE`s the existing `(type, name)`
  first and only then `PUT`s the new value, so two TXT records at the
  same owner name are not possible.
- **TXT delete body includes the value.** Spaceship's `TxtResourceRecordDeleteItem`
  requires `{type, name, value}` (other kinds only need `{type, name}`).
  epistle always includes `value` for TXT deletes so the right record is
  removed when multiple TXT records at the same name exist.
- **Pagination is followed.** `list` walks `?take=500&skip=N` until the
  number of fetched items reaches `total`, so a zone with hundreds of
  records is not silently truncated.
- **TXT values are unquoted.** Spaceship stores TXT content verbatim on
  the wire — epistle sends `value: "v=DMARC1; p=none"` rather than
  `"value: "\"v=DMARC1; p=none\""`.
- **Supported record kinds:** A, AAAA, TXT, CNAME, TLSA. MX and SRV are
  rejected (`Unsupported`) for the same reason as the other providers.

### `[[accounts]]`
A mail account. An account with no `password_hash` is receive-only.

| Key | Meaning |
|---|---|
| `name` | Lowercase alphanumeric/hyphen; becomes the mailbox directory name. |
| `addresses` | One or more addresses (each in a configured domain). |
| `password_hash` | argon2id PHC string. Omit for receive-only. |
| `catch_all` | Domains for which this account receives mail to unknown local users. |
| `quota_bytes` | Per-account mailbox quota (bytes). Overrides the domain/server default. |
| `forward` | External addresses this account's mail is also forwarded to (SRS-rewritten; bounces and looping mail are never forwarded). Empty disables forwarding. |
| `forward_keep_local` | Keep the local copy when forwarding (default `true`). Set `false` for pure forwarding. |

### `[[alias]]`
A multi-target alias: one address that delivers to several local accounts.

| Key | Meaning |
|---|---|
| `address` | The alias address (e.g. `team@example.org`). |
| `members` | Member addresses it delivers to (each a local account address). |
| `senders` | Addresses allowed to send *as* the alias (From / MAIL FROM). Empty means any member may; a non-member is always refused. |
| `hidden` | Keep the membership private — not disclosed through directory queries (default `true`). |
| `list_id` | Treat the alias as a **mailing list**: delivered copies gain `List-Id` (this value), `List-Post`, and `List-Unsubscribe` headers (RFC 2369/2919). Absent means a plain alias. |

### `[[transport]]`
Outbound routing rules. Each rule matches by sender `account` (the envelope sender's local part) **or** recipient `domain`; a rule with neither is the catch-all. The most specific match wins (account > domain > catch-all). With no rule, mail is delivered directly via MX. Empty `[[transport]]` keeps that default.

| Key | Meaning |
|---|---|
| `account` | Match mail from this local sender account. |
| `domain` | Match mail to this recipient domain. |
| `kind` | `direct` (MX, the default), `relay` (smarthost), or `fail` (refuse). |
| `host`, `port` | Smarthost address (required for `relay`). |
| `starttls` | Upgrade to TLS before AUTH/mail on a relay. Required when AUTH is set. |
| `username`, `password` | SMTP AUTH for the relay (submission). Sent only over TLS — never in plaintext (fail closed). |
| `socks_proxy` | `host:port` of a SOCKS5 proxy to reach the smarthost through. |

### `[queue]`
Outbound queue settings. Absent keeps the secure defaults.

| Key | Meaning |
|---|---|
| `outbound_tls` | STARTTLS certificate authentication for a hop that is **not** otherwise mandated or DANE-protected. `strict` (the default) verifies the certificate against the public trust anchors and the MX hostname, exactly like a browser — a self-signed/expired certificate with no DANE/MTA-STS defers the message. `opportunistic` completes the handshake with any certificate (encryption without authentication): it stops passive eavesdropping but not an active man-in-the-middle, and is the historical SMTP norm. |

This knob never weakens an authenticated hop: MTA-STS enforce, a sender's REQUIRETLS, and DANE (TLSA records) always authenticate the certificate regardless of `outbound_tls`, and a remote that does not offer STARTTLS where TLS is mandated still defers (never cleartext).

## Example

```toml
hostname = "mail.example.org"
data_dir = "/var/lib/glyndor/epistle"
domains  = ["example.org"]

queue_give_up_secs = 432000   # 5 days (the default)
greylist_delay_secs = 60

[tls]
cert_file = "/etc/glyndor/epistle/tls/fullchain.pem"
key_file  = "/etc/glyndor/epistle/tls/privkey.pem"

[dkim]
selector = "ed1"
key_file = "/etc/glyndor/epistle/dkim/ed1.pem"

[privileges]
user  = "glyndor-epistle"
group = "glyndor-epistle"

[[listeners]]
kind = "smtp"
addr = "0.0.0.0"

[[listeners]]
kind = "submission"
addr = "0.0.0.0"

[[listeners]]
kind = "imaps"
addr = "0.0.0.0"

[[listeners]]
kind = "manage-sieve"
addr = "0.0.0.0"

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
```
