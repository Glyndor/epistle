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
| `public_ipv4` | IPv4 | unset | Public IPv4 the hostname resolves to. Required by `verify-dns` to check the PTR and confirm the address matches the published A record; absent leaves `verify-dns` to look it up on the fly. Loopback, link-local, RFC 1918, multicast, broadcast and the documentation ranges are refused at validate time: only a global unicast address is accepted. |
| `public_ipv6` | IPv6 | unset | Same for IPv6. Publishing SPF for a host that also has AAAA without listing the v6 makes mail sent over IPv6 fail SPF. |
| `data_dir` | path | — (required) | Absolute path where all server state lives (mail, spool, suppression, …). |
| `domains` | list | `[]` | Domains this server accepts mail for. Required once any listener is configured. |
| `domain_aliases` | table | `{}` | `alias → target`: mail to `user@alias` is delivered as `user@target`. |
| `dnsbl_zones` | list | `[]` | DNS blocklist zones (RFC 5782) screened against unauthenticated clients. Empty disables the IP screen. |
| `dnsbl_domain_zones` | list | `[]` | Right-hand-side blocklist zones queried with the envelope sender's domain (RFC 5782 §2.3). Empty disables the sender-domain screen. |
| `dnsbl_url_zones` | list | `[]` | URI blocklist zones queried with the host of every URL found in the body (RFC 5782 §2.3). Empty disables the URL-host screen. |
| `first_time_sender_delay_secs` | int | `0` | Delay a first-time (no-reputation) unauthenticated sender before accepting. Requires `[database]`. `0` disables. |
| `greylist_delay_secs` | int | `0` | Seconds an unseen (client, sender, recipient) triplet is greylisted (451) before a retry is accepted. `0` disables. |
| `srs_secret` | string | unset | Secret for Sender Rewriting Scheme on forwarded mail (SPF survives the next hop). Absent disables SRS. |
| `quota_bytes` | int | 5 GiB | Default per-account mailbox quota (RFC 9208), used when an account has no per-account or per-domain quota. |
| `domain_quotas` | table | `{}` | `domain → bytes`: default mailbox quota for accounts in a domain (overridden by a per-account `quota_bytes`). |
| `submission_rate_limit_per_min` | int | unset | Max messages an authenticated account may submit per minute (deferred with 450 over the limit). Absent disables it. |
| `new_recipients_per_day` | int | unset | Cap on first-time recipients an authenticated account may write to in a rolling 24h window. Refused: SMTP `450 4.7.1 too many new recipients today; retry tomorrow`, REST `429 rate_limited`, JMAP `tooManyRecipients`. Absent disables the cap (the default). The `init` scaffold later sets a default of 200. |
| `domain_submission_limits` | table | `{}` | `domain → msgs/min`: per-domain override for `submission_rate_limit_per_min`. An account picks up its own domain's entry when one is set; otherwise the server-wide default applies; otherwise no limit. The domain is taken from one of the account's own addresses (the same walk `domain_quotas` performs), not from the first configured domain. |
| `inbound_rate_limit_per_ip_per_min` | int | unset | Max messages an unauthenticated client IP may start per minute. Sessions that authenticate are charged against the submission limiters instead; bounces (null sender) are not charged against the per-sender limit. A send over the cap is deferred with `450 4.7.1 too many messages from this client; retry later`; the temporary code lets a real burst (a mailing list, a resend after an outage) retry rather than bounce. Absent disables the per-IP limit. |
| `inbound_rate_limit_per_sender_per_min` | int | unset | Max messages a single envelope sender may start per minute across all clients (lowercased reverse path). Excludes the null sender used by bounces. A send over the cap is deferred with `450 4.7.1 too many messages from this sender; retry later`. Absent disables the per-sender limit. |
| `masked_addresses_max` | int | `100` | Per-account cap on server-generated masked email addresses (the disposable aliases at `POST /api/v1/accounts/{name}/masked`). `0` disables the feature; requests above the cap return `429`. |
| `max_connections_per_listener` | int | per-protocol | Max concurrent connections per listener; excess are dropped. Absent uses the built-in default (SMTP 1000, IMAP 500, POP3 500, ManageSieve 100). |
| `queue_give_up_secs` | int | 5 days | Outbound give-up window: undelivered mail older than this is bounced. A delay-warning DSN is sent once at ~4h. |
| `scanner_hook_url` | string | unset | External scanner hook (ClamAV/Rspamd behind HTTP) for unauthenticated inbound mail. Absent disables scanning. |
| `antispam_llm` | section | unset | LLM-assisted screening for unauthenticated mail whose Bayesian score lands in an uncertain band. Absent disables the hook. |
| `log_format` | `text`\|`json` | `text` | Log output format. |
| `rules` | array | `[]` | Delivery rules that route or flag locally delivered mail by sender/header. |
| `alerts` | array | `[]` | Metric alerts: rules that fire a webhook or email when a counter crosses its configured threshold over a sample window. |
| `tenant` | array | `[]` | Tenant definitions: named groups of domains with optional aggregate caps on accounts, domains, storage and submission rate. Empty means no tenancy is in effect. See [`[[tenant]]`](#tenant). |

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

Key rotation is **automatic and always on** when a `[dns]` provider is configured: the server rotates the signing key every **90 days** and keeps the previous selector's TXT published for a **14-day overlap** so in-flight mail still verifies. The interval is a property of the server, not a per-deployment preference, and is fixed in code (aligned with the 90-day TLS certificate cycle). When `[dns]` is absent, rotation cannot publish the new selector's TXT and is therefore inactive; a notice is logged once at startup.

| Key | Meaning |
|---|---|
| `selector` | Ed25519 selector (the `s=` tag). |
| `key_file` | Ed25519 private key (PKCS#8 PEM); generate with `epistle dkim-keygen`. |
| `rsa_selector` | Optional RSA selector. |
| `rsa_key_file` | Optional RSA private key. |
| `rotate_days` | **Deprecated.** Ignored. Kept so existing configs keep parsing; a one-shot warning is logged at startup when present. Will be removed in a future release. |
| `rotate_overlap_days` | **Deprecated.** Ignored. Same backward-compatibility note as `rotate_days`. |

### `[api]`
Management API (consumed by `epistle-panel`). Closed by default.

| Key | Meaning |
|---|---|
| `token_hash` | `sha256:<hex>` (from `epistle token-hash`) or an argon2id PHC string. |
| `admins` | Optional list of account names allowed to authenticate to the admin panel (via `POST /api/v1/auth/verify`). Empty (default) means no account can administer the panel. |

### Domain-confined API keys (multi-tenancy)

A key in `api_keys.toml` may carry a `domains` list, on top of its scopes:

```toml
[[keys]]
label = "tenant-a"
hash = "sha256:..."
scopes = ["read", "write"]
domains = ["a.example"]
```

Create one with `epistle api-key-create --domain a.example` (repeat the
flag for more). The key then sees only those domains in `GET /domains`,
only the accounts that live entirely inside them in `GET /accounts`, and
is refused on any account or address outside them.

Absent or empty, `domains` means every configured domain — which is what
every key did before the field existed, so an upgrade never narrows a key
that is already deployed. The configured `token` is never confined.

Two rules are worth knowing before you rely on this:

- An account holding an address in two domains belongs to both tenants and
  is therefore out of scope for a key confined to either one. Deleting it,
  or resetting its password, would reach a domain the key was not given.
- A refusal answers `404`, not `403`. A key confined to one tenant must not
  be able to enumerate another tenant's account names by reading the status
  code, so an account it may not touch looks exactly like one that does not
  exist.

### Uploaded blob storage

JMAP uploads live under `<data_dir>/blobs/`, sharded two levels deep by the
**last** four characters of the blob id: `blobs/ab/cd/<id>`, with the `.type`
and `.owner` sidecars beside the payload.

The shard comes from the end of the id rather than the start because blob ids
are UUIDv7, whose first 48 bits are a timestamp — every blob written in the
same era shares its leading characters, so sharding on them would file almost
everything into one bucket while looking sharded.

There is no migration. A blob written by an older version stays where it is
and is still read, still counted against quota, and still reclaimed; only new
blobs are written into the shards. Nothing needs to be moved and nothing needs
configuring.

### IMAP COMPRESS=DEFLATE

Advertised in `CAPABILITY` and enabled per connection by `COMPRESS DEFLATE`
(RFC 4978). There is nothing to configure: a client that asks gets a deflate
stream in both directions for the rest of the connection, and one that does
not is unaffected.

The compression context is kept for the whole connection rather than reset
per message, which is where the saving comes from — IMAP repeats the same
command names, flag names and header keys endlessly. The tagged `OK` for the
command itself travels uncompressed, as the RFC requires. A second `COMPRESS`
on the same connection answers `NO [COMPRESSIONACTIVE]`: restarting the
context underneath a client that is already decoding would desynchronise it.

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
PostgreSQL backing for the antispam engine (reputation, Bayes). The server
refuses to start against a PostgreSQL major older than 14 (the oldest major
still in upstream support today); `serve` reads `SHOW server_version_num`
after the pool is built and aborts with a `ServerTooOld` error before any
migration runs, so a server below the floor fails as a sentence at startup
rather than as an SQL syntax error in the first query.

| Key | Meaning |
|---|---|
| `url` | Connection URL (keep the password in `${VAR}`). Must be `sslmode=require` (or `verify-ca` / `verify-full`); an absent or weaker `sslmode` is rejected. A Unix-domain socket URL (`postgres://%2Fpath/...` or `postgres:///db?host=/path`) is accepted as is because there is no network on the path to intercept. |
| `max_connections` | Pool size. |
| `tls` | How the connection authenticates the PostgreSQL server. Defaults to `require`, which rejects any `sslmode` weaker than `require`. Set to `insecure` to assert that the connection stays on a network you trust (typically an internal container network with no gateway to the outside); an `insecure` connection is the operator's responsibility. |
| `directory` | Resolve mail accounts from the SQL directory tables (off by default). |

An unreachable database does not stop the server: the antispam engine is
disabled, mail keeps flowing unfiltered, a warning is logged and the
`database_unavailable` counter is incremented (alert on it). The exception is
`directory = true`: the accounts themselves come from SQL, so there would be
nobody to deliver to and the start fails.

The same database backs the shared authentication ban store: every
listener (SMTP submission, IMAP, POP3, ManageSieve, the API, OAuth
device and PKCE grants) records failed authentications into the
`auth_failure` table and consults the `auth_ban` table before any
password hashing. Without `[database]`, the per-connection three-strikes
counters each listener already maintains are the only defence.

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

### `[[alerts]]`
Metric alerts. Each block is one rule; an empty list (the default) disables
the engine entirely. Every `window_secs` the engine reads the chosen counter,
compares the per-window delta against `op threshold`, and on a fire either
posts a webhook event (when `webhook = true` and `[webhook]` is configured)
or queues an email through the outbound spool (one copy per address in
`email`). The reverse-path of an alert email is
`epistle-alerts@<hostname>`, so a DSN from a stuck MX comes back to the
server.

A rule that has fired will not fire again until `cooldown_secs` have
elapsed **and** the condition has stopped holding for at least one tick.
Without the second half, a sustained "queue high" alert would page every
window.

| Key | Meaning |
|---|---|
| `name` | Stable rule identifier; appears in the webhook payload, the email subject and the logs. Must be unique. |
| `metric` | Counter name (the short identifiers exposed by `Metrics::snapshot`). The validator rejects unknown names with the full valid list in the error message. |
| `op` | One of `>=`, `>`, `<=`, `<`, `==`. |
| `threshold` | Right-hand side of `op`. Compared against the per-window delta of `metric`. |
| `window_secs` | Sample interval in seconds. Must be `> 0`. |
| `webhook` | When `true`, fire a `metric_alert` webhook event. Requires `[webhook]`. |
| `email` | One email per entry. The alert is queued as an outbound message for each address (delivered through the queue worker like any other mail). |
| `cooldown_secs` | Minimum seconds between consecutive fires. Must be `> 0`. |

Example: a 50-bounce-storm alarm, paging on webhook and email, with a 15-min
cooldown to keep the noise down once it has fired.

```toml
[[alerts]]
name = "bounce-storm"
metric = "bounced"
op = ">="
threshold = 50
window_secs = 300
webhook = true
email = ["ops@example.org"]
cooldown_secs = 900
```

The counter names accepted by `metric` (the ones `Metrics::snapshot` exposes)
are: `abuse_dropped`, `accepted`, `bounced`, `connections`, `deferred`,
`forwarded`, `quarantined`, `rejected_dmarc`, `rejected_dnsbl`,
`rejected_loop`, `rejected_reputation`, `rejected_scanner`, `rejected_spf`,
`relayed`, `sieve_rejected`, `vacation_sent`, `webhook_failed`,
`webhook_sent`, `database_unavailable`.

### `[privileges]`
Drop OS privileges after binding ports (run the daemon unprivileged).

| Key | Meaning |
|---|---|
| `user` | Unprivileged user to switch to (must exist). |
| `group` | Optional; defaults to the user's primary group. |

### `[storage]`
Optional at-rest encryption of stored message files and retention of expunged
messages. Defaults to off for encryption (relying on full-disk encryption) and
off for retention (current behaviour: an expunge deletes the on-disk files
immediately). When encryption is on, `.eml` bodies, the outbound spool and
JMAP blobs are encrypted with ChaCha20-Poly1305; reads decrypt transparently.
The key must be sourced off the data disk. With `encrypt_at_rest = true` and
no usable key the server refuses to start (fail closed). See the security
guide's "Data at rest".

| Key | Meaning |
|---|---|
| `encrypt_at_rest` | Encrypt new message writes at rest (default `false`). |
| `encryption_key_env` | Name of an env var holding the base64 32-byte key. |
| `encryption_key_file` | Path to a file holding the base64 32-byte key (ideally outside `data_dir`); takes precedence over `encryption_key_env`. |
| `deleted_retention_days` | Days to keep expunged messages in `<account>/.archive/` before the hourly sweeper removes them (default `0`). Setting this to a positive value moves expunged messages into the archive instead of deleting them; restore with `epistle archive restore` or `POST /api/v1/accounts/{name}/archive/{id}/restore`. Archived messages count toward the account's quota. |

Generate a key with `epistle storage-keygen` (prints a fresh base64 32-byte key
to stdout; place it in the env var or key file). Mirrors `epistle dkim-keygen`.

### `[storage.blobs]`
Where uploaded JMAP blobs (`POST /jmap/upload/{account}`) live. Absent (or
`backend = "fs"`) keeps the historical default of `<data_dir>/blobs/`,
sharded two levels by the **last** four characters of the blob id, with a
fallback to the flat layout for blobs written by older versions. Setting
`backend = "s3"` redirects uploads to an S3-compatible bucket; the
download handler and the `.owner` / `.type` sidecars follow the same path.

| Key | Meaning |
|---|---|
| `backend` | Either `"fs"` (default; same as omitting the section) or `"s3"`. |
| `endpoint` | S3 endpoint URL (`https://s3.us-east-1.amazonaws.com`, or a compatible service like MinIO at `http://minio.local:9000`). Required when `backend = "s3"`. |
| `bucket` | Bucket name. Object keys are the raw blob id (`<uuid>` for the payload and `<uuid>.type` / `<uuid>.owner` for the sidecars). |
| `region` | AWS region used for SigV4 signing (e.g. `us-east-1`). Setting it wrong returns `SignatureDoesNotMatch` from the server. |
| `access_key_id` | Public access key id. Not a secret, so it lives in the config file. |
| `secret_access_key_env` | Name of an env var holding the secret access key. The secret never appears in the config file. |
| `secret_access_key_file` | Path to a `0600` file holding the secret access key. Takes precedence over `secret_access_key_env` when both are set. |

Example S3 block:

```toml
[storage.blobs]
backend = "s3"
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "mail-blobs"
region = "us-east-1"
access_key_id = "AKIA-EXAMPLE"
secret_access_key_env = "EPISTLE_S3_SECRET"
```

The S3 backend speaks the four verbs S3 exposes — `PutObject`, `GetObject`,
`DeleteObject`, `ListObjectsV2` — over HTTPS with SigV4 signed by hand (no
SDK dependency; the AWS SDK tree would be heavier than the four HTTP
calls). A bucket that returns 401 or 403 surfaces as
`BlobError::Auth`, never as "object not found", so an operator chasing
wrong credentials is not led to chase a phantom missing blob. When
`backend = "s3"` is set, blob-store reclaim (`reclaim_blobs`) and the
`/api/v1/accounts/{name}/quota` path no longer walk the local filesystem
— quota is enforced by the configured per-account limit and the operator
manages bucket lifecycle on the S3 side.

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
| `ovh` | Application key + secret + consumer key; signed with `$1$`+SHA1; see specifics below. |
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
#### `[dns]` — OVH specifics

```toml
[dns]
provider = "ovh"
zone = "example.org"
access_key = "your_application_key"          # AK from the OVH API portal
secret_key = "your_application_secret"       # AS; prefer secret_key_env
secret_key_env = "OVH_APP_SECRET"
consumer_key = "your_consumer_key"           # CK; prefer consumer_key_env
consumer_key_env = "OVH_CONSUMER_KEY"
endpoint = "ovh-eu"                          # ovh-eu (default) | ovh-ca | ovh-us
```

- **Three credentials.** OVH's REST API authenticates each call with
  `X-Ovh-Application` (AK), `X-Ovh-Consumer` (CK) and an `X-Ovh-Signature`
  header — a SHA-1 over `AS + "+" + CK + "+" + METHOD + "+" + full URL + "+"
  + body + "+" + timestamp`, prefixed with `$1$`. AK and AS come from
  <https://eu.api.ovh.com/createApp/>; CK is generated once the operator
  validates the rights at the URL the `/auth/credential` call returns.
- **Endpoints.** `ovh-eu` resolves to `https://eu.api.ovh.com/1.0`,
  `ovh-ca` to `https://ca.api.ovh.com/1.0`, `ovh-us` to
  `https://api.us.ovhcloud.com/1.0`. A full URL is also accepted as the
  `endpoint` value (e.g. for a private gateway). Each region has separate
  credentials; do not reuse an EU `consumer_key` against the US API.
- **Records are id-addressed.** `upsert` lists records of `(fieldType,
  subDomain)` first, then PUTs the existing id (or POSTs a new one). After
  every write OVH requires `POST /domain/zone/{z}/refresh` to publish;
  epistle calls it for you. Records are not actually live until the refresh
  propagates, but epistle's call returns success as soon as OVH accepts the
  write.
- **TXT values.** OVH silently wraps TXT targets in double quotes on read;
  epistle strips them so `list` returns what you put in `upsert`. On write,
  the value is sent verbatim — do not pre-quote.
- **TLSA is not supported.** OVH's `/record` endpoint does not accept the
  TLSA tuple, so `RecordKind::Tlsa` returns `provider does not support
  writes` and epistle skips publishing it. Publish TLSA at a different
  provider (or split the zone) if you need DANE.

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

### Masked email addresses
Per-account disposable aliases, surfaced under `/api/v1/accounts/{name}/masked`. The server picks the random suffix (8 lowercase base32 chars from the CSPRNG); the client only supplies a human-readable label. The local part of every mask is `<label-slug>.<random>@<first configured domain>`. Disabled masks reject exactly like unknown users (no leak that one existed). The per-account cap is `masked_addresses_max` (default 100); going over returns `429`.

### `[[tenant]]`
A tenant is a named group of domains with optional aggregate caps. Tenancy is what makes a resellable deployment work: each tenant gets its own per-account cap (already covered by `quota_bytes` / `domain_quotas`) plus aggregate caps the operator can promise to the tenant without having to revisit per-account limits. With no `[[tenant]]` block the server behaves exactly as it always has; the empty list is the identity.

```toml
[[tenant]]
name = "acme"
domains = ["acme.example", "acme-mail.example"]
quota_bytes = 1073741824        # 1 GiB aggregate across every account in the tenant
max_accounts = 50                # hard cap on accounts in the tenant's domains
max_domains = 5                  # operator guard; never smaller than domains.len()
submission_rate_limit_per_min = 200   # aggregate SMTP submission rate, on top of submission_rate_limit_per_min
```

| Key | Meaning |
|---|---|
| `name` | Stable identifier shown in error messages. Operators see it; the network never does. |
| `domains` | Domains that belong to the tenant. Every entry must also appear under the top-level `domains` list. |
| `quota_bytes` | Aggregate storage cap (bytes) across every account in every domain of the tenant. Absent means no aggregate cap; the per-account and per-domain quotas still apply. |
| `max_accounts` | Maximum number of accounts (static + dynamic) this tenant may hold. Absent means no cap. |
| `max_domains` | Maximum number of domains this tenant may declare. Absent means no cap. The cap cannot be lower than `domains.len()` because that would make the tenant unloadable. |
| `submission_rate_limit_per_min` | Aggregate submission rate ceiling for the tenant (messages per minute, summed across every authenticated sender in every domain of the tenant). Sits on top of — not in place of — the global `submission_rate_limit_per_min` per-account limiter. |

Rules:

- A domain can only belong to one tenant. A config that lists the same domain under two `[[tenant]]` blocks fails to load, with both tenant names in the message.
- `quota_bytes` smaller than the sum of `domain_quotas` entries that fall inside the tenant is rejected at load time: a cap that cannot be reached would be a lie on the reseller agreement.
- `max_accounts` is enforced on `POST /api/v1/accounts` as `409 Conflict` (not `429`): waiting will not lift it, the cap lifts when an account is deleted or the operator raises it.
- `quota_bytes` is enforced on `POST /jmap/upload` alongside the per-account quota, with the JMAP limit problem type (`urn:ietf:params:jmap:error:limit`, `limit: "tenant_storage"`, HTTP `507`).
- `submission_rate_limit_per_min` is enforced on authenticated `MAIL FROM` (over SMTP) and on `POST /api/v1/send`, on top of the global per-account limiter. A rejection is `429` from the API or `450 4.7.1` from SMTP.

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

## JMAP submission

The JMAP `EmailSubmission/set` and `Email/set` (create) handlers stamp a
fresh `Message-ID` and `Date` header on every message that lacks them. The
stamped `Message-ID` is `<uuidv7@envelope-domain>`, where the
envelope-domain is the `envelope.mailFrom` domain (or the `From` header's
domain for `Email/set` create), and the stamped `Date` is the RFC 5322
form of the server's current UTC time. Client-supplied `Message-ID` and
`Date` are left unchanged: a client that wants to set its own id sends
one. The stamp only fires on authenticated submission; inbound relay
mail from other servers is not modified.

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
