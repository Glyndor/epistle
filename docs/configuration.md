# Configuration

`epistle` is configured with a single TOML file, passed to
every command with `--config`:

```sh
epistle serve --config /etc/epistle/mail.toml
epistle config-check --config /etc/epistle/mail.toml   # validate without starting
```

The file must be owner-only — the server refuses to load a file that is group-
or world-readable:

```sh
chmod 600 /etc/epistle/mail.toml
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

## Sections

### `[tls]`
TLS material, shared by all transports. Required by `submissions`/`imap`/`imaps`/`manage-sieve`; enables STARTTLS on `smtp`/`submission`.

| Key | Meaning |
|---|---|
| `cert_file` | PEM certificate chain. |
| `key_file` | PEM private key. |

### `[dkim]`
Outbound DKIM signing. Ed25519 is primary; an RSA selector can be added for receivers that lack Ed25519 support.

| Key | Meaning |
|---|---|
| `selector` | Ed25519 selector (the `s=` tag). |
| `key_file` | Ed25519 private key (PKCS#8 PEM); generate with `epistle dkim-keygen`. |
| `rsa_selector` | Optional RSA selector. |
| `rsa_key_file` | Optional RSA private key. |

### `[api]`
Management API (consumed by `epistle-panel`). Closed by default.

| Key | Meaning |
|---|---|
| `token_hash` | `sha256:<hex>` (from `epistle token-hash`) or an argon2id PHC string. |

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

### `[privileges]`
Drop OS privileges after binding ports (run the daemon unprivileged).

| Key | Meaning |
|---|---|
| `user` | Unprivileged user to switch to (must exist). |
| `group` | Optional; defaults to the user's primary group. |

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

## Example

```toml
hostname = "mail.example.org"
data_dir = "/var/lib/epistle"
domains  = ["example.org"]

queue_give_up_secs = 432000   # 5 days (the default)
greylist_delay_secs = 60

[tls]
cert_file = "/etc/epistle/tls/fullchain.pem"
key_file  = "/etc/epistle/tls/privkey.pem"

[dkim]
selector = "ed1"
key_file = "/etc/epistle/dkim/ed1.pem"

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
