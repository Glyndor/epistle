# CLI reference

All administration is done through the `epistle` command. Every command that needs
configuration takes `--config <FILE>`. Run `epistle <command> --help` for the exact
flags.

## Output

Every `epistle` subcommand splits its output into two streams by purpose:

- **stdout** carries command data or listings. The four data commands below
  never carry an ANSI escape sequence there, no matter the terminal, no matter
  `NO_COLOR`, no matter `CLICOLOR_FORCE`; the property is pinned by
  `tests/cli_stdout_clean.rs`. `clap`'s `--help` and `--version` also write to
  stdout and follow the same precedence, so `--help` may colourise its text
  under `CLICOLOR_FORCE=1` or a real terminal.
- **stderr** carries status, warnings, errors and progress and is the only
  stream that may carry colour or a `\r`-rewritten progress line.

Four commands produce binary or quoted data on stdout and would silently break if
an escape sequence or spinner frame were ever written there, so they are pinned by
`tests/cli_stdout_clean.rs`:

| Command | stdout payload |
|---|---|
| `epistle backup --config F` | A gzip-compressed tar of `data_dir` (and a `pg_dump` when configured). |
| `epistle export --config F --account N` | An mbox stream (`From MAILER-DAEMON@localhost` separators). |
| `epistle storage-keygen` | A single base64 32-byte at-rest key. |
| `epistle oauth-keygen` | A PKCS#8 ES256 private key plus the matching public point. |

`backup`'s `warnings` sink (the externally-referenced paths that are not in the
archive) is also stderr, by the same rule.

The colour decision on stderr follows the standard precedence: `NO_COLOR`
disables it, `CLICOLOR_FORCE=1` enables it regardless of whether stderr is a
terminal, otherwise it follows whether stderr is a terminal and `TERM`.
`clap`'s `--help` and `--version` on stdout follow the same precedence. To
force a specific look in a script:

```sh
# Coloured status, plain stdout data:
epistle backup --config /etc/mail.toml > backup.tar.gz

# Plain everywhere, for a log file:
NO_COLOR=1 epistle backup --config /etc/mail.toml > backup.tar.gz
```

Progress is a single line on stderr (one tick per message for `import`, one tick
per check for `verify-dns`) that gets cleared when the command finishes. When
stderr is not a terminal, the progress line is suppressed and the summary is
printed once at the end.

## Running the server

| Command | What it does |
|---|---|
| `epistle serve --config F` | Bind the configured listeners and run. |
| `epistle mta-sts-serve --policy-dir DIR --cert FILE --key FILE [--listen ADDR]` | Serve the public MTA-STS policy over HTTPS. |
| `epistle config-check --config F` | Validate the configuration and exit. |
| `epistle verify --config F` | Check on-disk data integrity (run before an upgrade). |
| `epistle local --dir DIR [--port-base N]` | Self-contained loopback test harness. NOT a deployment: see below. |

## `epistle mta-sts-serve`

Run a second instance of the same binary for the public policy endpoint:

```sh
epistle mta-sts-serve --policy-dir /var/lib/epistle/mta-sts \
  --cert /etc/epistle/mta-sts-cert.pem --key /etc/epistle/mta-sts-key.pem \
  --listen 0.0.0.0:8443
```

`--listen` defaults to `0.0.0.0:8443`. Make this listener reachable on public
HTTPS port 443 at `mta-sts.<domain>`. The certificate must cover that hostname
for every served domain; a certificate covering only the mail hostname is
insufficient. The command needs no mail configuration or database.

`GET` and `HEAD` at `/.well-known/mta-sts.txt` read `DIR/mta-sts.txt` on each
request and return `Content-Type: text/plain; charset=utf-8` with
`Cache-Control: max-age=<policy max_age>`. Other paths and a missing policy
return an empty 404. Other methods on the policy path return 405 with
`Allow: GET, HEAD`. Invalid policy contents or read failures other than a
missing file return an empty 500.

TLS 1.2 and 1.3 are enabled. The HTTP request line and headers together are
limited to 8 KiB, and each connection has a 30-second lifetime including the
TLS handshake. Certificate and key file changes are checked on new
connections. Valid replacements take effect without restarting; an invalid
replacement retains the previous certificate and is retried on the next
connection.

Configure [`[mta_sts] policy_dir`](configuration.md#mta_sts) on the ordinary
`serve` process to write the shared policy directory at startup. After changing
the policy configuration, restart `serve` and republish the `_mta-sts` TXT
record printed by `dns-records`; its ID is derived from the policy content.

## `epistle local` (test harness)

`epistle local --dir <DIR> [--port-base 10000]` is a complete server that touches
nothing outside `--dir` and the loopback interface. It exists so anything that
needs persistent external effects (the coming `init`, DNS publishing, ACME)
can be exercised against a single `127.0.0.1` server without a domain, DNS
records or certificates. It is its own subcommand and not a flag of `serve`,
because a flag is something that gets left on in production.

What it does:

- Identity is fixed: hostname `mail.local.test`, one domain `local.test`.
  `.test` is reserved by RFC 6761 and never resolves, so nothing here can reach
  a real zone.
- Every listener binds `127.0.0.1` only. There is no option for another
  address. Ports are `port-base + {25, 587, 465, 143, 993, 8025}` for SMTP,
  submission, submissions, IMAP, IMAPS and the management API. `--port-base`
  must keep every port inside `1024..=65535`; a value outside the range is a
  usage error that names the computed port.
- The first run on an empty or missing `--dir` creates, all `0700`/`0600`:
  a marker file `.epistle-local`, a `data/` directory, a self-signed
  certificate and key for `mail.local.test`, a DKIM Ed25519 key, a
  `mail.toml` that `epistle config-check` accepts, and one account
  `user@local.test` whose password is generated from the system CSPRNG and
  stored as argon2id.
- A later run on a `--dir` that carries the marker REUSES everything byte
  for byte (same key, same certificate, same password hash). A `--dir` that
  exists, is not empty, and has no marker is refused with
  `<DIR> is not empty and was not created by "epistle local"` and no writes.
- Outbound delivery is held: mail submitted for a recipient outside
  `local.test` stays in the spool, no outbound SMTP connection is ever
  opened, and there is no `[database]` section. The flag is internal to
  `Config` (`hold_outbound`) and `serde` cannot set it; only `epistle local`
  sets it.
- On start it prints to STDERR: a first line that says `epistle local:
  starting`, followed by the directory, the six `127.0.0.1:<port>`
  endpoints, the account name, and the password ONLY on the run that
  generated it, with a line saying it is shown once. The summary uses
  `starting` because `serve` does not hook the operator from "bound" to
  "first failure" and `epistle local` does not add that hook here. stdout
  stays empty.

This is a test harness, not a deployment. There is no ACME, no DNS lookups at
startup, no DNSBL, no greylisting, no `[database]`, and the configuration
generated by `epistle local` is not a template for production.

## Keys and tokens

| Command | What it does |
|---|---|
| `epistle dkim-keygen --out F` | Generate an Ed25519 DKIM key and print the DNS record value. |
| `epistle dkim-keygen --rsa [--bits 2048\|4096] --out F` | Generate an RSA DKIM key (delegates to `openssl genpkey`) and print the `k=rsa` record. The RSA `p=` value is large enough to need 255-octet TXT splitting; the printed record is already in the form a zone file accepts. |
| `epistle storage-keygen` | Print a fresh base64 32-byte key for at-rest message encryption (`[storage]`). |
| `epistle token-hash` | Read a bearer token on stdin, print the `sha256:<hex>` for `[api] token_hash`. |

## Accounts

| Command | What it does |
|---|---|
| `epistle accounts --config F` | List configured accounts. |
| `epistle account-add --config F --name N --address a@b [--address …]` | Create an account; reads the password from stdin (one line). |
| `epistle account-remove --config F --name N --queue discard\|drain` | Remove a dynamic account and its whole footprint: mailbox, masked addresses, app passwords, per-account suppression, and queued outbound mail. `--queue` is required and chooses what to do with queued mail on behalf of the account (`discard` drops it, `drain` leaves it to be delivered). Prints the per-record counts removed. |
| `epistle app-password-create --config F --account N --label L [--expires-at EPOCH] [--ip-cidr CIDR]` | Create an app password for an account (IMAP/SMTP); prints the generated secret once. |
| `epistle app-passwords --config F [--account N]` | List app passwords (label, expiry, IP restriction). |
| `epistle app-password-revoke --config F --account N --label L` | Revoke an app password. |
| `epistle api-key-create --config F --label L [--expires-at EPOCH] [--ip-cidr CIDR] [--domain D] --scope S` | Create a management-API key; prints the generated key once. `--scope` is required and may be repeated (`read`, `write`, `send`, `scim`). `--domain` may be repeated to confine the key to those domains; omitted, it reaches every configured domain. |
| `epistle api-keys --config F` | List API keys (label, expiry, IP restriction). |
| `epistle api-key-revoke --config F --label L` | Revoke an API key. |

## Mail in and out

| Command | What it does |
|---|---|
| `epistle export --config F --account N` | Export an account's mailboxes as an mbox stream on stdout. |
| `epistle import --config F --account N [--maildir DIR]` | Import an mbox stream from stdin, or a Maildir tree. |
| `epistle queue --config F` | List the outbound delivery queue. |
| `epistle suppression --config F [--remove ADDR]` | List suppressed (hard-bounced) recipients, or remove one. |
| `epistle report-abuse --config F` | Read an offending message on stdin, print an RFC 5965 ARF report to send to the sender's abuse address. |
| `epistle reports --config F [--days N]` | Summarise the DMARC aggregate and TLS-RPT reports that arrived for our domains over the last `N` days (default 7). Per policy domain: reporters seen, total rows, and failing rows by `source_ip` (DMARC) or failing sessions by `result_type` and `sending_mta_ip` (TLS-RPT). Reads the JSONL store under `data_dir/reports/`; never writes to it. |

## Expunged-message archive

Active only when `[storage] deleted_retention_days` is set to a positive value.
With retention off, an expunge deletes the on-disk files immediately and no
archive directory is created. With retention on, an expunge moves the message
into `<account>/.archive/`, and an hourly sweeper drops entries older than the
configured window.

| Command | What it does |
|---|---|
| `epistle archive list --config F <ACCOUNT>` | List every archived message for an account (id, mailbox, unix time). |
| `epistle archive restore --config F <ACCOUNT> <ID>` | Re-append an archived message to its original mailbox (or INBOX when that mailbox is gone), then remove it from the archive. |
| `epistle archive purge --config F <ACCOUNT> [--older-than-days N]` | Delete archived entries. Without `--older-than-days`, every entry for the account is purged; with it, only entries older than the threshold. The sweep uses the same threshold. |

## Client autodiscovery

These print documents the operator publishes so clients configure themselves
from just an email address and password. Thunderbird autoconfig and Microsoft
Autodiscover can also be served **live** by adding an `autoconfig` listener (see
the [configuration reference](configuration.md)) and pointing the
`autoconfig.<domain>`/`autodiscover.<domain>` subdomains at it.

| Command | What it does |
|---|---|
| `epistle srv-records --config F` | Print the RFC 6186 SRV records to publish in DNS. |
| `epistle autoconfig --config F [--domain D]` | Thunderbird autoconfig XML — host at `autoconfig.<domain>/mail/config-v1.1.xml`. |
| `epistle autodiscover --config F [--domain D]` | Microsoft Autodiscover v1 XML — host at `autodiscover.<domain>/autodiscover/autodiscover.xml`. |
| `epistle mobileconfig --config F --account N` | Apple `.mobileconfig` profile for a user to install on iOS/macOS. |

## Outbound retry policy

The queue retries transient failures with exponential backoff (1m, 2m, 4m, …
capped at 1h). It gives up by **message age** — `queue_give_up_secs` (default 5
days) — not by attempt count, so a recipient whose server is down for hours does
not lose mail. A single "delivery delayed" warning DSN is sent at ~4h. A
permanent (5xx) failure bounces immediately and adds the recipient to the
suppression list, after which mail to that address is dropped without retrying
(clear it with `epistle suppression --remove`).
