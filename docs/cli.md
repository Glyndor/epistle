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
| `epistle config-check --config F` | Validate the configuration and exit. |
| `epistle verify --config F` | Check on-disk data integrity (run before an upgrade). |

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
