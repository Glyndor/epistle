# CLI reference

All administration is done through the `epistle` command. Every command that needs
configuration takes `--config <FILE>`. Run `epistle <command> --help` for the exact
flags.

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
| `epistle storage-keygen` | Print a fresh base64 32-byte key for at-rest message encryption (`[storage]`). |
| `epistle token-hash` | Read a bearer token on stdin, print the `sha256:<hex>` for `[api] token_hash`. |

## Accounts

| Command | What it does |
|---|---|
| `epistle accounts --config F` | List configured accounts. |
| `epistle account-add --config F --name N --address a@b [--address …]` | Create an account; reads the password from stdin (one line). |
| `epistle app-password-create --config F --account N --label L [--expires-at EPOCH] [--ip-cidr CIDR]` | Create an app password for an account (IMAP/SMTP); prints the generated secret once. |
| `epistle app-passwords --config F [--account N]` | List app passwords (label, expiry, IP restriction). |
| `epistle app-password-revoke --config F --account N --label L` | Revoke an app password. |
| `epistle api-key-create --config F --label L [--expires-at EPOCH] [--ip-cidr CIDR]` | Create a management-API key; prints the generated key once. |
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
