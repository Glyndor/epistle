# Security

epistle is built secure-by-default and fail-closed: a misconfiguration or a
failed safety check aborts rather than degrading silently. This page summarizes
the controls in place and how to report a vulnerability.

For the requirement-by-requirement mapping to OWASP ASVS Level 3 — each control
tied to the file and mechanism that implements it — see the
[ASVS L3 sweep](asvs.md).

## Transport

- **Authentication never crosses cleartext.** SMTP `AUTH` and IMAP `LOGIN`/
  `AUTHENTICATE` are refused until the session is inside TLS; POP3 is
  implicit-TLS only (no plaintext port 110), and ManageSieve requires a
  STARTTLS upgrade before authentication.
- **TLS for the mail protocols** is the server's own job (built-in ACME, or
  manual PEM). Outbound delivery is opportunistic TLS, upgraded to *mandatory
  verified* TLS when MTA-STS enforce, DANE, or a sender's REQUIRETLS applies.

## Authentication

- **Passwords** are stored as **argon2id** PHC hashes — never plaintext, never
  reversible.
- **SCRAM-SHA-256** authenticates without the password crossing the wire, and
  **SCRAM-SHA-256-PLUS** adds TLS channel binding (`tls-server-end-point`) with
  downgrade rejection (RFC 5802 §6). `-PLUS` is offered when a static `[tls]`
  certificate is configured; under ACME (where the certificate is renewed at
  runtime) it is omitted and clients use SCRAM-SHA-256.
- **OAuth2/OIDC** (OAUTHBEARER/XOAUTH2) bearer tokens are verified against the
  configured issuer/audience/key.
- **TOTP** two-factor (RFC 6238) is checked in the IMAP/SMTP auth paths.
- **No user-enumeration oracle**: an unknown user fails exactly like a wrong
  password, and repeated failures close the connection.

## Authorization

- An authenticated sender may only use a `MAIL FROM` it owns — no spoofing, no
  null reverse-path from an authenticated session.
- Every recipient is resolved against the directory before any network work; an
  empty directory rejects everything (fail-closed).

## Process and host

- **Privilege separation**: with `[privileges]`, the daemon drops to an
  unprivileged user/group once the privileged ports are bound, and verifies the
  drop cannot be reversed (see the [configuration reference](configuration.md)).
- The configuration file must be owner-only (`0600`); the server refuses to load
  a group/world-readable file. Secrets stay in the environment via `${VAR}`.

## Email authentication and anti-spoofing

Inbound mail is checked with **SPF**, **DKIM**, **DMARC** (with aggregate
reports), and **ARC**; outbound is **DKIM-signed**, with **MTA-STS**, **DANE**
and **TLS-RPT** for transport authentication. See the [DNS guide](dns.md).

## Anti-abuse

- Layered inbound filtering: **greylisting**, a **Bayesian** filter, sender
  **reputation**, and optional **DNSBL** lookups, plus an external scanner hook.
- **Outbound suppression**: a hard bounce (permanent 5xx) suppresses the
  recipient so the server stops sending to dead addresses, protecting the
  sending IP's reputation.
- The outbound queue gives up by **message age** (5 days), not a low attempt
  count, so transient outages don't lose mail; a delay-warning DSN is sent once.
- **ARF** abuse reports can be generated for offending messages
  (`epistle report-abuse`).

## Data at rest

The default is **full-disk encryption (LUKS)** on the data volume, which
protects against stolen-disk/offline access while keeping search and Bayes
working. Message and config files are written `0600` under the isolated user.

### Optional at-rest message encryption (`[storage]`)

For defence in depth against **offline disk/backup theft**, the stored message
files (`.eml` bodies, the outbound spool, JMAP blobs) can be transparently
encrypted with ChaCha20-Poly1305. Enable it with `encrypt_at_rest = true` in
`[storage]` and supply a 32-byte key. This **complements, not replaces**, LUKS:
the server holds the key in memory and decrypts on every read, so it cannot
defend against a live-server compromise — its value is that a stolen disk or
backup, on its own, yields only ciphertext.

- **The key must live off the encrypted disk** (otherwise encrypting files on
  the same disk is pointless against theft). Source it from `encryption_key_env`
  (the name of an environment variable holding the base64 key) or
  `encryption_key_file` (a path the operator manages, ideally outside
  `data_dir`). Generate one with `epistle storage-keygen`. The server never
  auto-generates a key inside `data_dir`.
- **Fail closed:** with `encrypt_at_rest = true` and no usable key the server
  refuses to start; a decryption failure on read is an error, never a fall-back
  to serving ciphertext.
- **Transparent migration:** encrypted files carry a magic prefix, so encrypted
  and pre-existing plaintext files coexist — turning encryption on encrypts only
  new writes, and old plaintext mail still reads correctly.
- **Backups stay encrypted:** `epistle backup` archives the on-disk bytes
  verbatim, so a backup of an encrypted store remains ciphertext — restore it on
  a host with the same key. Use `epistle export` for a decrypted copy.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this
repository rather than opening a public issue. Include reproduction steps and
the affected version; we will acknowledge and coordinate a fix and disclosure.
