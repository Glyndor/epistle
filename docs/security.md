# Security

epistle is built secure-by-default and fail-closed: a misconfiguration or a
failed safety check aborts rather than degrading silently. This page summarizes
the controls in place and how to report a vulnerability.

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
  (`mail report-abuse`).

## Data at rest

The default is **full-disk encryption (LUKS)** on the data volume, which
protects against stolen-disk/offline access while keeping search and Bayes
working. Message and config files are written `0600` under the isolated user.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this
repository rather than opening a public issue. Include reproduction steps and
the affected version; we will acknowledge and coordinate a fix and disclosure.
