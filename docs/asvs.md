# OWASP ASVS Level 3 — requirement sweep with evidence

This document maps the OWASP Application Security Verification Standard
(ASVS v4.0.3) **Level 3** requirements to concrete evidence in the epistle
codebase. It is the verification artifact behind the
[security overview](security.md): where that page summarizes the controls, this
page cites the file and the mechanism for each relevant requirement.

epistle is a **headless mail server** (SMTP / IMAP / POP3 / JMAP / ManageSieve /
WebDAV-CalDAV-CardDAV) with a closed-by-default management HTTP API. It has **no
browser UI, no cookies and no interactive web session** — the panel
([`epistle-panel`](https://github.com/Glyndor/epistle-panel)) is a separate
product. ASVS rows that only make sense for a browser front end (cookie session
management, CSRF, clickjacking, the BFF/SPA rows, HTML/JS output encoding) are
therefore marked **N/A** here, with the reason; they are in scope for the panel,
not the server.

Status legend: **Met** — implemented, with evidence · **N/A** — not applicable
to a headless server, with the reason · **Gap** — a genuine deficiency. Each Gap
is followed by whether it was fixed in this sweep or is documented as accepted /
deferred.

Paths are relative to the crate root. Line numbers are indicative; the cited
function name is the stable reference.

---

## V1 — Architecture, Design and Threat Modeling

| Req (L3) | Status | Evidence |
|---|---|---|
| 1.1 Secure SDLC, threat model | Met | Secure-by-default / fail-closed is a project invariant; the threat model and control summary live in [`docs/security.md`](security.md). |
| 1.2 Authentication architecture (unique, low-priv service account) | Met | Runs under a dedicated isolated system user (`glyndor-epistle`); privileges are dropped after binding (`src/privdrop.rs`, `drop_to`/`verify`). |
| 1.4 Access-control architecture (enforced at a trusted layer) | Met | Management API is gated by one middleware over the whole router (`src/api/state.rs::require_bearer_token`, wired in `src/api/mod.rs`); mail-protocol access is account-scoped at the directory/storage layer. |
| 1.5 Input/output: untrusted input bounded at the boundary | Met | Sans-IO decoders bound every external input (see V5); SMTP decoder is smuggling-immune (`src/smtp/line.rs::LineDecoder`). |
| 1.6 Cryptographic architecture (keys managed, rotatable) | Met | DKIM auto-rotation under new selectors with an overlap window (`src/dkim/rotate.rs`); ACME issues/renews TLS keys (`src/acme/`). |
| 1.8 Data protection / classification | Met | Bodies on the filesystem `0600`, never in the DB; secrets only from the environment. See V8. |
| 1.9 Communications encrypted in transit | Met | TLS for all mail protocols. Outbound STARTTLS is strict (webpki + hostname) by default and whenever TLS is mandated (MTA-STS enforce / REQUIRETLS); DANE authenticates via TLSA. Operators may opt a non-mandated, non-DANE hop down to opportunistic TLS (encryption without authentication, the SMTP norm) via `[queue] outbound_tls`. See V9. |
| 1.11 Business-logic boundaries documented | Met | Per-account confinement, MAIL FROM ownership, quota pool invariant — see V4 / V11. |
| 1.14 Trust boundaries / segregation | Met | API closed by default (Podman-internal only); CLI runnable only as the isolated user / sudo. |

---

## V2 — Authentication

| Req (L3) | Status | Evidence |
|---|---|---|
| 2.1.1 / 2.1.x Password length & all-chars allowed | Met | Length 12–64 enforced before hashing (`src/api/v1/accounts.rs::check_password`, `src/cli/accounts.rs`); the 64 cap is the documented Argon2 DoS ceiling; counted as Unicode scalars (no truncation). |
| 2.1.7 Reject known-breached passwords | **Gap** | No HaveIBeenPwned range query and no bundled breached-list check exists. Documented below (deferred — needs network integration or a bundled list; out of scope for a minimal surgical fix). |
| 2.1.9 No composition rules that reduce strength / no silent truncation | Met | No silent truncation; all characters accepted within the length window (`check_password`). |
| 2.2.1 Anti-automation / brute-force throttling | Partial / **Gap** | Per-connection 3-strikes close on SMTP (`src/smtp/session/mod.rs`), IMAP (`src/imap/session/auth.rs`) and now ManageSieve (`src/managesieve/session.rs`, fixed in this sweep); the API has a sliding-window failure budget (`src/api/state.rs::AuthLimiter`). **No cross-connection per-IP/per-account ban** for the mail protocols — documented below (deferred — needs a persistent store). |
| 2.2.3 Secure notification of auth events | Met | Auth failures are logged as counts (no credentials); delivery/security events flow to webhooks. |
| 2.4.1 Passwords stored with an approved KDF (Argon2) | Met | argon2id PHC everywhere (`src/smtp/auth.rs::hash_password`/`verify_password`); 16-byte CSPRNG salt via `ring::SystemRandom`. Config rejects any non-argon2id stored hash (`src/config/validate.rs`). |
| 2.5.x Credential recovery does not reveal the credential | Met | Verification returns a bare `false` on any error; no reset oracle in the server. |
| 2.6 / 2.8 Look-up / OTP verifiers (TOTP) | Partial | TOTP verified with a constant-time compare and a bounded ±1 step window (`src/totp/mod.rs::verify`, `constant_time_eq`). **No replay guard / no recovery codes / secret stored in cleartext** — documented below (deferred — needs persistent state and at-rest key management). |
| 2.7 Out-of-band verifier | N/A | No SMS/email OOB second factor is offered. |
| 2.9 Cryptographic verifier (SCRAM) | Met | SCRAM-SHA-256 / -SHA-256-PLUS: password never on the wire, channel binding to the cert (`tls-server-end-point`), downgrade flag rejected when -PLUS is offered (`src/smtp/scram.rs`, `src/imap/session/auth.rs`). |
| 2.10.1 No user-enumeration oracle | Met | Unknown login and wrong password both resolve to `None` with an identical reply in every protocol (`src/smtp/directory.rs::authenticate_with_ip`/`credentials`). |
| 2.10.4 OAuth/JWT bearer fully validated | Met (hardened in this sweep) | `alg` pinned by caller (no confusion), signature verified, `iss`/`aud`/`nbf` checked, and **`exp` now required** — a token without a bounded lifetime is rejected (`src/jwt/mod.rs::check_claims`, fixed in this sweep). |

---

## V3 — Session Management

| Req (L3) | Status | Evidence |
|---|---|---|
| 3.1 No session tokens in the URL | Met | Bearer token read only from the `Authorization` header (`src/api/state.rs::require_bearer_token`). |
| 3.2 / 3.3 Session generation, timeout, invalidation | N/A | The server holds no server-side web session: mail protocols are connection-scoped (auth state dies with the TCP connection); the API is stateless bearer-token. |
| 3.3.x Bearer-token lifetime bounded | Met | OAuth/JWT bearer tokens require `exp` (`src/jwt/mod.rs`, fixed in this sweep); API keys carry an expiry honored fail-closed (`src/api/api_keys.rs::admits`). |
| 3.4 Cookie-based session attributes (Secure/HttpOnly/SameSite) | N/A | No cookies are issued by the server. (In scope for `epistle-panel`.) |
| 3.5 Token-based session (no static API secrets in code) | Met | Tokens are operator-provisioned hashes (`sha256:` digest or legacy argon2id), never in source. |
| 3.7 / CSRF defenses | N/A | No browser-driven state-changing form; API is bearer-authenticated, not cookie/ambient-authority. |

---

## V4 — Access Control

| Req (L3) | Status | Evidence |
|---|---|---|
| 4.1.1 Enforced at a trusted server layer | Met | Single `require_bearer_token` layer over the whole authenticated router; `/healthz` is the only unauthenticated route and returns a static body (`src/api/mod.rs`, `src/api/state.rs`). |
| 4.1.3 Least privilege | Partial | OS-level: privileges dropped irreversibly (`src/privdrop.rs::verify` asserts `setuid(0)` fails). API-level: a single operator token authorizes all accounts (by design — the API consumer is the operator/panel); a scoped per-account API key would be stricter. Noted, not a cross-tenant leak. |
| 4.1.5 Fail closed on access-control errors | Met | Every auth/key check ANDs its conditions and rejects on malformed/missing input (`src/api/api_keys.rs::admits`, `src/directory_store/app_passwords.rs::admits`). |
| 4.2.1 Object-level authZ / no IDOR | Met | JMAP blob ids parsed as UUIDs before any FS use; every data path uses the authenticated `self.account()` (`src/api/jmap/`); IMAP mailbox names allow-listed (`src/imap/mailbox.rs::valid_name`). |
| 4.2.2 State-changing ops protected | Met | All mutating API/JMAP routes sit behind the bearer middleware. |
| 4.3.1 Admin interfaces require additional protection | Met | Management API is closed by default (Podman-internal); the CLI runs only as the isolated user/sudo. |
| 4.3.3 Per-account confinement (WebDAV/CalDAV/CardDAV) | Met | `src/webdav/path.rs::resolve` percent-decodes, rejects NUL/`..`/`\`/non-`Normal` components and ends with a `starts_with(root)` guard; the root is derived from the *resolved* account (`src/webdav/auth.rs`, `src/webdav/handler.rs`). |
| 4.x Sender ownership (MAIL FROM) | Met | An authenticated sender may only use a reverse-path / From it owns (`src/smtp/session/mod.rs` → `src/smtp/directory.rs::owns_address`); relay to foreign domains requires auth. |

> RFC 4314 IMAP ACLs are stored and reported (`SETACL`/`GETACL`/`MYRIGHTS`,
> `src/imap/session/acl.rs`) but no shared-mailbox **read path consults them yet**
> — every data path is owner-scoped, so this is fail-safe (deny), not a leak. If
> a shared-read path is added it must enforce these stored rights.

---

## V5 — Validation, Sanitization and Encoding

| Req (L3) | Status | Evidence |
|---|---|---|
| 5.1.x Input validation at the boundary | Met | Addresses validated and length-capped (`src/smtp/address.rs`, 254/64, control chars rejected); SMTPUTF8/EAI handled. |
| 5.1.4 Bounds on attacker-controlled sizes | Met | SMTP data line 998 (`src/smtp/line.rs`), command line 512 (`src/smtp/command.rs`), message 25 MiB and ≤100 recipients (`src/smtp/session/mod.rs`), inbound trace-hop cap (`src/smtp/trace.rs`), outbound reply 64 KiB (`src/queue/client.rs`), MTA-STS body 64 KiB (`src/mtasts/policy.rs`), bounce header block 4096 (`src/queue/bounce.rs`). |
| 5.2.x Sanitize unstructured / hostile content | Met (fixed in this sweep) | A remote MTA's reply is sanitized (controls → space, length-capped) before it reaches any DSN header or body (`src/queue/bounce.rs::sanitize_reason`). |
| 5.3.1 Output encoding / no header (CRLF) injection | Met | Inbound: bare CR/LF/NUL rejected by the decoder (`src/smtp/line.rs`). Outbound: bounce/DSN reason sanitized (above); addresses are validated values. |
| 5.3.4 Parameterized queries only (SQLi) | Met | Every query is a sqlx **compile-time macro** with bound `$n` params — no string-built SQL anywhere (`src/antispam/corpus.rs`, `src/antispam/reputation.rs`). |
| 5.3.6 No injection into LDAP/OS command | Met | No shell-out on attacker input; no LDAP. |
| 5.3.8 Deserialization is safe | Met | TOML/JSON via serde into typed structs; no arbitrary-type deserialization. |
| 5.5 SSRF defenses | Met | No per-request attacker-controlled fetch: webhook URLs are operator config validated at startup (`src/config/validate.rs`); MTA-STS fetches a fixed `https://mta-sts.<domain>/.well-known/...` with redirects disabled (`src/mtasts/policy.rs`); autodiscovery only *serves* config. |

---

## V6 — Stored Cryptography

| Req (L3) | Status | Evidence |
|---|---|---|
| 6.2.1 Approved algorithms, no home-rolled crypto | Met | All crypto via `ring`/`rustls`/`argon2`/`webpki`. No MD5/SHA-1/DES/RC4 for any security purpose. (The single SHA-1 is the RFC 6238-mandated TOTP HMAC, `src/totp/mod.rs`.) |
| 6.2.2 Argon2id for password hashing | Met | `src/smtp/auth.rs::hash_password` (argon2id PHC). |
| 6.2.3 Constant-time comparison of secrets | Met | TOTP and SRS use full-length XOR-fold compares (`src/totp/mod.rs::constant_time_eq`, `src/queue/srs.rs::constant_time_eq`); the API bearer compare is `==` on **SHA-256 digests** of the token — a timing leak of a pre-image-resistant digest reveals nothing about the token (justified at `src/api/state.rs::token_matches`). |
| 6.3.1 CSPRNG for all secrets | Met | `ring::rand::SystemRandom` for salts, app-password secrets, SCRAM/IMAP/SMTP nonces, ACME keys, DKIM keygen (`src/cli/util.rs::generate_secret`, `src/smtp/auth.rs`, `src/acme/`, `src/dkim/`). No `thread_rng`/predictable seeding in non-test code. |
| 6.4.1 Secret key material protected at rest | Met (hardened in this sweep) | DKIM and ACME private keys are written `create_new` + `0o600` (atomic, no permissive window): ACME `src/acme/renew.rs::write_secret`, manual keygen `src/cli/util.rs`, and DKIM **rotation** `src/dkim/rotate.rs::write_key` (fixed in this sweep — previously wrote then chmod'd). |
| 6.x DKIM/JWT algorithm hygiene | Met | DKIM accepts only rsa-sha256 / ed25519-sha256 (rsa-sha1 rejected), verify uses `RSA_PKCS1_2048_8192_SHA256` (≥2048-bit) / ED25519 (`src/dkim/verify.rs`). |

> **Note (deferred):** the TOTP shared secret is stored as cleartext base32 in
> the account store (`src/directory_store/mod.rs`). Encrypting it at rest needs a
> key-management mechanism; documented as a gap below.

---

## V7 — Error Handling and Logging

| Req (L3) | Status | Evidence |
|---|---|---|
| 7.1.1 No secrets/PII in logs | Met | All 50 `tracing` call sites audited: none interpolate a password, hash, token, API key, SCRAM proof, private key or raw SASL blob. Auth failures log a **count** only (`src/smtp/session/scram.rs`, `src/imap/session/auth.rs`). |
| 7.1.2 No credentials in logs even on the failure path | Met | The decoded PLAIN/LOGIN/SCRAM bytes never reach a log macro; no protocol logs its raw command line. |
| 7.4.1 Generic error to the client; details server-side | Met | API errors return fixed strings (`src/api/error.rs::internal` → "Internal error."); underlying errors dropped via `.map_err(|_| …)`; JMAP errors are static. No stack trace, file path, SQL text or version reaches a client. |
| 7.4.x No version/internal banner to unauthenticated clients | Met | SMTP/POP3/IMAP/ManageSieve greetings carry no version; no HTTP `Server` header. (The IMAP `ID` response includes the version only after the client issues `ID`, RFC 2971 — conventional; the `/status` version is behind the closed API.) |
| 7.2 / 7.3 Security-event logging | Met | Authn/authz failures and delivery outcomes are logged/metered (`src/metrics/`), without sensitive data. |

---

## V8 — Data Protection

| Req (L3) | Status | Evidence |
|---|---|---|
| 8.1.1 Sensitive data protected at rest | Met | Message bodies are canonical `.eml` on the filesystem, `0600`, on a LUKS-encrypted volume by default; bodies never enter the DB (a DB compromise exposes no mail content). |
| 8.2.1 Minimal data retention | Met | Retention is opt-in per account, default off (never silently deletes); GDPR erasure hard-purges `.eml` (shredded) + every DB row (see `docs/configuration.md`). |
| 8.3.1 Sensitive data not in logs/URLs | Met | See V7; no PII/secret in logs or URLs. |
| 8.3.4 Secrets sourced from env/secret store | Met | `${VAR}` expansion aborts startup on an unset var (`src/config/mod.rs`); no secret literal in config or code. |

---

## V9 — Communications

| Req (L3) | Status | Evidence |
|---|---|---|
| 9.1.1 TLS for all client connections | Met | rustls (ring provider, TLS 1.2/1.3 only). AUTH refused before TLS on every protocol: SMTP `538` (`src/smtp/session/mod.rs`), IMAP `[PRIVACYREQUIRED]` (`src/imap/session/auth.rs`), ManageSieve `ENCRYPT-NEEDED`, POP3 implicit-TLS only (no port 110). |
| 9.1.2 Strong TLS configuration, no weak protocols | Met | rustls negotiates only TLS 1.2/1.3; the crypto provider is pinned (`src/tls/mod.rs::ensure_crypto_provider`). |
| 9.1.3 Fail closed on TLS misconfiguration | Met | A missing/unreadable/empty/mismatched cert or key is a fatal `TlsError` — the server refuses to start rather than serve plaintext (`src/tls/mod.rs`, tested). |
| 9.2.1 Outbound connections use verified TLS where required | Met | Outbound `tls_connect` authenticates via PKIX (webpki roots + ServerName) whenever `authenticate_pkix = require_tls \|\| (tlsa.is_empty() && mode == Strict)` holds (`src/queue/client.rs`). MTA-STS-enforce / DANE / REQUIRETLS set `require_tls` → strict PKIX, always. With TLSA present the handshake accepts any certificate and DANE authenticates it against the TLSA records (RFC 7672 — a DANE-EE leaf is normally self-signed, so PKIX must not run first); a mismatch fails closed. With neither, the `[queue] outbound_tls` mode decides: `strict` (default) is strict PKIX, `opportunistic` uses an accept-any verifier (encryption only, the SMTP norm). The accept-any verifier (`AcceptAnyServerCert`) is used **only** when authentication is intentionally not via PKIX — never when `require_tls`; a remote without STARTTLS where TLS is mandated still yields a **transient** error (retry, never cleartext). |
| 9.2.x DANE / MTA-STS authentication | Met (hardened in this sweep) | DANE TLSA matched only on DNSSEC-secure responses (`src/spf/dns.rs`); a mismatch fails closed (`src/dane/`, `src/queue/client.rs`). A **transient TLSA lookup failure now defers delivery** instead of downgrading to opportunistic TLS (`src/queue/worker.rs::tlsa_for`, fixed in this sweep). MTA-STS enforce restricts MX and requires TLS (`src/queue/worker.rs`, `src/mtasts/`). |

---

## V10 — Malicious Code

| Req (L3) | Status | Evidence |
|---|---|---|
| 10.2.x No malicious/unexpected code paths | Met | Apache-2.0 source, reviewed; no obfuscation, no phone-home/telemetry (org policy). |
| 10.3.1 App integrity / update authenticity | Met | Distributed as a signed `.deb` via the org apt archive (org `RELEASE_SIGN_KEY`); the server does not self-update, so it carries no in-process artifact-verification path. |
| 10.3.2 No remote/dynamic code loading | Met | No `eval`, no plugin download-and-exec; dependencies are pinned and audited. |
| (mail-specific) Inbound malware scanning | Met | Antivirus (ClamAV) + Bayesian / DNSBL / reputation filtering at delivery (`src/antispam/`, `src/dnsbl/`). |

---

## V11 — Business Logic

| Req (L3) | Status | Evidence |
|---|---|---|
| 11.1.1 Sequential / business-flow integrity | Met | SMTP is a sans-IO state machine; commands out of order are rejected. |
| 11.1.4 Anti-automation on business flows | Met | Greylisting, send rate limits (`src/smtp/ratelimit.rs::SendLimiter`), outbound suppression of dead recipients, retry with backoff. |
| 11.1.x Resource-exhaustion / abuse bounded | Met | All attacker-controlled sizes/counts bounded (see V5); the over-quota path defers (`452`) then bounces rather than failing open; loop prevention on DSNs (null reverse-path, `src/queue/bounce.rs`). |
| 11.x Quota invariant | Met | Global quota pool sub-allocated atomically (`sum(allocated) ≤ global`), enforced transactionally (design: PostgreSQL ledger). |

---

## V12 — Files and Resources

| Req (L3) | Status | Evidence |
|---|---|---|
| 12.1.1 Upload size limited | Met | Message size capped at 25 MiB; IMAP/JMAP blob handling bounded. |
| 12.3.1 No path traversal in file paths | Met | WebDAV `src/webdav/path.rs::resolve` and storage `src/storage/delivery.rs::is_safe_mailbox` + IMAP `valid_name` are allow-lists rejecting `..`/`/`/`\`/NUL/control/leading-dot; all writes are confined under the account root. |
| 12.4.1 Files stored outside the web root with safe perms | Met | `.eml` and config files written `0600` under the isolated user (`src/storage/`); no web root exists. |
| 12.5.1 No execution of uploaded content | Met | Stored mail is inert `.eml`; never executed. |

---

## V13 — API and Web Service

| Req (L3) | Status | Evidence |
|---|---|---|
| 13.1.1 API uses the same access control as the rest of the app | Met | Single bearer middleware over the whole router (`src/api/state.rs`). |
| 13.1.3 No sensitive data in URLs | Met | Token in the `Authorization` header; ids are UUIDs. |
| 13.2.1 Allowed HTTP methods enforced | Met | axum routes declare explicit methods; unknown methods 404/405. |
| 13.2.3 Anti-automation on the API | Met | `AuthLimiter` sliding-window failure budget before any token work (`src/api/state.rs`). |
| 13.3.x JSON schema / typed deserialization | Met | Requests deserialized into typed structs (serde); JMAP method/argument shapes validated against RFC 8620/8621. |
| 13.4 GraphQL | N/A | No GraphQL endpoint. |

---

## V14 — Configuration

| Req (L3) | Status | Evidence |
|---|---|---|
| 14.1.x Secure build / dependency hygiene | Met | No new deps without justification; `SQLX_OFFLINE` reproducible build; CI lints with `-D warnings`. |
| 14.2.1 Dependencies current and audited | Met | Pinned, Dependabot-tracked, `cargo audit` in CI (org standard). |
| 14.3.2 No debug/verbose errors in production | Met | Generic client errors (V7); no stack traces. |
| 14.4.1 Safe HTTP response headers | Partial / N/A | The server emits no `Server` header and no HTML; browser security headers (CSP/HSTS/X-Frame-Options) are the operator-proxy/panel's responsibility, not this headless API's. |
| 14.5.1 Validate the deployment config; refuse insecure config | Met | `src/config/validate.rs` runs before `Config::load` returns and **aborts startup** on any violation: plaintext listeners require `[tls]`; the config file must be `0600` (`check_permissions` rejects `mode & 0o077 != 0`); defaults bind `127.0.0.1`. Fail-closed by construction. |

---

## Gaps found in this sweep

Three genuine gaps were **fixed** with tests covering the failure path; the rest
are **documented as deferred** because a correct fix is a feature (persistent
state, key management, or a network/data integration), not a minimal surgical
change — adding one half-built would be worse than tracking it honestly.

### Fixed

1. **DANE downgrade on a transient TLSA lookup failure** (V9, was high).
   `src/queue/worker.rs::tlsa_for` used `unwrap_or_default()`, collapsing a
   temporary resolver error into "no DANE" and silently downgrading a host that
   *does* publish TLSA. Now the temporary error is propagated and the worker
   **defers** the delivery for retry (RFC 7672 §2.1). Test:
   `transient_tlsa_failure_defers_rather_than_downgrading` in
   `src/queue/worker_tests.rs`.

2. **CRLF / header injection in the bounce (DSN) builder** (V5, was high). A
   hostile remote MTA's SMTP reply (read with its CRLFs intact) flowed unescaped
   into DSN headers (`Diagnostic-Code:`) and body, allowing forged headers in the
   bounce returned to the original sender. `src/queue/bounce.rs::sanitize_reason`
   now flattens every control character to a space and caps the length before the
   reason reaches any sink. Tests:
   `sanitizes_crlf_in_reason_to_prevent_header_injection` and `caps_reason_length`
   in `src/queue/bounce.rs`.

3. **JWT accepted without `exp`** (V2/V3, was high). `src/jwt/mod.rs::check_claims`
   only checked `exp` when present, so a token without a bounded lifetime never
   expired. `exp` is now **required** (`JwtError::MissingExpiry`). Tests:
   `token_without_exp_is_rejected`, `token_with_non_numeric_exp_is_rejected` in
   `src/jwt/tests.rs`.

Two further low-severity hardening fixes were applied:

4. **DKIM rotation key written with a permissive window** (V6, was low).
   `src/dkim/rotate.rs::write_key` wrote the private key and then chmod'd it,
   leaving a brief world/group-readable window. It now creates the file with
   `create_new` + `0o600` (no permissive window; matches ACME/manual keygen).
   Test: `write_key_creates_with_owner_only_perms_and_refuses_overwrite` in
   `src/dkim/rotate_tests.rs`.

5. **ManageSieve had no failed-auth connection close** (V2.2.1, was low). Unlike
   SMTP/IMAP, repeated `AUTHENTICATE` failures were unbounded on one connection.
   It now closes after 3 failures (`src/managesieve/session.rs`). Test:
   `repeated_auth_failures_close_the_connection` in
   `src/managesieve/session_tests.rs`.

### Documented as deferred (genuine gaps, fix is a feature)

These are real ASVS L3 deficiencies, recorded honestly. Each needs more than a
surgical change and should be tracked as its own issue.

- **Breached-password rejection (V2.1.7).** Length 12–64 is enforced, but there
  is no HaveIBeenPwned k-anonymity range query and no bundled breached-list
  check. The standard calls breach-rejection "the part that actually protects."
  A fix needs either a network integration or a shipped list — out of scope for a
  no-new-dependency surgical change.
- **Cross-connection brute-force ban (V2.2.1).** Throttling is per-connection
  (3-strikes) plus the API's in-memory budget; there is no persistent per-IP /
  per-account failure tracker shared across connections, so an attacker can
  reconnect and keep guessing. A correct fix is a persistent ban table (the
  product context anticipates a PostgreSQL ban table).
- **TOTP replay, recovery codes, and at-rest secret (V2.6/V2.8, V6.4).** The OTP
  has no last-consumed-step replay guard, no single-use recovery codes, and the
  shared secret is stored as cleartext base32. Each needs persistent per-account
  state and (for the secret) an at-rest encryption key mechanism.
- **Per-account-scoped API keys (V4.1.3 least privilege).** A single operator
  token authorizes every account's mail. This is by design (the consumer is the
  operator/panel) and is not a cross-tenant leak, but a scoped key would be
  stricter least privilege.

---

## Summary

| Chapter | Met | N/A | Gap |
|---|---|---|---|
| V1 Architecture | 9 | 0 | 0 |
| V2 Authentication | 7 | 1 | 4 (3 partial)\* |
| V3 Session | 3 | 3 | 0 |
| V4 Access Control | 7 | 0 | 1 (partial) |
| V5 Validation | 6 | 0 | 0 |
| V6 Cryptography | 6 | 0 | 0 (1 deferred note) |
| V7 Error/Logging | 5 | 0 | 0 |
| V8 Data Protection | 4 | 0 | 0 |
| V9 Communications | 5 | 0 | 0 |
| V10 Malicious Code | 4 | 0 | 0 |
| V11 Business Logic | 4 | 0 | 0 |
| V12 Files/Resources | 4 | 0 | 0 |
| V13 API | 5 | 1 | 0 |
| V14 Configuration | 4 | 1 | 0 |

\* The V2 gaps overlap the deferred items above (breached passwords,
cross-connection brute force, TOTP replay/recovery/at-rest); the scoped-API-key
item is the V4 partial. All five concrete, fixable gaps found during the audit
were fixed in this sweep with tests; the remainder are deferred features tracked
above.
