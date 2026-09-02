# Threat model

What epistle protects, against whom, with which control, and how each control
is known to work. [security.md](security.md) lists the controls for an
operator; this page is the assessor's view: one row per threat, the control
that answers it, and the evidence behind it. Residual risks and the things the
product does not yet do come last, on purpose, so they are not mistaken for
controls.

Every `path:line` below was read from the tree at the commit this page was
written against (`develop`, 2026-09-02). Line numbers drift; the file and the
symbol are what to search for when they do. A bare workflow name (`release.yml`,
`ci.yml`) is under `.github/workflows/`, a bare fuzz target under
`fuzz/fuzz_targets/`, and a bare `.toml` beside the mail store is under
`data_dir`. Evidence is of three kinds: a
**test** is a case that fails when the control is removed; a **gate** is a CI
job or a step a release cannot pass; **none** means the control exists as code
and nothing exercises it.

## What epistle is, and is not

epistle is a self-hosted mail server written in Rust: SMTP (relay and
submission), IMAP4rev2, POP3, JMAP, ManageSieve, a management HTTP API and a
CLI, all in one binary. Whoever installs it operates it. Glyndor runs no
instance, receives no telemetry, and holds none of the data, so the **operator
is the data controller** for every mailbox on the machine.

It is not a web application. It has no user interface, no reverse proxy, and
no web TLS: the panel that fronts the API is a separate product, and TLS for
anything that is not a mail protocol is the operator's proxy. TLS for the mail
protocols is the server's own job (built-in ACME under `src/acme/`, or manual
PEM in `[tls]`).

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Message bodies | `.eml` files under `data_dir`, plus the JMAP blob pool and the outbound spool | the content of every mailbox; written `0600` under the service user |
| Account directory and antispam corpus | `<data_dir>/accounts.toml`, `api_keys.toml`, `app_passwords.toml`, and PostgreSQL (`migrations/0001` to `0004`) | who exists, what they may do, what the Bayes filter has learned |
| Credentials | argon2id PHC hashes and SCRAM verifiers in the directory; TOTP secrets beside them | a stolen hash is a slow offline attack; a stolen TOTP secret is a second factor gone |
| DKIM private keys | the `key_file` paths in `[dkim]` (`src/config/dkim.rs:13`) and the rotated keys the server writes | whoever holds one signs mail as the domain |
| The at-rest master key | `encryption_key_env` or `encryption_key_file` in `[storage]` | turns a stolen disk or backup from plaintext into ciphertext, and back |
| The API bearer token and labeled API keys | `[api] token_hash` and `<data_dir>/api_keys.toml` (`src/api/api_keys.rs:8`) | full administration of accounts, domains, queue and mail |
| ACME account key and issued certificates | `<data_dir>/acme/account.key` (`src/acme/renew.rs:27`) and the certificate beside it | the mail protocols' TLS identity |
| DNS provider tokens | `[dns]` `token_file` or `token_env` (`src/config/dns.rs:33`) | a leaked token edits the zone: MX, SPF, DKIM, TLSA |
| Backups | whatever `epistle backup` writes to (`src/cli/backup.rs:1`) | a complete copy of everything above, wherever the operator keeps it |

## Actors and trust boundaries

- **Anonymous internet SMTP client** on port 25: any host on the internet, presumed hostile.
- **Authenticated submission client** on 587 or 465: a user with a password, an app password, or an OAuth token. Trusted for its own addresses only.
- **IMAP, POP3 and JMAP clients**: authenticated users reading their own mailbox.
- **The management API consumer**: the panel or the CLI, holding the bearer token or a labeled key. The listener binds to loopback unless configured otherwise; the only intended exposure is a private container network.
- **The CLI**: runs as whoever invokes it, reads the config and the data directory, so it is as privileged as the operator.
- **The operator**: root on the host. Trusted; a compromised operator is out of scope.
- **The DNS provider**: reached with a zone-scoped token; trusted to serve the zone, not to keep the token.
- **Remote MTAs**: peers for outbound delivery; authenticated only as far as MTA-STS, DANE and DKIM allow.
- **PostgreSQL**: a sibling process or container reached with a URL from the config; trusted for what it stores, never given mail bodies.
- **The filesystem**: the trust anchor for mail bodies and keys, protected by file mode and by the service user; full-disk encryption is the recommended baseline against offline theft.

## Threats and controls

### Port 25: unauthenticated SMTP from the internet

| Threat | Control | Evidence |
|---|---|---|
| SMTP smuggling through bare CR or LF | the line decoder rejects a bare CR, a bare LF and a NUL anywhere in the stream and caps a line at 998 bytes (`src/smtp/line.rs:8`, `:47-73`) | test: `rejects_bare_lf`, `rejects_bare_cr` and the NUL and length cases in the same file (`:132-167`); fuzz target `fuzz/fuzz_targets/smtp_line.rs` |
| Oversized or malformed addresses | 254-byte address and 64-byte local-part caps, domain label rules (`src/smtp/address.rs:8`, `:10`, `:40`, `:72`) | test: the `TooLong` and `InvalidLocalPart` cases (`:186-193`); fuzz targets `smtp_address.rs`, `smtp_command.rs` |
| Open relay | a recipient outside the configured domains answers `550 5.7.1` unless the session is authenticated; unknown local users are refused; an empty directory refuses everything (`src/smtp/session/mod.rs:496-499`) | test: `unknown_user_in_local_domain_is_denied` (`src/smtp/session_tests_basic.rs:266`), `empty_directory_resolves_nothing` (`src/smtp/directory_tests.rs:139`) |
| Resource exhaustion by size or count | 25 MiB message cap advertised as ESMTP `SIZE` and enforced (`src/smtp/session/mod.rs:21`, `:464`); a per-listener connection semaphore, 1000 for SMTP by default (`src/smtp/server/mod.rs:25`, `:308`, `max_connections_per_listener` at `src/config/mod.rs:215`); a full data filesystem defers new transactions instead of accepting mail it cannot write (`src/smtp/diskspace.rs:1-11`) | test: `src/smtp/session_tests_diskspace.rs`; the size cap: none named |
| Header injection through inbound content that the server re-emits | ARF reports, bounces, vacation replies and JMAP-built headers pass through `sanitize_header_value`, which strips CR and LF (`src/util/header.rs:25`; used at `src/antispam/arf.rs:64-69`, `src/api/jmap/objects.rs:30-33`, `src/sieve/vacation.rs:37`, `src/queue/bounce.rs:370`) | test: `strips_cr_lf_to_prevent_header_injection` (`src/util/header.rs:50`), `subject_with_crlf_does_not_inject_headers` (`src/sieve/vacation.rs:133`), `jmap_email_set_sanitises_header_injection_in_subject` (`src/api/jmap_tests_b.rs:338`), the ARF cases (`src/antispam/arf.rs:371-447`) |
| Forwarding loops | forwarding stops at 25 `Received:` hops (`src/storage/delivery.rs:24`) | test: `src/storage/delivery_forward_tests.rs` |
| Spoofed sender domains | SPF, DKIM, DMARC and ARC verification on inbound; DNSBL and greylisting when configured (`src/spf/`, `src/dkim/verify.rs`, `src/dmarc/`, `src/arc/`, `src/antispam/hook.rs`) | test: `src/dkim/verify_tests.rs` and the per-module suites; greylist state is in memory (`src/antispam/greylist.rs:79`) and resets on restart |

### Submission, IMAP, POP3 and JMAP: authenticated users

| Threat | Control | Evidence |
|---|---|---|
| Credentials crossing plaintext | SMTP `AUTH` answers `538` until the session is inside TLS (`src/smtp/session/mod.rs:274`); IMAP answers `PRIVACYREQUIRED` and advertises `LOGINDISABLED` (`src/imap/session/auth.rs:87-90`, `:129-130`); POP3 exists only behind implicit TLS (`src/pop3/server.rs:88`); `imaps`, `imap`, `pop3s` and `manage-sieve` listeners refuse to load without `[tls]` (`src/config/validate.rs:338-353`) | test: `auth_rejected_outside_tls` (`src/smtp/session_tests_auth.rs:193`), `plaintext_session_disables_login_until_starttls` (`src/imap/session/session_tests_misc.rs:4`); gate: `tests/e2e.rs` drives the release binary over real TLS in `e2e.yml` |
| Password guessing and user enumeration | argon2id with a fresh 16-byte CSPRNG salt per hash (`src/smtp/auth.rs:56-67`); an unknown user fails exactly like a wrong password; the third failure closes the connection (`src/smtp/session/mod.rs:325-327`, `src/imap/session/auth.rs:359-363`); the bundled breached-password list and the 12 to 64 printable-ASCII policy in `src/password/` | test: `unknown_user_gets_same_reply_as_wrong_password` (`src/smtp/session_tests_auth.rs:311`), `third_failure_closes_connection` (`:318`), `scram_repeated_failures_close_the_connection` (`src/smtp/session_tests_scram.rs:166`) |
| Sending as someone else | an authenticated `MAIL FROM` must be an address the account owns, and the null reverse-path is refused from an authenticated session (`src/smtp/session/mod.rs:425-432`) | test: `authenticated_sender_must_own_the_address` (`src/smtp/session_tests_auth.rs:367`) |
| A compromised account flooding outbound mail | per-account submission rate with a per-domain override (`src/smtp/ratelimit.rs:41`), plus an aggregate per-tenant ceiling (`src/api/tenant_limits.rs`) | test: `src/smtp/session_tests_ratelimit.rs:9-97`, `aggregate_rate_blocks_a_second_send_within_the_window` (`src/api/tenant_limits_tests_e2e.rs:280`) |
| Second-factor bypass | TOTP verified in constant time with a skew of one step either side (`src/totp/mod.rs:13`, `:37-44`, `:95`); app passwords are argon2id-hashed, expire, and can be pinned to a CIDR (`src/directory_store/app_passwords.rs:1-12`) | test: `verify_accepts_current_and_skewed_codes` (`src/totp/mod.rs:125`), `src/directory_store/app_passwords_tests.rs` |
| Reading another user's JMAP blob by guessing its id | a blob id is parsed into a `Uuid` at the boundary, so no path fragment reaches the backend (`src/api/jmap/blobs.rs:28-30`, `src/api/jmap/blob_path.rs:40-46`, trait at `src/storage/blob_backend/mod.rs:64-73`); an `.owner` sidecar must name the requesting account or the blob is not served (`src/api/jmap/blobs.rs:31-43`) | test: `blob_without_owner_sidecar_is_not_served` (`src/api/jmap_tests_d.rs:224`), `upload_writes_owner_sidecar`, `empty_owner_sidecar_is_treated_as_missing` (`src/api/jmap_tests_e2.rs:18`, `:67`), `src/api/jmap/blob_path_tests.rs:9-65` |
| Unbounded uploads | JMAP uploads are capped at 50 MB, then checked against the account quota and the tenant's aggregate quota (`src/api/jmap/mod.rs:24`, `:339-386`) | test: `aggregate_quota_blocks_an_over_cap_upload` (`src/api/tenant_limits_tests_e2e.rs:208`) |
| Hostile Sieve scripts or messages | the parser and interpreter are sans-IO and fuzzed (`fuzz/fuzz_targets/sieve_script.rs`, `sieve_message.rs`, `imap_command.rs`, `pop3_command.rs`, `managesieve_command.rs`) | gate: `fuzz.yml`, nightly on `main` (`:12`) |

### The management API and the CLI

| Threat | Control | Evidence |
|---|---|---|
| Reaching the API without a credential | every route except `/healthz` sits behind `require_bearer_token` (`src/api/mod.rs:31-72`, `src/api/state.rs:605-673`); the listener binds to loopback by default (`src/config/mod.rs:347`); CORS allows nothing (`src/api/mod.rs:60`) | test: `default_bind_is_loopback` (`src/config/mod.rs:560`), `verify_requires_the_bearer_token` (`src/api/auth_tests.rs:106`) |
| Token comparison leaking timing | the token is stored as `sha256:<hex>` and compared in constant time (`src/api/state.rs:540-553`) | test: `configured_token_still_authorizes`, `wrong_api_key_rejected` (`src/api/state_tests.rs:47`, `:64`) |
| Brute-forcing the token | 20 failures in 60 seconds put the whole API into `429` until the window passes (`src/api/state.rs:90-91`, `:610-620`) | none named for the limiter itself |
| A leaked key doing more than it was issued for | labeled keys carry `read`, `write`, `send` and `scim` scopes, an expiry and a CIDR, all of which must hold (`src/api/api_keys.rs:24-38`, `:135-150`); the scope a route needs is inferred from method and path and tightened per JMAP method (`src/api/state.rs:580-602`, `:531-536`) | test: `expired_key_rejected`, `ip_mismatch_rejected_match_accepted`, `write_scope_rejected_for_read_only_key`, `write_scope_does_not_imply_read_or_send` (`src/api/api_keys_tests.rs:34-71`); `ip_restricted_api_key_enforced` (`src/api/state_tests.rs:80`) |
| One tenant's key reaching another tenant's accounts | a key that declares `domains` is confined to them, and an account with an address outside them is out of scope even when one address matches (`src/api/domain_scope.rs:23-33`, `:58-72`) | test: `src/api/domain_scope_tests.rs:15-48`; `a_scoped_key_cannot_delete_another_tenants_account`, `a_scoped_key_cannot_reset_another_tenants_password`, `a_scoped_key_cannot_mint_an_address_outside_its_domains` (`src/api/tenancy_tests.rs:112-144`) |
| A tenant exceeding what it was sold | per-tenant caps on accounts, storage and submission rate (`src/api/tenant_limits.rs`) | test: `max_accounts_rejects_with_409_when_cap_reached` (`src/api/tenant_limits_tests_e2e.rs:158`) |
| SQL injection | every query is a `sqlx::query!` macro with bound parameters, checked at compile time against the committed `.sqlx` cache (`src/antispam/reputation.rs:84`, `:146`, `src/antispam/corpus.rs:64-118`, `src/directory_store/sql.rs:32-36`; `SQLX_OFFLINE` at `debian/rules:38`); LDAP filters are escaped (`src/directory_store/ldap.rs:246`) | gate: `db.yml` runs the database suite against a real PostgreSQL; test: `escaping_neutralizes_a_filter_injection_attempt` (`src/directory_store/ldap_tests.rs:55`) |
| Error responses revealing internals | API errors map to a fixed set of codes; internal failures return a generic `internal` (`src/api/error.rs:41-44`) | none named |
| Silent privilege changes | auth attempts and privilege changes are logged with the client IP (`src/api/audit.rs:75`, `:97`) | test: `src/api/audit_tests.rs` |
| A local user reading secrets from the config | the config file must be `0600` or the server refuses to load it; `${VAR}` references that are unset abort the load (`src/config/mod.rs:355`, `:386`) | test: `rejects_group_or_world_accessible_config` (`src/config/mod.rs:461`) |

### Keys, storage and the host

| Threat | Control | Evidence |
|---|---|---|
| DKIM key theft | keys are read from operator-owned paths (`src/config/dkim.rs:13-20`); rotated keys are written `0600` (`src/dkim/rotate.rs:275`); rotation every 90 days with a 14-day overlap (`:82`, `:91`) | test: `src/dkim/rotate_tests.rs` |
| ACME account key exposure | written `0600` into a fresh temp file, fsynced and renamed into place (`src/acme/renew.rs:58-72`) | none named for the mode |
| The at-rest key left in memory or in a log | the key bytes are read into `Zeroizing` buffers and wiped once the AEAD key is built (`src/storage/crypto.rs:263-295`); `Debug` never prints key material (`:94-101`); `zeroize` is pinned exactly (`Cargo.toml:55`); a message that fails to decrypt is an error, never served as ciphertext (`:192-216`); enabling encryption without a key refuses to start (`:126-133`) | test: `decode_fails_closed_when_tampered`, `decode_fails_closed_when_encrypted_but_no_key`, `from_config_enabled_without_key_fails_closed` (`src/storage/crypto_tests.rs:54`, `:64`, `:89`) |
| A restored backup exposing mail | `epistle backup` archives the on-disk bytes, so an encrypted store stays ciphertext without the key (`src/cli/backup.rs:1-5`); the key is expected off the data disk (`security.md`) | test: `src/cli/backup_tests.rs` |
| Clock drift | TOTP tolerates one 30-second step either side and no more (`src/totp/mod.rs:13`); API key expiry and DKIM rotation read the system clock; the host's time source is the operator's | test: `verify_accepts_current_and_skewed_codes` (`src/totp/mod.rs:125`) |
| A compromised process acting as root | with `[privileges]` the daemon drops uid and gid after binding and refuses to run if root can be regained (`src/privdrop.rs:16`, `:76-94`); the sample unit runs as `DynamicUser` with a read-only system, no new privileges and a `@system-service` syscall filter (`docs/epistle.service:38-69`) | test: `src/privdrop_tests.rs` |
| The server calling out to an attacker-chosen host | webhook URLs must be `https` or loopback (`src/config/validate.rs:97-102`); the ACME directory must be `https` (`:112`); DNS tokens are zone-scoped and read from a file or the environment (`src/config/dns.rs:28-38`) | test: `src/config/validate_tests*.rs` |

### Dependencies and the release path

| Threat | Control | Evidence |
|---|---|---|
| A vulnerable or yanked crate | `cargo audit --deny warnings` on the main lockfile and on `fuzz/Cargo.lock` (`.github/workflows/reusable-rust-audit.yml:83-108`), weekly and on every lockfile change (`rust-audit.yml:10-27`); `cargo deny` allows crates.io only and an explicit license list (`deny.toml:38-42`); Dependabot covers `/`, `/fuzz` and the signing script's pip requirements (`.github/dependabot.yml:15-43`) | gate: `rust-audit.yml`; the two ignored advisories are argued in `deny.toml:3-11` and `.cargo/audit.toml` |
| A toolchain nobody agreed on | CI, the `.deb` image and the release job pin 1.98 (`ci.yml:21`, `release.yml:108`, `:222`); the MSRV floor in `debian/control` is compared with CI | test: `workflow_toolchain_pins_agree` (`tests/workflow_toolchain_pins.rs:72`), `ci_msrv_matches_the_declared_rust_version` (`tests/msrv_agrees_with_ci.rs:27`) |
| Releasing unpromoted or unaudited code | the tag must match `Cargo.toml` and `debian/changelog`, be reachable from `main`, pass `cargo audit`, and not already be published (`release.yml:43-96`) | gate: the `verify` job, which every later job needs |
| Unsigned or unattested artifacts | every artifact, each `.deb` and `SHA256SUMS` get a detached Ed25519 signature from a hash-pinned venv (`release.yml:270-283`); build provenance is attested for the `.deb` and the binary (`:186-189`, `:285-288`); the `.deb` builds in a digest-pinned image (`:108`) | gate: the job fails closed when the key is absent (`:266-269`); test: `.github/scripts/test_sign.py` in `scripts.yml` |
| A test that nothing runs | every test is a Rust test that `cargo test` discovers, and a guard fails when a file that runs only by name appears | test: `tests/test_discovery_premise.rs` |

## Not implemented

Things the product context describes and this tree does not do. Listed so a
reader does not infer a control from a plan.

- **A ban table shared across listeners.** Each protocol counts failures per connection (three strikes) and the API keeps one in-memory budget (`src/api/state.rs:90-91`). Reconnecting resets the count, and nothing is shared between SMTP, IMAP, JMAP and the API (`docs/asvs.md:274-278`).
- **A per-token request rate on the API.** Only failed authentications are budgeted; a valid token is not throttled.
- **TOTP replay protection, recovery codes, and an encrypted TOTP secret.** The secret is stored as base32 beside the account (`src/directory_store/mod.rs:80`; `docs/asvs.md:279-282`).
- **A system user created by the package.** `debian/` carries no `postinst` and no unit; the sample unit uses `DynamicUser` (`docs/epistle.service:38`) and `[privileges]` is opt-in.
- **Panel wiring over a private container network.** Nothing in this repository configures Podman; the API's only default protection is the loopback bind.
- **Offsite, client-side-encrypted backups with rotation.** `epistle backup` writes one tar to stdout (`src/cli/backup.rs:1-5`); the S3 backend under `src/storage/blob_backend/` stores JMAP blobs, not backups.
- **Encrypted storage of DNS provider tokens.** They are read from a `0600` file or the environment (`src/config/dns.rs:33-38`), not encrypted.
- **Antivirus in an isolated container.** There is one generic `scanner_hook_url` (`src/config/mod.rs:164`).
- **A distinct admin role with mandatory 2FA.** The API authenticates keys, not people (`src/api/domain_scope.rs:3-7`).

## Residual risks and accepted decisions

- **Plaintext-capable listeners warn instead of refusing.** `submission`, `webdav`, `api`, `autoconfig` and `metrics` bound to a non-loopback address without `[tls]` log a warning and start (`src/config/validate.rs:354-369`, `:384-393`). The 2026-08-16 review rated this high; it stands, on the argument that these are fronted by the operator's TLS proxy. The metrics endpoint carries no authentication.
- **`scanner_hook_url` is not validated** the way the webhook and ACME URLs are: any URL the operator writes is called with inbound message bytes. Operational risk, since it needs write access to the config, but it is the one outbound URL that skips the `https`-or-loopback rule.
- **Message content leaves the host when the operator opts in.** The LLM antispam band posts message text to an OpenAI-compatible endpoint (`src/config/antispam.rs:29-34`), the scanner hook posts it to the hook, and OpenTelemetry exports traces (`src/config/otel.rs:8-10`). All three are off unless configured.
- **The release job installs third-party tooling beside the signing key.** `build` runs `cargo install --locked cargo-cyclonedx` (`release.yml:230`) in the same job that holds `GLYNDOR_RELEASE_ED25519_KEY` (`:261`) and `contents: write` (`:204`). `cargo install` runs every crate's build script, and `--locked` does not stop a yanked crate. The organisation's CI standard records this as the worst combination it has, and the check that would catch it (`workflow-lint`'s tooling isolation) does not run in this repository. Accepted until the SBOM moves to a job with `contents: read` and no secrets; the signing script itself is hash-pinned (`:274`).
- **Two advisories are ignored** (`RUSTSEC-2023-0071`, `RUSTSEC-2026-0221`), both reached only through `sqlx` code paths the PostgreSQL driver never executes (`deny.toml:3-11`). The argument is written down; it is not a proof.
- **One maintainer.** Every pull request is reviewed and merged by its author; a required check is matched by name, so the author could replace a gate with a job of the same name.
- **The greylist and the API failure budget live in memory** and reset on restart (`src/antispam/greylist.rs:79`, `src/api/state.rs:85-91`).
- **Full-disk encryption is recommended, not enforced.** The at-rest envelope covers message files; the directory, the TOTP secrets and PostgreSQL rely on the volume.
- **No independent audit.** Every measurement on this page was made by the project.

## Out of scope

- The panel (`epistle-panel`): its sessions, its admin role, its CAPTCHA and its web TLS.
- The apt archive, the bootstrap installer, and the runner image's own trust in Debian's archive; see the archive's threat model.
- A compromised operator, a compromised host kernel, or an adversary holding the release signing key.
- PostgreSQL's own hardening and the network between the two containers.
- Deliverability: PTR, IP reputation and what remote providers do with mail.

## How to verify this document

```sh
git log -1 --format='%H %ci'                       # the commit the citations were read from
grep -n 'MAX_LINE_LENGTH' src/smtp/line.rs         # each cited symbol still lives where cited
grep -n 'fn require_bearer_token' src/api/state.rs
grep -n 'plaintext_listener_warn' src/config/validate.rs
grep -rn 'sqlx::query' src --include='*.rs' | grep -v tests   # every site is the macro form
cargo test --locked                                # every test named above runs here
cargo audit --deny warnings && cargo deny check    # the dependency gates, locally
ls fuzz/fuzz_targets                               # the eight fuzz targets
grep -n 'cargo install\|contents: write\|RELEASE_ED25519' .github/workflows/release.yml
```

A line that no longer matches means the citation moved or the control changed;
either way this page is stale for that row and should be edited in the same
pull request as the code.

## Reporting

Report vulnerabilities privately through the repository's **Security tab**.
The organisation's [security policy](https://github.com/Glyndor/.github/blob/main/SECURITY.md)
carries the response targets.
