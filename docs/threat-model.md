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
| DKIM private keys | the `key_file` paths in `[dkim]` (`src/config/dkim/mod.rs:13`) and the rotated keys the server writes | whoever holds one signs mail as the domain |
| The at-rest master key | `encryption_key_env` or `encryption_key_file` in `[storage]` | turns a stolen disk or backup from plaintext into ciphertext, and back |
| The API bearer token and labeled API keys | `[api] token_hash` and `<data_dir>/api_keys.toml` (`src/api/api_keys/mod.rs:8`) | full administration of accounts, domains, queue and mail |
| ACME account key and issued certificates | `<data_dir>/acme/account.key` (`src/acme/renew/mod.rs:27`) and the certificate beside it | the mail protocols' TLS identity |
| DNS provider tokens | `[dns]` `token_file` or `token_env` (`src/config/dns/mod.rs:33`) | a leaked token edits the zone: MX, SPF, DKIM, TLSA |
| Backups | whatever `epistle backup` writes to (`src/cli/backup/mod.rs::run`) | a complete copy of everything above, wherever the operator keeps it |

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
| SMTP smuggling through bare CR or LF | the line decoder rejects a bare CR, a bare LF and a NUL anywhere in the stream and caps a line at 998 bytes (`src/smtp/line/mod.rs:8`, `:47-73`) | test: `rejects_bare_lf`, `rejects_bare_cr` and the NUL and length cases in the same file (`:132-167`); fuzz target `fuzz/fuzz_targets/smtp_line.rs` |
| Oversized or malformed addresses | 254-byte address and 64-byte local-part caps, domain label rules (`src/smtp/address/mod.rs:8`, `:10`, `:40`, `:72`) | test: the `TooLong` and `InvalidLocalPart` cases (`:186-193`); fuzz targets `smtp_address.rs`, `smtp_command.rs` |
| Open relay | a recipient outside the configured domains answers `550 5.7.1` unless the session is authenticated; unknown local users are refused; an empty directory refuses everything (`src/smtp/session/mod.rs:495-498`) | test: `unknown_user_in_local_domain_is_denied` (`src/smtp/session/tests/mods/tests_basic.rs:266`), `empty_directory_resolves_nothing` (`src/smtp/directory/tests/base.rs:139`) |
| Resource exhaustion by size or count | 25 MiB message cap advertised as ESMTP `SIZE` and enforced (`src/smtp/session/mod.rs:21`, `:463`); a per-listener connection semaphore, 1000 for SMTP by default (`src/smtp/server/mod.rs:25`, `:308`, `max_connections_per_listener` at `src/config/mod.rs:215`); a full data filesystem defers new transactions instead of accepting mail it cannot write (`src/smtp/diskspace/mod.rs:1-11`) | test: `src/smtp/session/tests/mods/tests_diskspace.rs`; the size cap: none named |
| Header injection through inbound content that the server re-emits | ARF reports, vacation replies and JMAP-built headers pass through `sanitize_header_value`, which strips CR and LF (`src/util/header/mod.rs:25`; used at `src/antispam/arf/mod.rs:64-69`, `src/api/jmap/objects/mod.rs:30-33`, `src/sieve/vacation/mod.rs:64`); a bounce DSN flattens the remote reply on its own (`src/queue/bounce/mod.rs::sanitize_reason`) | test: `strips_cr_lf_to_prevent_header_injection` (`src/util/header/mod.rs:50`), `subject_with_crlf_does_not_inject_headers` (`src/sieve/vacation/tests/base.rs:112`), `jmap_email_set_sanitises_header_injection_in_subject` (`src/api/jmap_tests_b.rs:338`), the ARF cases (`src/antispam/arf/tests/base.rs:157-228`) |
| Forwarding loops | forwarding stops at 25 `Received:` hops (`src/storage/delivery/mod.rs:32`) | test: `src/storage/delivery/tests/forward.rs` |
| Spoofed sender domains | SPF, DKIM, DMARC and ARC verification on inbound; DNSBL and greylisting when configured (`src/spf/`, `src/dkim/verify/mod.rs`, `src/dmarc/`, `src/arc/`, `src/antispam/hook/mod.rs`) | test: `src/dkim/verify/tests/base.rs` and the per-module suites; greylist state is in memory (`src/antispam/greylist/mod.rs:79`) and resets on restart |

### Submission, IMAP, POP3 and JMAP: authenticated users

| Threat | Control | Evidence |
|---|---|---|
| Credentials crossing plaintext | SMTP `AUTH` answers `538` until the session is inside TLS (`src/smtp/session/mod.rs:273`); IMAP answers `PRIVACYREQUIRED` and advertises `LOGINDISABLED` (`src/imap/session/auth.rs:87-90`, `:129-130`); POP3 exists only behind implicit TLS (`src/pop3/server/mod.rs:88`); `imaps`, `imap`, `pop3s` and `manage-sieve` listeners refuse to load without `[tls]` (`src/config/validate/mod.rs:415-452`) | test: `auth_rejected_outside_tls` (`src/smtp/session/tests/mods/tests_auth.rs:193`), `plaintext_session_disables_login_until_starttls` (`src/imap/session/tests/base/misc.rs:4`); gate: `tests/e2e.rs` drives the release binary over real TLS in `e2e.yml` |
| Password guessing and user enumeration | argon2id with a fresh 16-byte CSPRNG salt per hash (`src/smtp/auth/mod.rs:56-67`); an unknown user fails exactly like a wrong password; the third failure closes the connection (`src/smtp/session/mod.rs:324-326`, `src/imap/session/auth.rs:359-363`); the bundled breached-password list and the 12 to 64 printable-ASCII policy in `src/password/` | test: `unknown_user_gets_same_reply_as_wrong_password` (`src/smtp/session/tests/mods/tests_auth.rs:311`), `third_failure_closes_connection` (`:318`), `scram_repeated_failures_close_the_connection` (`src/smtp/session/tests/mods/tests_scram.rs:166`) |
| Sending as someone else | an authenticated `MAIL FROM` must be an address the account owns, and the null reverse-path is refused from an authenticated session (`src/smtp/session/mod.rs:424-431`); the message must carry one `From` field naming one address the account owns (`src/smtp/session/author.rs`) | test: `authenticated_sender_must_own_the_address` (`src/smtp/session/tests/mods/tests_auth.rs:367`), `src/smtp/session/tests/mods/tests_author.rs` |
| A compromised account flooding outbound mail | per-account submission rate with a per-domain override (`src/smtp/ratelimit/mod.rs:41`), plus an aggregate per-tenant ceiling (`src/api/tenant_limits.rs`) | test: `src/smtp/session/tests/mods/tests_ratelimit.rs:9-97`, `aggregate_rate_blocks_a_second_send_within_the_window` (`src/api/tenant_limits_tests_e2e.rs:280`) |
| Second-factor bypass | TOTP verified in constant time with a skew of one step either side (`src/totp/mod.rs:13`, `:37-44`, `:95`); app passwords are argon2id-hashed, expire, and can be pinned to a CIDR (`src/directory_store/app_passwords/mod.rs:1-12`) | test: `verify_accepts_current_and_skewed_codes` (`src/totp/tests/base.rs:22`), `src/directory_store/app_passwords/tests/base.rs` |
| Reading another user's JMAP blob by guessing its id | a blob id is parsed into a `Uuid` at the boundary, so no path fragment reaches the backend (`src/api/jmap/blobs.rs:28-30`, `src/api/jmap/blob_path.rs:40-46`, trait at `src/storage/blob_backend/mod.rs:64-73`); an `.owner` sidecar must name the requesting account or the blob is not served (`src/api/jmap/blobs.rs:31-43`) | test: `blob_without_owner_sidecar_is_not_served` (`src/api/jmap_tests_d.rs:224`), `upload_writes_owner_sidecar`, `empty_owner_sidecar_is_treated_as_missing` (`src/api/jmap_tests_e2.rs:18`, `:67`), `src/api/jmap/blob_path_tests.rs:9-65` |
| Unbounded uploads | JMAP uploads are capped at 50 MB, then checked against the account quota and the tenant's aggregate quota (`src/api/jmap/mod.rs:24`, `:339-386`) | test: `aggregate_quota_blocks_an_over_cap_upload` (`src/api/tenant_limits_tests_e2e.rs:208`) |
| Hostile Sieve scripts or messages | the parser and interpreter are sans-IO and fuzzed: lex and parse (`fuzz/fuzz_targets/sieve_script.rs`), the message reader (`sieve_message.rs`), a script run against a message (`sieve_run.rs`) and the save-time check (`sieve_validate.rs`), plus a seeded random run in the test suite (`src/sieve/tests/random_run.rs`); and `imap_command.rs`, `pop3_command.rs`, `managesieve_command.rs`) | gate: `fuzz.yml`, nightly on `main` (`:12`) |
| A Sieve script that fans one message out, or smuggles SMTP commands, through `redirect` | a run forwards to at most 4 addresses, each once, and delivery keeps only targets the strict address parser accepts, in canonical form (`src/sieve/interp.rs`, `src/storage/delivery/trace.rs`) | test: `a_script_cannot_ask_for_more_forwards_than_the_limit`, `a_redirect_that_is_not_an_address_is_never_queued` (`src/sieve/tests/interp_redirects.rs`, `src/storage/delivery/tests/redirects.rs`) |
| A Sieve script that exhausts the parser (long `not` chains, deep blocks, a huge string) | 64 levels of nesting counting blocks, test lists and `not`; 1 MiB per script; a reason never repeats the script (`src/sieve/parser.rs`, `src/managesieve/store_check/mod.rs`) | test: `a_long_chain_of_nots_is_refused_as_too_deep`, `a_reason_never_repeats_the_scripts_own_text`, `hostile_shapes_are_answered_not_run_into` |
| A Sieve script, or the mail it runs on, that exhausts a delivery (`:matches` with many wildcards over a long Subject, `set` doubling a variable, thousands of `fileinto`, a filter that makes a folder per message, a message made to cost more by being bigger) | one fixed budget per run (20000 steps, 256 MiB of work, whatever the size of the message), variables cut to 4096 octets and 64 KiB, tests that read a fixed window (1 MiB of body, 1000 header values and 64 KiB per name, 16 names) of the first 10 000 headers (mail with more than 9 900 header fields is refused by one check, `refuse_padded_headers` (`src/smtp/trace/mod.rs`), at DATA and where local delivery starts, which every submission goes through, counted by `src/util/header_block/mod.rs`, so padding cannot hide a header; blanks in a value are collapsed before its 64 KiB window), and a `:contains` list of eight keys or more read in one pass (`src/sieve/key_set/mod.rs`); a run that overspends keeps what it decided about where the message goes, drops what it would have sent and keeps the message if anything outward was dropped; `fileinto` files once per folder and into 8 folders, folders made by a filter stop at 200 counting every level and under one lock (`src/sieve/env/mod.rs`, `src/sieve/compare/mod.rs`, `src/sieve/message/mod.rs`, `src/storage/delivery/io.rs`); a long text never turns into "no match" without a trace (`mail_sieve_inspection_truncated_total`, one log line per account and hour) | test: `src/sieve/tests/memory.rs` (counting allocator), `src/sieve/compare/tests/bounds.rs`, `src/sieve/tests/interp_limits.rs`, `src/sieve/tests/interp_sender.rs`, `src/sieve/tests/interp_window.rs`, `src/storage/delivery/tests/sieve_limits.rs` |
| A JMAP request that makes the server check one script blob over and over (500 objects in a call, 16 calls, one blob of 1 MiB), or read many blobs it will refuse | a blob is checked once per request whatever the number of objects that name it, an id that names no script is refused before its blob is looked at, and after four blobs read and put aside for the byte budget no more are read (`src/api/jmap/sieve_content.rs`, `src/api/jmap/uploads.rs`) | test: `src/api/jmap_tests_sieve_cost.rs` |
| A credential with `write` only that makes the server forward or answer mail | storing or activating a script that redirects, replies or rejects takes the `send` scope (`src/api/jmap/sieve_script_edit.rs`, `src/sieve/analysis.rs`) | test: `src/api/jmap_tests_sieve_scope.rs` |
| Reading or changing another account's Sieve scripts over JMAP, by id, blob or name | the account is admitted like every JMAP call, ids and blobs are looked up in that account's store and partition, and names are validated before they reach a path (`src/api/jmap/sieve_script*.rs`, `src/managesieve/store/mod.rs`) | test: `src/api/jmap_tests_sieve_authz.rs` |

### The management API and the CLI

| Threat | Control | Evidence |
|---|---|---|
| Reaching the API without a credential | every route except `/healthz` sits behind `require_bearer_token` (`src/api/mod.rs:31-72`, `src/api/state/mod.rs:605-673`); the listener binds to loopback by default (`src/config/mod.rs:347`); CORS allows nothing (`src/api/mod.rs:60`) | test: `default_bind_is_loopback` (`src/config/mod.rs:560`), `verify_requires_the_bearer_token` (`src/api/auth_tests.rs:106`) |
| Token comparison leaking timing | the token is stored as `sha256:<hex>` and compared in constant time (`src/api/state/mod.rs:540-553`) | test: `configured_token_still_authorizes`, `wrong_api_key_rejected` (`src/api/state/mod_tests.rs:47`, `:64`) |
| Brute-forcing the token | 20 failures in 60 seconds put the whole API into `429` until the window passes (`src/api/state/mod.rs:90-91`, `:610-620`) | none named for the limiter itself |
| A leaked key doing more than it was issued for | labeled keys carry `read`, `write`, `send` and `scim` scopes, an expiry and a CIDR, all of which must hold (`src/api/api_keys/mod.rs:24-38`, `:135-150`); the scope a route needs is inferred from method and path and tightened per JMAP method (`src/api/state/mod.rs:580-602`, `:531-536`) | test: `expired_key_rejected`, `ip_mismatch_rejected_match_accepted`, `write_scope_rejected_for_read_only_key`, `write_scope_does_not_imply_read_or_send` (`src/api/api_keys/mod_tests.rs:34-71`); `ip_restricted_api_key_enforced` (`src/api/state/mod_tests.rs:80`) |
| One tenant's key reaching another tenant's accounts | a key that declares `domains` is confined to them, and an account with an address outside them is out of scope even when one address matches (`src/api/authorization.rs::Principal::of_key`, `::admits_domains`) | test: `domains_admit_only_addresses_in_scope`, `domains_reject_account_with_no_addresses` (`src/api/authorization_tests.rs`); `a_scoped_key_cannot_delete_another_tenants_account`, `a_scoped_key_cannot_reset_another_tenants_password`, `a_scoped_key_cannot_mint_an_address_outside_its_domains` (`src/api/tenancy_tests.rs:112-144`) |
| A tenant exceeding what it was sold | per-tenant caps on accounts, storage and submission rate (`src/api/tenant_limits.rs`) | test: `max_accounts_rejects_with_409_when_cap_reached` (`src/api/tenant_limits_tests_e2e.rs:158`) |
| SQL injection | every query is a `sqlx::query!` macro with bound parameters, checked at compile time against the committed `.sqlx` cache (`src/antispam/reputation/mod.rs:84`, `:146`, `src/antispam/corpus/mod.rs:64-118`, `src/directory_store/sql/mod.rs:32-36`; `SQLX_OFFLINE` at `debian/rules:38`); LDAP filters are escaped (`src/directory_store/ldap/mod.rs:246`) | gate: `db.yml` runs the database suite against a real PostgreSQL; test: `escaping_neutralizes_a_filter_injection_attempt` (`src/directory_store/ldap/tests/base.rs:55`) |
| Error responses revealing internals | API errors map to a fixed set of codes; internal failures return a generic `internal` (`src/api/error.rs:41-44`) | none named |
| Silent privilege changes | auth attempts and privilege changes are logged with the client IP (`src/api/audit.rs:75`, `:97`) | test: `src/api/audit_tests.rs` |
| A local user reading secrets from the config | the config file must be `0600` or the server refuses to load it; `${VAR}` references that are unset abort the load (`src/config/mod.rs:355`, `:386`) | test: `rejects_group_or_world_accessible_config` (`src/config/mod.rs:461`) |

### Keys, storage and the host

| Threat | Control | Evidence |
|---|---|---|
| DKIM key theft | keys are read from operator-owned paths (`src/config/dkim/mod.rs:13-20`); rotated keys, ed25519 and the RSA dual-signing key alike, are written `0600` (`write_key` in `src/dkim/rotate/steps.rs`); rotation every 90 days with a 14-day overlap (`ROTATE_INTERVAL_DAYS`, `ROTATE_OVERLAP_DAYS` in `src/dkim/rotate/mod.rs`) | test: `src/dkim/rotate/tests/base.rs` |
| ACME account key exposure | written `0600` into a fresh temp file, fsynced and renamed into place (`src/acme/renew/mod.rs:58-72`) | none named for the mode |
| The at-rest key left in memory or in a log | the key bytes are read into `Zeroizing` buffers and wiped once the AEAD key is built (`src/storage/crypto/mod.rs:263-295`); `Debug` never prints key material (`:94-101`); `zeroize` is pinned exactly (`Cargo.toml:55`); a message that fails to decrypt is an error, never served as ciphertext (`:192-216`); enabling encryption without a key refuses to start (`:126-133`) | test: `decode_fails_closed_when_tampered`, `decode_fails_closed_when_encrypted_but_no_key`, `from_config_enabled_without_key_fails_closed` (`src/storage/crypto/tests/base.rs:54`, `:64`, `:89`) |
| A restored backup exposing mail | `epistle backup` archives the on-disk bytes, so an encrypted store stays ciphertext without the key (`src/cli/backup/mod.rs::collect_files`); the key is expected off the data disk (`security.md`) | test: `src/cli/backup_tests.rs` |
| Clock drift | TOTP tolerates one 30-second step either side and no more (`src/totp/mod.rs:13`); API key expiry and DKIM rotation read the system clock; the host's time source is the operator's | test: `verify_accepts_current_and_skewed_codes` (`src/totp/tests/base.rs:22`) |
| A compromised process acting as root | with `[privileges]` the daemon drops uid and gid after binding and refuses to run if root can be regained (`src/privdrop/mod.rs:16`, `:76-94`); the sample unit runs as `DynamicUser` with a read-only system, no new privileges and a `@system-service` syscall filter (`docs/epistle.service:38-69`) | test: `src/privdrop/tests/base.rs` |
| The server calling out to an attacker-chosen host | webhook URLs must be `https` or loopback (`src/config/validate/mod.rs:149-160`); the ACME directory must be `https` (`:167`); DNS tokens are zone-scoped and read from a file or the environment (`src/config/dns/mod.rs:28-38`) | test: `src/config/validate/tests/*.rs` |

### Dependencies and the release path

| Threat | Control | Evidence |
|---|---|---|
| A vulnerable or yanked crate | `cargo audit --deny warnings` on the main lockfile and on `fuzz/Cargo.lock` (`.github/workflows/reusable-rust-audit.yml:105-139`), daily and on every lockfile change (`rust-audit.yml:15-43`); `cargo deny` allows crates.io only and an explicit license list (`deny.toml:38-42`); Dependabot covers `/`, `/fuzz` and the signing script's pip requirements (`.github/dependabot.yml:15-43`); a labelled issue opens itself the moment the audit on either `develop` or `main` finds anything (`rust-audit.yml:70-118`), and closes when the next run on both refs is clean (`:120-152`) | gate: `rust-audit.yml`; no advisory is ignored as of 2026-09-03 |
| A toolchain nobody agreed on | CI, the `.deb` image and the release job pin 1.98 (`ci.yml:21`, `release.yml:108`, `:222`); the MSRV floor in `debian/control` is compared with CI | test: `workflow_toolchain_pins_agree` (`tests/workflow_toolchain_pins.rs:72`), `ci_msrv_matches_the_declared_rust_version` (`tests/msrv_agrees_with_ci.rs:27`) |
| Releasing unpromoted or unaudited code | the tag must match `Cargo.toml` and `debian/changelog`, be reachable from `main`, pass `cargo audit`, and not already be published (`release.yml:43-96`) | gate: the `verify` job, which every later job needs |
| Unsigned or unattested artifacts | every artifact, each `.deb` and `SHA256SUMS` get a detached Ed25519 signature from a hash-pinned venv (`release.yml:270-283`); build provenance is attested for the `.deb` and the binary (`:186-189`, `:285-288`); the `.deb` builds in a digest-pinned image (`:108`) | gate: the job fails closed when the key is absent (`:266-269`); test: `.github/scripts/test_sign.py` in `scripts.yml` |
| A test that nothing runs | every test is a Rust test that `cargo test` discovers, and a guard fails when a file that runs only by name appears | test: `tests/test_discovery_premise.rs` |

## Not implemented

Things the product context describes and this tree does not do. Listed so a
reader does not infer a control from a plan.

- **A ban table shared across listeners.** Each protocol counts failures per connection (three strikes) and the API keeps one in-memory budget (`src/api/state/mod.rs:90-91`). Reconnecting resets the count, and nothing is shared between SMTP, IMAP, JMAP and the API (`docs/asvs.md:274-278`).
- **A per-token request rate on the API.** Only failed authentications are budgeted; a valid token is not throttled.
- **TOTP replay protection, recovery codes, and an encrypted TOTP secret.** The secret is stored as base32 beside the account (`src/directory_store/mod.rs:127`; `docs/asvs.md:279-282`).
- **Verification that the isolated account is set up as intended.** Since 2026-09-03 the package creates it: `debian/epistle.postinst` adds `glyndor-epistle` with `adduser --system`, gives it `/var/lib/glyndor/epistle` at `0700`, adds a 65536-id subuid/subgid block that overlaps no other account (packages up to 0.10.1 added the fixed `100000-165535`, the block `useradd` gives the first regular user; `epistle check subid` reports such an overlap), enables linger, runs `podman system migrate` and applies the port floor from `debian/epistle.sysctl`; the sample unit runs under that account (`docs/epistle.service`) instead of a transient one. What is still missing is the other half: the postinst only attempts each step and warns on stderr, so nothing yet refuses to run on a host where the ranges, the linger flag or the floor did not take. `epistle init` is where that check belongs.
- **Panel wiring over a private container network.** Nothing in this repository configures Podman; the API's only default protection is the loopback bind.
- **Offsite, client-side-encrypted backups with rotation.** `epistle backup` writes one tar to stdout (`src/cli/backup/mod.rs::run`); the S3 backend under `src/storage/blob_backend/` stores JMAP blobs, not backups.
- **Encrypted storage of DNS provider tokens.** They are read from a `0600` file or the environment (`src/config/dns/mod.rs:33-38`), not encrypted.
- **Antivirus in an isolated container.** There is one generic `scanner_hook_url` (`src/config/mod.rs:164`).
- **A distinct admin role with mandatory 2FA.** The API authenticates keys, not people (`src/api/authorization.rs`, module doc).

## Residual risks and accepted decisions

- **DMARC and TLS-RPT reports are unauthenticated input.** Any host on the internet can drop a forged report into `postmaster@` or `tlsrpt@`; the ingester accepts it on the sender's word (`src/storage/delivery/reports/mod.rs:21`). A forged report cannot move mail, change policy, or read anything, but it can plant a JSONL line under `data_dir/reports/{dmarc,tlsrpt}/{YYYYMMDD}/{org}.jsonl` and influence what the operator reads with `epistle reports` (`src/cli/reports.rs:48`). The line is bounded by the per-recipient rate limits on port 25, the [`MAX_COMPRESSED`] / [`MAX_DECOMPRESSED`] gates in `src/reports/decompress/mod.rs`, the field-length and list caps in `src/reports/bounds/mod.rs`, and the 90-day prune in `src/reports/store/mod.rs`. Inside those bounds the ingester does not verify the sender; the operator reads the JSONL, decides what to do with the information, and the server drives no automatic decision from it. A report whose `org_name` is a path traversal lands inside the day directory as a single segment (`src/reports/bounds/mod.rs:45`), so a forged report cannot escape `data_dir/reports/`.
- **Plaintext-capable listeners warn instead of refusing.** `submission`, `webdav`, `api`, `autoconfig` and `metrics` bound to a non-loopback address without `[tls]` log a warning and start (`src/config/validate/mod.rs:460-469`, `:484-493`). The 2026-08-16 review rated this high; it stands, on the argument that these are fronted by the operator's TLS proxy. The metrics endpoint carries no authentication.
- **`scanner_hook_url` is not validated** the way the webhook and ACME URLs are: any URL the operator writes is called with inbound message bytes. Operational risk, since it needs write access to the config, but it is the one outbound URL that skips the `https`-or-loopback rule.
- **Message content leaves the host when the operator opts in.** The LLM antispam band posts message text to an OpenAI-compatible endpoint (`src/config/antispam/mod.rs:29-34`), the scanner hook posts it to the hook, and OpenTelemetry exports traces (`src/config/otel/mod.rs:8-10`). All three are off unless configured.
- **The release job installs third-party tooling beside the signing key.** `build` runs `cargo install --locked cargo-cyclonedx` (`release.yml:230`) in the same job that holds `GLYNDOR_RELEASE_ED25519_KEY` (`:261`) and `contents: write` (`:204`). `cargo install` runs every crate's build script, and `--locked` does not stop a yanked crate. The organisation's CI standard records this as the worst combination it has, and the check that would catch it (`workflow-lint`'s tooling isolation) does not run in this repository. Accepted until the SBOM moves to a job with `contents: read` and no secrets; the signing script itself is hash-pinned (`:274`).
- **No advisories are ignored** (as of 2026-09-03). The `RUSTSEC-2023-0071` ignore that `deny.toml` and `.cargo/audit.toml` carried through the sqlx 0.8 lifecycle is gone with the sqlx 0.9 bump: 0.9 drops `rsa` and `rand 0.8` from the graph, so the warning no longer reaches this lockfile (`fuzz/Cargo.lock` the same), and the gate now reports nothing to ignore.
- **One maintainer.** Every pull request is reviewed and merged by its author; a required check is matched by name, so the author could replace a gate with a job of the same name.
- **The greylist and the API failure budget live in memory** and reset on restart (`src/antispam/greylist/mod.rs:79`, `src/api/state/mod.rs:85-91`).
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
grep -n 'MAX_LINE_LENGTH' src/smtp/line/mod.rs         # each cited symbol still lives where cited
grep -n 'fn require_bearer_token' src/api/state/mod.rs
grep -n 'plaintext_listener_warn' src/config/validate/mod.rs
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
