# Security

epistle is built secure-by-default and fail-closed: a misconfiguration or a
failed safety check aborts rather than degrading silently. This page summarizes
the controls in place and how to report a vulnerability.

For the requirement-by-requirement mapping to OWASP ASVS Level 3 — each control
tied to the file and mechanism that implements it — see the
[ASVS L3 sweep](asvs.md). For the assessor's view, one row per threat with the
control, its test and the residual risks, see the [threat model](threat-model.md).

## Transport

- **Authentication never crosses cleartext.** SMTP `AUTH` and IMAP `LOGIN`/
  `AUTHENTICATE` are refused until the session is inside TLS; POP3 is
  implicit-TLS only (no plaintext port 110), and ManageSieve requires a
  STARTTLS upgrade before authentication.
- **TLS for the mail protocols** is the server's own job (built-in ACME, or
  manual PEM). Outbound delivery is opportunistic TLS, upgraded to *mandatory
  verified* TLS when MTA-STS enforce, DANE, or a sender's REQUIRETLS applies.
- **`TLS-Required: No`** (RFC 8689) lets one of your own senders deliver a
  message where MTA-STS or DANE would refuse an unverified connection, for
  instance to tell a domain its certificate expired. The queue still uses
  STARTTLS when the MX offers it, accepts any certificate for that message,
  and logs each policy it set aside. The field is honoured only on mail your
  accounts submit: inbound mail loses it before it is stored or forwarded,
  so nobody else can downgrade your policy. REQUIRETLS on the same message
  wins and the field is ignored (RFC 8689 section 4.1).

## Authentication

- **Passwords** are stored as **argon2id** PHC hashes — never plaintext, never
  reversible.
- **Breached / common passwords are refused locally**, with no network call.
  The bundled set merges the curated starter list under `src/password/`
  with the NCSC top-100k most-used passwords from `danielmiessler/SecLists`
  (`Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`,
  committed under `src/password/breached_top100k.txt` so the build needs no
  network, and filtered to the 1,203 entries of 12 to 64 printable-ASCII
  characters, the only ones the lookup can reach). SecLists is MIT-licensed;
  the underlying list was published by the UK National Cyber Security Centre
  under the Open Government Licence v3.0. The file header and
  `debian/copyright` carry both credits. The
  lookup is case-insensitive (the in-memory set is keyed by the
  case-folded form) and only runs on inputs that have already cleared the
  12-to-64-character printable-ASCII gate, so a strong random credential
  is unaffected.
- **Password character set**: length 12-64 printable ASCII by default.
  Operators that need non-ASCII passwords can opt in with
  `[auth] unicode_passwords = true`. With the flag on the policy accepts
  any non-control Unicode scalar, normalises with NFKC on both set and
  verify (RFC 8265 OpaqueString profile, RFC 5802 SASLprep / RFC 7677
  in spirit), counts length in scalars, and keeps the 64-character
  ceiling on the normalised form. A password set with one keyboard
  verifies from another. The flag is off by default because older IMAP
  and POP clients mangle non-ASCII credentials in AUTH PLAIN/LOGIN on
  the wire — the operator opts in knowing their clients need to normalise
  consistently, which SCRAM-SHA-256's standard preparation already does.
  See [the configuration reference](configuration.md#auth-unicode-passwords).
- **SCRAM-SHA-256** authenticates without the password crossing the wire, and
  **SCRAM-SHA-256-PLUS** adds TLS channel binding (`tls-server-end-point`) with
  downgrade rejection (RFC 5802 §6). `-PLUS` is offered when a static `[tls]`
  certificate is configured; under ACME (where the certificate is renewed at
  runtime) it is omitted and clients use SCRAM-SHA-256.
- **The SCRAM exchange over SMTP ends with an acknowledgement.** The server
  sends the server-final (the `v=...` signature the client checks) as a `334`
  challenge, and the client acknowledges it with the empty line; only then does
  the server answer `235 2.7.0 authentication successful`. The server-final
  cannot ride on the `235`, because SMTP has no room for the SASL "additional
  data with a successful outcome" (RFC 4954 §4), so it travels as a challenge
  instead. A client that answers that challenge with anything other than the
  empty line (or `*`, which cancels the exchange) gets a `501` and stays
  unauthenticated: a correct proof alone does not open the session. IMAP has no
  such last round — there the server-final travels in the response code of the
  `OK` that closes the `AUTHENTICATE` — so an IMAP client sees one message
  fewer than an SMTP one.
- **SCRAM verifiers** stored next to the argon2id hash are derived with
  600000 PBKDF2-HMAC-SHA256 iterations (the OWASP 2023 figure), so the
  verifier is not a cheaper target than the hash for someone who reads
  `accounts.toml`. A verifier from an older version keeps the iteration
  count it was derived with, which the server announces in the exchange,
  and is rewritten at 600000 under a fresh salt the next time the account
  logs in successfully with PLAIN or LOGIN. Accounts in `mail.toml` carry
  no verifier and are never rewritten. `[auth] scram = false` turns SCRAM
  off entirely: the mechanisms are no longer offered and no verifier is
  stored for new passwords, so `accounts.toml` holds only argon2id hashes
  once every account has changed its password.
- **OAuth2/OIDC** (OAUTHBEARER/XOAUTH2) bearer tokens are verified against the
  configured issuer/audience/key.
- **TOTP** two-factor (RFC 6238) is checked in the IMAP/SMTP auth paths. The
  secret is encrypted at rest only when at-rest encryption is on (see "Data at
  rest").
- **One set of account rules for every way in.** PLAIN, LOGIN, SCRAM, OAUTHBEARER,
  XOAUTH2, SASL EXTERNAL, app passwords, POP3, ManageSieve, WebDAV and the API
  credential check all end in the same decision (`Directory::admit_login`): a
  disabled account never signs in, the account's `allowed_protocols` list must
  include the protocol, and a login by an address in a switched-off domain
  fails because the address no longer resolves. The account name still works in
  a switched-off domain, as `domain disable` documents. SCRAM is refused for an
  account with a TOTP secret, because the SCRAM proof is derived from the
  password alone and cannot carry the code; such an account uses PLAIN or LOGIN
  with the code appended. A bearer token from an external identity provider is
  refused for such an account in the same way, unless `[oauth]
  idp_enforces_second_factor = true` declares that the provider enforces a
  second factor itself; a token of the built-in authorization server counts as
  having passed it, since the server asks for the code when it issues one. A
  bearer token names a mailbox only through an `email` claim with
  `email_verified` true, matched against the exact address of an account.
  The same exact match applies to a SASL EXTERNAL client certificate: one that
  carries a catch-all, masked or sub-address (`user+tag@`) no longer signs in.
  A token of the built-in authorization server lives one hour. The checks of
  an app password (its network range, expiry and revocation) apply when the
  token is issued, not while it lives, and a token issued before TOTP was
  turned on for the account is good until it expires. With `signing_key` the
  configuration is refused unless the key is the private half of
  `public_key`. A refused exchange runs on decoy credentials and ends
  at the final step as a wrong password, so nothing tells a refusal from a bad
  proof. Client certificates are not asked for a TOTP code (the certificate is the
  factor), and bearer tokens are asked for it unless the issuer is declared to
  be the factor; both are asked for everything else. Before 0.12.2 SCRAM skipped the TOTP code and the disabled flag, and a
  bearer token or client certificate skipped the disabled flag.
- **No user-enumeration oracle**: an unknown user fails exactly like a wrong
  password, and repeated failures close the connection. For a password
  mechanism that includes the time: a login with no password of its own
  (unknown, disabled, receive-only, or a TOTP code that is missing) checks the
  candidate against an argon2id hash made for the purpose, so the refusal costs
  what a wrong password on a real account costs. For SCRAM, a login nobody
  holds, an account without a verifier and an account the rules refuse get the
  same server-first message as a real account: the salt is a keyed hash of the
  login (stable for that login, not computable by the client) and the iteration
  count is the current one, and the exchange ends at the proof like a wrong
  password. Before 0.12.2 an unknown login was refused at the first message,
  instantly, while a real one was challenged, and a failed IMAP or SMTP password
  check for an unknown login returned in microseconds.
  A right password, or a right app password, for an account whose
  `allowed_protocols` leaves this protocol out is refused after the same hashes
  as a wrong one.
- **Password checks are bounded.** The sessions run the argon2id check on the
  async worker that drives them, so a burst of sign-in attempts could hold every
  worker and keep a hash in memory per connection. Every password check now
  goes through one gate shared by the process: it hands the worker over for the
  duration of the check and lets only half the cores run at once (two at least,
  eight at most), with a line of sixteen per place behind them. An attempt that
  finds the line full is not tried at all: it gets the temporary failure of its
  protocol (IMAP `NO [UNAVAILABLE]`, SMTP `454 4.7.0`, POP3 `-ERR [SYS/TEMP]`),
  moves no strike in the ban store and does not count as a failed login. It is
  counted in `mail_auth_hash_gate_rejected_total` and the log says so at most
  every 30 seconds (`auth.hash_gate_full`). The answer depends on the load and
  never on the login, so it tells nothing about an account. The REST API keeps
  its own gate for bearer tokens. What is left:
  - While a burst lasts, a legitimate sign-in waits behind it, and with the
    line full it is told to try again. A distributed flood of about
    `17 x places` simultaneous attempts keeps the line full; a client that
    retries gets in between them, and clients that stop after one temporary
    failure do not.
  - The wait cannot be cut short by the session's own deadlines or by the
    client hanging up, and it grows with the largest number of app passwords
    any account holds, because every refusal does that much work.
  - The memory held live is bounded by the places (about 19 MiB each). The
    published builds use musl, where a busy server measured 210 MB at eight
    places and 87 MB at two. A build from source against glibc may keep the
    memory of freed hashes (glibc raises its mmap threshold after the first
    one), so its resident size stays well above that.

## Authorization

- An authenticated sender may only use a `MAIL FROM` it owns — no spoofing, no
  null reverse-path from an authenticated session.
- The message itself must carry exactly one `From` field naming one address the
  account owns, on SMTP submission and on JMAP `EmailSubmission/set`. That is
  the field the DKIM signature covers and the one DMARC judges at the receiver.
- "Owns" is one rule for SMTP submission, `POST /api/v1/send` and JMAP
  (`Directory::owns_address`), in any letter case. An account owns the
  addresses stored for it (a dot in the local part, such as
  `name.surname@example.org`, is an ordinary address), and an enabled alias
  or list it may send as: any member when the alias names no senders, only
  the named senders when it does. An alias in another served domain works the
  same way. It does **not** own what only delivers to it: a `+tag` sub-address
  of its own address, the unknown local parts a catch-all receives, or an
  address on a domain alias (`alias.example.org`). Those are refused with
  `553` at `MAIL FROM`, `550 5.7.1` at the `From` header, `forbiddenFrom` in
  JMAP and `forbidden_from` in the API, as is any address of another account
  or of another domain. Loosening any of them is a decision about spoofing,
  not a fix. The table of cases lives in `src/smtp/directory/send_as_fixture.rs`.
- Every recipient is resolved against the directory before any network work; an
  empty directory rejects everything (fail-closed).
- JMAP and `POST /api/v1/send` act for the **principal** the bearer carries,
  never for an `accountId` the request names:
  - **Admin**: the configured token, or an API key with neither `domains` nor
    `account`. Reaches every account.
  - **Domains**: an API key with `domains`. Reaches only accounts whose
    addresses all sit in those domains.
  - **Account**: an API key with `account = "<name>"` in `api_keys.toml`.
    Reaches that one account, and only through JMAP and `/api/v1/send`:
    every other route (`/api/v1/accounts`, `domains`, `queue`, SCIM, ...)
    refuses it with `403 forbidden`.
  Every route with per-tenant data applies the key's domains, not only the
  accounts routes (see "Domain-confined API keys" in the configuration
  reference for the list). A route is added together with its rule in
  `src/api/tests/route_rules.rs`, or that test fails.
  A credential that matches no key reaches nothing. Every JMAP method, upload,
  download and the WebSocket check the account against the principal; a
  refused account gets the same `accountNotFound` (HTTP 404 on upload and
  download) as one that does not exist, and the Session lists only the
  accounts the principal reaches.
- `/api/v1/send` acts for the bound account, or for the account that owns
  `from` if the principal reaches it. `from` must be owned by that account,
  the same check `EmailSubmission/set` applies to `mailFrom`; otherwise
  `403 forbidden_from`, before any rate limit is spent.
- Uploaded blobs live in a partition per account
  (`<data_dir>/blobs/accounts/<account>/`). A blob is never found under
  another account's name, whoever asks. Blobs from older versions in the
  shared pool are served only to the owner their `.owner` sidecar records.

## Process and host

- **Privilege separation**: with `[privileges]`, the daemon drops to an
  unprivileged user/group once the privileged ports are bound, and verifies the
  drop cannot be reversed (see the [configuration reference](configuration.md)).
- The configuration file must be owner-only (`0600`); the server refuses to load
  a group/world-readable file. Secrets stay in the environment via `${VAR}`.
- **The container stack** runs every service with no capabilities except four
  clamd uses to step down to its own user, on a read-only root filesystem, with
  memory and process limits; `mail` connects to PostgreSQL as a role without
  superuser that owns only its database. The measurements and the upgrade path
  are in [the container stack](operations/container.md#what-each-container-may-do).

### A private subordinate id range

Rootless Podman runs each container of the `glyndor-epistle` stack in a user
namespace whose ids map onto the block of host ids listed for the account in
`/etc/subuid` and `/etc/subgid`. Those host ids are what owns the files the
containers write, in volumes and in image storage. If another account's block
covers the same host ids, a process in its containers runs as the owner of the
mail stack's files (the database volume included), and the reverse also
holds: the namespaces are separate, the file ownership is not.

`useradd` on Debian and Ubuntu gives the first regular user `100000-165535`
(`SUB_UID_MIN 100000`, `SUB_UID_COUNT 65536` in `/etc/login.defs`), so a
fixed block for the service account would collide on most hosts. The postinst
therefore picks the lowest block of 65536 ids within `SUB_UID_MIN`/`SUB_UID_MAX`
and `SUB_GID_MIN`/`SUB_GID_MAX` that overlaps no existing entry. Packages up
to 0.10.1 assigned the fixed `100000-165535`, and `epistle check subid` fails
while that block, or any other, is shared. On upgrade the postinst moves a
shared block to a free one of the same size and shifts the owner of the
stack's files with it; the [CLI reference](cli.md#moving-an-overlapping-subordinate-id-range)
says what it does and how to run it again.

### Port 25 without root

The production shape is a rootless Podman stack under the isolated
`glyndor-epistle` account, and a rootless container cannot ask the kernel for
`CAP_NET_BIND_SERVICE`. The package therefore ships
`/usr/lib/sysctl.d/30-glyndor-epistle.conf`, which sets
`net.ipv4.ip_unprivileged_port_start = 25` so that the account can bind the
SMTP port without ever being root.

Read that as a machine-wide change, because it is one: the setting is a single
global floor, not a per-user grant, so after it is applied **any** local
unprivileged user can bind any port from 25 up, including 25, 80, 110, 143,
443, 465, 587, 993 and 995. On a dedicated mail host, where the only accounts
are the operator's and this one, that is the intended trade and it buys a
server that never holds root. On a host shared with other services or other
people, weigh it before installing: a low-privilege account there could squat a
port a real service expects to claim later. `/etc/sysctl.d` stays yours, so a
file with a higher `ip_unprivileged_port_start` there overrides the vendor one
and survives upgrades of this package; the cost is that the rootless stack then
needs a proxy or a port mapping in front of it.

## Email authentication and anti-spoofing

Inbound mail is checked with **SPF**, **DKIM**, **DMARC** (with aggregate
reports), and **ARC**; outbound is **DKIM-signed**, with **MTA-STS**, **DANE**
and **TLS-RPT** for transport authentication. See the [DNS guide](dns.md).

An inbound ARC chain is verified with the algorithm each of its headers
declares: `a=ed25519-sha256` with Ed25519 over the SHA-256 digest of the
signed data, `a=rsa-sha256` with RSA over a key whose modulus is at least
1024 bits. The key type the DNS record declares has to be the one the
algorithm needs, and a record that publishes another kind of key is refused
instead of being read as whichever primitive the verifier happened to use.

## Anti-abuse

- Layered inbound filtering: **greylisting**, a **Bayesian** filter, sender
  **reputation**, and optional **DNSBL** lookups across three lists (client
  IP, envelope sender domain, URL hosts in the body), plus an external
  scanner hook. All three DNSBL lists fail open on resolver errors so a
  misconfigured upstream never blocks delivery.
- **Per-IP and per-sender message rate limits** on unauthenticated
  `MAIL FROM` (`inbound_rate_limit_per_ip_per_min`,
  `inbound_rate_limit_per_sender_per_min`). A peer or envelope that
  exceeds the cap is deferred with `450 4.7.1` so a real burst retries
  rather than bounces; the counters live under the same
  `mail_messages_rejected_total{reason="rate_limit"}` line as the other
  inbound rejections. Bounces use the null reverse-path and are skipped
  from the per-sender charge.
- **Shared authentication ban table** (requires `[database]`). Every
  listener (SMTP submission, IMAP, POP3, ManageSieve, the API, OAuth
  device and PKCE grants) records every password-authentication outcome
  into the `auth_failure` table and consults the `auth_ban` table
  before doing any password hashing. The product context's defaults:
  5 failed authentications within 15 minutes fire a ban; the first ban
  lasts 15 minutes, the next on the same subject doubles (30 minutes,
  then an hour, ...), capped at 24 hours. Failures are counted on three
  subjects. The client (`ip:<addr>`) is the peer address, or its /64 for
  IPv6, because one host there owns a whole /64 and rotating inside it is
  free. The pair (`pair:<login>|<client>`) is one account seen from one
  client. The account (`account:<login>`) counts every failure too, but it
  fires at four times the threshold (20 in 15 minutes): a guess spread over
  many clients, each too few to be banned, still ends in a ban, while a
  single client cannot lock an account out for its owner, because its own
  counters stop it after five. A successful authentication clears the ban
  and the failure history of the account and of that pair, and never of the
  client, so an attacker with an account of its own cannot reset its count by
  logging in between guesses at others. A shared address (a NAT, a proxy)
  therefore accumulates the typos of everyone behind it: allow-list it
  (`epistle ban allow add`) if that is a problem. An allow-listed client is
  never banned on its address or /64 (and for IPv6 the /64 it shares with
  others is not asked about for it, so a neighbour's ban does not reach it),
  but its failures still count on the account (not on the pair, so typos
  behind a shared proxy cannot lock one account's owner out of it), or a
  trusted network could guess without limit. A route that has no client address
  (WebDAV now passes one) counts every attempt on an account as one client,
  `unknown`, so the pair still stops guessing at five. Residual risk,
  left to the owner: counting is per /64, so a client with a whole IPv6
  allocation can spread guesses over its /64s (300 /64s of one /48 with four
  failures each never reach a ban); the account ceiling above is what stops it
  for one account, and spraying across many accounts is not banned. The owner
  decides between two readings of the same trade-off: (a) no ban on the /48,
  today's choice, which lets one attacker with an allocation rotate through its
  /64s; (b) a /48 counter at a high factor, which bans every user of a shared
  /48 (hosting, ISP, office, campus) because of one attacker. A middle point,
  not built: a /48 counter at a high factor that applies only to /64s that have
  already failed themselves, so a /64 without failures of its own is never
  blocked for its neighbours, at the price of a more intricate rule and of
  not stopping a rotation that spends one failure per /64. The owner of an
  account that many clients are guessing at is locked out for the length of the
  account ban as well. A credential stuffing wave from one client trips
  that client's counters. The wire response to a banned subject is identical to a wrong password (no
  oracle); the audit log records the rule that fired under the
  `auth.banned` event. The store is fail-open on database errors: a
  flapping pool returns `None` to the ban check and bumps the
  `database_unavailable` counter, the same discipline the reputation
  screen follows.
- **Banned account, known network** (requires `[database]`). When an
  account is banned, the right credentials let it in only from a
  network the account has signed in from successfully within the
  configured window (`known-network-window`, 30 days by default;
  the per-account cap of 32 networks keeps the list bounded, the
  oldest non-current row is dropped on each insert past the cap).
  The decision lives in one place (`Directory::check_ban` /
  `authenticate_verdict`), so every listener that goes through the
  shared gate inherits the policy: SMTP submission, IMAP, POP3,
  ManageSieve, the API (with the trusted-proxy-resolved client IP)
  and WebDAV. A ban an operator placed by hand (`epistle ban add`) is
  never bypassed, and neither is an IP ban: the exception is for the
  ban that failed sign-ins cause on the account, not for a decision
  somebody took. From the unknown network the response to a banned
  account is identical to today's: same message, same hash work,
  same outcome for a wrong password as for a right one, so the
  ban cannot be used as an oracle for guessing passwords from
  elsewhere. A successful sign-in writes the network onto the
  bypass list; a wrong sign-in from a known network still records
  the strike. An attempt cannot insert itself onto the list: the
  write only happens through the success path of
  `record_ban_outcome`, so a guessed password does not register
  itself. The write is throttled inside SQL to at most one row
  per (account, network) per hour, and the cap eviction runs in
  the same transaction, so the latency-sensitive sign-in path
  never grows the table without bound. A `/64` is the unit for
  IPv6 clients, the same keying the ban store already uses for the
  client counter, so a roaming client does not have to re-auth
  every time its host half changes. The `is_known_network` lookup
  fails closed on a database error (a missing row must not let a
  banned account in), and the audit log emits the same `auth.banned`
  event it would for any other ban check. The bypass only lifts bans
  placed on the account. A ban placed on the client address (by the
  threshold counter or by the operator) is not lifted from a known
  network: that address stays refused for the whole ban, so lifting it
  for the account would also lift it for everyone else behind the same
  address. A ban placed on the `(account, client)` pair is also not
  lifted from a known network: that pair is what caps repeated failures
  from one client, and a known network (a NAT, a corporate VPN) still
  needs it, otherwise an attacker on the same network could guess
  without limit while the owner is admitted. The `check_ban` loop
  only evaluates the bypass when the ban subject is the account, so a
  pair ban in force refuses the request even from the owner's known
  network; the pair counter keeps rising for wrong-password attempts
  from the known network, so the pair ban can fire from that network
  itself. A successful sign-in via the bypass does not call
  `clear_success`: the ban row stays in force for any other client,
  and only the bypass list `(account, network)` is refreshed.
- **Trusted reverse proxies.** `[api] trusted_proxies` defaults to `[]`, so
  forwarded headers have no authority by default. Only a peer in a configured
  IPv4 or IPv6 CIDR may supply `X-Forwarded-For`. The entire header must be a
  valid IP chain; Epistle selects the first untrusted address from right to
  left. Missing, malformed and wholly trusted chains use the TCP peer. Trust
  only controlled proxies that append the real connecting address or replace
  the header. API failure limits, credential IP restrictions, audit events,
  OAuth password bans and device grant counters use this effective IP, with
  the existing IPv6 /64 grouping. Invalid CIDRs prevent startup. Changes need
  a restart. See [configuration](configuration.md#api).
  API authentication-window `429` responses carry `Retry-After` with the
  remaining seconds rounded up. OAuth `429 slow_down` responses report the
  remaining grant expiry or polling wait; password bans keep their ordinary
  authentication failure response.
- **REST bearer token guesses.** Wrong tokens are counted per client (an IPv4
  address or an IPv6 /64) and a client over 20 failures a minute is refused
  before its token is looked at; a valid call does not give the failures back.
  An IPv6 /48 (eight times a client's budget) and the whole server (2000
  failures) only turn the `401` of a request that already failed into `429`;
  they are never asked of a valid token, because a budget anyone can fill would
  let an attacker refuse the operator. API keys are matched first by SHA-256.
  With a legacy argon2id `token_hash` the verification runs off the async
  workers, two at a time (the turn is held until the argon2 ends, even if the
  client hangs up), behind a queue of 64; the next request is told `429`, and
  every request reserves its failure under the same lock as the limit check
  and gives it back if the token is valid, so requests arriving together
  cannot all pass a client's limit. After the real token has been seen once a
  wrong one is rejected by digest with no argon2. One client holds at most two
  places in the queue and an IPv6 /48 four, so a single origin cannot fill it.
  A sustained flood from some 300 distinct clients (about 105 requests a
  second, the rate two cores verify at) can still keep the queue full: until
  the real token has been seen once since start-up, its first use is then told
  `429` and a retry gets the same answer for as long as the flood lasts. That
  only concerns a legacy argon2id `token_hash` and never API keys; store the
  token as `sha256:` (what `epistle token-hash` writes) and the exposure
  disappears. Two consequences of the places per origin, both only before the
  first successful use of an argon2 `token_hash` since start-up: an operator
  who shares an IPv6 /48 with an attacker is told `429` for as long as the
  flood lasts (measured: from another /48 the real token got in within 38 ms,
  from the same /48 1250 answers in a row were `429` over 20 seconds), and a
  panel that opens three or more requests in parallel on its first use gets
  `429` on the surplus ones, because one client holds two places, until the
  first of them verifies the token.

  Known limits, measured by the second review and not changed: a ban on a real
  account answers in under a millisecond where an unknown login pays for its
  hashing, which tells that the name exists to someone who first spends twenty
  failures from five clients on it (not verified against the fix); the device
  grant pool scans its entries under one lock, about 0.45 ms a request when
  full; each attempt on an unknown login writes three rows to the ban tables
  where it used to write one, and they expire with the 24-hour sweep; every
  refusal costs one hash plus as many as the account with the most app
  passwords has, and nothing caps the app passwords an account can hold; the
  HTTP clients of the antispam hook and the LLM scanner, and the ACME and S3
  clients, still follow redirects. The /48 question above is also still open,
  and was not re-measured after the revert. Residual risk: guesses spread over
  many clients are not capped as a whole, so the defence is the entropy of the
  token (use a long random one, or a `sha256:` hash of one).
- **Device authorization grants are bounded** (`POST /oauth/device_authorization`
  needs no credentials). A client (an IPv4 address or an IPv6 /64) may hold 10
  grants, an IPv6 /48 100, the server 10000; expired ones are dropped at the
  caps, and a client or /48 over its cap gets `429 slow_down`. With the pool
  full, the oldest *pending* grant of the group holding the most pending grants
  (an IPv6 /32, or an IPv4 address) is evicted, but only if that group holds
  strictly more than the requester's own; a requester who is itself the
  heaviest group, or a pool with nothing pending, is refused. An approved grant
  is never evicted. So a newcomer gets in while anyone is above it and a heavy
  group can only displace itself. Residual risk: an attacker with many
  distinct /32s (or IPv4 addresses) can fill the pool with groups no heavier
  than a newcomer, for the ten minutes the grants live. Two refinements were
  considered and left out because each trades one weakness for another:
  grouping IPv4 by /24 (a botnet inside one /24 would then count as one group,
  but a shared office or carrier NAT would be evicted as one) and a hierarchy
  /32 to /48 for eviction (it catches an attacker who stays under one /48's
  cap in many /48s of different /32s, at the price of a rule that is harder to
  state and test).
- **Antivirus on outbound mail** (with `[antispam] clamd_socket`, on by
  default through `scan_authenticated`). A compromised account must not
  relay malware, so what local accounts submit over SMTP, the REST API and
  JMAP is scanned by clamd before it is routed, for local and remote
  recipients alike. A detection is refused (`554 5.7.1` on SMTP), logged
  with the account's pseudonym and the signature, counted in
  `outbound_virus` and announced with the `outbound_virus` webhook event, so
  the operator learns that the account may be compromised. The scan fails
  open when clamd cannot be reached, like the inbound one, and `epistle
  status` warns while scans keep failing, so an antivirus that is silently
  not scanning does not go unnoticed.
- **Forwarding loops.** Every copy stored in a mailbox starts with
  `Return-Path` (any one the message arrived with is removed) and the
  `Delivered-To` of the address it was delivered to, and a forwarded copy
  carries the `Delivered-To` of the address that forwarded it. A message
  that comes back to an address about to forward it again (an account
  forward or a Sieve `redirect`) is refused with a `554 5.4.6` bounce
  instead of going round, on top of the `Received` hop limit.
- **Outbound suppression**: a reply proving the address bad (5.1.x, 551,
  553) suppresses that recipient so the server stops sending to dead
  addresses, protecting the sending IP's reputation. Policy refusals, full or
  disabled mailboxes and oversized messages never suppress.
- The outbound queue gives up by **message age** (5 days), not a low attempt
  count, so transient outages don't lose mail; a delay-warning DSN is sent once.
- **ARF** abuse reports can be generated for offending messages
  (`epistle report-abuse`).
- **Slow exfiltration via a compromised account**: a per-account submission
  rate limit (`submission_rate_limit_per_min`) only sees volume, so a
  hijacked account that stays under the per-minute ceiling can still
  write to thousands of addresses it never legitimately contacted. The
  daily new-recipient cap (`new_recipients_per_day`) closes that
  loophole by tracking which recipients an account has written to and
  refusing any submission whose set of fresh addresses would push the
  rolling 24h total over the configured ceiling. Refusals are `450
  4.7.1` on SMTP, `429 rate_limited` on the REST submission endpoint,
  and the JMAP `tooManyRecipients` error type on `EmailSubmission/set`;
  the audit channel carries `send.new_recipients_limited` with the
  account, count and limit, and the `send_limited_new_recipients`
  Prometheus counter bumps so an operator can alert on it.
- **Reply fast path for known correspondents**: the same per-account
  correspondent store powers an inbound optimisation. If the envelope
  sender of an unauthenticated message is known to **any** local
  recipient account of the same message, the greylist deferral and the
  reputation `first_time_delay` are skipped. Nothing else changes:
  DNSBL, SPF, DKIM, DMARC, the scanner and the LLM band still run,
  because a known correspondent's account can itself be compromised.
- **Signed token for the uncertain band (SubjectPass).** A message whose
  local Bayesian score lands in the configured uncertain band and has no LLM
  verdict to lean on faces a binary choice: accept or reject. Both have a
  cost: a quiet accept teaches the classifier that "uncertain" is the same
  as "ham" if it is not, and a silent reject loses legitimate mail.
  SubjectPass splits the difference: the server refuses the message with
  `550 5.7.1` and a token the sender can paste in the `Subject:`, and accepts
  the resend that carries it. The refusal is permanent, not a `4xx`, because
  a sending server retries a `4xx` with the same message, which never carries
  the token, and its author hears nothing until that queue gives up days
  later; a `5xx` is bounced to the author at once with the reply text in it.
  A spam cannon does not read its bounces. A challenged message is not stored
  and does not train the corpus. The token is per `(sender, recipient, day)`
  and signed with an HMAC key held on disk under `data_dir/subjectpass.key`
  (`0600`, generated on first use), so a stolen token gains one pair for one
  day. The check runs after DNSBL, SPF, DMARC and the scanner hook, so a
  valid token never overrides a hard rejection. Opt-in
  (`subjectpass.enabled = true`) because it changes what remote senders see,
  and requires `[database]` because the band needs the Bayesian score to test
  against. **Cost:** one bounce and one resend for unknown legitimate senders
  whose mail lands in the band, and a lost message for automated senders
  whose bounces nobody reads. The reply text (`550 5.7.1 this message needs a
  human; resend it with EP-XXXXXXXXXXXX anywhere in the subject`) is what a
  person will read; keep it short and human, because the alternative is a
  real person hitting a wall.

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

The outbound spool envelope (sender, recipients, per-recipient state, last
error string) is sealed with the same key and bound to the message id as
associated data, so a stolen spool file on its own discloses nothing more
than the spool id and a Poly1305 tag. Spool files and directories are
pinned to `0600`/`0700`, regardless of the umask under which the server
started. A legacy plaintext envelope is sealed on its next read. See
[`storage.md`](storage.md) for the on-disk layout, the AEAD envelope, the
magic-tag migration path and the `epistle status` `spool` area that
observes the current state.

- **The key must live off the encrypted disk** (otherwise encrypting files on
  the same disk is pointless against theft). Source it from `encryption_key_env`
  (the name of an environment variable holding the base64 key) or
  `encryption_key_file` (a path the operator manages, outside `data_dir`).
  `epistle init` generates one in `secrets/` beside data_dir and names it in
  `encryption_key_file`; `epistle storage-keygen` prints another. Nothing puts
  a key inside `data_dir`, and backups do not carry it.
- **Fail closed:** with `encrypt_at_rest = true` and no usable key the server
  refuses to start; a decryption failure on read is an error, never a fall-back
  to serving ciphertext.
- **Transparent migration:** encrypted files carry a magic prefix, so encrypted
  and pre-existing plaintext files coexist — turning encryption on encrypts only
  new writes, and old plaintext mail still reads correctly.
- **Backups stay encrypted:** `epistle backup` archives the on-disk bytes
  verbatim, so a backup of an encrypted store remains ciphertext — restore it on
  a host with the same key. Use `epistle export` for a decrypted copy.
- **TOTP secrets** in `accounts.toml` are encrypted with the same key
  (stored as `enc:v1:<base64>`) when `encrypt_at_rest = true`, and are
  protected only then: without at-rest encryption they are stored in
  cleartext, guarded by the `0600` file mode and the disk encryption alone.
  A secret written before encryption was turned on keeps working and is
  encrypted the next time the server writes `accounts.toml`. If a stored
  secret cannot be decrypted (key missing or wrong), that account's
  password login fails instead of skipping the second factor.

## Logs and account names

Server logs never carry an account name. A log line identifies an account by a
stable pseudonym, `acct-<12 hex>`: an HMAC-SHA256 of the name under a per-server
key that lives in `<data_dir>/log-pseudonym.key` (created `0600` on first use,
like the other data-directory keys). The same account always maps to the same
pseudonym on one server, so its lines can still be followed, but the log alone
does not reveal who it is about. Paths under an account directory are logged
with that directory replaced by the pseudonym. The operator, who holds the key,
maps in either direction with `epistle account show` and
`epistle account find-log-id` (see [the CLI reference](cli.md#accounts)).
Test diagnostics follow the same rule: an assertion message names the field,
never the credential or account data it checked.

Two lines an SMTP session writes at the default level (`info`) carry those
pseudonyms and nothing else:

- **`message accepted`** — one per accepted inbound message. `log_id` is the
  recipient account's pseudonym (`unknown` when the recipient is not served
  here), `size` the octets delivered, `protocol` the protocol that carried
  it (`smtp`), `recipients` how many recipients the envelope named, and
  `result` the outcome. No address, no sender, no subject and no body reach
  the line. An accepted message used to leave no line at all, so the log
  could not say whether mail had arrived.
- **`authentication attempt`** — one per attempt on the mechanisms that do not
  go through the password check: SCRAM, OAuth and SASL EXTERNAL. `log_id` is
  the account's pseudonym, or `unknown` when the attempt was refused: a
  refused attempt never says which account it tried to be, the same way the
  wire answer does not. `protocol`, `mechanism`, `result` and `failures` say
  the rest. A refused attempt on those mechanisms used to leave a warning
  without the protocol, and a successful one left nothing at all. The
  password mechanisms (SASL PLAIN, AUTH LOGIN) write the audit channel
  `epistle::auth` instead, which carries the same facts.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this
repository rather than opening a public issue. Include reproduction steps and
the affected version; we will acknowledge and coordinate a fix and disclosure.
