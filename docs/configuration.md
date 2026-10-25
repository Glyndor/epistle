# Configuration

`epistle` is configured with a single TOML file, passed to
every command with `--config`:

```sh
epistle serve --config /etc/glyndor/epistle/mail.toml
epistle config-check --config /etc/glyndor/epistle/mail.toml   # validate without starting
```

The file must be owner-only — the server refuses to load a file that is group-
or world-readable:

```sh
chmod 600 /etc/glyndor/epistle/mail.toml
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
| `public_ipv4` | IPv4 | unset | Public IPv4 the hostname resolves to. Required by `verify-dns` to check the PTR and confirm the address matches the published A record; absent leaves `verify-dns` to look it up on the fly. Loopback, link-local, RFC 1918, carrier-grade NAT (`100.64.0.0/10`, RFC 6598), multicast, broadcast and the documentation ranges are refused at validate time: only a global unicast address is accepted. |
| `public_ipv6` | IPv6 | unset | Same for IPv6. Publishing SPF for a host that also has AAAA without listing the v6 makes mail sent over IPv6 fail SPF. |
| `data_dir` | path | — (required) | Absolute path where all server state lives (mail, spool, suppression, …). |
| `domains` | list | `[]` | Domains this server accepts mail for. Required once any listener is configured. A domain needs at least one dot: `localhost` and `intranet` are refused, because RFC 5321 §2.3.5 keeps unqualified names out of an SMTP transaction and mail for them cannot be delivered on the public internet. |
| `domain_aliases` | table | `{}` | `alias → target`: mail to `user@alias` is delivered as `user@target`. |
| `disabled_domains` | array | `[]` | Entries of `domains` that are switched off: mail for them is rejected like mail for an unknown user and nobody may send as an address in them. Accounts, DNS records and DKIM keys are kept. Every entry must be in `domains`, once; with listeners configured at least one domain must stay enabled. `epistle domain disable\|enable` edits it. |
| `dnsbl_zones` | list | `[]` | DNS blocklist zones (RFC 5782) screened against unauthenticated clients. Empty disables the IP screen. |
| `dnsbl_domain_zones` | list | `[]` | Right-hand-side blocklist zones queried with the envelope sender's domain (RFC 5782 §2.3). Empty disables the sender-domain screen. |
| `dnsbl_url_zones` | list | `[]` | URI blocklist zones queried with the host of every URL found in the body (RFC 5782 §2.3). Empty disables the URL-host screen. |
| `first_time_sender_delay_secs` | int | `0` | Delay a first-time (no-reputation) unauthenticated sender before accepting. Requires `[database]`. `0` disables. |
| `greylist_delay_secs` | int | `0` | Seconds an unseen (client, sender, recipient) triplet is greylisted (451) before a retry is accepted. `0` disables. |
| `srs_secret` | string | unset | Secret for Sender Rewriting Scheme on forwarded mail (SPF survives the next hop). Absent disables SRS. |
| `quota_bytes` | int | 5 GiB | Default per-account mailbox quota (RFC 9208), used when an account has no per-account or per-domain quota. Absent means 5 GiB; `0` means no limit, here and in `domain_quotas` or an account's own `quota_bytes`. IMAP QUOTA, JMAP `Quota/get` and `epistle limits show` report the same limit (none when it is `0`). Enforced on every path, measured as IMAP QUOTA reports it (archived mail included): IMAP APPEND answers `NO [OVERQUOTA]`; SMTP refuses a full mailbox at `RCPT TO` with `452 4.2.2` for that recipient only, and a message that would overfill one is accepted for the other recipients with a DSN to the sender, or refused with `552 5.2.2` when it fits none; `POST /api/v1/send` answers `507 mailbox_full` and JMAP `EmailSubmission/set` `overQuota`, with nothing queued. |
| `domain_quotas` | table | `{}` | `domain → bytes`: default mailbox quota for accounts in a domain (overridden by a per-account `quota_bytes`). `0` means no limit. |
| `submission_rate_limit_per_min` | int | unset | Recipients an authenticated account may submit per minute, on SMTP, `POST /api/v1/send` and JMAP `EmailSubmission/set` together: one budget per account whatever the protocol, app password or sender address. A message costs one unit per recipient: on SMTP every `RCPT TO` the server accepted, on the API every `to`, `cc` and `bcc` address, on JMAP the envelope `rcptTo` or, without an envelope, the deduplicated `To`, `Cc` and `Bcc` (RFC 8621). It is charged once, when the message is accepted, all of it or none: a transaction ended by `RSET`, a message over the limit and one refused on the way out cost nothing. Over the limit: SMTP `450 4.7.1 sending rate limit exceeded; retry later` (at `MAIL FROM` once the budget is spent, at the end of the data when the message has more recipients than are left), REST `429` `rate_limited` with the message `sending rate limit exceeded; retry later`, JMAP `SetError` `rateLimit` with the same description. Absent disables it (the default); `epistle limits` refuses `0`, which the server reads as no limit. Changes apply when the server restarts. |
| `new_recipients_per_day` | int | unset | Cap on first-time recipients an authenticated account may write to in a rolling 24h window. Refused: SMTP `450 4.7.1 too many new recipients today; retry tomorrow`, REST `429 rate_limited`, JMAP `tooManyRecipients`. Absent disables the cap (the default). The `init` scaffold later sets a default of 200. |
| `default_feedback_id` | bool | `true` | Write a `Feedback-ID` of the sending domain and the class on a submission that carries none (`epistle:<class>:<domain>`). `false` leaves the field to the client. See [headers](headers.md#identification-headers). |
| `default_list_unsubscribe` | bool | `true` | Give a bulk `transactional` submission a `mailto:` `List-Unsubscribe` naming the sender, when it has none. Marketing mail is left alone (it must carry a one-click unsubscribe) and personal mail never gets one. Nothing on the server answers the address it points at: it is the sender's own mailbox, and the sender's own tooling has to act on it. `false` turns it off for every class. |
| `bulk_recipients` | int | `20` | Recipients above which a `transactional` submission counts as bulk for `default_list_unsubscribe`: `20`, the default, means twenty-one or more. A notice to a handful of people is correspondence, not bulk mail. Refused below `1`: it is a count of recipients, and zero would make every transactional submission bulk. For no unsubscribe at all, turn `default_list_unsubscribe` off. |
| `default_list_id` | bool | `true` | Write the `List-Id`, `List-Post` and `List-Unsubscribe` of the list the envelope sender speaks for, when that sender is a `[[alias]]` with a `list_id`. The first two replace whatever the client wrote; a `List-Unsubscribe` the client already sent is kept, one-click included. `false` leaves them to the client. |
| `system_auto_submitted` | bool | `true` | Write `Auto-Submitted: auto-generated` on the mail the server generates itself: bounces and delay notices, alert emails, DMARC and TLS-RPT reports. `false` leaves the field out of that mail, failure and delay notices among them, so nothing marks those as generated and the null return path is what keeps a bounce from looping. The abuse report builder does not read this switch and always writes `auto-generated`, and the report `epistle report-abuse` prints carries no `Auto-Submitted` at all. A vacation reply is always `auto-replied (vacation)` and is not affected. |
| `x_epistle_header` | bool | `false` | Write `X-Epistle: 1` on every submission, on all three paths. The fixed value carries no version and no version field sits beside it. Off by default: no receiver acts on it. |
| `organization_header` | bool | `true` | Write the `Organization` of the sending domain on a submission, using `domain_organization`. The configured value replaces whatever the client wrote. `false` leaves the field alone. |
| `domain_organization` | table | `{}` | `domain → name`: the `Organization` each domain publishes (RFC 2369). The key is a DNS name, the value printable ASCII with no control character. A domain with no entry gets no `Organization` from the server. |
| `domain_submission_limits` | table | `{}` | `domain → recipients/min`: per-domain override for `submission_rate_limit_per_min`, counted and refused the same way. An account picks up its own domain's entry when one is set; otherwise the server-wide default applies; otherwise no limit. The domain is taken from the account's own addresses (the same walk `domain_quotas` performs), not from the first configured domain; an account with addresses in several limited domains gets the strictest entry. Edited through `epistle limits set submission-rate --domain <NAME> <N>`. |
| `inbound_rate_limit_per_ip_per_min` | int | unset | Max messages an unauthenticated client IP may start per minute. Sessions that authenticate are charged against the submission limiters instead; bounces (null sender) are not charged against the per-sender limit. A send over the cap is deferred with `450 4.7.1 too many messages from this client; retry later`; the temporary code lets a real burst (a mailing list, a resend after an outage) retry rather than bounce. Absent disables the per-IP limit. |
| `inbound_rate_limit_per_sender_per_min` | int | unset | Max messages a single envelope sender may start per minute across all clients (lowercased reverse path). Excludes the null sender used by bounces. A send over the cap is deferred with `450 4.7.1 too many messages from this sender; retry later`. Absent disables the per-sender limit. |
| `masked_addresses_max` | int | `100` | Per-account cap on server-generated masked email addresses (the disposable aliases at `POST /api/v1/accounts/{name}/masked`). `0` means no cap; the request that would go above it returns `409 conflict`. |
| `max_message_size` | int | 25 MiB | Per-instance message-size cap; `0` means the default. Not below 64 KiB: RFC 5321 §4.5.3.1.7 makes 64K octets the least a server may accept. A smaller value in the file is raised to 65536 bytes when it loads, with a warning that names both values, in the log, in `epistle config-check` and in `epistle status`; `epistle limits set max-message-size 64k` writes the floor into the file, and `limits set` refuses anything smaller. It may not exceed the effective `message_memory_budget` unless the budget is `0`: the server refuses to start (and `epistle limits set` refuses the change) rather than accept a size it could never receive. The same number is the SMTP `SIZE` extension value, the `MAIL FROM` SIZE parameter cap, the per-line running size check, the end-of-DATA check, the per-chunk BDAT cap, the JMAP upload route's body limit, the JMAP `Email/set` create builder cap, and the REST `POST /api/v1/send` body limit. The cap is advertised in EHLO `SIZE` and the JMAP Session resource (`maxSizeUpload`, `maxSizeAttachmentsPerEmail`). Oversize is refused with `552 5.3.4 message exceeds maximum size` (SMTP), the JMAP `limit` problem (`maxSizeUpload`), or the REST `413 message_too_large`. |
| `max_connections_per_listener` | int | per-protocol | Max concurrent connections per listener, at most 1000000; excess are dropped. Absent uses the built-in default (SMTP 1000, IMAP 500, POP3 500, ManageSieve 100). |
| `max_connections_per_ip` | int | 20 | Max concurrent connections from a single client IP per SMTP listener (IMAP, POP3, ManageSieve and plain HTTP have their own, below). A peer over the cap is answered `421 4.7.0 too many connections from your address` and closed; the per-listener semaphore still bounds the total. An IPv6 client is counted by its /64, and an IPv4-mapped address as the IPv4 address. No peer is exempt. `0` uses the built-in default. Behind a proxy or NAT that hides the client address (Podman rootless bridge networking reports every client as one gateway address) every client shares one count. |
| `message_memory_budget` | int | derived | Shared byte budget every SMTP `DATA` / `BDAT` reservation draws from. When the cap is exhausted a new transaction is refused with `452 4.3.1 insufficient system resources; try again later` (a refused `BDAT` chunk is still read and discarded). A `BDAT` chunk is charged as its octets arrive, like a `DATA` body, never for the size it announces, so a client that announces a large chunk and sends it slowly holds only what it has sent. One client (an IPv4 address or an IPv6 /64) may hold at most a quarter of the budget, and never less than one message of `max_message_size`. An accepted body stays counted until its delivery is over; reservations are released on every path that drops the body (reply, `RSET`, `EHLO`, disconnect, timeout, panic). Must be at least `max_message_size`. `0` disables the cap (every reservation succeeds, the historical unbounded behaviour). Unset, it is a fifth, in whole MiB, of the memory the `mail` container may use (its cgroup v2 `memory.max`, else the `mem_limit` of `mail` in the generated `compose.yaml`, else 1 GiB), at least `max_message_size` and at most 1 GiB: a message in flight peaks at about 2.9 times its body, so a full budget costs about three times its size, 60% of the limit. A set budget whose triple is more than 70% of that limit is kept, with a warning at start-up and in `epistle status` (area `resources`). See [Sizing](container.md#sizing). |
| `min_data_rate` | int | 10240 | Minimum average transfer rate of one inbound message, in bytes per second. The clock runs over the whole transaction: from the `354` of `DATA`, or from the first `BDAT` chunk, until the final dot or the `LAST` chunk. The time between chunks counts, commands sent in it and replies the client leaves unread included, and octets past `max_message_size` buy no time. Once `data_rate_grace` is over, a client whose average since that start is below the floor gets `421 4.4.2 transfer too slow, closing connection` and is disconnected; its memory reservation is released at once and its per-IP slot when the connection closes (a client that does not read the 421 is dropped when the 300 s write timeout runs out). At the default a 25 MiB message has about 43 minutes. `0` turns the check off (only the 300 s idle timeout per read remains). At most 1 GiB/s. |
| `data_rate_grace` | int | 120 | Seconds from the start of a message transaction before `min_data_rate` applies, given once per transaction, not per chunk. Between 1 and 3600. |
| `junk_command_limit` | int | 100 | Commands without progress one SMTP session may send before it gets `421 4.7.0 too many commands without progress, closing connection` and is disconnected (the same default as Postfix). Two counts share the limit. Commands that never move a message count for the whole session: `NOOP`, `RSET` and `VRFY` whatever their reply, unknown commands (`EXPN`, `HELP`, `ETRN`), a repeated `EHLO` or `HELO` (the one after the banner and the one after `STARTTLS` are free), a `BDAT 0` chunk that is not `LAST`, and every `AUTH` response line; a delivered message or a successful login does not reset them, and a logged-in session has the same limit, so a client that sends `RSET` before each message reconnects after about a hundred. Refused commands (syntax errors, refused `MAIL` and `RCPT`, commands out of sequence) count only since the last message the server accepted (after every check on its body), as Postfix forgives earlier errors once a message is received: a relay delivering a list with many recipients that no longer exist keeps its connection while its messages are accepted, and a client that only collects refusals is cut. Runs of consecutive refusals are bounded separately (20). `0` turns it off; otherwise between 10 and 10000. |
| `max_session_time` | int | 1800 | Seconds one SMTP session may last. Past it the client gets `421 4.4.2 session time limit reached` and is disconnected at the next command boundary: while the server waits for a command or an `AUTH` response line, or before it runs one. A message body being received (`DATA`, or the chunks of a `BDAT` transaction) is never cut, since `min_data_rate` bounds it; the command after it is, except `QUIT`, and a client whose body ended past the limit has one 300 s idle timeout to send it. `0` turns it off; otherwise between 60 and 86400. |
| `preauth_timeout` | int | 60 | Seconds an IMAP, POP3 or ManageSieve client gets, from the start of the connection, to sign in. One deadline covers the TLS handshake, every command and every literal (or `AUTHENTICATE` response) before authentication; bytes arriving slowly and a stream of harmless commands (`NOOP`, `CAPABILITY`) do not move it. At the deadline IMAP answers `* BYE idle timeout` and ManageSieve `BYE`, POP3 closes. A signed-in session is not held to it: it gets the idle timeout of its protocol (30 minutes IMAP and ManageSieve, 10 minutes POP3) for each command, counted from the moment the server starts waiting for it, and `IDLE` keeps its own limit. A client that signs in with a very slow password hash or over a very slow link needs a longer value. From 5 to 3600, but on IMAP and POP3 the phase never outlasts the idle timeout of the protocol, so a value above 600 acts as 600 on POP3 and above 1800 acts as 1800 on IMAP. ManageSieve uses the configured pre-authentication deadline without this idle-timeout cap. |
| `max_mailbox_connections_per_ip` | int | 200 (ManageSieve 40) | Max concurrent connections one client may hold on each IMAP, POP3 and ManageSieve listener. A client over the cap is answered `* BYE too many connections from your address` (IMAP), `-ERR too many connections from your address` (POP3) or `BYE "too many connections from your address"` (ManageSieve) and closed before any handshake or session is set up; a listener that is full gets `... too many connections, try again later`. On the implicit-TLS ports (993, 995) the line arrives in clear, ahead of a TLS handshake that never starts. An IPv6 client is counted by its /64, an IPv4-mapped address as the IPv4 address, and no peer is exempt. The count is released when the connection ends, however it ends. `0` uses the default. A mail client keeps several connections open (three to six, one per folder it watches with `IDLE`), so at four per device and two devices a user holds about eight: 200 serves about 25 active users behind one address, and an office or a mobile carrier sharing one address with more people needs a higher value. 200 is also 40% of the IMAP and POP3 listener (500), so three such addresses can fill it. ManageSieve defaults to 40 because its listener holds 100 and a script editor keeps one or two connections: a cap above the listener's would never act. A value you set applies to the three protocols alike. Behind a proxy or NAT that hides the client address, and with a bridge network or `rootlessport` instead of `pasta` (Podman rootless reports every client as one gateway address), every client shares one count and the ceiling of the listener falls from 500 connections to this value, about 25 users: raise it to about the listener's `max_connections_per_listener`. |
| `max_http_connections` | int | 1024 | Max concurrent connections each plain-HTTP listener serves, at most 1000000: the API and JMAP, WebDAV, autoconfig without TLS, the ACME responder and metrics. A connection over the cap gets `503 Service Unavailable` with `Connection: close` and is closed without reading its request. `0` uses the default. A JMAP push (WebSocket) connection keeps its place in both this cap and `max_http_connections_per_ip` for as long as the socket is open, not only until the upgrade. A panel or proxy that carries the sockets of many users from one address needs `max_http_connections_per_ip` raised to match. |
| `max_http_connections_per_ip` | int | 256 | Max concurrent connections one client may hold on each plain-HTTP listener (API, JMAP, WebDAV, autoconfig without TLS, ACME, metrics), answered with the same `503`, and on each listener that terminates TLS in the server (autoconfig over HTTPS, MTA-STS), where the connection is closed before any TLS handshake so no `503`/`BYE`/`-ERR` is ever written. The cap uses the TCP peer address from the socket, never a forwarded header, so the server never reads `X-Forwarded-For` before admission and `[api].trusted_proxies` does not affect it: the only way to share it is to actually be the same source address. An IPv6 client is counted by its /64 (the /48 a single subscriber receives usually lives in the same /64) and an IPv4-mapped address as the IPv4 address. No peer is exempt. `0` uses the default. The plain-HTTP and TLS caps share this key and value. A reverse proxy or the panel in front of the API is one client for all its users, so raise this to the listener cap (`max_http_connections` for plain HTTP, `max_connections_per_listener` for the autoconfig listener over HTTPS and MTA-STS) when the listener only talks to it; behind a proxy every connection looks like the proxy, so a small default (256) is one user per proxy connection and a single proxy saturating the cap is a denial of service for everyone behind it. The MTA-STS default of 32 (one eighth of the listener default of 256) covers a single resolver fleet refetching at the same time; raise it for a fleet. |
| `queue_give_up_secs` | int | 5 days | Outbound give-up window: undelivered mail older than this is bounced. A delay-warning DSN is sent once at `queue_delay_warning_secs`. |
| `queue_retry_base_secs` | int | 60 | Wait after a recipient's first failed attempt; each later wait doubles up to `queue_retry_cap_secs`. Every wait is spread by a random ±20% so mail deferred together does not all retry in the same second. At least 60. |
| `queue_retry_cap_secs` | int | 3600 | Longest wait between attempts for one recipient. Not below `queue_retry_base_secs`. |
| `queue_delay_warning_secs` | int | 4 hours | Message age at which the one "delivery delayed" DSN is sent for the recipients still pending. Below `queue_give_up_secs`. |
| `scanner_hook_url` | string | unset | External HTTP scanner for unauthenticated inbound mail. Mutually exclusive with `antispam.clamd_socket`. |
| `antispam` | section | unset | Unix socket clamd scanner. See the settings below. |
| `antispam_llm` | section | unset | LLM-assisted screening for unauthenticated mail whose Bayesian score lands in an uncertain band. Absent disables the hook. |
| `subjectpass` | section | disabled | Signed token for the uncertain Bayesian band: when no LLM verdict decides a message in the band, the server refuses it with `550 5.7.1` and a token the sender can put in the `Subject:`, and accepts the resend that carries it. Requires `[database]`. Disabled by default (changes what remote senders see). See [`[subjectpass]`](#subjectpass). |
| `log_format` | `text`\|`json` | `text` | Log output format. |
| `rules` | array | `[]` | Delivery rules that route or flag locally delivered mail by sender/header. |
| `alerts` | array | `[]` | Metric alerts: rules that fire a webhook or email when a counter crosses its configured threshold over a sample window. |
| `tenant` | array | `[]` | Tenant definitions: named groups of domains with optional aggregate caps on accounts, domains, storage and submission rate. Empty means no tenancy is in effect. See [`[[tenant]]`](#tenant). |

## `[antispam]` clamd scanner and Bayesian thresholds

| Key | Type | Default | Meaning |
|---|---|---|---|
| `clamd_socket` | path | unset | Unix socket for clamd, for example `/run/clamav/clamd.sock` on a shared volume. Setting it enables scanning of unauthenticated inbound mail, and of what local accounts submit (see `scan_authenticated`). Cannot be combined with the top-level `scanner_hook_url`: only one scanner per server. |
| `clamd_on_found` | `quarantine` or `reject` | `quarantine` | Quarantine a detected message in the Rejects mailbox, or reject it during SMTP delivery. Other values are invalid. |
| `clamd_on_error` | `accept` or `defer` | `accept` | What a scan clamd could not run does. `accept` lets the message through unscanned; `defer` answers `451 4.7.1 content scan unavailable, try again later`, inbound and on submission, so the sender retries and nothing passes unscanned. A message clamd can never take (see `clamd_max_bytes`) is refused for good with `552 5.3.4`, not retried. `epistle init` writes `defer` into a new configuration with clamd; an existing configuration without the key keeps `accept`. |
| `clamd_timeout_secs` | integer | `30` | Deadline in seconds for the entire connection, write, and reply exchange. |
| `clamd_max_bytes` | integer | `26279936` (25 MiB + 64 KiB) | Messages above this size are not sent to clamd. With `clamd_on_error = "accept"` they are accepted unscanned; with `defer` they are refused with `552 5.3.4 message too large for the content scan`. The size counts the trace and authentication headers the server adds, so `defer` requires at least `max_message_size` + 64 KiB (the configuration is refused otherwise). A message exactly at the limit is scanned. |
| `scan_authenticated` | boolean | `true` | Also scan what this server's own accounts send: SMTP submission after AUTH, `/api/v1/send` and JMAP `EmailSubmission/set`, to local and remote recipients alike. A detection is always refused, whatever `clamd_on_found` says. Only the antivirus runs on that mail, never the Bayesian filter, reputation, DNSBL or greylisting. Has an effect only with `clamd_socket` set. |
| `bayes_junk_at` | float in `[0.0, 1.0]` | `0.95` | Score at or above which an unauthenticated message is delivered to the recipient's Junk mailbox with `X-Spam-Status: Yes` and the score in `X-Spam-Score`. Authenticated mail is never scored this way. A corpus below `MIN_TRUSTED_MESSAGES` (200) ham AND spam does not decide anything: a threshold acts only on a trained corpus: the account's own, or the shared one for an account with too little of its own, an alias or a list. |
| `bayes_reject_at` | float in `[0.0, 1.0]` | unset | Score at or above which an unauthenticated message is refused during DATA with `550 5.7.1 message rejected as spam`. Absent disables the rejection path (default). When set, must be at least `bayes_junk_at` so the rejected band is a subset of the junked one. |

```toml
[antispam]
clamd_socket = "/run/clamav/clamd.sock"
clamd_on_found = "quarantine"
clamd_timeout_secs = 30
clamd_max_bytes = 26279936
```

Epistle sends the raw message using clamd's
[INSTREAM protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html).
It decompresses nothing locally. Set `MaxScanSize` and `MaxRecursion` in
`clamd.conf` to bound decompression, and enable `AlertExceedsMax yes` so
exceeding those limits yields a detection handled by `clamd_on_found`.
Set `StreamMaxLength` at least as high as `clamd_max_bytes`; when clamd
answers `INSTREAM size limit exceeded. ERROR` the message is treated as too
large, like one over `clamd_max_bytes`, because every retry gets the same answer.
See the [clamd configuration reference](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamd.conf.5.in).

Scanner errors, missing sockets, malformed replies, and timeouts increment
`scanner_clamd_failed`, and the message follows `clamd_on_error`: accepted
unscanned with `accept`, refused for now with `451 4.7.1` with `defer`. A
message too large for clamd (over `clamd_max_bytes`, or answered with
`INSTREAM size limit exceeded. ERROR`) increments `scanner_clamd_skipped`
instead and is never deferred, since a retry would be just as large: it is
accepted unscanned with `accept`, and refused for good with `552 5.3.4` with
`defer`, which is what keeps "nothing passes unscanned" true. The Prometheus names are
`mail_scanner_clamd_failed_total` and `mail_scanner_clamd_skipped_total`.
Failure warnings are limited to one per minute per hook; detections log the
signature and message size without message content.

With `scan_authenticated` on, a message an account submits is scanned before
it is routed. A detection refuses it: `554 5.7.1 message rejected: virus
detected (<signature>)` on SMTP, `422` with the code `virus_detected` on
`/api/v1/send`, and a `forbiddenToSend` SetError with the same text as its
`description` on JMAP. Nothing is stored or queued. The server logs the
account's pseudonym and the signature, counts it in `outbound_virus`
(`mail_outbound_virus_total`), and fires the `outbound_virus` webhook event,
because an account sending malware is usually a compromised one. A clamd
that cannot be reached follows `clamd_on_error` here too: with `defer` the
submission gets `451 4.7.1` on SMTP and `503` with the code
`scan_unavailable` on `/api/v1/send`.

Every scan that fails is also recorded in `<data_dir>/clamd-health.json`,
and the first one that works again closes the record. `epistle status` reads
it: while scans keep failing, the antivirus area warns with how many failed,
since when, and whether that mail was accepted unscanned or deferred, even
if clamd answers `PING` at that moment.

## `[attachments]` attachment policy

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `off`, `flag`, `quarantine` or `reject` | `flag` (`epistle init` writes `quarantine`) | What a disguised or dangerous attachment does: a warning header, the Rejects mailbox, or `550 5.7.1` during SMTP. |
| `macros` | `allow`, `flag` or `quarantine` | `flag` (`init`: `quarantine`) | Office documents with VBA macros, never above `mode`. |
| `encrypted_archives` | `allow`, `flag` or `quarantine` | `flag` | Archives no scanner can read, never above `mode`. |
| `block_extensions` | list | empty | Extensions treated as dangerous on top of the built-in list. |
| `allow_extensions` | list | empty | Extensions taken off the dangerous list, for names only. The always-dangerous ones are refused. |

What each finding means, what `allow_extensions` can and cannot do, and the
residual risks are in [attachments.md](attachments.md).

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
| `acme` | 80 | ACME HTTP-01 challenge responder. Needed only with `[acme] challenge = "http-01"` (the default). |
| `autoconfig` | 8091 | Serves Thunderbird autoconfig + Microsoft Autodiscover. Point `autoconfig.<domain>`/`autodiscover.<domain>` here (behind your TLS proxy). |

| `acme` | 80 | ACME HTTP-01 challenge responder. |
| `autoconfig` | 8091 | Serves Thunderbird autoconfig, Microsoft Autodiscover and the Apple profile (`/mobileconfig?email=`) over plain HTTP, for a deployment that keeps its own TLS proxy. |
| `autoconfigs` | 443 | The same documents over HTTPS with the server certificate, so `autoconfig.<domain>`/`autodiscover.<domain>` need no proxy. Requires `[tls]`; the certificate (or `[acme] domains`) must cover both names. |
| `web-dav` | 8090 | WebDAV (RFC 4918) files + CardDAV (RFC 6352) addressbooks + CalDAV (RFC 4791) calendars. HTTP Basic auth as the mail account; each account is confined to its own tree. Run behind a TLS proxy. |

Plaintext listeners (`submission` 587, `web-dav` 8090, `api` 8025, `autoconfig` 8091, `metrics` 9090) are accepted without a `[tls]` block ONLY when bound to a loopback address. When `addr = 0.0.0.0` (or any non-loopback address) and `[tls]` is unset, a warning is emitted at validate time. Hardening follows in the next release: an opt-in `allow_insecure_no_tls` flag, then a hard rejection when the flag is absent.

`[tls]` does not encrypt `api`, `web-dav` or `autoconfig`: those three carry plain HTTP and the mail certificate is not offered on them. Configuring `[tls]` leaves them in plaintext, so the way to expose them is a TLS reverse proxy in front of a loopback listener, which is where I keep them. `epistle service enable` gives them loopback for that reason, on a host install as much as on the container stack, `epistle service set <name> --bind <address>` refuses any address outside loopback, and the generated compose map publishes them on `127.0.0.1` even when nothing narrowed it explicitly.

### A listener on a private interface

`addr` is resolved in the network namespace `serve` runs in. On the
container stack that is the container's namespace, so `addr = "10.0.0.1"` (a
WireGuard address of the host, say) names an address the container does not
own: the bind fails with `EADDRNOTAVAIL` and `serve` stops starting. Only `::`
gets a fallback to another address, and it does not need one.

What keeps a listener off the public interfaces is the **published port** on
the host, and a private `addr` does not do it. `epistle init` publishes every
non-loopback listener as `<port>:<port>` and gives a loopback listener no
`ports:` entry at all. The three listeners with no TLS transport are the
exception: the map publishes them on `127.0.0.1` unless it names another
address, so `api` arrives as `127.0.0.1:8025:8025` and not as `8025:8025` on
every host address.

An install that still carries an older map has those three published wide, and
the next command that writes the map takes them off every address of the host:
`epistle service enable`, `epistle service disable`, `epistle service set`, an
`epistle init` rerun and `epistle stack update` all re-render it, so an upgrade
can be what cuts a service off. The command that does it names the service and
the port on stderr, or in the `init` report, so the loss of reachability is
never silent. That is deliberate: a listener with no TLS transport reachable
from the internet is one more thing to expose, and the way to expose it is
`compose.override.yaml` as below, behind a TLS reverse proxy. A concrete
address the map already names, such as `10.0.0.1:8025:8025`, is left alone: the
rule is about a wildcard, not about a decision. Set the listener to `addr = "0.0.0.0"` (the container
side) and pin the host side in `<data_dir>/compose/compose.override.yaml`,
which survives both an `init` rerun and `stack update`. A plain `ports:` list
there is **merged** with the one `init` writes, so `8025:8025` and
`10.0.0.1:8025:8025` would both be requested and the engine fails with
"Address already in use". The `!override` tag replaces the list, so it has to
carry every port the stack publishes, the mail ones included:

```yaml
services:
  mail:
    ports: !override
      - "25:25"
      - "143:143"
      - "465:465"
      - "587:587"
      - "993:993"
      - "10.0.0.1:8025:8025"
```

After this the API answers on `10.0.0.1:8025` and nowhere else. `epistle stack
update` and `epistle probe` check the API on the loopback of the host, so they
report `5 of 6 listeners answer` even though the stack is running as intended.

Keys meant for that listener should carry `--ip-cidr` and `--expires-at`, and
each key should hold only the scopes its program uses. `--ip-cidr` is matched
against the address the server sees on the socket, so a `mail` service that is
not on `network_mode: "pasta"` (a bridge, and rootless Podman on a bridge
funnels every connection through `rootlessport`) filters on the container's
address instead of the client's. `epistle api-key create`, `epistle api-key
list` and `epistle status` say so when they see it.
[Exposing the API on a private interface](api.md#exposing-the-api-on-a-private-interface)
has the whole case.

### Public-install firewall

A public install has to let inbound TCP through the host firewall (or fronting load balancer) on every port a real client has to reach. The defaults `init` ships on a public hostname:

| Port | Protocol | Required for |
|---|---|---|
| 25 | SMTP | Inbound mail from other servers. |
| 80 | HTTP | Certificate issuance with `[acme] challenge = "http-01"` (the default): the HTTP-01 challenge responder (`acme` listener). Open to the public internet, the CA connects from outside. Not needed with `tls-alpn-01` or `dns-01`. |
| 143 | IMAP+STARTTLS | Mail clients that negotiate TLS on connect. |
| 465 | Submissions | Mail clients that use implicit TLS for submission. |
| 587 | Submission+STARTTLS | Mail clients that submit with STARTTLS. |
| 993 | IMAPS | Mail clients that use implicit TLS for IMAP. |

Optional ports the operator turns on per `[[listeners]]`: `995` (POP3S) when `services.pop3 = true`, `4190` (ManageSieve) when `services.managesieve = true`, `8090` (WebDAV) when `services.webdav = true`, `8025` (loopback management API) when `services.api = true`, `443` (`autoconfigs`) when the operator wants Thunderbird/Outlook/Apple autodiscovery over HTTPS (or `8091`, `autoconfig`, behind a TLS proxy).

With the default `http-01` challenge, port 80 has to be open even when no certificate renewal is in flight: the first certificate and every renewal are validated through the same responder, so closing it means the first certificate never lands. Port 80 is needed only with `http-01`. With `tls-alpn-01` the CA connects to port 443 instead, and with `dns-01` it connects to nothing on this host (see [`[acme]`](#acme)).

## Sections

### `[mta_sts]`

Configure the policy published for this server's own mail domains:

```toml
[mta_sts]
policy_dir = "/var/lib/epistle/mta-sts"
mode = "testing"
max_age = 604800
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `policy_dir` | path | unset | Directory where `serve` writes `mta-sts.txt` at startup. Unset disables writing. |
| `mode` | `testing`, `enforce`, or `none` | `testing` | Enforcement mode announced to sending mail servers. |
| `max_age` | unsigned integer | `604800` | Policy cache lifetime in seconds. |

The file contains `version: STSv1`, the selected mode, an `mx:` line naming
the configured `hostname` (the same host used in DNS MX records), and
`max_age`. All configured domains share this policy. Startup creates the
directory if needed and replaces the file atomically with permissions 0644.
A write failure aborts startup.

The `_mta-sts` TXT record printed by `epistle dns-records --config FILE` uses
a content hash for its `id=` value. Identical policy contents keep the same ID;
changing the mode, hostname, or cache lifetime changes it. Restart `serve`
after changing these settings and publish the regenerated DNS records.

Run [`epistle mta-sts-serve`](cli.md#epistle-mta-sts-serve) with the same policy
directory and make it reachable at
`https://mta-sts.<domain>/.well-known/mta-sts.txt` on port 443. Its default
bind address is `0.0.0.0:8443`. The HTTPS certificate must cover
`mta-sts.<domain>` for each domain, even when the CNAME points to the mail
hostname. Supply that certificate and its private key with `--cert` and `--key`.

### `[tls]`
TLS material, shared by all transports. Required by `submissions`/`imap`/`imaps`/`manage-sieve`; enables STARTTLS on `smtp`/`submission`.

Without `[acme]` the pair is yours to renew (certbot, a Cloudflare origin certificate, one you made). The server looks at both files every minute and, when either changed, loads the new pair, checks that every certificate of the chain parses and that the key belongs to the certificate, and only then puts it in service on every listener: SMTP, submission, IMAP, POP3, ManageSieve, the HTTPS API and autoconfig, and DAV. Open connections keep the certificate they started with; no restart is needed. A pair that does not load (half written, a key from another certificate, a broken chain) is logged once and the certificate in service stays until the files form a valid pair. SCRAM-SHA-256-PLUS follows the new certificate. Replace the files by writing them beside and renaming them over the old ones when you can; the server retries a pair it caught mid-write as soon as the files change again.

The DANE TLSA record (`_25._tcp.<hostname>`, `3 0 1 <sha256 of the certificate>`) changes with the certificate. When a `[dns]` provider is configured, the server publishes the new record through it, as ACME renewal does. Without one, or when the provider refuses, it logs a warning with the record to publish by hand. `epistle status` fails the `tls` check while a DNSSEC-signed TLSA record does not match the certificate in use, and warns when the certificate expires within 14 days and nothing renews it. With `[acme]`, ACME renews and reloads its own pair and the files are not watched.

| Key | Meaning |
|---|---|
| `cert_file` | PEM certificate chain. |
| `key_file` | PEM private key. |
| `client_ca` | PEM trust anchor for verifying TLS **client** certificates. When set, a client may authenticate with a certificate via SASL `EXTERNAL` (the account comes from the certificate's verified email SAN); clients without one fall back to password auth. Absent disables client-certificate auth. Requires a static certificate (not available under ACME, like SCRAM-SHA-256-PLUS). |

### `[dkim]`
Outbound DKIM signing. Ed25519 is primary; an RSA selector is also required from version 0.10 on so receivers that verify RSA alone still see a valid signature. Until then the server warns at startup and on `epistle config-check` / `epistle verify-dns` when the RSA pair is missing; the warning names `epistle dkim-keygen --rsa` as the remedy.

Key rotation is **automatic and always on** when a `[dns]` provider is configured: the server rotates the signing key every **90 days** and keeps the previous selector's TXT published for a **14-day overlap** so in-flight mail still verifies. A new key starts signing only after the system resolver shows its TXT record, with that key, for every signing domain; the server checks for about an hour, and if the record never shows it withdraws the new selector, keeps signing with the current key, and reports it in `epistle dkim show`, the log and the `dkim_rotation_failed` webhook event. The interval is a property of the server, not a per-deployment preference, and is fixed in code (aligned with the 90-day TLS certificate cycle). When `[dns]` is absent, rotation cannot publish the new selector's TXT and is therefore inactive; a notice is logged once at startup.

A rotation survives a crash or a kill at any step. It is written to `<data_dir>/dkim-rotation.json` as `pending` before its key exists, and the next tick (or start) either finishes it, reusing the key already written, or withdraws its TXT records and key file; the current key signs until the new one is committed. `epistle dkim show` lists a rotation in progress. Every save of the state is synced to disk and keeps the state it replaces as `dkim-rotation.json.bak`. If the state cannot be read, the server signs with the key the `.bak` names (its TXT is still published), logs a warning, `epistle status` reports it, and rotation stays stopped until the file is restored, for example by copying the `.bak` over it. Key files and TXT records that no rotation names, left by crashes in older releases, are logged when the rotation task starts and removed only through `epistle dkim cleanup`.

With `rsa_selector` and `rsa_key_file` set (dual signing), each rotation also replaces the RSA key: a new 2048-bit key (made with `openssl genpkey`, as `epistle dkim-keygen --rsa` does) under its own selector `rsa<day>`, written to `<data_dir>/dkim-rsa<day>.key`. Both keys are journaled in the same `pending` entry, published and confirmed in every signing domain, and switch together in the one save that commits the rotation, so the server never signs with one new key and one that receivers cannot look up yet. If either key cannot be made, published or seen in DNS, the whole rotation is withdrawn and both current keys keep signing. The RSA key a rotation replaces stays published for the same 14-day overlap and is then retired with the previous ed25519 selector. The first rotation replaces the configured RSA key, whose file and TXT record are left in place, the same as the configured ed25519 key; `dkim-rotation.json` names the RSA key in service from then on, and a state file written by an older release, without RSA entries, still loads. Turning dual signing off withdraws a rotation in progress that covered RSA, and the next rotation retires the RSA key the state named. There is no command to go back to an earlier key once a rotation is committed.

| Key | Meaning |
|---|---|
| `selector` | Ed25519 selector (the `s=` tag). |
| `key_file` | Ed25519 private key (PKCS#8 PEM); generate with `epistle dkim-keygen`. |
| `rsa_selector` | RSA selector. Required from the version above; a startup warning is logged before that whenever the field is absent. |
| `rsa_key_file` | RSA private key paired with `rsa_selector`. Required from the version above. Generate with `epistle dkim-keygen --rsa`. Automatic rotation replaces this key under an `rsa<day>` selector (see above); the configured pair is used until the first rotation. |
| `rotate_days` | **Deprecated.** Ignored. Kept so existing configs keep parsing; a one-shot warning is logged at startup when present. Will be removed in a future release. |
| `rotate_overlap_days` | **Deprecated.** Ignored. Same backward-compatibility note as `rotate_days`. |

#### `[[dkim.domain]]`
Optional per-domain keys. A domain listed here signs with its own key instead of the `[dkim]` default, so one domain's key can be replaced, or kept from another server, without touching the others; every other domain keeps the default. The signer picks the key of the signature's `d=` domain and never another domain's. `epistle dns-records`, `verify-dns`, `status` and `dkim show` show each domain's own selector and record.

```toml
[dkim]
selector = "mail"
key_file = "/etc/glyndor/epistle/dkim/mail.pem"

[[dkim.domain]]
name = "example.net"
selector = "net2024"
key_file = "/etc/glyndor/epistle/dkim/example.net.pem"
rsa_selector = "net2024r"
rsa_key_file = "/etc/glyndor/epistle/dkim/example.net.rsa.pem"
```

| Key | Meaning |
|---|---|
| `name` | A domain in `domains` or `domain_aliases`, compared without regard to case. Listing a domain the server does not host, or the same domain twice, is a configuration error. |
| `selector`, `key_file` | Ed25519 selector and key, as in `[dkim]`. |
| `rsa_selector`, `rsa_key_file` | Optional RSA pair, set together, as in `[dkim]`. |

The keys are read when the server starts, like the default key: an unreadable or invalid file stops the start, and a changed key or a new entry takes effect after a restart. Per-domain keys are **not rotated**. Automatic rotation covers the `[dkim]` default only, and it neither publishes nor retires records of a domain listed here, so a listed domain outside the `[dns]` zone does not stop it. To replace a per-domain key, generate one (`epistle dkim-keygen`), publish its record under a new selector, point the entry at it and restart; `epistle dkim rotate --domain <name>` refuses and says the same. `epistle dkim cleanup` never offers a listed key or its record for removal.

### `[api]`
Management API (consumed by `epistle-panel`). Closed by default.

| Key | Meaning |
|---|---|
| `token_hash` | `sha256:<hex>` (from `epistle token-hash`) or an argon2id PHC string. |
| `trusted_proxies` | Optional CIDR list for trusted reverse proxies. Default `[]`. See below. |
| `admins` | Optional list of account names allowed to authenticate to the admin panel (via `POST /api/v1/auth/verify`). Empty (default) means no account can administer the panel. |

`trusted_proxies` is an optional list of IPv4 and IPv6 CIDR networks, empty by
default. Invalid CIDRs stop configuration loading. For example:

```toml
[api]
token_hash = "${API_TOKEN_HASH}"
trusted_proxies = ["192.0.2.10/32", "2001:db8:100::/48"]
```

Trust only the addresses of reverse proxies under your control. The proxy must
append the address it connected from to `X-Forwarded-For`, or replace the header
with the actual client address. When the TCP peer is trusted, Epistle validates
the whole header and scans its addresses from right to left, taking the first
address outside `trusted_proxies`. A missing or malformed header, or a chain
containing only trusted addresses, uses the TCP peer. An untrusted peer's header
is ignored. IPv4-mapped IPv6 client addresses are canonicalized to IPv4.

A universal prefix (`0.0.0.0/0` or `::/0`) is refused at load time: a `/0`
tricks the server into treating every direct peer as a trusted proxy, so a peer
that sets its own `X-Forwarded-For` would pick the address the server uses for
limits, audit and credential IP checks. Duplicates are dropped, and the list is
capped at 1024 entries to bound the cost of the linear lookup on every
forwarded address.

This address is used for API authentication limits, credential IP restrictions,
audit events, OAuth password bans and device grant counters. IPv6 clients still
share their /64 budget. The default empty list preserves socket-based attribution.
Restart the server after changing `trusted_proxies`.

Authentication-window `429` responses include `Retry-After`, the remaining
seconds rounded up. OAuth `429 slow_down` responses include the wait until
blocking grants expire or the next allowed poll. Password bans retain their
ordinary authentication failure response.

### Domain-confined API keys (multi-tenancy)

A key in `api_keys.toml` may carry a `domains` list, on top of its scopes:

```toml
[[keys]]
label = "tenant-a"
hash = "sha256:..."
scopes = ["read", "write"]
domains = ["a.example"]
```

Create one with `epistle api-key-create --domain a.example` (repeat the
flag for more). The key then sees only those domains in `GET /domains`,
only the accounts that live entirely inside them in `GET /accounts`, and
is refused on any account or address outside them.

Absent or empty, `domains` means every configured domain — which is what
every key did before the field existed, so an upgrade never narrows a key
that is already deployed. The configured `token` is never confined.

Two rules are worth knowing before you rely on this:

- An account holding an address in two domains belongs to both tenants and
  is therefore out of scope for a key confined to either one. Deleting it,
  or resetting its password, would reach a domain the key was not given.
- A refusal answers `404`, not `403`. A key confined to one tenant must not
  be able to enumerate another tenant's account names by reading the status
  code, so an account it may not touch looks exactly like one that does not
  exist.

SCIM obeys the same confinement. A key with `scim` and `domains` lists, reads,
creates, replaces, patches (including `active` and `password`) and deletes only
the accounts that sit entirely inside its domains. An account outside them
answers `404` on every `/scim/v2/Users` route, and a `POST` or `PUT` that names
an address outside them is refused with `400`. A `userName` that is malformed or already held by an account outside the key's domains answers the same `400` (`userName is not available`), so a tenant cannot probe the other tenants' names; a name held inside its own domains still answers `409`. Moving an account to a domain of another tenant at its `max_accounts` cap answers `409`. Before 0.12.2 SCIM ignored
`domains`, so a key meant for one tenant reached all of them: if you issued
`scim` keys with `--domain`, rotate them and review the accounts they changed.

A confined key holds to the same rule on every route that has per-tenant
data, not only on the accounts routes:

| Route | For a key confined to some domains |
|---|---|
| `GET /api/v1/status` | `domains` and `accounts` count only what the key covers; `queue_size` is left out because the queue is shared |
| `GET /api/v1/queue`, `DELETE /api/v1/queue/{id}` | only entries whose sender is in the key's domains; an entry with an empty sender (a bounce) is for unconfined keys; any other entry answers `404` |
| `GET /api/v1/suppression`, `DELETE /api/v1/suppression/{address}` | the shared list answers `403`; `?account=` works for an account the key covers and answers `404` for any other |
| `/api/v1/accounts/{name}/masked`, `.../archive` | `404` unless the account is covered, unknown accounts included |
| `POST /api/v1/auth/verify` | checks only the passwords of covered accounts; any other login answers `valid: false` without the password being tried |
| `POST /api/v1/accounts`, `POST /scim/v2/Users` | a name that is malformed or held outside the key's domains gives the same `400`, so the answer does not reveal other tenants' names |

Before 0.12.2 these routes ignored the key's domains. If you handed out keys
with `domains`, treat them as having had access to the whole server and rotate
them. `src/api/route_rules_tests.rs` lists every route with the rule it
follows, and fails when a route is added without one.

### What each key scope reaches

Scopes are independent: holding one does not grant another.

- `read`: the JMAP Session, every JMAP method that returns account data
  (`*/get`, `*/query`, `*/changes`, `*/queryChanges`, `Identity/get`,
  `Quota/get`, `SieveScript/validate`), downloads, the WebSocket and the event source, and the
  `GET` routes of the management API.
- `write`: JMAP `*/set` and `Email/copy`, uploads, and the mutating routes
  of the management API.
- `send`: JMAP `EmailSubmission/set` and `POST /api/v1/send`.
- `scim`: `/scim/v2`.

A key that only sends or only writes therefore cannot read the mailbox; give
it `read` too if the client needs to.

### `POST /api/v1/send`

Mail sent here takes the same path as SMTP submission: DKIM-signed for the
sender's domain, delivered at once to local recipients, queued for the rest.
The response's `queued` id names the queue entry.

| Field | Meaning |
|---|---|
| `from`, `from_name`, `to`, `cc`, `bcc`, `reply_to`, `sender`, `subject` | Addresses and subject. `bcc` is envelope only. `sender` must be an address the account owns, like `from`. |
| `text`, `html` | Bodies; both make a `multipart/alternative`, text first. |
| `attachments`, `inline` | `[{name, content_type, data, content_id}]`, `data` in base64. An empty `content_type` is detected. `inline` parts need `content_id` and go into `multipart/related` with the HTML. An attached `message/rfc822` is written unencoded with CRLF line ends. |
| `in_reply_to`, `references` | `<id@domain>` message ids, space separated. |
| `importance` (or `priority`) | `high`, `normal` or `low`: writes `Importance` and `X-Priority`. |
| `list_unsubscribe`, `list_unsubscribe_post` | `mailto:` and `https://` URLs; `true` adds the RFC 8058 one-click header (needs an `https://` URL). |
| `auto_submitted`, `feedback_id` | `Auto-Submitted` (RFC 3834 values) and `Feedback-ID`. |
| `headers` | Custom headers, `X-` names only. |

A control character in any of these is refused with `400`. A message over
25 MiB once encoded is refused with `413 message_too_large`.

### JMAP `Email/set` create

A new Email is built from `textBody`, `htmlBody` and `attachments` (inline
parts with a `cid` go beside the HTML in `multipart/related`), or from an
explicit `bodyStructure`, with the same MIME builder as `/api/v1/send`. Text
comes from `bodyValues` by `partId`; octets by `blobId`, from an upload or
from a stored message or one of its parts. `bcc` is kept on the stored
draft only: `EmailSubmission/set`, like SMTP submission, removes the Bcc
header before sending and keeps those recipients on the envelope.
`Content-*` headers on the Email
itself, `bodyStructure` together with the body lists, more than one part in
`textBody` or `htmlBody`, or a part with both or neither of `partId` and
`blobId` are refused with `invalidProperties`; a message over 25 MiB with
`tooLarge`. The Session's `maxSizeAttachmentsPerEmail` is the attachment
size that still fits 25 MiB once base64-encoded (about 18 MB).

### Uploaded blob storage

JMAP uploads live under `<data_dir>/blobs/`, sharded two levels deep by the
**last** four characters of the blob id: `blobs/ab/cd/<id>`, with the `.type`
and `.owner` sidecars beside the payload.

The shard comes from the end of the id rather than the start because blob ids
are UUIDv7, whose first 48 bits are a timestamp — every blob written in the
same era shares its leading characters, so sharding on them would file almost
everything into one bucket while looking sharded.

There is no migration. A blob written by an older version stays where it is
and is still read, still counted against quota, and still reclaimed; only new
blobs are written into the shards. Nothing needs to be moved and nothing needs
configuring.

### IMAP COMPRESS=DEFLATE

Advertised in `CAPABILITY` and enabled per connection by `COMPRESS DEFLATE`
(RFC 4978). There is nothing to configure: a client that asks gets a deflate
stream in both directions for the rest of the connection, and one that does
not is unaffected.

The compression context is kept for the whole connection rather than reset
per message, which is where the saving comes from — IMAP repeats the same
command names, flag names and header keys endlessly. The tagged `OK` for the
command itself travels uncompressed, as the RFC requires. A second `COMPRESS`
on the same connection answers `NO [COMPRESSIONACTIVE]`: restarting the
context underneath a client that is already decoding would desynchronise it.

### IMAP mailbox names and folders

Folders nest. The hierarchy delimiter is `/`, so `Work/Project` is the
folder `Project` inside `Work`, and `INBOX/Receipts` lives under the inbox.
Each level is ASCII letters, digits, space, `-`, `_` and `.`, plus any
non-ASCII character (clients without UTF-8 send it in modified UTF-7, RFC
3501 §5.1.3). A level cannot be empty, start with `.` or end with a space.
A name has at most 16 levels and 128 bytes per level, and at most 255 bytes
on disk.

| Command | Behaviour |
|---|---|
| `CREATE a/b/c` | Also creates `a` and `a/b` when they are missing. A trailing `/` is dropped. |
| `DELETE a` | Refused with `NO [HASCHILDREN]` while `a` has folders under it; delete those first. |
| `RENAME a x/y` | Moves `a` and every folder under it to `x/y`, creating `x`. A folder cannot move under itself. |
| `LIST` / `LSUB` | `%` stops at one level. `\HasChildren`/`\HasNoChildren` come from the folders that exist. A missing level with folders under it is returned `\Noselect \HasChildren` where `%` stops at it (`\NonExistent` under LIST-EXTENDED), and LSUB returns an unsubscribed level above a subscribed folder as `\Noselect`. LIST-EXTENDED takes several patterns and `SUBSCRIBED`, `REMOTE` and `RECURSIVEMATCH` (with `CHILDINFO`). |

Every folder is one directory under `<data_dir>/accounts/<name>/folders/`
whatever its depth: the name with each `/` written as `&AC8-` (the modified
UTF-7 spelling of `/`), so `Work/Project` is `folders/Work&AC8-Project/`.
A folder name can never contain `&AC8-` itself, so each directory maps back
to exactly one name, and folders created before nesting existed need no
migration. JMAP shows the same tree through `parentId`, as does the `tree`
of `GET /api/v1/accounts/{name}/mailboxes`; Sieve `fileinto` and routing
rules accept nested names, and `epistle export --maildir` writes
`Work/Project` as the Maildir++ folder `.Work.Project` (an import reads a
`.` in a Maildir++ folder name as a level).

### IMAP keywords

`SELECT` advertises the system flags (`\Seen`, `\Answered`, `\Flagged`,
`\Deleted`, `\Draft`) plus every user keyword currently in use in the
mailbox, and `PERMANENTFLAGS` carries the same plus `\*` so STORE may
introduce new keywords. The keywords per message are persisted on the
sidecar next to the message body, and round-trip through FETCH, SEARCH
and STORE without change.

`SEARCH KEYWORD <atom>` and `SEARCH UNKEYWORD <atom>` match by atom,
case-insensitively (RFC 9051 §2.3.2). A keyword is an atom: no
leading `\`, no `(` `)` `{` `%` `*` `"` `]` `\`, no spaces, no
control bytes, at most 64 bytes. A message carries at most 32
keywords; STORE and APPEND reject more with `BAD` so the sidecar
stays bounded.

Reserved keywords the server keeps constants for are `$Junk`,
`$NotJunk`, `$Forwarded`, `$Phishing`, and `$Important`. Clients
can use any other valid atom too. `$Junk` is the spam signal:
IMAP STORE that crosses the `$Junk` boundary trains the
account's Bayesian scope (see below).

### JMAP keyword round-trip

JMAP `Email/set` accepts any `$keyword` value on a `keywords` patch;
the four fixed JMAP keywords (`$seen`, `$answered`, `$flagged`,
`$draft`) map to their IMAP system flags, and every other `$atom`
is preserved as a `Flag::Keyword`. `Email/get` renders the keyword
list back through the same mapping, so a custom `$keyword` set on
a message round-trips through set+get without loss. `\Deleted` is
intentionally not exposed on the JMAP side (RFC 8621 §4.1.1: J
MAP has a separate `isDeleted` boolean).

### JMAP incremental sync

`Email/changes`, `Mailbox/changes`, `Thread/changes` (RFC 8620 §5.2) and
`Email/queryChanges`, `Mailbox/queryChanges` (§5.6) answer from a
per-account change journal that IMAP, POP3, SMTP delivery and JMAP all
write, so a flag set over IMAP shows up in `Email/changes`. The journal
lives at `<data_dir>/accounts/<name>/.jmap_changes` (with `.jmap_state`
and `.jmap_lock`); it is trimmed to its newer half past 1 MiB.

- `maxChanges` pages end on an intermediate `newState` with
  `hasMoreChanges: true`; following them loses nothing.
- `Mailbox/changes` sets `updatedProperties` to the four count
  properties when only counts moved. A rename is the old id destroyed
  and the new one created (a mailbox id is its name).
- `Email/queryChanges` covers `Email/query` with no filter or only
  `inMailbox`, sorted newest first (no sort or `receivedAt`
  descending); `Email/query` reports `canCalculateChanges: false` for
  anything else. `Mailbox/queryChanges` covers every `Mailbox/query`.
- `cannotCalculateChanges` answers a malformed state, a state of another
  type or account, one older than the trimmed journal, and one ahead of
  it. `epistle restore` never brings back the journal header
  (`.jmap_state`), so after a restore every JMAP client resyncs once
  instead of trusting positions the restore rewound.
- Push over an event source (RFC 8620 §7.3) is served at
  `/jmap/eventsource?types=..&closeafter=..&ping=..`. It reads the same
  journal once a second for every account the key reaches, sends a
  `state` event when one moved and a `ping` (1 to 300 seconds) when idle,
  and ends once the key or its account stops being valid. No event ids
  are sent; a reconnecting client catches up with `/changes`. One
  credential holds at most 4 streams open at once; the next answers 429
  with the JMAP `limit` error.

### `/scim/v2` (SCIM 2.0 provisioning)
Mounted under `/scim/v2` when the management API listener is enabled.
Authenticates against the same bearer token plus the labeled keys in
`api_keys.toml`, but requires the dedicated `Scim` scope: a `read`- or
`write`-only key cannot enumerate or mutate users here, so an IdP
integration can be scoped tighter than the operator's own panel access.

The implementation is the minimum that Entra ID, Okta and Keycloak
actually use: `ServiceProviderConfig`, `Schemas`, `ResourceTypes` for
discovery; full `Users` lifecycle (list with `userName eq "x"` filter,
create, read, replace, patch, delete). `Groups` returns `501` — the
directory has no group membership yet, so provisioning groups would be
a no-op pretending to be a feature.

`GET /Users` reports `totalResults` for all resources matching the filter
within the caller's domain scope, independent of pagination. `startIndex` is
1-based, and `itemsPerPage` is the number of resources returned in that page.
Use `count=0` to return the total without resources.

`active: false` is honoured: the account stays on disk and keeps its
mailboxes, but `authenticate` rejects every password before any
hashing. `PUT` and `PATCH` refuse to change `userName` (renames are
not supported — the account name is the directory primary key).
`PATCH` accepts only `replace` of `active` and `password`. Every
response carries `Content-Type: application/scim+json`; errors follow
RFC 7644 §3.7 (`{ schemas: [Error URN], status, detail }`).

A key confined to domains (`api-key create --domain`) sees and changes only
the accounts inside them (see [Domain-confined API keys](#domain-confined-api-keys-multi-tenancy)),
and `POST /Users` honours a tenant's `max_accounts` cap with `409`, as
`POST /api/v1/accounts` does.

### `[database]`
PostgreSQL backing for the antispam engine (reputation, Bayes). The server
refuses to start against a PostgreSQL major older than 18 (the major the
stack `epistle init` writes runs); `serve` reads `SHOW server_version_num`
after the pool is built and aborts with a `ServerTooOld` error before any
migration runs, so a server below the floor fails as a sentence at startup
rather than as an SQL syntax error in the first query.

| Key | Meaning |
|---|---|
| `url` | Connection URL. Must be `sslmode=require` (or `verify-ca` / `verify-full`); an absent or weaker `sslmode` is rejected. A Unix-domain socket URL (`postgres://%2Fpath/...` or `postgres:///db?host=/path`) is accepted as is because there is no network on the path to intercept. Omit the password when `password_file` is set; sqlx rejects the empty-host form `postgres://user@/db?host=...`. |
| `password_file` | Path to a file holding the PostgreSQL password. Read once at pool construction; one trailing newline is stripped (and a preceding carriage return, the form a Windows editor would leave). The file must exist, be a regular file, and not be group- or world-accessible (`mode & 0o077 == 0`, the rule `Config::load` applies to the config file itself; `0400` and `0600` both pass). Refused when the URL also carries a password (two sources for one secret is ambiguous). Use this when the secret cannot live in the config file: the recommended container deployment mounts the password as a read-only podup secret at a known path. |
| `max_connections` | Pool size. |
| `tls` | How the connection authenticates the PostgreSQL server. Defaults to `require`, which rejects any `sslmode` weaker than `require`. Set to `insecure` to assert that the connection stays on a network you trust (typically an internal container network with no gateway to the outside); an `insecure` connection is the operator's responsibility. |
| `directory` | Resolve mail accounts from the SQL directory tables (off by default). |

Example: a Unix-socket deployment with the password held outside the config file.

```toml
[database]
url = "postgres://epistle@%2Frun%2Fpostgresql/epistle"
password_file = "/run/secrets/epistle_db_password"
```

The percent-encoded host (`%2Frun%2Fpostgresql`) is the form sqlx accepts for a
Unix-domain socket URL: every `/` in the socket directory is encoded as `%2F`.
The `host=` query-parameter form (`postgres:///db?host=/run/postgresql`) is also
accepted, with three slashes after the scheme because the authority is empty;
sqlx rejects the empty-host form `postgres://user@/db?host=...` and the URL
must use one of the two spellings above.

An unreachable database does not stop the server: the antispam engine is
disabled, mail keeps flowing unfiltered, a warning is logged and the
`database_unavailable` counter is incremented (alert on it). The exception is
`directory = true`: the accounts themselves come from SQL, so there would be
nobody to deliver to and the start fails.

The same database backs the shared authentication ban store: every
listener (SMTP submission, IMAP, POP3, ManageSieve, the API, OAuth
device and PKCE grants) records failed authentications into the
`auth_failure` table and consults the `auth_ban` table before any
password hashing. Without `[database]`, the per-connection three-strikes
counters each listener already maintains are the only defence.

### Per-account Bayesian training

The Bayesian corpus is keyed by scope. Two scopes are in play:

- The **shared** scope (`""`) is the server's own accept/reject learning.
  SMTP accept/reject decisions feed it: mail the server rejects or
  quarantines is learned as spam, mail it accepts as ham from a sender it
  verified. That mail comes from anyone, so the learning is bounded (see
  below).
- The **account** scope (the local account name) is the per-user learning.
  IMAP STORE and JMAP `Email/set` train it on a `$Junk` / `$NotJunk`
  transition. Adding `$Junk` trains spam; adding `$NotJunk` or removing
  `$Junk` trains ham. A STORE that touches neither keyword does not
  train (the equality skip in `Snapshot::store_flags` keeps the
  no-op out of the trainer).

  Moving mail teaches the same corpus. A message copied or moved into the
  account's Junk mailbox (`Junk`, `Spam` or `Rejects`, the name the server
  lists with the `\Junk` special use) trains spam. A message moved out of
  Junk into any mailbox but Trash trains ham: Junk to Trash is the user
  throwing spam away, and a copy out of Junk leaves the message in Junk, so
  neither says the message is not junk. A folder that only ends in `Junk`
  (`Archive/Junk`) has no role. IMAP COPY and MOVE and the mailbox change of
  JMAP `Email/set` all take this decision, and when an update also sets
  `$Junk` or `$NotJunk` the move is the last word. IMAP APPEND into Junk
  does not train, because a migration tool appends whole folders.

  The server records what each account has learned, one row per message in
  `bayes_learned`, keyed by a keyed hash of the first 256 KiB of the message
  (the same window and the same key file as the token hashes). That makes the
  lessons idempotent however many ways a message reaches the same verdict:
  moved into Junk, then marked `$Junk`, then copied again counts once. When
  the user decides the other way (a message goes back to the inbox), the
  earlier lesson is taken back token by token and the new verdict added, so a
  message that goes back and forth leaves the corpus where the last move put
  it. The row, the token counts and the message totals change in one
  transaction: when the record cannot be written nothing is trained, and a
  transaction PostgreSQL abandons (a deadlock) is run again up to four times.
  The locks are always taken in the same order, so the server and
  `epistle learning reset` can run at the same time. What an account taught
  before the ledger existed (through `$Junk`, or by the server's own
  decisions) is in the corpus but not in the ledger: it counts again if the
  user moves it and cannot be taken back. `epistle learning status` shows
  that number as `unrecorded`.

  Learning is bounded, per command, per account and in the worker:
  - Each IMAP COPY or MOVE, each IMAP STORE and each JMAP `Email/set` call
    queues at most 100 lessons; the rest are dropped and counted in
    `mail_bayes_training_dropped_total`. The queue to the worker holds 256,
    and one account may have 32 of those places at a time, so one account (or
    any seven) cannot take them all. Eight accounts at their share fill it
    (8 x 32 = 256): another account's lesson is then dropped, counted, and one
    that is accepted waits behind up to 256 others, which at a few hundred
    milliseconds each is about a minute. The queue is served in order, not
    account by account, so this is a limit of a deployment with many accounts
    sending at once, for instance several of one tenant.
  - One account may teach 200 lessons a minute and 5000 a day, and may keep
    the single worker busy for 10 seconds in a minute, measured from the work
    of its own lessons (reading the message and writing the corpus, every
    attempt of a lesson that fails or is retried included), not from the time
    they waited behind other jobs. Lessons over a limit are dropped and
    counted.
  - A message is read the way the SMTP path reads it: its headers and its text
    parts, decoded and in the charset they declare, without attachments, cut to
    a window of the first and the last half of 256 KiB of words. A lesson
    touches at most 5000 distinct tokens of it, the same cap and the same keyed
    sample the server's own training takes, written with two statements
    whatever their number. The worker reads the stored file whole, up to
    32 MiB, because the structure is what tells text from an attachment; a
    larger file, or one that cannot be read, teaches nothing, spends none of
    the day's tokens and gives back its place in the minute and day counts
    (`mail_bayes_learning_unreadable_total`); the time spent reading it is
    still charged to the account. The message is reduced on the worker's own
    task, as the SMTP path does, so one lesson of a large message holds one
    runtime thread for about a second.
  - One account holds at most 250000 token rows (about 100 MB with the index)
    and spends at most 1000000 tokens a day. A lesson past either is refused
    or held back, and counted per account as `refused` and `throttled`. A
    lesson that only reuses words the account already has pays for the rows it
    adds. Taking a lesson back writes the same rows and spends the same.
  - The ledger keeps at most 100000 messages; at the limit the oldest tenth is
    forgotten, so those can no longer be taken back and count again if moved.
  - Lessons lost for another reason are counted in the server's metrics:
    `mail_bayes_learning_unreadable_total` (the file was gone when the worker
    came to it, which is normal after emptying Junk),
    `mail_bayes_learning_failed_total` (the database refused the lesson) and
    `mail_bayes_learning_refused_total` (a ceiling or the day's budget). They
    are warnings, not a guarantee that every move taught something.
  - The shared scope is never taught by a user, and an account only ever
    teaches its own scope. The message is named by the file the server wrote
    and the mailbox by the server's own special-use table: a header or a
    flag a client invents decides nothing.
  - A message with several local recipients is scored with the corpus of the
    first of them. That is the existing behaviour of the SMTP path and is not
    changed here.

  Training never sends mail. `epistle learning` shows the counters per
  account and switches learning off or on; see `docs/cli.md`. Without
  `[database]` there is no corpus and nothing is learned.

The LLM-assisted uncertain band uses `BayesStore::score_for_account`,
which falls back to the shared scope for any account whose own scope
has fewer than `MIN_TRUSTED_MESSAGES` (200) on either side. Below
the threshold the per-account classifier is not trustworthy, so the
user gets the server's general training rather than a coin-flip.

What a message is read as. The filter reads what a person reads: the header
block and the `text/*` parts, decoded (base64 and quoted-printable text is
read for what it says), as a stream of words. Attachments, images and any
other part that is not text are skipped and cost nothing, so a message with a
PDF or a photo scores as the message without it. Whitespace, punctuation and
one-letter words are not words and cost nothing either. A message that two
readers could split into parts differently is read as raw bytes as well. A message whose
structure cannot be followed (nested more than 32 levels deep, more than
10 000 parts, or a text part
larger than 2 MiB once decoded, or a message inside it that size) is read as
raw bytes, as the filter always did, and counts as not read in full (see the
floor of 0.5 below), since text that travels encoded is not decoded that way.
Files that no client could show as text do not use up the 2 MiB. A part that
declares two transfer encodings is read under each. Text in UTF-16, or in an
8-bit charset such as Latin-1 or Windows-1251, is also read as its bytes would
be shown; RFC 2047 encoded words in the headers are read decoded; zero width
characters and soft hyphens do not split a word; and letters outside ASCII are
lowercased. A token with a capital outside ASCII ("Привет", "École") that the
corpus learned before 0.12.2 is looked up now under its lower case form and is
learned again; the old rows stay in the table, unused, because the corpus
holds keyed hashes and cannot convert them. UTF-32, UTF-7 and the tags and
entities of HTML are not read.

What a message costs. Learning from, and scoring, one message costs a fixed
amount whatever its size. Of the words, the first and the last 128 KiB are
read; of those, at most 5000 distinct words. A message under both bounds is
scored on all of it, exactly as before. A message over either is not read in
full: its first and last 1000 distinct words are read, the rest of the 5000
are chosen by a keyed hash of the word (the sender does not hold the key, so
it cannot choose which of them are read by where it puts them), and it is
scored on that and never below 0.5, because filler is what a sender hiding
spam would send. A score of 0.5 is not Junk with the default `bayes_junk_at`
(0.95), and only `[antispam_llm]` turns it into a second opinion; so on a
server without it, spam padded with more than 256 KiB of words or 5000
distinct words, with the spam in the middle, can still reach the inbox. That
is the detection lost to the bound; the 0.12.1 read the whole message at a cost
of hundreds of MiB per message. Every figure is a constant, not a setting.

Training is written in one statement, and the transactions of a training and
of an account removal take their locks in the same order (the totals row, then
the token rows in ascending order), so they cannot deadlock. A message of 5000
new words adds 5000 rows, about 1.7 MB of table and 3.5 MB of write-ahead log;
nothing prunes the shared corpus yet, so the limits below are also the growth of
the disk: one address can add 30 such messages an hour.

The SMTP server hands each message to a queue of 64 jobs served by 2
workers, so no more than 2 trainings run at once and the queue holds about
16 MiB. Ham and spam are counted apart. A client address counts under its
own block and under the wider one around it (IPv4 /32 and /24, IPv6 /64 and
/48), and a sender domain counts only when the server verified it, because
the envelope sender is written by the client. A single address or domain
may have 4 jobs waiting or running and add 30 per hour; a wider block, 8
waiting and 120 per hour; a whole network (an IPv4 /16, an IPv6 /32), 16
waiting over ham and spam together and 125 per hour; the whole server, 2000
per hour, of which the last quarter is kept for networks that have used 31 or
fewer. A job with no client address is one network of its own with 4 waiting.
The tables of keys hold 8192 addresses, 8192 domains and 8192 networks and
drop the least recently used entry when full, so a flood of new addresses
forgets old ones and never shuts a new sender out. A job over a limit, or that
finds the queue full, is dropped and counted in
`mail_bayes_training_dropped_total`; the reply to the client never waits for
it, and a job the queue has no room for spends none of the budget. Behind a
container network that hides the client address (rootless Podman with a
bridge), every message comes from one address and the whole server learns at
the rate of one: 30 jobs per hour per kind.

What can be taught. Ham is learned only from a sender the server verified (SPF
or DKIM passed): a bounce, a SubjectPass resend or any mail from a sender with
neither teaches nothing. Spam is learned from what the server rejects or
quarantines, and a sender that fails the checks can make that happen on
purpose, so within its budget it can have text of its choosing learned as
spam: about 30 copies of a message are enough to make that message score as
spam. The limits are what one anonymous sender can do per hour, not a
guarantee that it can do nothing. A great many distinct networks can still
move the corpus, which is why a corpus below `MIN_TRUSTED_MESSAGES` is only a
fallback.

Who scores. An account's scope scores a message only when that account is the
single local recipient, was addressed as itself and has enough of its own
(`MIN_TRUSTED_MESSAGES`). Every other message is scored by the shared scope
when that has enough: one with two or more local recipients, one addressed to
an alias or a list, and one for an account without enough of its own. The
verdict (Junk, or a `550` at DATA) applies to every recipient, and what one
user taught their own corpus must not decide what another user receives. The
envelope order does not matter, and an alias with a single member counts as
an alias. Mail to aliases, lists and accounts that have not trained their own
corpus is therefore subject to `bayes_junk_at` and `bayes_reject_at` through
the shared corpus, where before it was not scored unless its first member had a
trained corpus.

Account deletion (`DELETE /api/v1/accounts/{name}`, `DELETE /Users/{id}`
on SCIM, `epistle accounts remove`) calls `BayesStore::forget_scope` to
drop every per-scope row. Without this, a recreated account would
inherit the previous user's training.

### `[acme]`
Automatic TLS certificates for the mail protocols (not the panel's web TLS).

| Key | Meaning |
|---|---|
| `directory_url` | ACME directory (must be `https://`). |
| `contacts` | Account contact URIs. |
| `domains` | Domains to issue for (each must be a configured `domains` entry). |
| `renew_before_days` | Renew this many days before expiry. |
| `challenge` | How the CA validates each domain: `http-01` (default), `tls-alpn-01` or `dns-01`. |

- `http-01`: the CA fetches a token from the `acme` listener on port 80.
- `tls-alpn-01` (RFC 8737): the CA opens TLS to port 443 with the `acme-tls/1` ALPN. Requires a listener that terminates TLS on port 443 (`submissions`, `imaps` or `pop3s` with `port = 443`); the start is refused otherwise. While an order is pending that listener answers `acme-tls/1` with the challenge certificate; ordinary handshakes keep the normal certificate. TLS listeners then negotiate ALPN and offer `acme-tls/1`, `imap`, `pop3`, `managesieve` and `smtp`, so a client that offers only some other ALPN identifier is refused.
- `dns-01`: the server publishes `_acme-challenge.<domain>` TXT through the `[dns]` provider, waits until every authoritative server of the zone returns it (up to 5 minutes, then the attempt fails with a message naming the record), asks the CA to validate, and removes the record afterwards whether the order succeeded or not. Requires a `[dns]` provider other than `manual`; the start is refused otherwise.

### `[arc]`
ARC sealing of inbound mail (RFC 8617), so authentication survives forwarders.

| Key | Meaning |
|---|---|
| `selector` | ARC selector. |
| `key_file` | Ed25519 sealing key (DKIM format). |

### `[auth]`
Authentication mechanisms. Absent keeps the defaults. As with every other
section, an unknown key fails the config load.

| Key | Meaning |
|---|---|
| `scram` | Offer SCRAM-SHA-256 (and SCRAM-SHA-256-PLUS where channel binding is available) and store a SCRAM verifier for each dynamic account (default `true`). With `false` the mechanisms are not advertised on SMTP, IMAP or ManageSieve, an `AUTH`/`AUTHENTICATE` with them is refused exactly like an unknown mechanism, no verifier is derived when an account is created or its password set (CLI, `/api/v1/accounts`, SCIM), and the next password change of an account that has one drops it. PLAIN and LOGIN stay available. |
| `unicode_passwords` | Accept non-ASCII passwords and normalise with NFKC on both set and verify (RFC 8265 OpaqueString profile, in spirit RFC 5802 SASLprep / RFC 7677). Default `false` keeps the historical ASCII-only policy. With the flag on the validator accepts any non-control Unicode scalar, the length is counted in scalars (still 12-64 on the normalised form), and the argon2id hash and the SCRAM verifier are derived from the same canonical form — a password set with one keyboard verifies from another. Scrambling on the client: SCRAM-SHA-256 clients already do SASLprep on the supplied credential, so a SCRAM login from a non-ASCII password works without further config. The flag is opt-in because older IMAP/POP clients mangle non-ASCII in AUTH PLAIN/LOGIN on the wire, and the operator who flips the flag is opting the deployment into the expectation that every client normalises consistently. Absent stays the historical default. |

### `[auth] unicode_passwords` (`[auth] unicode_passwords = true`)

The default policy (`unicode_passwords = false`) requires 12-64 printable-ASCII
characters and rejects control scalars, mirroring what every SMTP/IMAP
client can carry across `AUTH PLAIN` and `LOGIN` reliably. The breaches
list still applies.

With `unicode_passwords = true`, the policy:

- accepts any non-control Unicode scalar (U+0000..=U+001F, U+007F..=U+009F, the
  bidi / line-separator / paragraph-separator ranges from SASLprep are all
  out; see RFC 8265 OpaqueString);
- normalises the candidate with NFKC before hashing, so the canonical form
  is what lands on disk and what SCRAM's PBKDF2 sees;
- counts the password length in Unicode scalar values, and applies the
  12-64 ceiling on the normalised form (a 72-character decomposed form that
  collapses to 60 scalars is rejected; the 64-character ceiling holds on
  the post-normalise form).

A `contraseñaSegura` typed in NFC on an iOS keyboard and the same `n`+`˜`
decomposition typed on an Android keyboard both prepare to the same canonical
form, so the verifier matches. SCRAM-SHA-256 clients do SASLprep
automatically (RFC 5802 / RFC 7677); PLAIN/LOGIN clients do not, and the
caveat is theirs — the operator flips the flag knowing their clients must
normalise consistently.

```toml
[auth]
unicode_passwords = true
```

The setting is hot-disabled by the absence in an existing `[auth]` block:
configs that predate the field stay ASCII-only. There is no on-the-wire
advertisement of which policy the server is running; clients discover
it by trying a non-ASCII credential.

### `[oauth]`
OAuth2/OIDC bearer-token verification (OAUTHBEARER/XOAUTH2) for IMAP/SMTP/JMAP.

| Key | Meaning |
|---|---|
| `issuer` | Expected token issuer. |
| `audience` | Expected audience. |
| `algorithm` | Signing algorithm (e.g. `RS256`). |
| `public_key` | The IdP's public key. |
| `discovery_url` | OIDC discovery URL (alternative to `public_key`). |
| `signing_key` | Base64 PKCS#8 ES256 private key; turns the server into its own OAuth 2.0 authorization server. |
| `signing_key_file` | A file holding the same key, read at startup; instead of `signing_key`. `epistle init` keeps one at `secrets/oauth_signing.key` beside data_dir, mounted read-only into `mail`. A file that cannot be read stops the server. |
| `allow_private_jwks` | Permit the discovery document's `jwks_uri` to resolve to a loopback, private (RFC 1918 / RFC 4193), link-local or unspecified address. Default `false`. The check exists because the `jwks_uri` is chosen by the IdP, not the operator, and a hostile or compromised IdP could pivot it at a cloud-metadata service (`169.254.169.254`) or an internal host. Set this only when the IdP genuinely lives on a private network and the trust relationship justifies it. |
| `allow_unverified_email` | Accept a token whose `email` claim has no `email_verified` claim at all. Default `false`: the address in a token names the mailbox only when the identity provider says it verified it (`true`, or the string `"true"`), and a token that says `false` is refused either way. The `sub` claim is never read as an identity. Set this only for a provider that does not emit `email_verified` but confirms every address it issues tokens for. |
| `idp_enforces_second_factor` | Declare that the identity provider enforces a second factor itself before it issues a token. Default `false`: a bearer token cannot carry a TOTP code, so an account that has a TOTP secret cannot sign in with OAUTHBEARER or XOAUTH2 (the same refusal SCRAM gets), and its owner uses a password plus code instead. When `true`, a valid token stands for the second factor as well. |

### `[webhook]`
Outbound event notifications. The URL must be `https://` (or a loopback `http://`).

| Key | Meaning |
|---|---|
| `url` | Endpoint to POST events to. |
| `secret` | Optional HMAC-SHA256 signing secret. |
| `enabled` | Default `true`. With `false` the section stays in the file but no event is posted, not even for an alert with `webhook = true`. `epistle webhook disable\|enable` edits it. `webhook test` still posts. |

Each request is a JSON object whose `event` field names the event:
`message_received`, `delivery_failed`, `metric_alert`, `dkim_rotation_failed`
(a rotated DKIM key never showed up in DNS, so the previous key keeps signing),
`outbound_virus` (the antivirus refused a message one of your accounts sent;
it carries `account` and `signature`), and `test`. When `secret` is
set, `X-Webhook-Signature: sha256=<hex>` carries the HMAC-SHA256 of the body.

The events for each recipient of outbound mail (`delivered`, `delayed`,
`suppressed`, `canceled`), the warm-up events, how to verify the signature and
what is and is not retried are in the [HTTP API guide](api.md#webhooks).

`delivery_failed` is sent per recipient when outbound delivery fails for good
(refused, or expired in the queue). `reason` is the remote reply as one line, or
the local error when no server answered; `remote` is the server that answered
(or `null`); `class` is one of `invalid_address`, `mailbox_full`,
`policy_rejected`, `too_big`, `other`:

```json
{"event":"delivery_failed","recipient":"carol@example.net","reason":"550 5.1.1 no such user","class":"invalid_address","remote":"mx.example.net"}
```

`test` is sent only by `epistle webhook test`, once, to check reachability and
signature verification. It has a single fixed field, so receivers can acknowledge
it and otherwise ignore it:

```json
{"event":"test","message":"epistle webhook test: connectivity check, no mail activity"}
```

### `[antispam.llm]`
LLM-assisted screening for the **uncertain band** — the slice of mail where the
local Bayesian classifier is not confident in either direction. Outside the band
the local classifier is trusted and the LLM is not paid for; inside it, the
server POSTs a minimal excerpt of the message (only `From`, `Subject`,
`Reply-To`, plus a truncated body) to a chat-completions endpoint and parses
the reply. Requires `[database]` so the Bayesian score can be computed.

Fails open on any failure (transport, timeout, parse, shape): the message is
accepted, a warning is logged, and `mail_llm_failed_total` increments. The LLM
is never trusted to reject mail outright — its strongest action is quarantine
to the `Rejects` mailbox.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | string | — (required) | Chat-completions URL (any OpenAI-compatible API). |
| `api_key_env` | string | — (required) | Name of the env var that carries the API key; the server reads it at start and refuses to start if unset. |
| `model` | string | — (required) | Model identifier sent in every request body. |
| `uncertain_low` | float | `0.35` | Inclusive lower bound of the uncertain band. Scores below this skip the LLM. |
| `uncertain_high` | float | `0.65` | Inclusive upper bound. Scores above this skip the LLM. |
| `timeout_secs` | int | `10` | Per-request HTTP timeout. |
| `max_body_bytes` | int | `16384` | Cap on the user-side bytes of the request body. The outbound prompt is always `≤` this plus the system prompt and JSON envelope. |

Example:

```toml
[antispam.llm]
endpoint = "https://api.openai.com/v1/chat/completions"
api_key_env = "EPISTLE_LLM_API_KEY"
model = "gpt-4o-mini"
```

### `[subjectpass]`
Signed token for the uncertain Bayesian band. When a message's local
Bayesian score lands in the configured uncertain band and no LLM verdict
decides it (no LLM hook configured, or the LLM call failed), the server
refuses it with `550 5.7.1 ... EP-XXXXXXXXXXXX`; the sender pastes the token
into the `Subject:` and resends, and the resend is accepted as ham. The check
runs after DNSBL, SPF, DMARC and the scanner hook, so a valid token never
overrides a hard rejection. The token is per `(sender, recipient, day)`, so a
stolen token gains one pair for one day.

The refusal is permanent on purpose. A sending server that is given a `4xx`
retries the same message, which never carries the token, and its author hears
nothing until that queue gives up days later. A `5xx` makes the sending
server bounce at once, and the bounce quotes the reply text below, token
included. A challenged message is not stored and does not train the Bayesian
corpus. The cost is that automated senders nobody reads the bounces of
(newsletters, notifications) lose any message that lands in the band.

Disabled by default: enabling it changes what remote senders see when their
mail lands in the band, so the operator opts in. Requires `[database]`
(without a Bayesian score there is no band to challenge). The key is held
under `data_dir/subjectpass.key` (`0600` on disk, generated on first use);
a token issued yesterday still verifies today, so a sender who resends past
midnight still passes.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Whether to issue and verify SubjectPass tokens on the uncertain band. |

Example:

```toml
subjectpass = { enabled = true }
```

The challenge text the sender sees:

```
550 5.7.1 this message needs a human; resend it with EP-XXXXXXXXXXXX anywhere in the subject
```

### `[[alerts]]`
Metric alerts. Each block is one rule; an empty list (the default) disables
the engine entirely. Every `window_secs` the engine reads the chosen counter,
compares the per-window delta against `op threshold`, and on a fire either
posts a webhook event (when `webhook = true` and `[webhook]` is configured)
or queues an email through the outbound spool (one copy per address in
`email`). The reverse-path of an alert email is
`epistle-alerts@<hostname>`, so a DSN from a stuck MX comes back to the
server.

A rule that has fired will not fire again until `cooldown_secs` have
elapsed **and** the condition has stopped holding for at least one tick.
Without the second half, a sustained "queue high" alert would page every
window.

| Key | Meaning |
|---|---|
| `name` | Stable rule identifier; appears in the webhook payload, the email subject and the logs. Must be unique. |
| `metric` | Counter name (the short identifiers exposed by `Metrics::snapshot`). The validator rejects unknown names with the full valid list in the error message. |
| `op` | One of `>=`, `>`, `<=`, `<`, `==`. |
| `threshold` | Right-hand side of `op`. Compared against the per-window delta of `metric`. |
| `window_secs` | Sample interval in seconds. Must be `> 0`. |
| `webhook` | When `true`, fire a `metric_alert` webhook event. Requires `[webhook]`. |
| `email` | One email per entry. The alert is queued as an outbound message for each address (delivered through the queue worker like any other mail). |
| `cooldown_secs` | Minimum seconds between consecutive fires. Must be `> 0`. |
| `enabled` | Default `true`. With `false` the rule stays in the file but takes no samples and never fires. `epistle alert disable\|enable` edits it. |

Example: a 50-bounce-storm alarm, paging on webhook and email, with a 15-min
cooldown to keep the noise down once it has fired.

```toml
[[alerts]]
name = "bounce-storm"
metric = "bounced"
op = ">="
threshold = 50
window_secs = 300
webhook = true
email = ["ops@example.org"]
cooldown_secs = 900
```

The counter names accepted by `metric` (the ones `Metrics::snapshot` exposes)
are: `abuse_dropped`, `accepted`, `bounced`, `connections`, `deferred`,
`forwarded`, `quarantined`, `rejected_dmarc`, `rejected_dnsbl`,
`rejected_header_fields`, `rejected_loop`, `rejected_reputation`, `rejected_scanner`, `rejected_spf`,
`relayed`, `sieve_inspection_truncated`, `sieve_rejected`, `vacation_sent`, `webhook_failed`,
`webhook_sent`, `database_unavailable`, `scanner_clamd_failed`,
`scanner_clamd_skipped`, `outbound_virus`.

### `[clock_external]`

Read-only external-clock probe `epistle status` and `epistle check clock`
run when the area is reached. Three independent sources, diagnostic
median, warn/fail thresholds. The probe runs once per `status` call and
never writes the host clock; it is a probe for the operator, not a
discipliner. A host with no route to the sources can switch it off with
`enabled = false`: the area then says the probe is switched off, at `ok`,
and makes no network call.

```toml
[clock_external]
enabled = true      # false turns the probe off entirely
warn_seconds = 1.0   # an offset at or above this reading is a Warn
fail_seconds = 5.0   # an offset at or above this reading is a Fail
sources = [
  { host = "nts.netnod.se",    kind = "nts" },
  { host = "nts.time.nl",      kind = "nts" },
  { host = "ptbtime2.ptb.de",  kind = "nts" },
]
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Run the probe. `false` switches it off: `epistle status` reports the switch at `ok` and queries nothing. The rest of the block is still validated, so a disabled probe cannot hide a broken file. |
| `warn_seconds` | float | `1.0` | Inclusive warn threshold (seconds). Below it all valid offsets are `Ok`; at or above it and below `fail_seconds` the largest absolute offset is `Warn`; at or above `fail_seconds` it is `Fail`. Must be positive, finite, and strictly less than `fail_seconds`. |
| `fail_seconds` | float | `5.0` | Inclusive fail threshold (seconds). See `warn_seconds`. |
| `allow_private_networks` | bool | `false` | Permit private, loopback and link-local destinations for internal deployments, including NTS-KE referrals. It grants nothing over ports. |
| `allowed_ports` | array | `[]` | Ports the probe may dial besides the standard one for the protocol (TCP 4460 for NTS-KE, UDP 123 for NTP), for a peer that answers elsewhere. Each entry is a port number; none may be `0` and none may repeat. |
| `sources` | array | the example above | Three entries, no duplicate hosts, at least one of them `nts`. Each is `{ host, kind, [port] }` where `kind` is `nts` (port 4460 by default) or `ntp` (port 123 by default); `port` overrides the default when set and has to be the standard port for the protocol or one listed in `allowed_ports`. Hostnames must be ASCII, not empty, and shorter than 253 octets. |

Validation rules `Config::validate` enforces: exactly three sources; at
least one NTS source; no duplicate hosts (case-insensitive); no empty
hosts; no non-ASCII hosts; no whitespace or control characters in hosts;
no `0` and no repeated entry in `allowed_ports`. The split between `nts`
and `ntp` is otherwise the operator's. A `[clock_external]` that fails
these checks refuses to load.

The probe bounds: each source gets a `2 s` per-source deadline
(`SOURCE_DEADLINE`) covering the whole probe, dial, TLS handshake,
key exchange and authenticated exchange included rather than each of
those separately; the whole run gets a `2.1 s` cap (`RUN_DEADLINE`).
A hung server is reported, never retried.

DNS uses asynchronous resolution with a separate 500 ms cap inside the
source deadline. Both A and AAAA results are checked before connecting;
if any returned address is forbidden, the whole answer is rejected. The
probe connects to the selected validated address without resolving again.
By default, sources and NTS-KE Server/Port referrals must use
global unicast addresses, excluding shared, documentation, benchmarking,
reserved, loopback, private and link-local networks,
and standard ports (TCP 4460 for NTS-KE, UDP 123 for NTP).
`allow_private_networks = true` is for deployments that dial internal
servers, and `allowed_ports` is for a public peer that answers somewhere
other than its standard port: neither one turns the other on. Even with
`allow_private_networks = true`, multicast, unspecified and limited
broadcast addresses are rejected. IPv4-mapped, IPv4-compatible, NAT64
(`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses are classified using their
embedded IPv4 address, and a transition address is refused on its own even
when that payload is global, so the clock refuses exactly what a
`public_ipv6` value is refused for. The NAT64 prefix your operator uses is not
known to the probe, so a NAT64 address under a prefix other than
`64:ff9b::/96` is read as a plain IPv6 address and the IPv4 it carries is not
classified. IPv6 zone identifiers such as `fe80::1%eth0` or `fe80::1%1`
are not supported and are rejected with a configuration error, even with
the opt-in, so the destination has to be one that needs no zone. Directed
broadcast addresses cannot be identified without the destination
network's prefix; blocking those networks is the job of the routing and
egress policy of the network.

The verdict currently uses the largest absolute offset among all valid
readings. The median and `smear_excluded` are diagnostic values only: an
outlier or a reading identified by the smear diagnostic can still cause
`Warn` or `Fail`.
They do not currently protect the verdict from a single incorrect peer.
With one or two valid readings, a healthy offset still gives `Warn`; any
valid offset at or above the fail threshold gives `Fail`. No valid readings
gives `Fail`. The area also retains individual source and smear warnings.

NTP eras are unfolded relative to the local wall clock. This handles the
2036 rollover while the local clock is within 68 years of the remote time;
it cannot establish an era independently of a severely incorrect host clock.

The shipped sources are `nts:nts.netnod.se`, `nts:nts.time.nl` and
`nts:ptbtime2.ptb.de`: Netnod (Sweden), SIDN Labs (Netherlands) and the
Physikalisch-Technische Bundesanstalt (Germany), three independent
operators, every offset authenticated. The diagnostic median is
insensitive to one drifting source, subject to the verdict limitation
above. All three answered the whole NTS exchange (key exchange, cookies,
authenticated poll) from the development host when the list was measured
on 2026-10-22. A whole NTS exchange costs a dial, a TLS handshake, the
key exchange and the authenticated poll, so on a slow link it comes close
to the `2 s` budget: `nts.netnod.se` took between 1.37 s and 1.82 s on
the development host across eight consecutive runs. The `2 s` per-source
budget is a constant in the binary, not a key here. A miss is reported as
a timeout, the run loses its diagnostic median, and the area gives at
least `Warn`; no valid readings or a valid offset at the fail threshold
gives `Fail`. Measure the three from the host that will run
`epistle status`, because a network can answer one operator and not
another.

Two other providers are not in the list because of what they answered:

- `time.cloudflare.com` answers plain NTPv4 in 82 ms to 106 ms on every
  attempt measured. Its NTS-KE endpoint answers the key exchange and
  returns cookies, then never answers the authenticated poll, on every run
  recorded for this branch and at budgets up to 15 s. Use it as
  `kind = "ntp"`, or set `kind = "nts"` on a network where its
  authenticated exchange does answer.
- `time.google.com` publishes no NTS-KE endpoint, so it can only be a plain
  NTPv4 source.

Replace any of them when the chosen peers change; keep one provider per
autonomous system, and set `kind` per source to what that source actually
answers.

Two notes an operator should have. The area renders one line saying how
many of the sources were authenticated over NTS and names them, so a run
with a plain source among them does not read as equally trusted offsets.
And the leap-second smear check compares one plain reading against two
authenticated readings that agree within 100 ms, so on the shipped list,
which has no plain source, it stays dormant; it can fire when an operator
replaces one `nts` source with a plain `ntp` one.

The defaults at `warn_seconds = 1`, `fail_seconds = 5` come from the
design that drove the first delivery. They are the same numbers
`docs/limits.md` would expose as adjustable limits if a catalog entry
were added later. Until then they live in `[clock_external]` and
`Config::validate` enforces the strict-less relation.

### `[privileges]`
Drop OS privileges after binding ports (run the daemon unprivileged).

| Key | Meaning |
|---|---|
| `user` | Unprivileged user to switch to (must exist). |
| `group` | Optional; defaults to the user's primary group. |

### `[storage]`
Optional at-rest encryption of stored message files and retention of expunged
messages. Defaults to off for encryption (relying on full-disk encryption) and
off for retention (current behaviour: an expunge deletes the on-disk files
immediately). When encryption is on, `.eml` bodies, the outbound spool and
JMAP blobs are encrypted with ChaCha20-Poly1305; reads decrypt transparently.
The key must be sourced off the data disk. With `encrypt_at_rest = true` and
no usable key the server refuses to start (fail closed). See the security
guide's "Data at rest".

| Key | Meaning |
|---|---|
| `encrypt_at_rest` | Encrypt new message writes at rest (default `false`). Also encrypts the TOTP secrets in `accounts.toml`. |
| `encryption_key_env` | Name of an env var holding the base64 32-byte key. |
| `encryption_key_file` | Path to a file holding the base64 32-byte key (ideally outside `data_dir`); takes precedence over `encryption_key_env`. |
| `deleted_retention_days` | Days to keep expunged messages in `<account>/.archive/` before the hourly sweeper removes them (default `0`). Setting this to a positive value moves expunged messages into the archive instead of deleting them; restore with `epistle archive restore` or `POST /api/v1/accounts/{name}/archive/{id}/restore`. Archived messages count toward the account's quota. |
| `delivery_log_days` | Days to keep one line of per-recipient delivery state under `<data_dir>/deliverylog/YYYY-MM-DD.jsonl` (default `30`; `0` turns the log off). The log is metadata only; the hourly sweep removes files older than this window. Records cover delivered, deferred (one per recipient per message for each distinct reply, at most eight: a retry deferred for the same reason as the one before adds no record), failed, suppressed and canceled outcomes, each with the number of the attempt it came from, never the subject or body, and never a message body. Read with `epistle delivery list` or `GET /api/v1/deliveries`. |
| _DMARC / TLS-RPT report retention_ | The constant `reports::RETENTION_DAYS` (90 days) controls how long ingested reports live under `data_dir/reports/{dmarc,tlsrpt}/YYYYMMDD/` before the hourly sweeper removes them. The retention ceiling is hard-coded: `epistle reports --days N` cannot read past it. The same sweep covers `data_dir/reports/tlsrpt-outbound/`, the TLS sessions of our own deliveries kept for the TLS-RPT reports we send (see `[queue] tlsrpt_reports`); a day there is normally deleted once its reports went out. |

Generate a key with `epistle storage-keygen` (prints a fresh base64 32-byte key
to stdout; place it in the env var or key file). Mirrors `epistle dkim-keygen`.

The outbound spool's envelope (sender, recipients, per-recipient state) is
sealed with the same key under the message id as associated data, so an
envelope cannot be swapped onto another message. Spool files and directories
are pinned to `0600`/`0700`. See [`storage.md`](storage.md) for the on-disk
format and the migration path.

### `[storage.blobs]`
Where uploaded JMAP blobs (`POST /jmap/upload/{account}`) live. Absent (or
`backend = "fs"`) keeps the historical default of `<data_dir>/blobs/`,
sharded two levels by the **last** four characters of the blob id, with a
fallback to the flat layout for blobs written by older versions. Setting
`backend = "s3"` redirects uploads to an S3-compatible bucket; the
download handler and the `.owner` / `.type` sidecars follow the same path.

| Key | Meaning |
|---|---|
| `backend` | Either `"fs"` (default; same as omitting the section) or `"s3"`. |
| `endpoint` | S3 endpoint URL (`https://s3.us-east-1.amazonaws.com`, or a compatible service like MinIO at `http://minio.local:9000`). Required when `backend = "s3"`. |
| `bucket` | Bucket name. Object keys are the raw blob id (`<uuid>` for the payload and `<uuid>.type` / `<uuid>.owner` for the sidecars). |
| `region` | AWS region used for SigV4 signing (e.g. `us-east-1`). Setting it wrong returns `SignatureDoesNotMatch` from the server. |
| `access_key_id` | Public access key id. Not a secret, so it lives in the config file. |
| `secret_access_key_env` | Name of an env var holding the secret access key. The secret never appears in the config file. |
| `secret_access_key_file` | Path to a `0600` file holding the secret access key. Takes precedence over `secret_access_key_env` when both are set. |

Example S3 block:

```toml
[storage.blobs]
backend = "s3"
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "mail-blobs"
region = "us-east-1"
access_key_id = "AKIA-EXAMPLE"
secret_access_key_env = "EPISTLE_S3_SECRET"
```

The S3 backend speaks the four verbs S3 exposes — `PutObject`, `GetObject`,
`DeleteObject`, `ListObjectsV2` — over HTTPS with SigV4 signed by hand (no
SDK dependency; the AWS SDK tree would be heavier than the four HTTP
calls). A bucket that returns 401 or 403 surfaces as
`BlobError::Auth`, never as "object not found", so an operator chasing
wrong credentials is not led to chase a phantom missing blob. When
`backend = "s3"` is set, blob-store reclaim (`reclaim_blobs`) and the
`/api/v1/accounts/{name}/quota` path no longer walk the local filesystem
— quota is enforced by the configured per-account limit and the operator
manages bucket lifecycle on the S3 side.

### `[otel]`
OpenTelemetry trace export. Present enables exporting tracing spans over OTLP/HTTP to a collector.

| Key | Meaning |
|---|---|
| `endpoint` | OTLP/HTTP endpoint of the collector (e.g. `http://localhost:4318`). |
| `service_name` | `service.name` resource attribute (default `epistle`). |

### `[dns]`
DNS provider for record automation (DKIM rotation, MTA-STS, TLS-RPT,
TLSA-on-cert-rotate, …). Records published through a provider are
**re-published on every change** — when this section is configured, epistle
stops asking the operator to add records by hand. Absent or unmatched
`provider` → manual mode (records printed for the operator to add).

| `provider` value | Notes |
|---|---|
| `bunny` | Bunny.net account access key; `AccessKey` header; `?search=` resolves the zone id; see limitations below. |
| `cloudflare` | API token; bearer auth; supports TLSA via structured data. |
| `desec` | deSEC API token; rrset-style bulk PUT; supports TLSA. |
| `digitalocean` | Personal access token; bearer auth; v2 REST API; see specifics below. |
| `gcloud` | Google Cloud DNS service-account JSON; RS256 JWT bearer; supports TLSA. |
| `dnsimple` | DNSimple API token + account id; bearer auth; record-id granularity. |
| `godaddy` | GoDaddy API key + secret; `sso-key` header; v1 REST API; production API access gated by account eligibility; see specifics below. |
| `namecheap` | Username + API key in `token`, plus `client_ip`; XML API; **SRV and TLSA not supported**; see limitations below. |
| `ovh` | Application key + secret + consumer key; signed with `$1$`+SHA1; see specifics below. |
| `porkbun` | Porkbun API key + secret; v3 JSON API; credentials in the request body, not a header; see specifics below. |
| `route53` | AWS access key + secret + hosted zone id; signed with SigV4. |
| `rfc2136` | TSIG-authenticated DNS UPDATE to a local nameserver (`host:port`); A/AAAA/TXT/CNAME/TLSA. |
| `spaceship` | API key + secret; `X-API-Key`/`X-API-Secret` headers; see specifics below. |
| `manual` | Always available; no credentials. |

Common keys (every provider):

| Key | Meaning |
|---|---|
| `provider` | One of `cloudflare`, `desec`, `digitalocean`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `cloudflare`, `desec`, `gcloud`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `cloudflare`, `desec`, `dnsimple`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `bunny`, `cloudflare`, `desec`, `namecheap`, `route53`, `manual`. |
| `provider` | One of `cloudflare`, `desec`, `digitalocean`, `namecheap`, `route53`, `rfc2136`, `spaceship`, `manual`. |
| `zone` | The DNS zone the token is scoped to (least privilege). |
| `token` | Inline API token — discouraged, prefer `token_file` or `token_env`. |
| `token_env` | Name of an env var holding the API token. |
| `token_file` | Path to a `0600` file holding the API token. |

#### `[dns]` — DigitalOcean specifics

```toml
[dns]
provider = "digitalocean"
zone = "example.org"
token = "your_personal_access_token"     # or token_file / token_env
```

- Generate the token at <https://cloud.digitalocean.com/account/api/tokens>
  with **Write** scope and a single domain. DigitalOcean tokens are not
  zone-scoped at the API level, so the zone restriction is enforced by
  epistle (records outside `zone` are rejected before any call).
- **API URL:** production is `https://api.digitalocean.com`. The provider's
  `with_base` constructor swaps to an alternate base for tests; no config
  knob for it yet.
- **TXT values are unquoted.** DigitalOcean adds the DNS wire-format quotes
  at the zone layer, so epistle sends `data: "v=DMARC1; p=none"` rather than
  `data: "\"v=DMARC1; p=none\""`. Quoting them would produce a double-quoted
  TXT record.
- **`upsert` is read-then-write.** epistle `GET`s records matching the name
  and type, then either `PUT`s the existing record's id (replacing) or
  `POST`s a new one. Two TXT records with the same name and type are not
  possible because of the lookup.
- **Pagination is followed.** `list` walks `links.pages.next` until exhausted,
  so a zone with hundreds of records is not silently truncated.
#### `[dns]` — DNSimple specifics

```toml
[dns]
provider = "dnsimple"
zone = "example.org"
account_id = "1010"             # not a secret; visible in the path /v2/{id}/...
token = "your_api_token"        # or token_file / token_env
```

- `account_id` is **required**: every URL is `/v2/{account_id}/zones/{zone}/records`,
  so a missing `account_id` fails the build rather than guessing. The id is
  not a secret; it sits in the config file in clear alongside the zone.
- `token` is a user token (DNSimple's "Account API token" or an OAuth token
  for the same user); the provider sends it as `Authorization: Bearer …`.
- **Upsert is list-then-write.** DNSimple's `POST` returns 400 if a record
  with the same name and type already exists, so every upsert first lists
  the zone (filtered to that `(name, type)`) and either `PATCH`es the
  existing record or `POST`s a new one. Two TXT records for the same name
  therefore cannot be created by mistake.
- **Delete is idempotent.** Deleting a record that does not exist is a no-op
  (no `DELETE` request is sent) — the list comes back empty.
- **List walks pagination.** The records endpoint is paginated; the
  provider requests `per_page=100` (the API maximum) and follows
  `pagination.total_pages`. Records are returned as FQDNs — the relative
  `name` from the API is joined to the configured zone.
- **Unsupported kinds:** MX (priority is not modelled by epistle yet), SRV
  (priority/weight/port), and TLSA (no structured-data field). The provider
  returns `provider does not support writes` for these.
- **API base:** `https://api.dnsimple.com/v2` — overridable through the
  provider's `with_base` for tests.
#### `[dns]`: GoDaddy specifics

```toml
[dns]
provider = "godaddy"
zone = "example.org"
access_key = "your_api_key"          # the public half; prefer env for production
secret_key_env = "EPISTLE_GODADDY_SECRET"   # or secret_key inline
```

- Generate the API key pair at <https://developer.godaddy.com/keys/>. The
  two halves travel in a single `Authorization: sso-key <key>:<secret>`
  header on every call. The key comes first, the secret second, a
  wrong order is a `401`, the same path the other providers treat as a
  missing token.
- **Production API access is gated.** GoDaddy does not enable the
  production DNS API on every account by default; an `HTTP 403` from
  the API is most often the verdict, not a bad key. The error message
  names the eligibility check so the operator knows the fix is at
  <https://developer.godaddy.com/getstarted>, not in the credentials.
- **API URL:** production is `https://api.godaddy.com/v1`. The
  provider's `with_base` constructor swaps to an alternate base for
  tests; no config knob for it yet.
- **Upsert replaces the whole record set.** `PUT
  /domains/{zone}/records/{type}/{name}` is called with a one-element
  JSON array body carrying `data` and `ttl` (A/AAAA/TXT/CNAME);
  MX adds `priority`, SRV adds `priority`/`weight`/`port`/`service`/
  `host`. The array shape is the contract, a single `DnsRecord` from
  the trait produces a one-element array, matching the way the other
  providers encode one record at a time.
- **TLSA is not supported.** The v1 endpoints' allowed-type set excludes
  TLSA
  (https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-replace-type-name),
  so a TLSA publish would round-trip a 4xx instead of a clean "this
  provider does not support TLSA" verdict. `RecordKind::Tlsa` returns
  `provider does not support writes` and epistle skips publishing it.
  Publish TLSA at a different provider (or split the zone) if you need
  DANE.
- **Concurrent writers to the same name can lose an update.** GoDaddy's
  API is read-modify-write without conditional writes: an upsert
  `GET`s the live set, merges the new value in, and `PUT`s the result.
  Two writers that observe the same starting set and PUT different
  values both succeed, and the loser's update silently disappears.
  The same race applies to `delete` (a concurrent add between the
  `GET` and the `DELETE` is removed by the follow-up `DELETE`).
  This is a limitation of the API, not the implementation: there is
  no `If-Match` header and no ETag on the per-name endpoints. The
  single-process epistle daemon does not hit it today, but two
  epistle processes (a primary and a hot standby) writing to the
  same zone can. Avoid that topology or accept that the second
  writer to commit wins.
- **Minimum TTL 600.** A TTL below 600 is raised to the floor before
  the request goes out, so a low-TTL DKIM or SPF never hits the wire.
- **Apex is the literal `@`.** The relative name GoDaddy expects is
  the label minus the zone suffix, or `@` for the apex (e.g. the
  path for an A record at the zone is `/records/A/@`).
- **MX and SRV are emitted** with the extra fields GoDaddy requires.
  The presentation form (`<prio> <target>` for MX, `<prio> <weight>
  <port> <target>` for SRV) is split out on write and reassembled on
  read.
- **No in-place update and no pagination** on the zone list. `list`
  reads the full set in one `GET /domains/{zone}/records` call and
  walks what the API returns.

#### `[dns]` — OVH specifics

```toml
[dns]
provider = "ovh"
zone = "example.org"
access_key = "your_application_key"          # AK from the OVH API portal
secret_key = "your_application_secret"       # AS; prefer secret_key_env
secret_key_env = "OVH_APP_SECRET"
consumer_key = "your_consumer_key"           # CK; prefer consumer_key_env
consumer_key_env = "OVH_CONSUMER_KEY"
endpoint = "ovh-eu"                          # ovh-eu (default) | ovh-ca | ovh-us
```

- **Three credentials.** OVH's REST API authenticates each call with
  `X-Ovh-Application` (AK), `X-Ovh-Consumer` (CK) and an `X-Ovh-Signature`
  header — a SHA-1 over `AS + "+" + CK + "+" + METHOD + "+" + full URL + "+"
  + body + "+" + timestamp`, prefixed with `$1$`. AK and AS come from
  <https://eu.api.ovh.com/createApp/>; CK is generated once the operator
  validates the rights at the URL the `/auth/credential` call returns.
- **Endpoints.** `ovh-eu` resolves to `https://eu.api.ovh.com/1.0`,
  `ovh-ca` to `https://ca.api.ovh.com/1.0`, `ovh-us` to
  `https://api.us.ovhcloud.com/1.0`. A full URL is also accepted as the
  `endpoint` value (e.g. for a private gateway), but it must be `https://`:
  the application key, the consumer key and the signature travel with every
  call, so a cleartext endpoint builds no provider (the same fail-closed path
  as a missing credential). Each region has separate
  credentials; do not reuse an EU `consumer_key` against the US API.
- **Records are id-addressed.** `upsert` lists records of `(fieldType,
  subDomain)` first, then PUTs the existing id (or POSTs a new one). After
  every write OVH requires `POST /domain/zone/{z}/refresh` to publish;
  epistle calls it for you. Records are not actually live until the refresh
  propagates, but epistle's call returns success as soon as OVH accepts the
  write.
- **TXT values.** OVH silently wraps TXT targets in double quotes on read;
  epistle strips them so `list` returns what you put in `upsert`. On write,
  the value is sent verbatim — do not pre-quote.
- **TLSA is not supported.** OVH's `/record` endpoint does not accept the
  TLSA tuple, so `RecordKind::Tlsa` returns `provider does not support
  writes` and epistle skips publishing it. Publish TLSA at a different
  provider (or split the zone) if you need DANE.

#### `[dns]`: Porkbun specifics

```toml
[dns]
provider = "porkbun"
zone = "example.org"
access_key = "pk1_xxxxxxxxxxxxxxxxxxxxxxxx"   # the public API key
secret_key_env = "EPISTLE_PORKBUN_SECRET"     # the secret API key, prefer env
```

- Generate the key pair at <https://porkbun.com/apiKeys>. The two
  halves are `apikey` and `secretapikey`; Porkbun takes them in the
  request **body** of every call rather than an `Authorization`
  header, so the wire shape has no auth header at all.
- **API URL:** production is `https://api.porkbun.com/api/json/v3`. The
  provider's `with_base` constructor swaps to an alternate base for
  tests; no config knob for it yet.
- **Records are id-addressed.** `POST /dns/retrieve/{zone}` returns
  every record in the zone (Porkbun stores them by numeric id, not by
  name+type). The upsert path matches by `(name, type)`, then either
  `POST /dns/create/{zone}` or `POST /dns/edit/{zone}/{id}` publishes
  the change; any duplicates at the same `(name, type)` are dropped
  so an upsert never widens the record set.
- **`status` is the source of truth.** Porkbun answers `200 OK` with
  `{"status":"ERROR", …}` for application-level failures as readily
  as it answers `400`, so every reply is decoded and the `status`
  field is checked; a non-`SUCCESS` status is an error regardless of
  the HTTP code, and the auth-flavoured `code` values map to
  `provider authentication failed`.
- **Apex is the blank name.** The relative name Porkbun expects is
  the label minus the zone suffix, or the empty string for the apex
  (Porkbun's "blank for root").
- **Minimum TTL 600.** A TTL below 600 is raised to the floor; the
  API also treats `0` as "use the account minimum".
- **MX/SRV/CAA/TLSA** are all emitted with the kind-specific fields
  Porkbun expects (Porkbun packs SRV's priority and weight into a
  single `prio` integer; the rest of the fields travel in `content`).
- **TXT values pass through verbatim**, the provider does not strip
  or add quotes. A zone imported with literal quotes around a TXT
  value keeps them on read.

#### `[dns]` — Namecheap specifics

```toml
[dns]
provider = "namecheap"
zone = "example.org"
token = "your_username:your_api_key"      # or token_file / token_env
client_ip = "203.0.113.25"                # IPv4 on the API whitelist
```

- `client_ip` is required. Namecheap's API takes it as the `ClientIp`
  parameter on every call and accepts IPv4 only; without it epistle stays in
  manual mode. Use the server's egress address, the one on the whitelist.
- The `token` carries **two** values separated by `:` — Namecheap's API
  requires `ApiUser`, `ApiKey`, and `UserName` on every call (the username
  doubles as both `ApiUser` and `UserName`). A missing colon, empty
  username, or empty key disables automation (fail closed).
- **API URL:** production is `https://api.namecheap.com/xml.response`. The
  provider's `with_api_url` constructor swaps to
  `https://api.sandbox.namecheap.com/xml.response` for sandbox credentials;
  no config knob for it yet.
- **IPv4 whitelist is mandatory.** Namecheap rejects API calls from any IP
  not on the account's whitelist at
  <https://www.namecheap.com/support/api/methods/>. The server's egress IP
  must be added there or every call returns an auth-flavoured error.
- **SRV is not supported** either: setHosts has no SRV record type, so an
  SRV write returns `provider does not support writes`, the same as TLSA.
- **TLSA is not supported** by Namecheap's UI or API. DANE records must be
  published at a different DNS host (or the zone must be split between
  providers) — epistle will return `provider does not support writes` for
  TLSA and skip publishing it.
- **`setHosts` is destructive.** It replaces the entire record set at the
  zone. epistle's upsert/delete is a read-modify-write (`getHosts` → mutate
  → `setHosts`), so if an operator also edits the zone by hand between
  those calls their changes are silently dropped. Pair with periodic drift
  checks (`epistle dns-check`) for zones that are not fully epistle-owned.

#### `[dns]` — RFC 2136 specifics
```toml
[dns]
provider = "rfc2136"
zone = "example.org"
endpoint = "127.0.0.1:5359"   # the nameserver that accepts UPDATE messages
key_name = "epistle-key."
token = "base64-of-shared-secret"
# token_file / token_env also accepted, like every provider
algorithm = "hmac-sha256"     # default; "hmac-sha384" and "hmac-sha512" supported
```
- **No HTTP API.** epistle sends DNS UPDATE messages (opcode 5) over TCP,
  framed with a 2-byte length prefix (RFC 1035 §4.2.4). The endpoint is
  `host:port` of a nameserver that has the zone configured and the TSIG
  key loaded — typically BIND, Knot, NSD, or dnsdist in front of any of
  those.
- **Authentication is TSIG** (RFC 8945). `key_name` is the key's name in
  the nameserver's config; `token` is the shared secret as base64 (the
  format `rndc-confgen` and similar tools print). The MAC is computed
  over the full UPDATE wire format, including the message id, so replays
  are non-viable on top of the time tolerance (`fudge`, 5 minutes by
  default — adjust the nameserver if you need more).
- **Supported algorithms:** `hmac-sha256` (default), `hmac-sha384`,
  `hmac-sha512`. `hmac-sha1`, `hmac-sha224`, and `hmac-md5` are rejected
  at build time — hickory's TSIG implementation does not implement the
  MAC primitives for them, so an attempt to sign would fail in
  non-obvious ways.
- **Upsert is `delete RRset (name,type)` + `add RR` in one message.**
  RFC 2136 §2.5 — the canonical replacement. Guarantees we never end up
  with two TXT records at the same owner name.
- **Delete is the same `delete RRset` with no `add` after it** —
  class NONE, TTL 0, empty RDATA. Idempotent by definition; the server
  answers NOERROR whether the RRset existed or not.
- **`list` is not implemented.** RFC 2136 defines UPDATE only; reading
  the zone back would need AXFR or per-name queries that the provider
  has no way to enumerate. Drift detection (`epistle dns-check`) will
  return `provider does not support writes` against an rfc2136 zone.
- **Supported record kinds:** A, AAAA, TXT, CNAME, TLSA. MX and SRV are
  rejected (`Unsupported`) because they carry extra fields
  (preference, weight, port) that epistle does not currently build.
#### `[dns]` — Google Cloud DNS specifics
provider = "gcloud"
token = "unused"                       # placeholder; auth is signature-based
credentials_file = "/etc/glyndor/epistle/dns/gcloud.json"
- **Auth is signature-based, not bearer-based.** `token` (and friends) is a
  placeholder; Google authenticates the service account with a JWT RS256
  signed with the private key from the credentials file. The bearer
  exchanged at `https://oauth2.googleapis.com/token` is cached in-process
  until one minute before `expires_in`, so the JWT is signed once per cache
  lifetime, not on every DNS API call.
- **`credentials_file`** is a Google service-account JSON (`client_email`,
  `private_key` in PKCS#8 PEM, `project_id`). The service account needs the
  **DNS Administrator** role on the project (scope
  `https://www.googleapis.com/auth/ndev.clouddns.readwrite`) and the
  `private_key` must be reachable by the process; a `0600` file outside
  `data_dir` is the recommended location.
- **Two-phase write.** Every change lists the zone's rrsets and submits one
  `POST .../changes` carrying `additions` (and, when replacing, `deletions`
  of the old rrset). A second upsert with identical value + TTL is a no-op
  (no second change request is submitted), so two TXT records for the same
  name cannot appear.
- **Delete is idempotent.** Deleting an absent rrset is a no-op; the
  provider only submits a change when the rrset exists in the zone.
- **TLSA is supported** via the structured `rrdatas` path. MX/SRV are not
  emitted yet and return `provider does not support writes`.
#### `[dns]` — Bunny specifics

```toml
[dns]
provider = "bunny"
zone = "example.org"
token = "your-bunny-account-key"      # or token_file / token_env
```

- The token is the Bunny.net account **Access Key** (Account → API → API Key
  in the panel). epistle sends it in the `AccessKey` HTTP header — *not*
  `Authorization: Bearer …`. Keep it in `token_file` (`0600`) or `token_env`
  in production.
- **Zone id, not name.** Bunny references a zone by numeric id; on first
  use epistle issues `GET /dnszone?search=<zone>` and picks the entry whose
  `Domain` matches the token's zone exactly (Bunny's search is a prefix
  match, so `example.org` also returns `evilexample.org` and
  `example.org.evil.test` — those are ignored). The id is cached for the
  life of the provider.
- **Create vs update.** Bunny's record fields are numeric types
  (`A=0`, `AAAA=1`, `CNAME=2`, `TXT=3`, `MX=4`, `SRV=8`, `TLSA=15`). epistle
  upserts by first reading the zone's record list, then choosing between
  `PUT /dnszone/{id}/records` (create) and `POST /dnszone/{id}/records/{rid}`
  (update); without that read-modify-write, Bunny rejects a second `TXT`
  at the same name as `400`. Two TXT records at the same name is the
  classic mistake and is covered by a test.
- **Delete is idempotent.** `DELETE` returns `404` for a record that is
  already gone (e.g. removed between our find and delete by another
  caller); epistle swallows the `404` and returns `Ok`.
- **TLSA and SRV are not supported** — Bunny's API takes a `Type` integer
  and the MX/SRV/TLSA wire formats need fields (`Priority`, `Port`,
  `Flags`, `Tag`) epistle does not yet emit. epistle returns
  `provider does not support writes` for those kinds and skips them.

#### `[dns]` — Spaceship specifics

```toml
[dns]
provider = "spaceship"
zone = "example.org"
access_key = "your_api_key"     # or secret_key for inline; secret_key_env is preferred
secret_key_env = "EPISTLE_SPACESHIP_SECRET"
```

- Generate the key pair at
  <https://www.spaceship.com/application/api-manager/> with the
  `dnsrecords:read` and `dnsrecords:write` scopes. The two halves travel as
  `X-API-Key` and `X-API-Secret` headers on every call; they are not
  zone-scoped at the API level, so the zone restriction is enforced by
  epistle (records outside `zone` are rejected before any call).
- **API URL:** production is `https://spaceship.dev/api/v1`. The provider's
  `with_base` constructor swaps to an alternate base for tests; no config
  knob for it yet.
- **No in-place update.** Spaceship's `PUT /dns/records/{zone}` *adds*
  items (with `force: true` to overwrite). epistle implements upsert as
  read-then-delete-then-add: it `DELETE`s the existing `(type, name)`
  first and only then `PUT`s the new value, so two TXT records at the
  same owner name are not possible.
- **TXT delete body includes the value.** Spaceship's `TxtResourceRecordDeleteItem`
  requires `{type, name, value}` (other kinds only need `{type, name}`).
  epistle always includes `value` for TXT deletes so the right record is
  removed when multiple TXT records at the same name exist.
- **Pagination is followed.** `list` walks `?take=500&skip=N` until the
  number of fetched items reaches `total`, so a zone with hundreds of
  records is not silently truncated.
- **TXT values are unquoted.** Spaceship stores TXT content verbatim on
  the wire — epistle sends `value: "v=DMARC1; p=none"` rather than
  `"value: "\"v=DMARC1; p=none\""`.
- **Supported record kinds:** A, AAAA, TXT, CNAME, TLSA. MX and SRV are
  rejected (`Unsupported`) for the same reason as the other providers.

### `[[accounts]]`
A mail account. An account with no `password_hash` is receive-only.

Addresses and domains here are used in lowercase (`config-check` names any written with capitals); an address claimed by two owners is kept by the first and reported in the log and `epistle status`. An address needs a domain with at least one dot, like `domains` does, so `torre@localhost` is refused and the refusal names the rule.

| Key | Meaning |
|---|---|
| `name` | Lowercase letters, digits and hyphens, no hyphen first, 64 characters at most; becomes the mailbox directory name. |
| `addresses` | One or more addresses (each in a configured domain). |
| `password_hash` | argon2id PHC string. Omit for receive-only. |
| `catch_all` | Domains for which this account receives mail to unknown local users. |
| `quota_bytes` | Per-account mailbox quota (bytes). Overrides the domain/server default. `0` means no limit. |
| `forward` | External addresses this account's mail is also forwarded to (SRS-rewritten; bounces and looping mail are never forwarded). Empty disables forwarding. Each target needs a domain with at least one dot. |
| `forward_keep_local` | Keep the local copy when forwarding (default `true`). Set `false` for pure forwarding. |
| `display_name` | The person's name used as sender name, kept as written (at most 128 characters, no line breaks). |
| `save_sent` | Whether the server saves a copy of every message the account submits into its `Sent` folder. Absent or unset means "on" (the default); `true` enables the save explicitly, `false` opts the account out. Per-request overrides (`POST /api/v1/send`'s `save_sent` field, JMAP `EmailSubmission/saveSent`) and per-credential overrides (an app password's `save_sent`) win over this setting. |

### `[[alias]]`
A multi-target alias: one address that delivers to several local accounts.

| Key | Meaning |
|---|---|
| `address` | The alias address (e.g. `team@example.org`). |
| `members` | Member addresses it delivers to (each a local account address, with a domain that has at least one dot). |
| `senders` | Addresses allowed to send *as* the alias (From / MAIL FROM). Empty means any member may; a non-member is always refused. |
| `hidden` | Keep the membership private — not disclosed through directory queries (default `true`). |
| `list_id` | Treat the alias as a **mailing list**: delivered copies gain `List-Id` (this value), `List-Post`, and `List-Unsubscribe` headers (RFC 2369/2919). Absent means a plain alias. The value is written between angle brackets as it stands, so it has to be an identifier those brackets can carry: a dot-atom of non-empty `atext` atoms joined by single dots, as in `team.example.org`. Anything else is refused at load, brackets and whitespace included; RFC 2919 puts a description outside the brackets (`Team List <team.example.org>`) and this server does not compose one |

### Masked email addresses
Per-account disposable aliases, surfaced under `/api/v1/accounts/{name}/masked`. The server picks the random suffix (8 lowercase base32 chars from the CSPRNG); the client only supplies a human-readable label. The local part of every mask is `<label-slug>.<random>@<first configured domain>`. Disabled masks reject exactly like unknown users (no leak that one existed). The per-account cap is `masked_addresses_max` (default 100); going over returns `429`.

### `[[tenant]]`
A tenant is a named group of domains with optional aggregate caps. Tenancy is what makes a resellable deployment work: each tenant gets its own per-account cap (already covered by `quota_bytes` / `domain_quotas`) plus aggregate caps the operator can promise to the tenant without having to revisit per-account limits. With no `[[tenant]]` block the server behaves exactly as it always has; the empty list is the identity.

```toml
[[tenant]]
name = "acme"
domains = ["acme.example", "acme-mail.example"]
quota_bytes = 1073741824        # 1 GiB aggregate across every account in the tenant
max_accounts = 50                # hard cap on accounts in the tenant's domains
max_domains = 5                  # operator guard; never smaller than domains.len()
submission_rate_limit_per_min = 200   # recipients per minute for the whole tenant, on top of the per-account limit
```

| Key | Meaning |
|---|---|
| `name` | Stable identifier shown in error messages. Operators see it; the network never does. |
| `domains` | Domains that belong to the tenant. Every entry must also appear under the top-level `domains` list. |
| `quota_bytes` | Aggregate storage cap (bytes) across every account in every domain of the tenant. Absent means no aggregate cap; the per-account and per-domain quotas still apply. |
| `max_accounts` | Maximum number of accounts (static + dynamic) this tenant may hold. Absent means no cap. |
| `max_domains` | Maximum number of domains this tenant may declare. Absent means no cap. The cap cannot be lower than `domains.len()` because that would make the tenant unloadable. |
| `submission_rate_limit_per_min` | Aggregate submission rate ceiling for the tenant: recipients per minute, summed across every authenticated sender in every domain of the tenant. Applies on top of the per-account `submission_rate_limit_per_min`, not in place of it. |

Rules:

- A domain can only belong to one tenant. A config that lists the same domain under two `[[tenant]]` blocks fails to load, with both tenant names in the message.
- `quota_bytes` smaller than the sum of `domain_quotas` entries that fall inside the tenant is rejected at load time: a cap that cannot be reached would be a lie on the reseller agreement.
- `max_accounts` is enforced on `POST /api/v1/accounts` as `409 Conflict` (not `429`): waiting will not lift it, the cap lifts when an account is deleted or the operator raises it.
- `quota_bytes` is enforced on `POST /jmap/upload` alongside the per-account quota, with the JMAP limit problem type (`urn:ietf:params:jmap:error:limit`, `limit: "tenant_storage"`, HTTP `507`).
- `submission_rate_limit_per_min` is enforced on SMTP submission, `POST /api/v1/send` and JMAP `EmailSubmission/set` with one counter per tenant shared by the three, counted and charged like the per-account limit (one unit per recipient, once, when the message is accepted, together with the per-account limit or not at all). An account with addresses in two tenants is charged by both. The refusal is the one the per-account limit gives and does not name the tenant.

### `[[transport]]`
Outbound routing rules. Each rule matches by sender `account` (the envelope sender's local part) **or** recipient `domain`; a rule with neither is the catch-all. The most specific match wins (account > domain > catch-all). With no rule, mail is delivered directly via MX. Empty `[[transport]]` keeps that default.

| Key | Meaning |
|---|---|
| `account` | Match mail from this local sender account. |
| `domain` | Match mail to this recipient domain. |
| `kind` | `direct` (MX, the default), `relay` (smarthost), or `fail` (refuse). |
| `host`, `port` | Smarthost address (required for `relay`). |
| `starttls` | Upgrade to TLS before AUTH/mail on a relay. Required when AUTH is set. |
| `username`, `password` | SMTP AUTH for the relay (submission). Sent only over TLS — never in plaintext (fail closed). |
| `socks_proxy` | `host:port` of a SOCKS5 proxy to reach the smarthost through. |
| `enabled` | Default `true`. With `false` the rule stays in the file but is never selected: its mail goes by the next rule that matches, or direct to the recipient's MX when none does. Only a `relay` rule may be switched off; a `fail` rule is a refusal and is removed, not paused. `epistle relay disable\|enable` edits it. |

### `[queue]`
Outbound queue settings. Absent keeps the secure defaults.

| Key | Meaning |
|---|---|
| `outbound_tls` | STARTTLS certificate authentication for a hop that is **not** otherwise mandated or DANE-protected. `strict` (the default) verifies the certificate against the public trust anchors and the MX hostname, exactly like a browser — a self-signed/expired certificate with no DANE/MTA-STS defers the message. `opportunistic` completes the handshake with any certificate (encryption without authentication): it stops passive eavesdropping but not an active man-in-the-middle, and is the historical SMTP norm. |
| `tlsrpt_reports` | Send TLS-RPT reports (RFC 8460) about our outbound TLS, default `true`. Each direct delivery to a recipient MX records its TLS outcome (success, or the failure type: `starttls-not-supported`, `certificate-expired`, `certificate-host-mismatch`, `certificate-not-trusted`, `tlsa-invalid`, `sts-policy-invalid`, `validation-failure`) under `data_dir/reports/tlsrpt-outbound/`. Once a UTC day is over, every domain with sessions that publishes a `_smtp._tls` TXT record gets one report per `rua=`: `mailto:` as a message from `postmaster@<hostname>` with the gzip report attached, queued and DKIM-signed like other mail; `https:` as a POST with `Content-Type: application/tlsrpt+gzip` (30 s timeout, no redirects, at most 1 MiB). Domains without the record get nothing, and the day's sessions are deleted once reported. Mail through a `[[transport]]` relay is not recorded. `false` records and sends nothing. |

| `concurrency` | Outbound SMTP conversations running at once, all destinations together, default `8`, between 1 and 1024. A slow or silent destination holds its own conversations and no others. Read and change it with `epistle limits show` and `epistle limits set queue-concurrency N`. |
| `per_domain_concurrency` | Outbound conversations running at once with any one recipient domain, default `2`, between 1 and `concurrency`. The cap covers every exchanger of the domain together. `epistle limits set queue-per-domain-concurrency N`. |
| `backoff_steps` | How long a destination that asks to slow down is held off, in seconds, one step per deferral in a row with the last repeating: default `[60, 300, 900, 3600]` (1, 5, 15 and 60 minutes), 1 to 16 steps of 1 to 86400 seconds each. `epistle limits set queue-backoff 1m,5m,15m,1h`. |

How the queue delivers:

- **Parallel and bounded.** Up to `concurrency` conversations run at once, at most `per_domain_concurrency` of them with one recipient domain, and a recipient is never in two conversations at once (two passes cannot deliver it twice). Waiting messages cost nothing until a slot frees.
- **Fair across senders.** One sender (the account the server recorded as submitting the message; mail the server sends on its own, such as bounces, auto-replies and forwards, shares one system bucket, whatever its reverse path) runs at most three quarters of `concurrency` at once (6 of the default 8, at least 1), and senders take turns for free slots, so an account queueing thousands of messages to slow or silent destinations never holds every slot, and another sender's message queued behind them goes out at once.
- **Timeouts** (RFC 5321 section 4.5.3.2, fixed): connect 30 s per exchanger (at most two of its addresses, 15 s each), greeting 5 min, EHLO, MAIL and other commands 5 min, each RCPT 5 min, DATA 2 min, each 64 KiB block of the message 3 min, the reply to the final dot 10 min, the STARTTLS handshake 60 s, QUIT 30 s. One whole delivery attempt to a domain, every exchanger and step together, ends after 1 hour. A timeout defers the recipients to their retry schedule.
- **Next exchanger.** A failure before the mail transaction begins (a refused or silent connection, a `4xx` or silent greeting, a failed TLS handshake) moves on to the next MX in the same attempt, at most five per attempt, still only those MTA-STS permits and with DANE checked per host. Once `MAIL` is sent, the replies are about the message and stand.
- **Slowing down.** A `421`, any `4.7.x` reply, or a `451`/`452` about a rate or a limit makes the recipients of that conversation wait for the next step of `backoff_steps` (an attempt counted), and holds their domain and the exchanger host that answered while they wait: no conversation starts with a held domain, every other message to it waits too (no attempt counted), and no other domain served by a held exchanger connects to that host either, so many domains hosted by one provider share its hold. The spool is the only record: each such recipient keeps its next attempt at the end of the wait and counts its slow-down deferrals in a row, which pick the next step and only go back to zero with any other answer, so the backoff grows across holds that ran out and starts over only after a delivery. There is no separate hold table to fill, evict or lose: a restart reads the holds back from the spool. `epistle queue destinations` lists them and `epistle queue release-destination` makes the waiting recipients due at once. A `452 4.5.3` (too many recipients) only sends the recipients left over in another transaction at once.

These keys are read when the server starts: after `epistle limits set` the command restarts the mail service of a stack it manages, or says the server must be restarted.

`outbound_tls` never weakens an authenticated hop: MTA-STS enforce, a sender's REQUIRETLS, and DANE (TLSA records) always authenticate the certificate regardless of `outbound_tls`, and a remote that does not offer STARTTLS where TLS is mandated still defers (never cleartext). The one exception is a message one of your accounts submitted with `TLS-Required: No` (RFC 8689) and without REQUIRETLS: for that message MTA-STS and DANE are set aside, any certificate is accepted, and STARTTLS is still used when offered. Inbound mail loses the field.

## JMAP submission

The JMAP `EmailSubmission/set` and `Email/set` (create) handlers stamp a
fresh `Message-ID` and `Date` header on every message that lacks them. The
stamped `Message-ID` is `<uuidv7@envelope-domain>`, where the
envelope-domain is the `envelope.mailFrom` domain (or the `From` header's
domain for `Email/set` create), and the stamped `Date` is the RFC 5322
form of the server's current UTC time. Client-supplied `Message-ID` and
`Date` are left unchanged: a client that wants to set its own id sends
one. The stamp only fires on authenticated submission; inbound relay
mail from other servers is not modified.

## JMAP VacationResponse

The JMAP session advertises `urn:ietf:params:jmap:vacationresponse` (RFC
8621 section 8) for every account. `VacationResponse/get` returns the
singleton (`ids` and `properties` work as for any `/get`) and
`VacationResponse/set` updates it; `create` and `destroy` are refused with
`forbidden`, the only id is `singleton`, and the properties are
`isEnabled`, `fromDate`, `toDate`, `subject`, `textBody` and `htmlBody`.
The account check is the one every JMAP method uses: an `accountId` the
credential cannot reach is `accountNotFound`.

`/set` refuses with `invalidProperties` a date that is not a UTCDate, a
`fromDate` after `toDate`, a `textBody` or `htmlBody` over 64 KiB, and a
`subject` with a line break or other control character or longer than 998
octets. The setting lives in the account's own directory, at
`<data_dir>/accounts/<account>/.vacation.json`. `htmlBody` is stored as
given and only ever sent as a `text/html` part, never rendered.

When `isEnabled` is true and the current time is inside `fromDate ..
toDate` (either bound optional), mail delivered to the account gets an
auto-reply following RFC 3834 and RFC 5230:

- It goes to the envelope sender (`MAIL FROM`), never to a header
  address, with a null reverse-path, `Auto-Submitted: auto-replied`,
  `In-Reply-To` and `References`. It is queued and DKIM-signed like any
  other outbound message.
- No reply to a null sender, to the account's own addresses, to
  `MAILER-DAEMON`, `LISTSERV`, `majordomo`, `owner-*` or `*-request`, to
  mail with `Auto-Submitted` other than `no`, to mail with any RFC 2369
  `List-*` header, or to `Precedence: bulk`, `list` or `junk`.
- Only when one of the account's addresses, or the address the copy was
  delivered to, is in the message's `To` or `Cc` (RFC 5230 section 4.5).
  Mail that reached the account through `Bcc`, a mailing list or an alias
  gets no reply.
- Only when the server itself verified the sender: the SMTP session
  logged in (local submission, `POST /api/v1/send`, JMAP
  `EmailSubmission/set`), or on the inbound hop SPF passed for the
  envelope sender's domain, or a DKIM signature passed for a domain with
  the same organizational domain as the envelope sender's. A signature by
  the From domain counts only when the From domain shares that
  organizational domain: the reply goes to the envelope sender, and a
  sender can sign mail From a domain of its own while naming someone else
  in `MAIL FROM`. The server takes these from its own checks of each
  message when it accepts it and never from `Authentication-Results`,
  `Received-SPF` or ARC headers in the message.
- One reply per sender per 7 days. Each reply leaves a marker under
  `<account>/.vacation/`, which survives restarts. The account keeps at
  most 4096 markers: when the store is full, markers older than the
  period are removed, and if none is, the new sender gets no reply. A
  marker that cannot be written means no reply.

The Sieve `vacation` action uses the same rules and markers (its `:days`
is held between 1 and 365, and a `:from` the account does not own is
ignored). Only one of the two answers a message: while the JMAP
VacationResponse is enabled it is the account's vacation, and the Sieve
action is ignored, including outside the JMAP date window, when no reply
is sent at all. With the JMAP setting disabled, the Sieve action answers
as before.

## JMAP Sieve scripts

The JMAP session advertises `urn:ietf:params:jmap:sieve` (RFC 9661). Its
session value names the implementation and version. Each account's value
carries the limits below and the extension list, and the Sieve account is a
primary account. The methods are `SieveScript/get`, `SieveScript/query`,
`SieveScript/set` and `SieveScript/validate`. `/get`, `/query` and
`/validate` need the `read` scope and `/set` the `write` scope, and `/set`
also the `send` scope for a script that sends mail (below). The account check
is the one every JMAP method uses. There is no `SieveScript/changes` (the RFC
defines none): a client re-reads with `/get`, which an account can always
answer in full because it holds at most 50 scripts.

**One store, two protocols.** JMAP and ManageSieve (RFC 5804) read and write
the same scripts under `<data_dir>/accounts/<account>/sieve/`, with the same
checks, so a script written by either is listed, valid and active in the
other. Each script has an id of 32 hex digits that survives a rewrite and a
rename through either protocol. `state` (and `queryState`) is a counter that
moves on every change by either protocol and at no other time. Every
operation runs under a lock per account, and a whole `/set` is one step under
it: `ifInState` is compared where the changes are made, so of several calls
carrying one state exactly one runs. Waiting for the lock does not hold a
runtime worker.

| Limit | Value | Advertised as |
|---|---|---|
| Script size | 1 MiB (1048576 octets), also the ManageSieve literal limit | `maxSizeScript` |
| Scripts per account | 50 | `maxNumberScripts` |
| Script name | 128 characters and 200 octets; no control character (U+0000 to U+001F, U+007F to U+009F), no U+2028 or U+2029, no `/` or `\`, no bidirectional formatting character; no leading or trailing white space; Unicode normal form C | `maxSizeScriptName` (200) |
| `redirect` actions per run of a script | 4, each address once | `maxNumberRedirects` |
| `sieveExtensions` | `fileinto envelope vacation imap4flags relational variables reject ereject copy body date mailbox subaddress comparator-i;octet comparator-i;ascii-casemap comparator-i;ascii-numeric`, the list ManageSieve puts in `SIEVE` | `sieveExtensions` |

`notificationMethods` and `externalLists` are `null`: `enotify` and
`extlists` are not run. **Known deviations from RFC 9661:** `maxSizeScriptName`
is 200 and not the 512 octets the RFC asks for, because a script name is a
file name and 200 octets is what fits next to the staging file of an atomic
write; and an empty script is accepted, as ManageSieve accepts it (the RFC
asks for at least one character), so that the one check is the same for both
protocols.

**Content is a blob.** A client uploads the script (`POST
/jmap/upload/{accountId}`) and names the blob in `blobId` on `create` or
`update`. A script's own `blobId` is `sieve-<id>-<revision>` and the
download URL serves that version as `application/sieve`. A script rewritten
since is a new blob id and the old one is a 404. `Blob/upload` and
`Blob/get` (RFC 9404) are not implemented.

**Checks, the same for `/set`, `/validate`, PUTSCRIPT and CHECKSCRIPT.**
UTF-8, at most 1 MiB, valid Sieve (at most 64 levels of blocks, test lists
and `not` chains; a literal `:matches` key of at most 256 characters and 32
wildcards), and `require` only of the extensions listed above. A refusal is
`invalidSieve` with a description that names the line and the kind of mistake
(`line 3: expected '{'`, `extension "enotify" is not supported`) and never
repeats the script. `/validate` answers `error: null` or that SetError,
`tooLarge` or a `blobNotFound` method error, and stores nothing. The check
runs when a script is stored; a script stored before this check and still
active keeps running as it is, but cannot be saved again while it requires an
extension that is not listed.

**`/set`.** `create` takes `name` (or none, and the server picks
`script-<8 hex>`) and `blobId`; `id` and `isActive` are the server's and
are `invalidProperties` if sent. `update` takes `name`, `blobId` or both and
changes nothing if either is refused. SetErrors: `alreadyExists` with the
`existingId` (a name is never overwritten), `tooLarge`, `overQuota` (the
script count), `invalidSieve`, `blobNotFound`, `invalidProperties` with the
property names, `invalidPatch`, `notFound`, `forbidden` (the `send` scope,
below) and `sieveIsActive` for the active script. `ifInState` mismatch is
`stateMismatch`. `#cid` names a creation of the same call in `destroy` and
in `onSuccessActivateScript`; as a key of `update` the dispatcher reads it as
a result reference (RFC 8620 section 3.7), so an update names the id the
server returned.

Exactly one script is active. `onSuccessActivateScript` and
`onSuccessDeactivateScript` run last and only if every create, update and
destroy succeeded, and they are one change: the script that ends up active
is the one named, or none when asked to deactivate, and it is reported as
`isActive` in `created` or `updated`, with the one that was active reported
inactive. An id that names no script is ignored. Activating copies the script
to `<data_dir>/accounts/<account>/filter.sieve`, which delivery reads, and
replaces the previous copy, so delivery always finds a filter; deactivating
removes it. The active script cannot be destroyed: deactivate it in a call of
its own first.

**Scopes.** A script that redirects, replies (`vacation`) or rejects (`reject`,
`ereject`) makes the server send mail when mail arrives, and `write` does not
originate mail. Creating such a script, replacing the content of one, or
activating one that exists takes the `send` scope as well; without it the
answer is `forbidden`, and an activation is refused before the call changes
anything. Renaming and deactivating need only `write`. The action names are
read without regard to case, as Sieve does. The same rule holds for the JMAP
`VacationResponse`, which also answers mail: `VacationResponse/set` that
switches the reply on, or changes one that is on, needs `send` as well
(`notUpdated` `forbidden` without it); switching it off, or editing one that
stays off, needs only `write`. Upgrading: a key with `read` and `write` only
that used to switch the reply on now gets `forbidden`. ManageSieve is reached
with the account's password and has no scopes.

**Vacation.** The JMAP `VacationResponse` is not a Sieve script (it lives
in `.vacation.json`), so a script cannot be confused with it. Both can
exist: while the `VacationResponse` is enabled it is the account's vacation
and the `vacation` action of the active script is ignored, including outside
its date window; with it disabled the script's `vacation` answers, under the
same rules as in the section above.

**What one run of a script may spend.** A script is text its owner wrote,
run against mail anyone can send, so a run is bounded by the server and not
by the script:

- 20000 commands and tests, and 256 MiB of work (octets read and compared).
  The ceiling is fixed: it does not grow with the size of the message, which
  is the sender's choice. A run that passes either stops where it is, as a
  `stop` would, and the log says what happened (once an hour per account).
  What it had decided about where the message goes (`discard`, `fileinto`,
  `keep`, flags) stands, so a big message cannot undo a `discard`. What it had
  asked to send outward (`redirect`, `reject`, `ereject`, `vacation`) is
  dropped, because a run that did not finish never originates mail; and if
  anything outward was dropped, no `discard` stands and the message is kept,
  since a run cannot both lose the forward and suppress the delivery. A
  message nothing local was decided about is kept in INBOX. A string that
  could not be built within the budget does not give its action: the action
  does not happen.
- **What a filter sees of a big message.** A test reads a window, not the
  whole message: the first 1 MiB of the body (the `body` test), and, for a
  `header`, `address` or `date` lookup, the first 1000 values and 64 KiB of
  the headers called each name it lists (a longer value is cut), for at most
  16 names. Every name has its own quota, so a thousand `Received` headers or
  a huge `X-` header cannot hide the `From` or `Subject` listed with them.
  Only the first 10 000 headers of a message are read at all. Mail with more
  than 9 900 header fields is refused before any filter reads it, whatever the
  way in, with one check: `554 5.6.0` at `DATA` and `BDAT`, `422
  too_many_header_fields` on `POST /api/v1/send`, `forbiddenToSend` on JMAP
  `EmailSubmission/set`; every refusal is counted in `rejected_header_fields`
  and logged once an hour. For a local recipient the fields the server adds
  (about a dozen) count too, so the limit there is that many fewer. So no
  sender can hide a `From` or a `Subject` behind padding. (A message stored by
  IMAP `APPEND` or JMAP `Email/import` is not read by a filter until it is
  sent.) The header block ends at the first `CRLF CRLF`, the longest block any reader
  of a message takes (IMAP and POP3 also end it at a bare `LF LF`), so that the
  count never sees fewer fields than a reader does; a message with bare `LF`
  line ends is counted whole, and one with more than 9 900 lines is refused as
  having too many fields.
  A header's value is read as follows: the blanks at its ends are dropped
  (space, tab, VT, FF, CR, NEL, NBSP and the other Unicode white space), every
  run of blanks inside it, folding included, is one space (so `:contains
  "a  b"`, two spaces, and `:contains "a<TAB>b"` no longer match `a  b` or
  `a<TAB>b`, and `:is "a b"` now matches `a  b`), an octet that is not UTF-8 is
  a `?`, and only its first 64 KiB are kept. A header name is at most 998
  octets: a line with a longer one is not a header, and the inspection is
  marked truncated. If a message with more fields got to a filter anyway it
  would be cut, every test that looks at headers (`exists` included) would say
  so as a truncated inspection, and `:count` would count the headers read.
  Text a sender
  puts past a window is not seen by the test, so a rule that must catch
  something should not depend on where in a huge message it is. The run goes
  on with what it saw, and a window that cut something is never silent: the
  log says so once an hour per account, and the counter
  `mail_sieve_inspection_truncated_total` (alert metric
  `sieve_inspection_truncated`) counts the messages for which a test did not
  see everything. Each value is paid for once per lookup, and a key that
  makes a pass over it (`:contains`, `:matches`) costs a quarter of its length
  more. A `:contains` test with 8 or more keys (up to 64 KiB of keys) finds
  them all in one pass, so a block-list of a thousand words costs what reading
  the text twice does, not a thousand passes; a `:matches` list, or a
  `:contains` list over 64 KiB, still costs a pass per key, and a list long
  enough to pass the ceiling on a mebibyte makes the run stop and skips the
  rules after it. 200 ordinary rules never reach the ceiling on a 25 MiB
  message.
- A variable is cut to 4096 octets, a run holds 64 KiB in at most 128 of them,
  and a string built with `${...}` is at most as long as the larger of what
  the script wrote and 4096 octets.
- `:matches` never looks at the length of the text it is given (a sender can
  make a Subject as long as the message allows, and the filter still sees
  it); its cost is counted in the run's budget. A key over 256 characters or
  32 wildcards is never run: saving a script that holds one is refused, and a
  script stored earlier that does treats that test as false and goes on, but
  from that test on the run does not `discard` or `reject`: it keeps the
  message instead, because `not` or `else` can turn that false into the branch
  that loses mail (what the run decided before the test stands; the log says
  so once an hour per account; shorten the key). Upgrading: a
  `:matches` key longer than that, which used to match, now never does.
- `fileinto` files into a folder once however often the script names it, and
  into at most 8 different folders. A folder the filter would make is made
  only while the account stays within 200 folders (INBOX included, every level
  of a deep name counted, at most 4 levels, a name of at most 128 characters
  and without bidirectional controls); past that the message is kept in INBOX
  and the log says so. The count and the creation are under one lock.
- A `redirect` is forwarded at most 4 times per message and to an address
  once, and only if the strict address parser accepts the target (it is
  written into an `RCPT TO` line, so a line break in it would have been an
  SMTP command). A redirect that names something that is not an address is a
  run-time error: the message is kept. Redirects past the limit are not
  forwarded and the log says so. Known gap: the forwards a script
  makes are not charged to the sending limits of
  `submission_rate_limit_per_min`, and a message forwarded to another local
  account is filtered again there. The loop check stops a message that comes
  back to an address it went through, but a chain across different accounts
  that each redirect is bounded only by the number of accounts.
- A filter file over 1 MiB (the store never writes one) is not run, and nor is
  one the parser refuses today (a script stored before a stricter check): mail
  goes to INBOX and the log says so. Every warning a filter causes (a run that
  stopped, a window that cut something, a key over the caps, redirects or
  folders past the limit, a filter that is not run) is logged once an hour per
  account, not once per message.
- `fileinto` past 8 different folders is counted and logged like `redirect`
  past 4. The `.flags` of a message hold at most 32 different flags.

## Example

```toml
hostname = "mail.example.org"
# Keep mail below the service home; never mount the home itself.
data_dir = "/var/lib/glyndor/epistle/data"
domains  = ["example.org"]

queue_give_up_secs = 432000   # 5 days (the default)
greylist_delay_secs = 60

[tls]
cert_file = "/etc/glyndor/epistle/tls/fullchain.pem"
key_file  = "/etc/glyndor/epistle/tls/privkey.pem"

[dkim]
selector = "ed1"
key_file = "/etc/glyndor/epistle/dkim/ed1.pem"

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
