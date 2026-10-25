# Limits and standards

This page is the operator-facing mirror of the catalog `epistle limits show`
enumerates. The two surfaces are kept in lockstep by a test
(`tests/limits_docs.rs`) that reads every row of the in-process catalog and
asserts a corresponding row here; a row the catalog gains without a row
added to this page trips the test, and a row removed trips it too.

Every limit the server enforces has one row below. The `kind` column says
whether the operator can change the value, and what the standard says
about that change:

- `adjustable`: the operator may set the value through
  `epistle limits set`. The value must pass the floors
  `Config::validate()` enforces.
- `recommended` (a SHOULD): the standard recommends a floor
  (`RFC 5321 §4.5.4.1` suggests 4-5 days for the queue give-up window, 30
  minutes for the first retry). The server accepts a value below the floor
  with a one-line warning naming the RFC clause, never refuses. The
  deviation is visible in the audit trail alongside the saved value.
- `must` (a MUST): the standard makes the floor mandatory. The operator may
  raise the value, but `limits set` refuses anything below the floor and
  leaves the file as it was (`0` is accepted and means the default). A
  configuration file that already holds a value below it still loads: the
  value is raised to the floor, with a warning that names the value in the
  file and the one in use, in the log, in `epistle config-check` and in
  `epistle status`.
- `fixed`: the value is hard-coded in the server. `limits show` lists it so
  the operator sees what the server enforces, but `limits set` has no path
  to change it.

The `bounds` column records the floor the standard imposes, when there is
one. The `reference` column names the RFC and section the
rule comes from.

## Adjustable limits

| key | default | unit | kind | bounds | reference |
| --- | --- | --- | --- | --- | --- |
| `quota` | 5368709120 | bytes | adjustable | | no standard mandate |
| `submission-rate` | | count | adjustable | | no standard mandate |
| `new-recipients-per-day` | | count | adjustable | | no standard mandate |
| `queue-give-up` | 432000 | seconds | recommended | at-least 345600 | RFC 5321 §4.5.4.1 (4-5 days recommended) |
| `queue-retry-base` | 60 | seconds | recommended | at-least 1800 | RFC 5321 §4.5.4.1 (30 minutes recommended) |
| `queue-retry-cap` | 3600 | seconds | adjustable | | no standard mandate |
| `queue-delay-warning` | 14400 | seconds | adjustable | | no standard mandate |
| `inbound-rate-per-ip` | | count | adjustable | | no standard mandate |
| `inbound-rate-per-sender` | | count | adjustable | | no standard mandate |
| `max-connections-per-listener` | protocol defaults | count | adjustable | | no standard mandate |
| `max-connections-per-ip` | 20 | count | adjustable | | no standard mandate |
| `max-connections-per-account-per-ip` | 10 | count | adjustable | | no standard mandate |
| `max-connections-per-account-total` | 50 | count | adjustable | | no standard mandate |
| `masked-addresses-max` | 100 | count | adjustable | | no standard mandate |
| `first-time-sender-delay` | 0 | seconds | adjustable | | no standard mandate |
| `greylist-delay` | 0 | seconds | adjustable | | no standard mandate |
| `queue-concurrency` | 8 | count | adjustable | | no standard mandate |
| `queue-per-domain-concurrency` | 2 | count | adjustable | | no standard mandate |
| `queue-backoff` | 60,300,900,3600 | seconds | adjustable | | no standard mandate |
| `max-message-size` | 26214400 | bytes | must | at-least 65536 | RFC 5321 §4.5.3.1.7 (at least 64K octets) |
| `max-recipients` | 100 | count | must | at-least 100 | RFC 5321 §4.5.3.1.8 (at least 100) |
| `message-memory-budget` | derived | bytes | adjustable | | no standard mandate |
| `min-data-rate` | 10240 | bytes-per-second | adjustable | | no standard mandate |
| `data-rate-grace` | 120 | seconds | adjustable | | no standard mandate |
| `junk-command-limit` | 100 | count | adjustable | | no standard mandate |
| `max-session-time` | 1800 | seconds | adjustable | | no standard mandate |
| `preauth-timeout` | 60 | seconds | adjustable | | no standard mandate |
| `known-network-window` | 2592000 | seconds | adjustable | | no standard mandate |
| `max-mailbox-connections-per-ip` | 200 | count | adjustable | | no standard mandate |
| `max-http-connections` | 1024 | count | adjustable | | no standard mandate |
| `max-http-connections-per-ip` | 256 | count | adjustable | | no standard mandate |

## Fixed limits

The limits the server hard-codes and a client can run into. A number is read
from the constant the server enforces, and a test fails when a constant that
reads as a limit in the SMTP, POP3, IMAP, ManageSieve, Sieve, JMAP and SPF
modules (and the address, mailbox name and header rules in `util`) is
neither a row here nor excused in the test with a reason. Two rows are rules
and not constants: `smtp-never-bounce-a-bounce` is fixed text, and
`tls-minimum-version` is the oldest of the versions every listener is built
with. `epistle limits set` has no path to change any of them.

The `class` column says how strongly a standard ties the limit:

- `must`: the standard makes it mandatory; the server is broken below it.
- `should`: the standard recommends it and clients may rely on it (the JMAP
  request limits are the least RFC 8620 §2 recommends a server to offer).
- `own`: no standard fixes the number; it is a bound epistle picked.

The idle timers of POP3 (10 minutes) and IMAP (30 minutes) are the
inactivity timers of a signed-in session. Before sign-in the session is
bounded by `preauth-timeout` (60 seconds by default), which is a limit of its
own and not one of the MUSTs above.

A script name longer than 200 octets, which RFC 5804 §1.6 requires a server
to accept up to 512, is kept under a file named after its SHA-256 digest,
with a `.name` file beside it that holds the name. A name that starts with
`~sha256-` is refused, and a script file put in the directory by hand is
listed only when its file name is its own name (200 octets or fewer) or it
has the `.name` file; any other is left out of the list, with a warning in
the log.

| key | value | unit | class | reference |
| --- | --- | --- | --- | --- |
| `smtp-line-length` | 998 | octets | must | RFC 5321 §4.5.3.1.6 (998 octets excl. CRLF; 1000 incl. CRLF) |
| `smtp-command-line` | 512 | octets | must | RFC 5321 §4.5.3.1.4 (at least 512 octets incl. CRLF; 512 are accepted excl. CRLF) |
| `smtp-command-minimum-timeout` | 300 | seconds | should | RFC 5321 §4.5.3.2.7 (a timeout of at least 5 minutes) |
| `smtp-never-bounce-a-bounce` | true | boolean | must | RFC 5321 §3.6.3 (no notification about a notification) |
| `smtp-address-length` | 254 | octets | must | RFC 5321 §4.5.3.1.3 (path of 256 octets with the angle brackets) |
| `smtp-local-part-length` | 64 | octets | must | RFC 5321 §4.5.3.1.1 (local part of 64 octets) |
| `smtp-domain-length` | 253 | octets | must | RFC 5321 §4.5.3.1.2 and RFC 1035 §2.3.4 (255 octets on the wire, 253 as written) |
| `smtp-domain-label-length` | 63 | octets | must | RFC 1035 §2.3.4 (labels of 63 octets) |
| `smtp-received-hop-limit` | 100 | count | should | RFC 5321 §6.3 (a Received count near 100 is a loop) |
| `smtp-header-fields` | 9900 | count | own | no standard mandate |
| `smtp-error-streak` | 20 | count | own | no standard mandate (consecutive error replies before the connection is dropped) |
| `pop3-command-line` | 512 | octets | must | RFC 2449 §4 (commands of at least 255 octets) |
| `pop3-idle-timeout` | 600 | seconds | must | RFC 1939 §3 (an inactivity timer of at least 10 minutes; before sign-in preauth-timeout bounds the session) |
| `pop3-error-streak` | 20 | count | own | no standard mandate (consecutive -ERR replies the client earns by its own errors before the connection is dropped; a [SYS/...] reply is not counted) |
| `pop3-unavailable-streak` | 200 | count | own | no standard mandate (consecutive replies for a message that cannot be read before the connection is dropped) |
| `pop3-messages-per-session` | 100000 | count | own | no standard mandate (messages a session lists; the newest when the inbox holds more) |
| `pop3-message-octets` | 67108864 | octets | own | no standard mandate (largest message a session lists and retrieves) |
| `imap-command-line` | 32768 | octets | own | no standard mandate |
| `imap-idle-timeout` | 1800 | seconds | must | RFC 3501 §5.4 (an autologout timer of at least 30 minutes; before sign-in preauth-timeout bounds the session) |
| `imap-error-streak` | 20 | count | own | no standard mandate (consecutive BAD replies before the connection is dropped) |
| `imap-keywords-per-message` | 32 | count | own | no standard mandate |
| `imap-keyword-length` | 64 | octets | own | no standard mandate |
| `imap-mailbox-depth` | 16 | count | own | no standard mandate |
| `imap-mailbox-name-length` | 255 | octets | own | no standard mandate (NAME_MAX of the common filesystems) |
| `imap-search-depth` | 64 | count | own | no standard mandate |
| `managesieve-script-size` | 1048576 | octets | own | no standard mandate |
| `managesieve-scripts-per-account` | 50 | count | own | RFC 9661 (maxNumberScripts capability) |
| `managesieve-script-name-length` | 128 | characters | must | RFC 5804 §1.6 (names of up to 128 characters) |
| `managesieve-script-name-bytes` | 512 | octets | must | RFC 5804 §1.6 (128 characters take up to 512 octets) |
| `managesieve-auth-failures` | 3 | count | own | no standard mandate (failed AUTHENTICATE attempts before the connection is dropped) |
| `managesieve-idle-timeout` | 1800 | seconds | own | no standard mandate |
| `sieve-redirects` | 4 | count | own | RFC 9661 (maxNumberRedirects capability) |
| `sieve-fileinto` | 8 | count | own | no standard mandate |
| `sieve-flags` | 32 | count | own | no standard mandate |
| `sieve-flag-length` | 64 | octets | own | no standard mandate (the IMAP keyword limit) |
| `sieve-nesting-depth` | 64 | count | own | no standard mandate |
| `sieve-variable-length` | 4096 | octets | own | RFC 5229 §4.1 (a server may keep as little as 4000 octets) |
| `sieve-variables-total-bytes` | 65536 | octets | own | no standard mandate |
| `sieve-variables` | 128 | count | own | no standard mandate |
| `sieve-variable-name-length` | 64 | octets | own | no standard mandate |
| `sieve-steps` | 20000 | count | own | no standard mandate |
| `sieve-work` | 268435456 | octets | own | no standard mandate |
| `sieve-headers` | 10000 | count | own | no standard mandate |
| `sieve-header-name-length` | 998 | octets | own | RFC 5322 §2.1.1 (lines of 998 octets) |
| `sieve-body-window` | 1048576 | octets | own | no standard mandate |
| `sieve-header-name-values` | 1000 | count | own | no standard mandate |
| `sieve-header-name-window` | 65536 | octets | own | no standard mandate |
| `sieve-header-names-per-lookup` | 16 | count | own | no standard mandate |
| `sieve-pattern-length` | 256 | characters | own | no standard mandate |
| `sieve-wildcards` | 32 | count | own | no standard mandate |
| `jmap-max-size-request` | 10000000 | octets | should | RFC 8620 §2 (maxSizeRequest, at least 10000000 recommended) |
| `jmap-max-calls-in-request` | 16 | count | should | RFC 8620 §2 (maxCallsInRequest, at least 16 recommended) |
| `jmap-max-concurrent-requests` | 4 | count | should | RFC 8620 §2 (maxConcurrentRequests, at least 4 recommended) |
| `jmap-max-concurrent-upload` | 4 | count | should | RFC 8620 §2 (maxConcurrentUpload, at least 4 recommended) |
| `jmap-max-objects-in-get` | 500 | count | should | RFC 8620 §2 (maxObjectsInGet, at least 500 recommended) |
| `jmap-max-objects-in-set` | 500 | count | should | RFC 8620 §2 (maxObjectsInSet, at least 500 recommended) |
| `jmap-event-source-min-ping` | 1 | seconds | own | RFC 8620 §7.3 (ping interval) |
| `jmap-event-source-max-ping` | 300 | seconds | own | RFC 8620 §7.3 (ping interval) |
| `jmap-event-streams-per-caller` | 4 | count | own | no standard mandate |
| `jmap-push-subscriptions-per-caller` | 16 | count | own | no standard mandate |
| `spf-max-dns-lookups` | 10 | count | must | RFC 7208 §4.6.4 (max 10 DNS-querying terms) |
| `spf-max-void-lookups` | 2 | count | should | RFC 7208 §4.6.4 (void lookups limited to 2) |
| `tls-minimum-version` | 1.2 | version | must | RFC 8996 (TLS 1.0/1.1 prohibited) |

## Failing a MUST or a SHOULD

`epistle limits set` runs the candidate value through three checks in
order: the value's own type (size, duration, count), the catalog's
standard floor (the `at-least` in the table above), and finally
`Config::validate()` on the resulting configuration. The `at-least 100`
floor on `max-recipients` (100) and the 64K floor on `max-message-size` are
the MUSTs among the adjustable keys (the operator may set a value above
them): a value below the first is refused with

```
refused: RFC 5321 §4.5.3.1.8 requires accepting at least 100 recipients
refused: RFC 5321 §4.5.3.1.7 requires accepting messages of at least 64K octets
```

The SHOULD floors on `queue-give-up` and `queue-retry-base`
are accepted with a warning naming the recommendation:

```
warning: queue-give-up is below the 4 days RFC 5321 §4.5.4.1 recommends; recipients will bounce sooner than the standard expects
warning: queue-retry-base is below the 30 minutes the RFC recommends; the first retry is sooner than receivers expect
```

The warnings are printed at start-up so a configuration that was
edited months ago still tells the operator what was crossed. The
audit trail keeps both the saved value and the warning line so the
deviation is visible later.
