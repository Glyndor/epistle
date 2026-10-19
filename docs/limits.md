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
- `recommended`: the standard recommends a floor (`RFC 5321 §4.5.4.1`
  suggests 4-5 days for the queue give-up window, 30 minutes for the
  first retry). The server accepts a value below the floor with a one-line
  warning naming the RFC clause, never refuses. The deviation is visible in
  the audit trail alongside the saved value.
- `fixed`: the standard forbids crossing the bound; the value is
  hard-coded in the server. `limits show` lists it so the operator sees
  what the server enforces, but `limits set` has no path to override it.

The `bounds` column records the floor or ceiling the standard imposes,
when there is one. The `reference` column names the RFC and section the
rule comes from.

## Adjustable limits

| key | default | unit | kind | bounds | reference |
| --- | --- | --- | --- | --- | --- |
| `quota` | 5368709120 | bytes | adjustable | | no standard mandate |
| `submission-rate` | | messages-per-minute | adjustable | | no standard mandate |
| `new-recipients-per-day` | | count | adjustable | | no standard mandate |
| `queue-give-up` | 432000 | seconds | recommended | at-least 345600 | RFC 5321 §4.5.4.1 (4-5 days recommended) |
| `queue-retry-base` | 60 | seconds | recommended | at-least 1800 | RFC 5321 §4.5.4.1 (30 minutes recommended) |
| `queue-retry-cap` | 3600 | seconds | adjustable | | no standard mandate |
| `queue-delay-warning` | 14400 | seconds | adjustable | | no standard mandate |
| `inbound-rate-per-ip` | | messages-per-minute | adjustable | | no standard mandate |
| `inbound-rate-per-sender` | | messages-per-minute | adjustable | | no standard mandate |
| `max-connections-per-listener` | protocol defaults | count | adjustable | | no standard mandate |
| `max-connections-per-ip` | 20 | count | adjustable | | no standard mandate |
| `masked-addresses-max` | 100 | count | adjustable | | no standard mandate |
| `first-time-sender-delay` | 0 | seconds | adjustable | | no standard mandate |
| `greylist-delay` | 0 | seconds | adjustable | | no standard mandate |
| `queue-concurrency` | 8 | count | adjustable | | no standard mandate |
| `queue-per-domain-concurrency` | 2 | count | adjustable | | no standard mandate |
| `queue-backoff` | 60,300,900,3600 | seconds | adjustable | | no standard mandate |
| `max-message-size` | 26214400 | bytes | adjustable | | no standard mandate |
| `max-recipients` | 100 | count | fixed | at-least 100 | RFC 5321 §4.5.3.1.8 (at least 100) |
| `message-memory-budget` | derived | bytes | adjustable | | no standard mandate |
| `min-data-rate` | 10240 | bytes-per-second | adjustable | | no standard mandate |
| `data-rate-grace` | 120 | seconds | adjustable | | no standard mandate |
| `junk-command-limit` | 100 | count | adjustable | | no standard mandate |
| `max-session-time` | 1800 | seconds | adjustable | | no standard mandate |
| `preauth-timeout` | 60 | seconds | adjustable | | no standard mandate |
| `max-mailbox-connections-per-ip` | 200 | count | adjustable | | no standard mandate |
| `max-http-connections` | 1024 | count | adjustable | | no standard mandate |
| `max-http-connections-per-ip` | 256 | count | adjustable | | no standard mandate |

## Fixed standards

The following limits the server enforces because the standards make them
mandatory (MUST). They are listed so the operator sees what is in force;
`epistle limits set` has no path to override any of them.

| key | value | unit | reference |
| --- | --- | --- | --- |
| `smtp-line-length` | 998 | octets | RFC 5321 §4.5.3.1.4 (998 octets incl. CRLF) |
| `smtp-command-minimum-timeout` | 300 | seconds | RFC 5321 §4.5.3.2 (5 minute minimum) |
| `smtp-never-bounce-a-bounce` | true | boolean | RFC 5321 §5.3.3 (no bounce of a bounce) |
| `spf-max-dns-lookups` | 10 | count | RFC 7208 §4.6.4 (max 10 DNS-querying terms) |
| `spf-max-void-lookups` | 2 | count | RFC 7208 §4.6.4 (max 2 void lookups) |
| `tls-minimum-version` | 1.2 | version | RFC 8996 (TLS 1.0/1.1 prohibited) |

## Failing a MUST or a SHOULD

`epistle limits set` runs the candidate value through three checks in
order: the value's own type (size, duration, count), the catalog's
standard floor (the `at-least` / `at-most` in the table above), and
finally `Config::validate()` on the resulting configuration. The
`at-least 100` floor on `max-recipients` is the only MUST the catalog
enforces today: a value below it is refused with

```
refused: RFC 5321 §4.5.3.1.8 requires accepting at least 100 recipients
```

The SHOULD floors on `queue-give-up` and `queue-retry-base` are accepted
with a warning naming the recommendation:

```
warning: queue-give-up is below the 4 days RFC 5321 §4.5.4.1 recommends; recipients will bounce sooner than the standard expects
warning: queue-retry-base is below the 30 minutes the RFC recommends; the first retry is sooner than receivers expect
```

The same warnings are printed at start-up so a configuration that was
edited months ago still tells the operator what was crossed. The
audit trail keeps both the saved value and the warning line so the
deviation is visible later.