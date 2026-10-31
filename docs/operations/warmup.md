# IP warm-up

A sending address with no history has no reputation. Gmail, Outlook,
Yahoo and iCloud defer or junk mail from it when its volume jumps. The
warm-up ramps the volume up per receiver group, judges each day, and
tells you how it went.

It is off on every install until you start it. `epistle init` offers it
on a new install.

## Start it

Say how old the address is and how much it sends a day, look at the
plan, then start:

```sh
epistle warmup plan --ip-age 0d --daily-volume 1000
epistle warmup start --ip-age 0d --daily-volume 1000
```

`--ip-age` takes days, weeks, months or years (`0d`, `3w`, `6m`, `1y`).
`--group gmail` limits it to one group. `plan` changes nothing; `start`
asks first (`--yes` off a terminal). Neither lowers a cap that is already
higher, or lifted, unless you add `--force`.

Where each group's cap starts (one table, `warmup::stages::STAGES`):

| Address age | Stage | Starting cap |
|---|---|---|
| under 1 week | `new` | 50 |
| 1 to 4 weeks | `weeks` | a quarter of the daily volume |
| 4 weeks to 3 months | `months` | half of the daily volume |
| 3 months or more | `established` | the daily volume |

A cap is never under 50, and a starting cap over 5,000 is no cap at all.
A new address that needs 1,000 a day reaches it after 8 good days.

## What it does

- **Groups** are read from the receiving exchanger, not the recipient
  domain: a Google Workspace domain is `gmail`, a Microsoft 365 domain is
  `outlook`. The groups are `gmail`, `outlook`, `yahoo`, `icloud` and
  `other`. A host only counts as a provider when the provider's name ends
  it on a label boundary.
- **The cap** is recipients a day per group. It is spread across the day
  (one every 24 h divided by the cap, after a burst of an hour's share),
  so 50 a day is not 50 at midnight. An account sending alone may use
  the whole cap. While another account has mail waiting for the same
  cap, each takes at most three quarters of the group's day; mail the
  server sends on its own counts as one more account, `system`.
- **Over the cap** a recipient waits in the queue. That is not a failure
  and not a deferral: no attempt is counted, nothing goes to the delivery
  log or the webhook, and `epistle queue list` shows `warm-up cap`. The
  wait does not count toward the give-up window (`queue-give-up`) or the
  delay warning. A message never expires because of the cap: once the cap
  opens, or the warm-up is turned off, its recipients go out and get the
  full window of real retries.
- **Days are UTC days**, the same days as the delivery log files.

Direct delivery only: mail through a smarthost (`epistle relay`) goes out
from the smarthost's address and is not capped.

## How a day is judged

From the delivery log, by reply code, never by reply text:

| Counted as | Replies |
|---|---|
| deferred | `421`, any `4.7.x` (one per recipient per day) |
| bounced | any `5xx` except `5.7.x`, unknown users included |
| spam block | `5.7.x` |

Unknown users count because receivers count them against the sender: a
list with many dead addresses must not grow. Mail a `[[transport]]`
relay rule hands to a smarthost leaves from the smarthost's address, so
the smarthost's replies are left out.

| Day | When | Effect on the cap |
|---|---|---|
| good | under 2 % deferred, under 2 % bounced, no spam block | grows ×1.5 if half the cap was used; past 5,000 it is lifted |
| bad | anything else | holds |
| very bad | over 10 % deferred, or any spam block | one step back, never under 50 |

In `other`, whoever owns a domain answers for its exchangers, so a spam
block counts with the bounces as a share of the day instead of backing
the group off by itself; over 10 % is very bad.

The warm-up needs the delivery log (`[storage] delivery_log_days` above
0); `enable` and `start` refuse without it.

## Raise it yourself

```sh
epistle warmup set gmail --cap 300     # raise or lower the cap
epistle warmup set gmail --next        # one growth step ahead
epistle warmup reset gmail             # back to 50
epistle warmup pause | resume          # caps stay, no day moves them
epistle warmup enable | disable
```

A raise is on trial on its first full day. If that day is good the raise
stays (`warmup.ok`, raise `kept`); if not, the cap goes back to where it
was (`warmup.backoff`, raise `reverted`). Every command takes `--json`,
and a running server picks the change up without a restart.

## Read the report

```sh
epistle warmup status
epistle status            # the warmup line
```

Per group: today's cap, recipients sent, deferred and bounced shares so
far, the verdict the day would get now, the cap it would leave, and the
mail waiting. Then the last judged day, with the accounts behind most bad
replies, and any order the server has not applied yet.

A day is judged within a minute of its end. Each judged day is also
sent as a webhook event, `warmup.ok`,
`warmup.held` or `warmup.backoff`, with the group, day, cap, shares,
verdict, next cap, raise outcome and those accounts. The counters
`warmup_held` and `warmup_backoff` can drive an `epistle alert` rule.

## One account can hurt everyone

Reputation belongs to the sending address, so all accounts are judged
together: an account mailing dead addresses or spam traps can hold or
step back a group's cap for everybody. The report names the accounts
with the most bad replies; slow them with `epistle limits set
submission-rate --tenant …` or deal with the account. The warm-up does
not leave such an account out of the verdict.

## It does not replace the basics

The warm-up only paces volume. Receivers still check SPF, DKIM, DMARC
and the PTR record (`epistle check dns`), and their own tools show what
they think of you: Google Postmaster Tools and Microsoft SNDS. Register
the address there before you start.

## Files

`<data_dir>/warmup.json` holds your settings and orders, written only by
`epistle warmup`. `<data_dir>/warmup-state.json` holds caps, today's use
and 90 days of history, written only by the server. Both are `0600`. A
file that is a link, writable by others, or owned by anyone but the
server's user, root or the owner of the data directory is not trusted: the server keeps the caps on and starts every group over, with
the day counted as used.
