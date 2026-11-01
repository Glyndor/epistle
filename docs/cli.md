# CLI reference

All administration is done through the `epistle` command. Every command that needs
configuration defaults to `/etc/epistle/mail.toml`. Use `--config <FILE>` to
select another file, for example `epistle account list --config /path/to/mail.toml`.
Run `epistle <command> --help` for the exact flags.

## Resources

Commands take the shape `epistle <resource> <action>`. Every command accepts
`--json` and then prints exactly one JSON document on stdout: a list an
array, a show an object. A change prints one object with `result` (`saved`,
`unchanged`, `dry-run`; `queued` for work the running server picks up,
`done` once a stack command finished, `passed` for a test), `action`, the
fields naming what changed (an account, an address, a label, a new secret
shown once) and `reload` when the command waits for the server: `loaded`,
`no-server`, `timed-out`, `restarted`, `restart-failed`, `restart-needed`
or `none`. Notes and errors stay on stderr, and so does the output of the
podup run a command starts, so a failure leaves stdout empty. The commands
whose stdout already is the product take no `--json`: `serve`, `local` and
`mta-sts-serve` (they run until stopped), `export` and `backup` (the mbox
and the archive), `completions`, `report-abuse`, `mobileconfig`,
`autoconfig` and `autodiscover` (the documents themselves); `stack logs`
refuses it. The older flat forms in the table below take `--json` too and
print what the resource form prints.
Exit codes: `0` done, `1` the operation failed (I/O, database), `2` usage
error or not found (unknown name, rejected input, a destructive action
without `--yes`), `3` refused by policy (a static account, a reached limit,
a setting the change needs that is missing, such as `srs_secret` for a
forward). Policy refusals exited `2` before they had their own code.

| Resource | Actions | Older flat form (hidden, still works) |
|---|---|---|
| `account` | `list`, `show`, `add`, `remove`, `password`, `enable`, `disable`, `address add\|remove`, `quota`, `protocols`, `save-sent`, `find-log-id` | `accounts`, `account-add`, `account-remove` |
| `account forward` | `list`, `add`, `remove` | |
| `account catch-all` | `list`, `add`, `remove` | |
| `account 2fa` | `show`, `disable` | |
| `app-password` | `list`, `create`, `rotate`, `rename`, `revoke` | `app-passwords`, `app-password-create`, `app-password-revoke` |
| `api-key` | `list`, `create`, `revoke`, `rotate` | `api-keys`, `api-key-create`, `api-key-revoke` |
| `suppression` | `list`, `show`, `add`, `remove`, `export`, `import` | `suppression`, `suppression --remove ADDR` |
| `warmup` | `status`, `plan`, `start`, `enable`, `disable`, `pause`, `resume`, `set`, `reset` | |
| `domain` | `list`, `show`, `add`, `remove`, `set`, `disable`, `enable`, `alias add\|remove` | |
| `db` | `upgrade`, `status` | |
| `evidence` | `verify`, `export`, `check`, `key show\|rotate`, `policy show\|set`, `timestamp show\|enable\|disable`, `clock accept`, `acknowledge`, `abandon` | |
| `learning` | `status`, `enable`, `disable`, `reset` | |
| `masked`, `ban`, `queue`, `alias`, `limits`, `relay`, `service`, `dkim`, `tls` | see each section below | |

## Shell completion and man pages

The Debian package installs completion for bash, zsh and fish, and a man page
per command: `man epistle`, `man epistle-account`, `man epistle-account-add`.
Both are generated from the binary at package build time, so they match the
installed version. With a binary installed by hand, print the script yourself:

```sh
epistle completions bash > ~/.local/share/bash-completion/completions/epistle
epistle completions zsh > ~/.zfunc/_epistle   # a directory on your $fpath
epistle completions fish > ~/.config/fish/completions/epistle.fish
```

## Common tasks

Every change is validated before it is written, keeps the comments in
`mail.toml`, accepts `--dry-run`, and restarts `mail` only when it has to.

| I want to… | Command |
|---|---|
| [Is it working?](#health-epistle-status-epistle-check) | `epistle status`, `epistle check <area>` |
| [Turn IMAP, POP3, 587… on or off](#service-listeners) | `epistle service list\|enable\|disable` |
| [Accounts: add, password, disable, quota, addresses](#accounts) | `epistle account …` |
| [Connect Roundcube webmail](roundcube.md) | IMAP/SMTP configuration and checks |
| [Aliases and mailing lists](#aliases-epistle-alias) | `epistle alias …` |
| [Domains and domain aliases](#domains-epistle-domain) | `epistle domain …` |
| [Masked addresses](#masked-addresses) | `epistle masked …` |
| [Limits: quota, send rate, connections](#server-limits-epistle-limits) | `epistle limits show\|set\|unset` |
| [Bans and the IP allow list](#authentication-bans) | `epistle ban …` |
| [Outbound queue: retry, hold, release](#outbound-queue) | `epistle queue …` |
| [IP warm-up for a new sending address](operations/warmup.md) | `epistle warmup …` |
| [Evidence of sending: verify, export, check](evidence.md) | `epistle evidence …` |
| [Antispam: DNSBL, greylisting, ClamAV](#antispam-epistle-antispam) | `epistle antispam …` |
| [Attachment policy and checking a message](#attachments-epistle-attachments) | `epistle attachments policy\|check` |
| [Relay through a smarthost](#smarthost-relay-epistle-relay) | `epistle relay …` |
| [DNS provider for DKIM and TLSA](#dns-provider-epistle-dns-provider) | `epistle dns provider …` |
| [Webhook and alerts](#webhook-epistle-webhook) | `epistle webhook …`, `epistle alert …` |
| [Blob storage (filesystem or S3)](#blob-storage-epistle-storage-blobs) | `epistle storage blobs …` |
| [Rotate DKIM, renew TLS, rotate an API key](#rotations-epistle-dkim-epistle-tls-epistle-api-key) | `epistle dkim rotate`, `epistle dkim cleanup`, `epistle tls renew`, `epistle api-key rotate` |
| [Containers: up, logs, update](#stack-epistle-stack) | `epistle stack …` |
| [Backup and restore](#backup-and-restore) | `epistle backup`, `epistle restore` |

## Output

Every `epistle` subcommand splits its output into two streams by purpose:

- **stdout** carries command data or listings. The five data commands below
  never carry an ANSI escape sequence there, no matter the terminal, no matter
  `NO_COLOR`, no matter `CLICOLOR_FORCE`; the property is pinned by
  `tests/cli/cli_stdout_clean.rs`. `clap`'s `--help` and `--version` also write to
  stdout and follow the same precedence, so `--help` may colourise its text
  under `CLICOLOR_FORCE=1` or a real terminal.
- **stderr** carries status, warnings, errors and progress, including the
  spinner of the long commands.

On a terminal, `status`, `check`, `probe`, `verify-dns` and the list commands
draw their state as ✔ (green), ⚠ (yellow) or ✘ (red; dimmed for something
switched off), with aligned columns cut with `…` to the window width, and the
long commands (`backup`, `restore`, `export`, `verify`, `verify-dns`, `probe`,
`status`, `check`, `dkim rotate`, `tls renew`) show a spinner on stderr with the
elapsed time, ending in a ✔ or ✘ row with the total. A command missing its
account, alias, domain or key label offers the existing ones to pick from.
Each stream is decided on its own, and nothing of this happens when that stream
is not a terminal (for the pick, stdin and stderr), when `NO_COLOR` is set, when
`TERM=dumb`, when `CLICOLOR=0`, or with `--json`: the output is then the plain
one scripts read, byte for byte, and a missing argument is a usage error with
exit code 2. `CLICOLOR_FORCE` never turns any of this on in a pipe.

Five commands produce binary or quoted data on stdout and would silently break if
an escape sequence or spinner frame were ever written there, so they are pinned by
`tests/cli/cli_stdout_clean.rs`:

| Command | stdout payload |
|---|---|
| `epistle backup` | A gzip-compressed tar of `data_dir` (and a `pg_dump` when configured). The `pg_dump` is taken inside the `db` service with `podup exec -T db pg_dump` when `<data_dir>/compose/compose.yaml` exists, and through the host `pg_dump` otherwise. |
| `epistle restore` | Replay a backup tar.gz (read from stdin) over `data_dir` and, when a database is configured, into the database. Reads the archive from stdin; a configured database that cannot be loaded is a hard error. |
| `epistle export --account N` | An mbox stream (`From MAILER-DAEMON@localhost` separators). |
| `epistle storage-keygen` | A single base64 32-byte at-rest key. |
| `epistle oauth-keygen --out F` | Write a PKCS#8 ES256 private key plus the matching public point to `F` (mode 0600, an existing file is refused). The private key is never printed. |

## Prompts and `--yes`

Questions and password prompts go to stderr. stdout carries only command
output, so `--json` stays parseable.

**Passwords.** On a terminal, `account add` and `account password` ask for the
password with echo off, then ask again (`Repeat password`); two different
values are refused with `passwords do not match`. The password policy still
applies (12 to 64 printable ASCII characters, not on the breached list) and the
error names the rule that failed. `account password` checks that the account
exists before it asks: an unknown name fails with `no such account: <name>`,
a static one with the hint to edit the config file. `relay add
--password-stdin` and `webhook set --secret-stdin` also read with echo off on
a terminal. Echo comes back when the read ends, Ctrl-C included.

**Destructive commands.** `account remove`, `account 2fa disable`,
`app-password revoke`, `app-password rotate`, `relay disable`, `api-key revoke`, `archive purge`, `domain remove`, `domain disable`, `domain alias remove`,
`alias remove`, `masked remove`, `queue remove` and `restore` ask before they
change anything, and the question names what goes: the account with its masked
addresses and app passwords, the API key's scopes, the queued message's sender
and recipient count, the number of archived entries (`Purge all N archived
entries` when `archive purge` has no `--older-than-days`). Only `y` or `yes`
goes ahead; anything else, Enter included, cancels with exit code 2. `restore`
reads the archive on stdin, so it asks on the controlling terminal. A
`--dry-run` asks nothing.

**Scripts.** Without a terminal (stdin or stderr redirected) nothing is asked.
A secret is read as one line from stdin, as before. A destructive command exits
2 with `<command> was not confirmed; re-run with --yes to apply, or answer the
question on a terminal` and changes nothing; pass `--yes` (`-y`) to go ahead.
On `restore`, `--yes` only answers the question: overwriting a non-empty
`data_dir` or running against a live service still needs `--force`.

`backup`'s `warnings` sink (the externally-referenced paths that are not in the
archive) is also stderr, by the same rule.

Colour (the `error:` and `warning:` prefixes, and clap's usage errors) is
decided once, in this order: `NO_COLOR` set and not empty turns it off;
`CLICOLOR_FORCE` set and not `0` turns it on, even in a pipe; `CLICOLOR=0`
turns it off; otherwise the stream must be a terminal and `TERM` not `dumb`.
`CI` and similar variables play no part. clap gets the same answer as epistle,
so a usage error and an `error:` line are always coloured alike; `--help` and
`--version` apply it to stdout, where they print. To force a specific look in
a script:

```sh
# Coloured status, plain stdout data:
epistle backup > backup.tar.gz

# Plain everywhere, for a log file:
NO_COLOR=1 epistle backup > backup.tar.gz
```

`import` keeps a single progress line on stderr (one tick per message) that
gets cleared when it finishes. When stderr is not a terminal, the progress line
is suppressed and the summary is printed once at the end.

## Service listeners

```sh
epistle service list
epistle service list --json
epistle service enable imaps
epistle service disable imap
epistle service set imap --bind 127.0.0.1
epistle service set api --bind 127.0.0.1 --port 8025
epistle service --config /path/to/mail.toml enable submission
```

`list` shows enabled or disabled state, port, and bind address. Enabled rows use
actual configured sockets, including custom ports; disabled rows show the defaults
that `enable` would use. JSON records contain `name`, `enabled`, `port`, and `bind`,
plus `host` on a container stack where the generated map pins one.

Names are `imap` (143), `imaps` (993), `submission` (587), `submissions` (465),
`pop3` (implicit TLS, 995), `managesieve` (4190), `webdav` (8090), and `api`
(loopback, 8025). IMAP and submission TLS siblings can be toggled independently.
`smtp` (25) cannot be disabled because inbound mail needs it.

Edits preserve every other configuration value, use init's comment-free TOML
formatting, and validate through the normal loader before atomically replacing
`/etc/epistle/mail.toml` (or `--config`). Existing TLS and API prerequisites must
be valid. New mail listeners inherit SMTP's bind address; the listeners with no
TLS transport of their own (`api`, `webdav`) start on loopback, so enabling one
publishes nothing until `set --bind` opens it.
An already enabled or disabled service reports no change and exits successfully,
and so does `set` asked for the socket the listener already has.

`set NAME [--bind ADDRESS] [--port PORT]` moves a listener that is already
enabled, so `enable` is what adds one. It refuses a port another enabled
listener answers on, a port 0, and an address the parser does not read; a value
of `--port 70000` is a usage error. Enabling the API creates `[api]` if absent, without asking for or generating
a static token. Labelled keys work independently of `token_hash`. API, WebDAV and
plain HTTP autoconfig have no TLS transport, so `set` refuses an address outside
loopback for these listeners, even when mail certificates are configured in
`[tls]`. I keep them behind a TLS reverse proxy on loopback.

Without a container stack the bind in `mail.toml` is the address the server
binds, so `set` writes the requested one there. With
`<data_dir>/compose/compose.yaml` the two sides split: inside the container the
listener binds the unspecified address of the family the operator named
(`0.0.0.0` for IPv4, `::` for IPv6), because a loopback or private address
there is not one the published mapping can reach, and the requested address
becomes the host side of the generated mapping as `ADDRESS:PORT:PORT`. A
container bind that already answers that family is left alone, so the dual-stack
`::` survives a move to an IPv4 host address. `list` then shows that address in
a `HOST` column, `-` where the mapping still answers on every host address. A
wildcard renders as `PORT:PORT` in both families, because a wildcard publishes
on every address the host owns either way, and pasta on Podman 5.4.2 refuses the
explicit `0.0.0.0:PORT:PORT` and `[::]:PORT:PORT` forms. A generated mapping
with no explicit address stays `PORT:PORT`, and the
host address one `set` wrote survives a later `enable`, `disable`, `init` rerun
or `stack update`, since every writer of the map reads it back first. If
`compose.override.yaml` already publishes a port for the same service, `set`
leaves it alone and says that the override merges with the generated map, or
replaces it where it carries `!override`. That notice is read out of the file
rather than parsed, so it sees the block form, the flow form (`mail: {ports:
[...]}`) and ranges of ports, in block or inline; it does not see a `ports` key
behind an anchor, an alias or a value a template fills in at run time, and a
file it cannot make sense of reports nothing.

The address has to be one of the host's own: a multicast group, `255.255.255.255`
and a link-local IPv6 address are refused before anything is written, both
wildcards are accepted, and an IPv4-mapped address is written as the IPv4
address it names. A listener the container holds on loopback publishes nothing
and is reported as `set` rather than as `published`. A listener with no TLS
transport of its own (`api`, `webdav`, plain `autoconfig`) is published on
`127.0.0.1` when the generated file names no address for it, so a map rebuilt
without the address one `set` wrote, or an `addr` an operator edited by hand,
puts it on loopback rather than on every address of the host.

`set`, `enable` and `disable` validate and stage both files before replacing
either, and a `compose.yaml` that is a symlink is read through the link and then replaced by a regular file: the file behind the link is left as it was, and the link is not followed for the write, so a path that changes between the read and the rename cannot redirect it. Keep the generated file where the command expects it, or put the symlink on the directory instead.
That write needs write access to that directory. A write error restores the
previous files and verifies their contents and permissions. If restoration
fails, the error names a retained recovery copy, which takes its own
`.service-recovery.*` name and is kept for a week instead of the hour a staged
copy is kept. A command killed between its two renames leaves its
staged copies in the directory of the file it was writing, and the next command
under the lock sweeps and names the ones the configuration directory holds; when
the generated map and `mail.toml` describe different ports, which is what that
kill leaves behind and what a port edited by hand also leaves behind, the
command that reconciles them says so before it writes. Service edits, `dns
provider set`, init reruns, stack writers and `db upgrade` share a
configuration-directory lock through the write and reload; the wait has a
deadline and names the command that holds it. The lock file is created `0600`
by the first command that takes it, so it belongs to the service user or to
root; a lock this command owns is put back to `0600`, and one it can only read
is still a lock, so a lock root created at `0644` keeps two commands apart. A
mode that lets other users write it, and a lock file a third user owns, are
refused with the mode it has and the `chmod` that fixes it.

`--dry-run` prints the diff of `mail.toml`, and on a container stack the
`ports:` change that comes with it. With `--json` the result object carries the
same diff and the map as `ports` with its `current` and `wanted` lists, so a
consumer does not read a stack change as an empty one.

When `<data_dir>/compose/compose.yaml` exists, the generated mail port map is
updated and the mail service is restarted through `epistle stack`. The operator
compose override stays untouched. Host installations print that the server must
be restarted. Status messages go to stderr; listings go to stdout. Running under
sudo delegates to the service account, like the other administration commands.

## Health (`epistle status`, `epistle check`)

```sh
epistle status            # one line per area
epistle status --json
epistle check tls         # one area, with its findings
epistle check dns --json
```

`status` runs every check and exits 1 if any area is `fail` (`warn` does not
change the exit code). `check <area>` runs one area and lists what it found.
Nothing sends mail or authenticates, and every network operation gives up
after 5 s. `--config` defaults to `/etc/epistle/mail.toml`.

| Area | `ok` | `warn` | `fail` |
|---|---|---|---|
| `config` | file loads | restart pending: `mail.toml` is newer than the `mail` container's start (needs the compose stack; skipped with a note otherwise) | does not load |
| `ports` | the same check as `epistle probe`: every enabled listener answers on loopback with its greeting (SMTP `220`, IMAP `* OK`, POP3 `+OK`, ManageSieve `OK`, HTTP status line), and TLS listeners present the configured certificate | no listeners | a listener refuses, is silent, greets wrongly or presents another certificate, or `podup ps` does not list a running `mail` container (during a restart, for example) |
| `tls` | 21 days or more left, hostname in the certificate, the TLSA record (when DNSSEC publishes one) matches it | under 21 days, under 14 days with nothing renewing it (no `[acme]`), the TLSA lookup failed | under 7 days, expired, or hostname not in the certificate; unreadable file; a TLSA record that does not match the certificate in use |
| `dns` | published records match | a lookup was inconclusive, or `dkim-rotation.json` is unreadable and the server signs with the last good state in `dkim-rotation.json.bak` | a record is missing, or the published DKIM `p=` is not the public key of the key actually signing (the rotation state in `<data_dir>/dkim-rotation.json` when present, else `[dkim] key_file`) |
| `db` | `[database]` connects and answers `SELECT 1` (or is not configured) | | cannot connect within 5 s |
| `api_keys` | every key has a distant expiry and a narrow reach, and each `scim` key has an associated domain | a key has no expiry, expires within 14 days or has expired, holds every scope (a legacy key), holds `write` or `send` with no domain, account or usable `--ip-cidr`, or is a `scim` key with no domain; findings identify the label and scopes. The store has no creation or last-use timestamps | |
| `antivirus` | clamd answers `PING` with `PONG` and reports its signature age (or is not configured) | `VERSION` fails | no `PONG` |
| `antispam` | something is wired in: greylisting, or the `[database]` features (Bayes, reputation, persistent bans, greylist persistence), or the clamd scanner; each feature is listed | no `[database]`: those four features are off and the finding says so; with nothing at all wired in the summary says antispam is off | |
| `queue` | oldest queued message under 4 h | over 4 h | over 24 h |
| `disk` | 10% or more free on the filesystem holding `data_dir` | under 10% | under 5%, or under 25 MiB free (SMTP then answers 452) |
| `spool` | no file or directory under `<data_dir>/spool/` is looser than owner-only; the finding also says whether messages are sealed (`encrypt_at_rest`) | a file or directory is looser than owner-only | the spool cannot be scanned, or the storage encryption cannot be set up |
| `resources` | the `mem_limit` values in `compose.yaml` add up to 85% of the host's `MemTotal` or less, and the message memory budget fits the `mail` container's `mem_limit` | the limits add up to more than 85% of `MemTotal` (the finding names the two largest and the `epistle stack resources set` command that brings the sum under it, never below what the service needs: for `mail` five messages of `max_message_size` and 256 MiB), `/proc/meminfo` is unreadable, or a configured `message_memory_budget` (or one raised to `max_message_size`) would take more than 70% of the `mail` limit when full, at about 3 times its size | |
| `clock` | the kernel reports the host clock disciplined by a time source (`adjtimex`, with `timedatectl show -p NTPSynchronized` when the syscall is refused), and the external probe is off, or every valid offset is below `warn_seconds` | the clock is not synchronised, or neither probe could tell; the finding gives the fix and nothing is changed; a valid offset reaches `warn_seconds`, or one or two readings are valid below it | no reading is valid, or a valid offset reaches `fail_seconds` |
| `evidence` | the last verification of the evidence is under an hour old and found nothing to flag | the server has not verified yet, timestamp tokens are pending or failing, timestamps are disabled, a task reported an error, the last verification took half of the time it is given or more, or it is older than an hour | transactional mail is held (clear it with `epistle evidence acknowledge` once understood), or the status cannot be read |
| `subid` | the ranges `glyndor-epistle` holds in `/etc/subuid` and `/etc/subgid` overlap no other account's | `glyndor-epistle` has no range in a table | a range overlaps another account's; the finding names that account and the shared interval (see [Moving an overlapping range](#moving-an-overlapping-subordinate-id-range)) |
| `warmup` | one finding per receiver group (cap, sent today, deferred and bounced share, verdict, next cap, waiting); also `off` when the warm-up is not running | a group's verdict is `very_bad`; the warm-up is off while the address looks new and 200 or more recipients went out today or are queued (see [warm-up](operations/warmup.md)); the warm-up files cannot be read | |

The `clock` area adds two read-only probes. The host probe asks the
kernel via `adjtimex`, with `timedatectl show -p NTPSynchronized` when
the syscall is refused; the area is `ok` when the kernel reports a
disciplined clock, `warn` when it does not or when neither probe can
tell. The external probe is the [clock_external] block: three
independent sources, a diagnostic median of the three valid readings,
configurable warn/fail thresholds (defaults 1 s / 5 s). The area
surfaces one line naming how many sources were authenticated over NTS,
then one line per source, the external verdict, and the diagnostic median.
The verdict uses the largest absolute valid offset, so any drifting peer
can cause `Warn` or `Fail`. The smear diagnostic
surfaces a `warn` when two authenticated sources agree within 100 ms and
a plain one differs from their midpoint by more than 250 ms (a typical
operator-visible signature of a leap-second smear on the plain server).
The probe runs only when the area is reached, never writes the host
clock, and uses no state between runs.

The three defaults, `nts.netnod.se`, `nts.time.nl` and `ptbtime2.ptb.de`
(all NTS), are three operators in three countries, so every offset of a
default run is authenticated, with a diagnostic median that is insensitive
to one drifting source. This median does not exclude that source from the
verdict. Each answered the whole NTS exchange inside the budget when the
list was chosen. `time.cloudflare.com` answers plain NTPv4 but its key
exchange returns cookies and the authenticated poll then goes unanswered
on the networks measured, and `time.google.com` publishes no NTS-KE
endpoint, so neither is in the default list; either can replace a source
as a plain `ntp` entry. Replace them when the chosen peers change; the
list and the protocol per source are both yours to set, and a host that
answers NTS on your network can be configured as `nts`. The two ports the probes
dial are `4460/tcp` (NTS-KE, RFC 8915) for the `nts` sources and
`123/udp` (NTPv4, RFC 5905) for the plain ones; both must be reachable
from the host that runs `epistle status`. The full run is capped at
`2.1 s` and each source at `2 s` for the whole probe, so a server that
answers the key exchange slowly cannot buy a second budget; a hung
server is reported, never retried. A whole NTS exchange costs a dial, a
TLS handshake, a key exchange and the authenticated poll, so it comes
close to the `2 s` per-source budget. A source that misses
the budget is reported as a timeout and the run loses its diagnostic
median. One or two healthy readings give `warn`; no valid readings or any
valid offset at or above the fail threshold gives `fail`. The budget
itself is a constant in the binary, not a setting. With no route to those
ports the probe stays red, and `enabled = false` in `[clock_external]`
turns it off so the area reports the switch instead.

The probe is read-only: nothing writes the host clock, and a Warn or
Fail from this area never produces a `clock_drift_exceeded` event
(`metrics.clock_drift_exceeded` only ticks on the host-jump probe,
which the kernel's existing time source catches). Configure chrony or
systemd-timesyncd for the host, and point that daemon at the servers of
one provider: a host daemon fed by two providers that smear differently
disagrees every night. The external probe is the opposite case on
purpose. It takes one host per provider, reports a diagnostic median,
and uses the largest absolute valid offset for its verdict. Smear
detection is diagnostic too; every valid reading still affects the verdict.

`--json` prints one object keyed by area, each `{"status", "detail", "items"}`,
where `items` lists the findings (`name`, `status`, `detail`).

`probe` and `check ports` try `::1` for a listener bound to `::`. If that
connection is refused or times out, they try `127.0.0.1` on the same port,
so IPv4 ports published by the container stack work from the host. Output
reports the address that answered. A `0.0.0.0` bind uses `127.0.0.1`.

When the generated compose file exists and the configured PostgreSQL socket
directory is absent on the host, `check db` runs inside `mail`, using the config
path from its compose command, and `status` asks `mail` for its `db` area while
every other area is checked from the host. If `mail` is stopped, run
`epistle stack up`.

### Moving an overlapping subordinate id range

Packages up to 0.10.1 gave `glyndor-epistle` the fixed block
`100000-165535`, which `useradd` also gives the first regular user on Debian
and Ubuntu. Newer packages pick a free block on install, and on upgrade the
postinst moves a block the account shares with another one:

1. It picks a free block of the same size with the allocator a fresh install
   uses, within `SUB_UID_MIN`/`MAX` and `SUB_GID_MIN`/`MAX`.
2. `epistle move-subids` stops the podup unit, its update timer and the
   account's Podman API units, runs `podman system migrate` so the pause
   process lets go of the old mapping, then stops the account's user manager
   (`user@<uid>.service`) and anything it left behind. `usermod` refuses to
   change the ranges of an account with a running process, so the move stops
   here, naming the processes, if any is left.
3. It rewrites only the account's lines in `/etc/subuid` and `/etc/subgid`
   with one `usermod` call and checks every other line came through
   unchanged.
4. It shifts the owner of every file in the old block by the same offset:
   image layers, container directories and named volumes (the database among
   them) under the account's home and Podman runtime directory, and the
   storage, volume and `data_dir` paths when they live elsewhere. Set-id bits
   and file capabilities, which `chown` clears, are put back.
5. It starts the user manager again (linger brings back the units enabled for
   it) and whatever else was running.

Any step that fails undoes the ones before it, and the message says the old
ranges are back in place. A move that was killed half way leaves a journal at
`/var/lib/glyndor/epistle/.subid-move`, and the next run undoes it before it
tries again. To run the move again, for example after freeing room in
`/etc/login.defs`:

```sh
sudo dpkg-reconfigure epistle
sudo epistle check subid
```

## Running the server

| Command | What it does |
|---|---|
| `epistle serve` | Bind the configured listeners and run. |
| `epistle mta-sts-serve --policy-dir DIR --cert FILE --key FILE [--listen ADDR]` | Serve the public MTA-STS policy over HTTPS. |
| `epistle config-check` | Validate the configuration and exit. Values an older release accepted that the current rules refuse (`public_ipv4`, `public_ipv6`, an alias `list_id`) are ignored with a warning rather than failing; any other validation error fails, and so it does for `backup`, `restore`, `stack rollback` and `serve`. `status` alone still reads such a file and reports the reason in its `config` area. |
| `epistle verify` | Check on-disk data integrity (run before an upgrade). |
| `epistle local --dir DIR [--port-base N]` | Self-contained loopback test harness. NOT a deployment: see below. |
| `epistle init` | First-run setup: answers, keys, config. See below. |

On SIGTERM (or SIGINT) `epistle serve` stops accepting connections and lets
the open ones finish for up to 25 seconds: an SMTP client in the middle of a
transaction gets its reply for the message and then `421 4.3.2`, an idle one
gets the `421` at once, and IMAP sessions get `* BYE server shutting down`
once their current command is done (also out of IDLE). The generated compose
file gives `mail` a 30 second `stop_grace_period`, so podup does not kill it
before the drain ends.

## Server limits (`epistle limits`)

```sh
epistle limits show
epistle limits show --json
epistle limits set quota 5G
epistle limits set submission-rate 120
epistle limits set submission-rate --tenant acme 200
epistle limits set queue-give-up 12h
epistle limits set queue-retry-base 5m
epistle limits set queue-concurrency 16
epistle limits set queue-per-domain-concurrency 4
epistle limits set queue-backoff 1m,5m,15m,1h
epistle limits set quota --domain example.org 10G
epistle limits set submission-rate --domain example.org 50
epistle limits set submission-rate --domain example.org 50 --json
epistle limits unset quota --domain example.org
epistle limits unset submission-rate --tenant acme
epistle limits set quota 10G --dry-run
epistle limits unset quota
```

`show` prints each effective value with `default` or `configured`. Disabled
rate caps and the protocol-specific connection defaults are shown explicitly.
Values equal to a built-in default are marked `default`, even when configured.
An unset `message-memory-budget` has no fixed default: `show` prints
`auto (409 MiB from the mail container limit)`, the budget the server derives
from the `mem_limit` of `mail` in `compose.yaml` (or `auto (204 MiB, no mail
container limit found, 1g assumed)`), marked `derived`, and `--json` gives its
bytes with `"source": "derived"`. The running server reads its cgroup instead,
which `podup` sets from that same `mem_limit`.
`show` also lists the limits the server hard-codes (`fixed`) and marks a floor
the RFC makes mandatory `must`; [Limits and standards](limits.md) has the full
table.
`unset` removes the field so its built-in default applies again. With
`--json`, `show` also lists every per-domain override and every named tenant
in addition to the global dials.

`set` and `unset` accept `--domain <NAME>` (quota or submission-rate) and
`--tenant <NAME>` (submission-rate only); combining the two is refused.
`set --json` and `unset --json` write a one-line JSON confirmation on stdout
instead of the human-readable status line, so a pipeline can audit which
dial just moved. Either way the command restarts the mail service to apply
the change, or says the server must be restarted when it runs outside the
stack.
`set submission-rate 0` is refused: the server reads zero as no limit, and
`unset` is how a limit is removed.

| Key | Value |
|---|---|
| `quota` | Bytes per account, default 5 GiB; `0` means no limit and shows as `unlimited`. |
| `submission-rate` | Recipients per minute per account, default disabled, across SMTP, `POST /api/v1/send` and JMAP; see `submission_rate_limit_per_min` in the configuration reference for what counts and the replies. |
| `new-recipients-per-day` | New recipients per account in a rolling 24 hours, default disabled. |
| `queue-give-up` | Queue age before bouncing, default 5 days. |
| `queue-retry-base` | Wait after a recipient's first failed attempt, doubling after each failure, default 1 minute, at least 1 minute. |
| `queue-retry-cap` | Longest wait between attempts, default 1 hour, not below `queue-retry-base`. |
| `queue-delay-warning` | Message age of the "delivery delayed" DSN, default 4 hours, below `queue-give-up`. |
| `inbound-rate-per-ip` | Inbound messages per minute per client IP, default disabled. |
| `inbound-rate-per-sender` | Inbound messages per minute per envelope sender, default disabled. |
| `max-connections-per-listener` | Concurrent connections, default depends on the protocol. |
| `max-recipients` | Recipients one message may name, on SMTP, REST send and JMAP submission, default 100. Not below 100 (RFC 5321 §4.5.3.1.8), and `limits set` refuses less. |
| `max-message-size` | Per-instance cap, default 25 MiB. Applied to SMTP, JMAP `Email/set` create, JMAP upload body limit, REST `POST /api/v1/send`. Refused above `message-memory-budget`. |
| `max-connections-per-ip` | Concurrent connections per client IP (IPv6: per /64) on each SMTP listener, default 20. Extra connections get `421 4.7.0` and are closed. |
| `message-memory-budget` | Shared byte budget every SMTP `DATA` / `BDAT` reservation draws from, by default a fifth of the `mail` container's memory limit (at least `max-message-size`, at most 1 GiB); one client may hold a quarter of it. Refused below `max-message-size`. `0` disables the cap. |
| `max-connections-per-account-per-ip` | Authenticated connections one account may hold from one client IP on the IMAP, POP3 and JMAP listeners together, default 10. Extra ones get `NO [LIMIT]`, `-ERR [IN-USE]` or `429` and are closed. |
| `max-connections-per-account-total` | Authenticated connections one account may hold across every client IP on the same listeners, default 50. |
| `min-data-rate` | Minimum average rate of one inbound message, in bytes per second (`K`/`M`/`G` suffixes), default 10240 (a 25 MiB message has about 43 minutes). Measured over the whole `DATA` or `BDAT` transaction, time between chunks included; below it the client gets `421 4.4.2` and is disconnected. `0` turns it off and shows as `disabled`. |
| `data-rate-grace` | Time from the start of a message before `min-data-rate` applies, once per transaction, default 120 seconds, between 1 second and 1 hour. |
| `junk-command-limit` | Commands without progress (`NOOP`, `RSET`, `VRFY`, unknown commands, a repeated `EHLO`, an empty `BDAT` chunk, `AUTH` response lines) one SMTP session may send before `421 4.7.0` and a disconnect, default 100, never reset during the session; refused commands count against the same limit since the last accepted message. `0` turns it off and shows as `disabled`; otherwise between 10 and 10000. |
| `max-session-time` | How long one SMTP session may last before `421 4.4.2` at the next command boundary, default 1800 seconds; a message body being received is never cut. `0` turns it off and shows as `disabled`; otherwise between 1 minute and 1 day. |
| `preauth-timeout` | How long an IMAP, POP3 or ManageSieve client gets, from the start of the connection, to sign in, default 60 seconds, between 5 seconds and 1 hour. One deadline covers the TLS handshake and everything before authentication; slow bytes and repeated cheap commands do not extend it. A signed-in session is not held to it. It acts as at most 600 seconds on POP3 and 1800 on IMAP, their idle timeouts. |
| `max-mailbox-connections-per-ip` | Concurrent connections one client (IPv6: per /64) may hold on each IMAP, POP3 and ManageSieve listener, default 200 (ManageSieve 40, whose listener holds 100). Extra ones get `* BYE`, `-ERR` or `BYE` and are closed. Behind a proxy or a bridge network every client shares one address, so raise it there. `0` is the default, not "no limit", and `limits set` says so. |
| `max-http-connections` | Concurrent connections each plain-HTTP listener (API and JMAP, WebDAV, autoconfig without TLS, ACME, metrics) serves, default 1024. Extra ones get `503` and are closed. `0` is the default, not "no limit", and `limits set` says so. |
| `max-http-connections-per-ip` | Concurrent connections one client (IPv6: per /64) may hold on each plain-HTTP listener, default 256, over the same `503`. `0` is the default, not "no limit", and `limits set` says so. |
| `masked-addresses-max` | Masked addresses per account, default 100. |
| `known-network-window` | Time a successful sign-in keeps a network on the list that lets a banned account in from it, default 30 days (`known_network_window_secs`); see [Authentication bans](#authentication-bans). |
| `first-time-sender-delay` | First-time sender delay, default 0 seconds. |
| `greylist-delay` | Greylist deferral window, default 0 seconds. |
| `queue-concurrency` | Outbound SMTP conversations at once, default 8, between 1 and 1024 (`[queue] concurrency`). |
| `queue-per-domain-concurrency` | Outbound conversations at once with one recipient domain, default 2, between 1 and `queue-concurrency` (`[queue] per_domain_concurrency`). |
| `queue-backoff` | Holds of a destination that asks to slow down, comma-separated durations, one per deferral in a row, default `1m,5m,15m,1h` (shown in seconds), 1 to 16 steps of 1 second to 1 day (`[queue] backoff_steps`). |

Sizes accept whole bytes or binary suffixes `K`, `M`, `G`, `T` (case insensitive);
`5G` means 5 GiB. Durations accept whole seconds or `s`, `m`, `h`, `d`, `w`.
Counts accept whole non-negative integers. Values must fit the configuration
field and TOML integer range. Zero retains each setting's server semantics:
it disables sender delays and masked addresses, and selects the built-in
queue window or connection caps. Use `unset` to disable an optional rate cap.

`--config <FILE>` works before or after the action and defaults to
`/etc/epistle/mail.toml`. Updates preserve every other TOML key and validate
before atomic replacement, keeping comments, ordering, permissions, and
ownership. `--dry-run` prints the validated unified diff without writing or
restarting. Domain overrides are supported for quota and submission-rate. A changed file triggers
`epistle stack restart mail` when `<data_dir>/compose/compose.yaml` exists;
otherwise a status message asks for a server restart. Restart failures leave
the saved limit in place and return the stack's exit code. Unchanged values
leave the file untouched and do not restart the service.

## Smarthost relay (`epistle relay`)

```sh
epistle relay list [--json]
epistle relay show [--account NAME | --domain DOMAIN] [--json]
epistle relay add --host smtp.example.net --starttls --username mailer --password-stdin < pass.txt
epistle relay add --domain example.net --host relay.example.net --port 2525
epistle relay remove [--account NAME | --domain DOMAIN]
epistle relay disable [--account NAME | --domain DOMAIN] [--yes|-y] [--dry-run]
epistle relay enable [--account NAME | --domain DOMAIN] [--dry-run]
epistle relay test [--account NAME | --domain DOMAIN]
```

Each command edits one `[[transport]]` rule with `kind = "relay"`. Without
`--account` or `--domain` it addresses the default route. `add` creates the rule or
updates it in place; the port defaults to 587 with `--starttls` and 25 otherwise.
`--username` needs `--starttls` (credentials never cross plaintext) and the password
on stdin as one line; it is stored inline in the 0600 configuration file and
`show` and `list` print only `set` or `unset`. A re-run without `--password-stdin`
keeps the stored password when the user is unchanged. A domain or account that
already has a `fail` or `direct` rule is refused.

`disable` writes `enabled = false` on the rule and keeps everything else, the
password included. It warns on stderr where the mail will go and asks first; off a
terminal it needs `--yes` (exit 2 without it). After the restart the rule is never selected: its mail goes
by the next rule that matches, or direct to the recipient's MX when none does,
so it leaves from this server's own address, and a rule switched off no longer
counts as a warm-up relay. `enable` takes the key out again. Both say `unchanged`
when the rule is already that way and refuse a selector with no relay behind it
with exit 2. `add` on a disabled rule updates it and leaves it disabled. `show`
and `list` print `enabled` (`list` marks a rule that is off).

`test` connects to the smarthost (through `--socks-proxy` when set), sends EHLO,
upgrades with STARTTLS and authenticates when configured, then QUITs. It never
starts a mail transaction and gives up after 10 seconds. All commands accept
`--dry-run` (print the diff, write nothing) and `--config FILE`.

## DNS provider (`epistle dns provider`)

```sh
epistle dns provider show [--json]
epistle dns provider set cloudflare --zone example.org --token-env CF_TOKEN
epistle dns provider set route53 --zone example.org --access-key AKIA... \
  --secret-key-env AWS_SECRET --hosted-zone-id Z123
epistle dns provider set manual --zone example.org
epistle dns provider unset
epistle dns provider unset --zone client.example
epistle dns provider test
```

`set` rewrites the entry for its `--zone`, so switching provider never leaves an old
credential behind. A zone that has no entry yet is added: the first extra zone turns
the single `[dns]` table into `[[dns]]` tables (see
[`configuration.md`](configuration.md) §`[dns]`), and every other entry, its token
and its mount in the generated compose file are left as they are. A token file that
two entries share is mounted once and stays mounted while one of them reads it.
`--store-token` keeps `secrets/dns_provider_token` for a configuration with one zone and
uses `secrets/dns_provider_token_<zone>` (dots as underscores) once there are several, so
replacing one token never overwrites another. `unset` removes every entry; `unset --zone`
removes the one for that zone, takes its token file mount and its variable out of the
generated compose file unless another entry still reads them, and refuses a zone that has none. `show`, `check` and `test`
report every entry: `show --json` prints a list when there are several entries, and
`check` prints each line with the zone in front (its `--json` is a list of
`{zone, provider, report}`). The provider name and the settings it needs are checked the way
the loader builds the provider; a setting the provider does not use is refused.
Secrets are never passed on the command line: name an environment variable
(`--token-env`, `--secret-key-env`, `--consumer-key-env`) or a 0600 file
(`--token-file`, `--credentials-file`). The variable must be visible to the
service account that runs the server.

| Provider | Settings |
|---|---|
| cloudflare, bunny, desec, digitalocean, namecheap | `--token-env` or `--token-file` |
| dnsimple | token source, `--account-id` |
| spaceship, godaddy, porkbun | `--access-key`, `--secret-key-env` |
| ovh | `--access-key`, `--secret-key-env`, `--consumer-key-env`, optional `--endpoint ovh-eu\|ovh-ca\|ovh-us` |
| route53 | `--access-key`, `--secret-key-env`, `--hosted-zone-id` |
| gcloud | token source, `--credentials-file` |
| rfc2136 | token source (TSIG key), `--key-name`, `--endpoint HOST:PORT`, optional `--algorithm` |
| manual | none (records are printed for you to publish) |

`show` prints where each secret comes from and `set` for an inline value, never
the value. `test` lists the zone's records through the provider (a read only call,
10 second limit) and reports the count. Every mutation accepts `--dry-run` and
`--config FILE`.

On a generated stack, `set` also writes the Compose file, so the credential
reaches the container: a `--token-file` is mounted read-only into `mail` at the
same path, a `--token-env` is forwarded as `${NAME}`, and the mount and the
environment entry the previous setting left behind are removed. `mail` is
recreated so the new mount is in the container. `--dry-run` previews the
configuration change and the Compose change, and writes neither. The preview
hides the credentials of the configuration over the TOML tree, so a value that
spans several lines is hidden whole.

## DNS lockdown (`epistle dns lockdown`)

```sh
epistle dns lockdown [<domain>] [--dry-run] [--yes] [--json] [--dmarc reject]
epistle dns lockdown [<domain>] --undo [--dry-run] [--yes]
```

Publishes the anti-spoofing records for the domain (the `[dns]` zone by
default): DMARC one step stricter per run, a null SPF and null MX on
names that send no mail, and a wildcard null SPF. Subdomains delegated to
other nameservers (NS records) are left alone. It asks first; `--yes`
skips the question. `--undo` removes what earlier runs published. See
[`docs/dns.md`](dns.md#locking-the-zone-against-spoofing).

## Blob storage (`epistle storage blobs`)

```sh
epistle storage blobs show [--json]
epistle storage blobs set fs
epistle storage blobs set s3 --endpoint https://s3.us-east-1.amazonaws.com \
  --bucket mail-blobs --region us-east-1 --access-key-id AKIA... --secret-env S3_SECRET
```

Chooses where uploaded JMAP blobs live: `fs` (under `<data_dir>/blobs/`, the
default) or an S3-compatible bucket. The secret access key is referenced with
`--secret-env VAR` or `--secret-file FILE` (0600), never given inline, and `show`
prints only where it comes from.

**Switching does not migrate existing blobs.** Blobs stored in the previous backend
stay there and stop being served, and the command says so every time the backend
changes. Moving from `fs` to `s3` is refused while `<data_dir>/blobs/` holds any
file, unless you pass `--force`. Leaving S3 cannot be checked from here, so it is
never refused. Supports `--dry-run` and `--config FILE`.

## Webhook (`epistle webhook`)

```sh
epistle webhook show [--json]
epistle webhook set https://hooks.example/mail --secret-stdin < secret.txt
epistle webhook unset
epistle webhook disable [--dry-run]
epistle webhook enable [--dry-run]
epistle webhook test
```

Manages the `[webhook]` section. The URL must be `https`, or `http` on a loopback
address (`127.0.0.1`, `::1`, `localhost`), and cannot carry credentials. The signing
secret arrives on stdin as one line and is stored inline in the 0600 configuration
file; `show` prints only `set` or `unset`. `set` without `--secret-stdin` keeps a
secret that is already configured. `unset` is refused while an alert still posts
to the webhook. A URL that names a private destination (a loopback address, a
private or link-local network) is refused by the server unless the section says
`allow_private_webhooks = true`; `set` writes that key when the URL needs it, and
`show` says whether it is on.

`disable` writes `enabled = false` into the section and keeps the URL and the
secret: after the restart no event is posted, alerts with `--webhook` included, and the warning on stderr lists which ones (`message_received`, `delivery_failed`, `metric_alert`, `dkim_rotation_failed`, `outbound_virus`, the warm-up reports) and the alerts that go quiet. While an alert posts to the webhook, `disable` asks first and off a terminal needs `--yes` (exit 2 without it), like `webhook unset` refusing. `config-check` warns about an alert whose webhook is off.
`enable` takes the key out again. Both say `unchanged` when the webhook is
already that way and refuse with exit 3 when no webhook is configured (a setting the command needs is missing; so is `unset` while an alert posts to the webhook, exit 3). `set`
keeps a disabled webhook disabled. `show` prints `enabled` and `allow_private_webhooks`.

`test` posts one `test` event (see [configuration](configuration.md)), signed like
any other, and reports the HTTP status. It fails on a non-2xx answer, a connection
error, or no answer within 10 seconds. Supports `--dry-run` and `--config FILE`.

## Alerts (`epistle alert`)

```sh
epistle alert list [--json]
epistle alert show bounce-storm [--json]
epistle alert disable bounce-storm [--dry-run]
epistle alert enable bounce-storm [--dry-run]
epistle alert add bounce-storm --metric bounced --op '>=' --threshold 50 \
  --window 5m --webhook --email ops@example.org --cooldown 1h
epistle alert remove bounce-storm
```

Manages the `[[alerts]]` rules. A rule compares how much a counter grew over each
`--window` against `--op` and `--threshold`, and notifies by webhook, email, or both
(`--email` can repeat). Quote the operator: `>=`, `>`, `<=`, `<` or `==`. Durations
take `s`, `m`, `h`, `d` or `w`; the cooldown defaults to `1h`. The metric must be one
of the counters in [configuration](configuration.md#alerts); an unknown name lists
the valid ones. `--webhook` needs a configured webhook, names are unique, and `add`
never overwrites a rule: remove it first. Supports `--dry-run` and `--config FILE`.

`show` prints one rule (`--json` gives the object `list` gives for it). `disable`
switches a rule off without removing it: it writes `enabled = false`, and after the
restart the rule takes no samples and never fires. `enable` takes the key out again.
Both say `unchanged` when the rule is already that way, and refuse an unknown name
with exit 2. `list` marks a rule that is off, and every JSON row has `enabled`.

## Domains (`epistle domain`)

```sh
epistle domain list
epistle domain list --json
epistle domain show example.org
epistle domain show example.org --json
epistle domain add new.example.org
epistle domain add new.example.org --dry-run
epistle domain remove old.example.org [--yes|-y]
epistle domain disable example.net [--yes|-y] [--dry-run]
epistle domain enable example.net [--dry-run]
epistle domain set example.org [--quota 10G | --no-quota] [--submission-rate 50 | --no-submission-rate] [--dry-run]
epistle domain alias add alias.example.org example.org
epistle domain alias remove alias.example.org [--yes|-y]
```

`list` writes every configured domain with the domains that target it
(`ALIASES TO`) and the domains it targets (`ALIASES FROM`). `show` writes
the alias edges plus the accounts and aliases that route mail through
the domain, so the operator can see what depends on it before removing
it. JSON records contain `domain`, `enabled`, `aliases_to`, `aliases_from`,
`accounts` and `aliases`.

`disable` switches a domain off without removing it: the name goes into
`disabled_domains`, and after the restart mail for it is rejected at RCPT
exactly like mail for an unknown user (a permanent 550, so senders get a
bounce, not a retry), and no account may send as an address in it (SMTP
submission, the API and JMAP all refuse). Accounts, mailboxes, aliases, DNS
records and DKIM keys stay. A mailbox is still reachable by the account's own
name over IMAP and POP3, but logging in with an address in the disabled domain
fails, because that address no longer resolves. Mail already in the outbound
queue with a sender in the domain is accepted mail and is still delivered; the
command says how many messages that is, and `queue remove` drops one.
Autoconfig and autodiscover stop answering for the domain, and
`GET /api/v1/domains` names it under `disabled`. `masked add` refuses a
disabled domain (exit 2), and `account add` and `alias add` create an address
there with a warning on stderr that it receives and sends nothing until the
domain is enabled. `disable` asks first (see
[Prompts and `--yes`](#prompts-and---yes)), refuses an unknown domain with
exit 2, and refuses to switch off the last enabled domain of a server that
has listeners (exit 3, a rule of the server). `enable` takes the name out of
`disabled_domains` again. Both report `result` `unchanged` when the domain is
already in that state, and the JSON result carries `domain` and `enabled`.

`set` writes the per-domain default storage quota (`domain_quotas`) and the
per-domain submission rate in messages per minute
(`domain_submission_limits`), the same overrides `limits set quota --domain`
and `limits set submission-rate --domain` write and `limits show` lists. Name
at least one of `--quota`, `--no-quota`, `--submission-rate`,
`--no-submission-rate`; a flag left out keeps its value, and `--no-…` removes
the override. A zero rate is refused (it would lift the limit; use
`--no-submission-rate`), and so is an unknown domain. The JSON result carries
`domain` and the overrides it touched (`quota`, `submission_rate`; `null`
once removed). `show` prints both overrides.

`add` validates the name (`validate_dns_name`, same rules the loader
uses), appends it to `[domains]` and prints the DNS records the operator
must publish for the new domain (filtered to that domain only). It
refuses when the domain is already configured, when it collides with
a `domain_aliases` source or target, or when the loader rejects the
final document.

With `[dkim]` configured, `add` also gives the new domain a DKIM key of its
own: the Ed25519 key (and the RSA key, when `[dkim]` signs with one) is written
`0600` under `<data_dir>/keys/dkim/<domain>/`, and a `[[dkim.domain]]` entry
names it with the selectors `own<day>` and `ownrsa<day>`, which are not the
ones `[dkim]` publishes, so the new record never replaces the one the default
key is still published under. The records `add` prints are that key's. A key
of the domain's own means a leaked key signs only as that domain.
`--shared-dkim-key` keeps the old behaviour (the domain signs with the
`[dkim]` key, which `config-check` and `status` then report). `--dry-run`
shows the entry and writes no key. `remove` and `alias remove` take the
domain's `[[dkim.domain]]` entry out with it and leave the key files, which are
yours to delete once the record is gone from DNS.

`remove` walks every account (static `[accounts]` plus `<data_dir>/accounts.toml`),
every `[alias]` and its members and senders, every `domain_aliases`
entry and every masked address on disk. If any of those still uses the
domain, the command fails with a message that lists each offender by
category (`account alice@example.org`, `alias team@example.org`,
`domain_aliases maps alias.example.org to example.org`,
`masked address ...`). The file is only written after every offender
has been cleaned up.

`domain alias remove` drops a single key. Both removals ask first (see
[Prompts and `--yes`](#prompts-and---yes)).

`domain alias add` writes an entry under `[domain_aliases]`. The target
must already be a configured domain; the alias name must not collide
with another `domain_aliases` key or with any configured domain.

Edits preserve every other TOML value, validate through the normal
loader before atomic replacement, and follow the same restart policy
as `service` and `limits` (compose restart or a manual restart message).
Secrets never appear in `show`/`list` output. `--dry-run` on `add` and
`remove` prints the validated unified diff without writing.

## Aliases (`epistle alias`)

```sh
epistle alias list
epistle alias list --json
epistle alias show team@example.org
epistle alias add team@example.org alice@example.org bob@example.org
epistle alias add team@example.org alice@example.org --sender ceo@example.org --list-id team.example.org --visible
epistle alias remove team@example.org [--yes|-y]
epistle alias member add team@example.org carol@example.org
epistle alias member remove team@example.org bob@example.org
epistle alias sender add team@example.org ceo@example.org
epistle alias sender remove team@example.org ceo@example.org
epistle alias enable team@example.org
epistle alias disable team@example.org
epistle alias add team@example.org alice@example.org --dry-run
```

`list` writes every `[[alias]]` with its enabled state and visibility
(default `hidden`, `visible` only with `--visible` on add). `show`
writes `address`, `members`, `senders`, `hidden`, `list_id` and
`enabled`. When `senders` is empty, `show` prints `(any member)` instead
of an empty string so the operator is not misled.

`add` writes one `[[alias]]` row. The address must not already be used
by another alias, by an account (static `[accounts]` or `<data_dir>/accounts.toml`),
or by a masked address (`<data_dir>/masked.json`). The address must also
live in a configured domain. Members and senders must be valid email
addresses; at least one member is required.

`remove` drops the whole row, after asking. `member add|remove` and
`sender add|remove` edit one entry on an existing alias; `member remove`
refuses to leave an alias with no members (use `alias remove` for that).
`enable` and `disable` toggle the disabled flag in `<data_dir>/aliases.json` through
`AccountStore::set_alias_enabled`. The dynamic store is hot-reloaded by
the 2 s file watcher, so the change takes effect without a restart and
without going through the config engine.

Edits to `[alias]` go through the same config-edit engine as `service`
and `limits` (validated, atomic, comment-preserving, restart-on-change
when compose exists). `enable`/`disable` do not touch `mail.toml` and
do not request a restart. `--dry-run` on the config edits prints the
validated unified diff without writing.

## Antispam (`epistle antispam`)

```sh
epistle antispam show
epistle antispam set greylist-delay 5m
epistle antispam set clamd-socket /run/clamav/clamd.sock
epistle antispam set clamd-on-found reject
epistle antispam set clamd-on-error defer
epistle antispam set scan-authenticated off
epistle antispam set first-time-sender-delay 1m
epistle antispam set clamd-timeout 30
epistle antispam set clamd-max-size 26M
epistle antispam set subjectpass on
epistle antispam set llm-uncertain-low 0.3
epistle antispam set llm-uncertain-high 0.9
epistle antispam unset greylist-delay
epistle antispam add dnsbl-zones zen.spamhaus.org
epistle antispam remove dnsbl-zones zen.spamhaus.org
epistle antispam add dnsbl-zones zen.spamhaus.org --dry-run
```

`show` writes every key and its current value. The three DNSBL list
keys (`dnsbl-zones`, `dnsbl-domain-zones`, `dnsbl-url-zones`) print as
`<key>\t<comma-separated values>\tconfigured` (or `(empty)\tdefault`).
The LLM block fields (`llm-endpoint`, `llm-model`, `llm-api-key-env`)
print as `set`/`unset` only, the values are secrets and never appear
on stdout.

Besides the DNSBL lists, the keys are `greylist-delay` and
`first-time-sender-delay` (durations such as `5m`; whole seconds also work), `clamd-socket`,
`clamd-on-found` (`quarantine` or `reject`), `clamd-on-error` (`accept` or
`defer`), `clamd-timeout` (whole seconds, default 30), `clamd-max-size` (bytes or a
`K`, `M`, `G`, `T` suffix), `scan-authenticated` and `subjectpass` (`on` or `off`),
the LLM block (`llm-endpoint`, `llm-model`, `llm-api-key-env`) and the band
`llm-uncertain-low` and `llm-uncertain-high` (numbers from 0.0 to 1.0, low below high).

`set <key> <value>` writes one key. For list keys the value replaces
the whole list; for every other key exactly one value is accepted.
`unset <key>` removes the key. `add <key> <value>` and `remove <key> <value>`
edit one entry on the three DNSBL lists. SubjectPass `on` requires a
`[database]` section (the uncertain band needs the Bayesian score);
`clamd-socket` is refused when `[scanner_hook_url]` is already set,
surfacing the loader's exact refusal message.

Every action preserves the rest of the file, validates before writing,
and follows the same restart policy as the other resources. Secrets are
never accepted as command-line arguments (the LLM endpoint and model
live in the config, and the API key is the name of an environment
variable the server reads at startup). `--dry-run` prints the validated
unified diff without writing or restarting.

## Attachments (`epistle attachments`)

```sh
epistle attachments policy show
epistle attachments policy show --json
epistle attachments policy set mode quarantine
epistle attachments policy set macros quarantine
epistle attachments policy set block-extensions docm xlsm
epistle attachments policy set allow-extensions svg --dry-run
epistle attachments policy unset allow-extensions
epistle attachments check suspicious.eml
epistle attachments check suspicious.eml --json
epistle attachments check suspicious.eml --strict
```

`policy show` prints one `key<TAB>value` line per key in effect: `mode`,
`macros`, `encrypted-archives`, `block-extensions`, `allow-extensions`, and
the built-in `always-dangerous` list no allowance can cover. `--json` prints
the same as one object, the lists as arrays.

`policy set <key> <value>` writes one key into `[attachments]`; for the two
extension lists the values replace the list and are stored without the dot
and in lower case. `policy unset <key>` restores the default. Each edit is
validated before it is written: an always-dangerous extension in
`allow-extensions` is refused with the loader's message. With `--json`,
`set` and `unset` print the result object of the other configuration edits
(`result`, `action`, `key`, for `set` the `value` stored, and `reload`);
`--dry-run` prints the diff instead, inside the object under `--json`. The
mail service is restarted as for the other configuration edits.

`check <file.eml>` inspects one message with the policy in the
configuration and delivers nothing. For every attachment it prints the
name candidates, the declared types, the real type and the reasons, then
the verdict (`deliver`, `flag`, `quarantine` or `reject`, with the reasons
that decided it) and whether a submission of that message would be
refused (never, when `scan_authenticated` is off). With `mode = "off"` the
parts are still judged, and the verdict is `deliver`. Names and types come from the sender: the text output shows
control and formatting characters as `\u{202e}` escapes, and `--json`
escapes every character outside ASCII. A file over `max_message_size` is
refused before it is read (exit `2`; an unreadable file exits `1`). Run
with `sudo`, the file is copied for the service account up to 25 MiB, the
default message size, so a larger message has to be checked by running the
command as the service account. A link is refused, not followed. The
exit code is `0` whenever the message was judged, whatever the verdict;
with `--strict` it is `3`, a refusal by policy, when the verdict is
`quarantine` or `reject`, so a script can gate on it and tell it from an
unreadable file (`1`) or a bad argument (`2`). `--json` prints the same
object either way. See [attachments.md](attachments.md) for what is detected.

## Stack (`epistle stack`)

Install the signed repository with the [installer](https://apt.glyndor.net/install/epistle).
With the repository configured, the production sequence is:

```sh
sudo apt install epistle
sudo epistle init
sudo epistle stack up
sudo epistle stack ps
```

Init writes `/etc/epistle/mail.toml` and
`<data_dir>/compose/compose.yaml`. Stack defaults to that config path;
`--config F` selects another file and works before or after the subcommand.
When invoked as root, init and every administration command that takes
`--config` run as `glyndor-epistle`, using its home directory and rootless
Podman environment. This includes account, password, API key, backup,
archive, and configuration-reading commands. The service manager runs
`serve` and `mta-sts-serve` directly; key generation, token hashing, help,
version, and the local test harness use the invoking user. If its user runtime
is absent, run `sudo loginctl enable-linger glyndor-epistle` and retry.
Use absolute paths for file arguments when invoking administration commands with sudo.

A file or directory you name on such a command does not have to be readable
by `glyndor-epistle`. Run as root, epistle copies the inputs (`init
--answers`, `import --maildir`, and `migrate`'s `--password-file`, `--ca-file`
and `--from`) into a private directory the account owns, and moves the
outputs (`migrate --passwords-out`, `export --maildir`) to where you asked
once the command succeeds, owned by root and readable only by it. The copy is
removed when the command ends. Symbolic links and special files are refused,
and a copy is bounded: 16 MiB for a file, 64 MiB for a Mox configuration
directory, and 4 GiB for a Maildir to import, which would otherwise take
twice its size on the data disk. For a larger Maildir, make it readable by
`glyndor-epistle` and run the import as that account. Run as root, `export
--maildir` writes into a missing directory or an empty one owned by root, and
stops, keeping nothing, if the export would leave its filesystem with less
than 5% free. An output that is a link, a hard link, or not owned by
`glyndor-epistle` is refused rather than copied. The paths in
`dns provider set` and `storage blobs set` are stored in the configuration
for the server to read, so those files must be readable by the account where
they are.

Stack requires podup 5.15.4 or newer. A failed podup command stops the
sequence and its exit code becomes epistle's exit code.

| Command | What it does |
|---|---|
| `sudo epistle stack up` | Runs `podup up -d`, then `podup autostart install` to enable and start the project's user service. It returns after starting; the service brings the stack back after reboot. |
| `sudo epistle stack down` | Runs `podup autostart uninstall`, then `podup down`. Database volumes and bind-mounted data are kept. |
| `sudo epistle stack ps [--json]` | Lists running services as a table or JSON. |
| `sudo epistle stack logs [--follow] [SERVICE]` | Streams service logs. |
| `sudo epistle stack restart [SERVICE]` | Restarts the stack or one service. |
| `sudo epistle stack stop [SERVICE]` / `sudo epistle stack start [SERVICE]` | Stop or start the whole stack, or one service, without removing containers or the autostart unit. `stack stop mail` is how to take the mail server down for `epistle restore` while the database stays up to receive the dump. |
| `sudo epistle stack update` | Renders `compose.yaml` again with this release's code, shows what changed and replaces it, then runs `podup up -d` so only changed services are recreated. In default mode it also restarts `mail` when its definition did not change, so it runs the host binary the new .deb installed; in custom image mode it runs `podup pull` first. Before any of that it dumps the stack's database to `<data_dir>/backups/pre-<version>-<timestamp>.sql.gz` (mode 0600, the newest three `pre-*` dumps kept while the update runs), because the new server migrates the schema when it starts; a failed dump stops the update before anything changes. Afterwards it waits up to five minutes for `mail` to report healthy and runs the `config`, `ports` and `db` checks of `epistle status`; a failure names the area and exits non-zero, and the apt upgrade prints it framed with the rollback command. When all of that passes, it deletes the `pre-<version>-*` dumps it took (a dump `db upgrade` took stays) and the images the previous compose file named and the new one does not, such as an older ClamAV digest or the version-tagged epistle image of a stack created by an earlier release. An image is removed only when no container of the service account uses it, so one that is still in use, or that carries another name, stays and the update says so; a failed update keeps the dumps and the images. Data and volumes are kept. Before it writes the new file it moves the storage and OAuth signing keys out of data_dir, and once `db` runs it takes SUPERUSER away from an `epistle` role an older release created (see [the container stack](operations/container.md#the-database-roles)). |
| `sudo epistle stack resources [--json]` | Lists each service's `mem_limit` and `pids_limit` from `compose.yaml`, and their sum. Does not run `podup`. |
| `sudo epistle stack resources set SERVICE [--memory SIZE] [--pids N] [--json]` | Changes the limit of `mail`, `db`, `clamav` or `freshclam` (`SIZE` is a whole number with `k`, `m` or `g`) in `compose.yaml`; `mail` is refused less than five messages of `max_message_size` and 256 MiB (381 MiB at the default 25 MiB), so the budget derived from its limit holds one message, where `init` records answered limits, so `stack update` keeps it. The running container keeps its old limit until `sudo epistle stack update` recreates it. `set` and `stack update` take the same lock on `compose.yaml` (`.compose.yaml.lock` beside it), so one waits for the other and neither loses the other's change. |
| `sudo epistle stack rollback [--to VERSION] [--yes]` | Asks before it changes anything (`--yes` skips the question; without a terminal and without `--yes` it exits 2). Puts back the binary the last upgrade replaced (the preinst keeps the two newest under `/var/lib/epistle-rollback`, root:root mode 0700) and, when the new release already migrated the schema, restores the dump `stack update` took before the restart. See [Rolling back an upgrade](#rolling-back-an-upgrade). |

Keep container customizations in
`<data_dir>/compose/compose.override.yaml`. Init preserves this file and its
permissions. Every stack invocation passes `-f compose.yaml`, then
`-f compose.override.yaml` when it exists; later values override the base.
Init regenerates the base file on reruns, and so does `stack update`: it
takes the database choice, a custom mail image, the DNS token forwarding and
the config path from the existing `compose.yaml`, and the published ports
from the listeners in the config. Anything else edited in `compose.yaml` is
replaced, so keep it in the override. Run stack up again after adding or
removing an override so the autostart unit records the current file list.

The default compose file runs the host's `/usr/bin/epistle`
(provided by the `.deb`, a statically linked musl binary) bind-mounted
read-only into the digest-pinned `gcr.io/distroless/static-debian13:nonroot`
base. An explicit `image` in the init answers lets the operator select a
custom mail image instead (the host binary is then not mounted). The
generated base records which mode the file is in via `x-epistle-managed-image`:
true for the default host-binary shape, false for a custom image.

Apt upgrades refresh the stack only when `podup-epistle.service` exists
and is enabled for `glyndor-epistle`. Failures print a warning and leave
the package installed; retry with `sudo epistle stack update`. Stacks
disabled with `stack down` stay disabled until `stack up`.

### What the package does on install and upgrade

The `postinst` of the `.deb` runs on every install, upgrade and
`dpkg-reconfigure epistle`. It creates the `glyndor-epistle` account and its
directories, adds the subordinate id ranges, turns on linger, enables the
account's `podman.socket`, applies the port floor and, on an upgrade of an
enabled stack, runs `epistle stack update`. Each step does only what is still
missing, so running the script again is safe.

Some steps depend on something that finishes a moment later: the lock that
`usermod` takes on `/etc/subuid`, a name service that has not caught up with a
new account, and the user manager that linger starts in the background
together with its bus (`/run/user/<uid>/bus`). The script tries those steps up
to five times, two seconds apart, and waits up to ten looks (about eighteen
seconds) for the user manager before it enables the socket or updates the
stack. `epistle move-subids` does the same for the lock and for the manager it
restarts.

A step that still fails does not stop the others and does not fail apt. The
script prints one line on stderr that names what failed and the command that
repeats it, and exits 0, so dpkg marks the package as installed even though
that step did not happen. What stays undone is exactly what the line names;
nothing is rolled back. When the account cannot be created, everything that
needs it is skipped (directories, subordinate ids, linger, the Podman socket,
the stack update) and the package is configured without them: running
`sudo dpkg-reconfigure epistle` repeats the whole script once the cause is
gone, and `epistle init` refuses to continue until the account exists. A
directory that already exists is never changed: when its owner is not
`glyndor-epistle` or its mode is looser than the one the package uses (`0700`
for the state directories, `0750` for `/etc/epistle`), the script prints the
`chown` and `chmod` that fix it.

Apt shows these lines at the end of the upgrade:

| Message starts with | What it means | What to run |
|---|---|---|
| `could not create the glyndor-epistle account` | `adduser` failed five times; the steps that need the account were skipped. | `sudo dpkg-reconfigure epistle` |
| `could not create <dir>` | `install -d` failed five times. | `sudo dpkg-reconfigure epistle` |
| `<dir> is owned by ... with mode ...` | An existing directory has another owner or a looser mode. Nothing was changed. | The `chown` and `chmod` in the message |
| `could not add the subuid/subgid ranges` | `usermod` found `/etc/subuid` or `/etc/subgid` locked, or failed for another reason (see the line above it). | `sudo dpkg-reconfigure epistle` |
| `no free block of 65536 subordinate ids` | `/etc/login.defs` leaves no room for a block. It is reported once and not retried. | `epistle check subid` |
| `loginctl enable-linger glyndor-epistle failed` | `logind` did not accept the request. | `sudo loginctl enable-linger glyndor-epistle` |
| `/run/user/<uid> does not exist` or `the user manager of glyndor-epistle did not answer` | The manager had not started when the wait ended, so the socket was not enabled or the stack was not updated. | `sudo systemctl start user@$(id -u glyndor-epistle).service`, then `sudo epistle stack update` |
| `could not enable the Podman API socket` | The manager answered but refused the unit. | `systemctl --user enable --now podman.socket` as `glyndor-epistle` |
| `the stack did not come back healthy after this upgrade` | `epistle stack update` failed; the error above the frame says which check. | `sudo epistle stack update`, or `sudo epistle stack rollback` |
| `could not look up the uid of glyndor-epistle` | The account is missing or the name service did not answer. | `getent passwd glyndor-epistle`, then `sudo dpkg-reconfigure epistle` |

To diagnose an upgrade that printed one of these, read the lines above it in
the apt output, then `systemctl status user@$(id -u glyndor-epistle).service`
and `journalctl -u user@$(id -u glyndor-epistle).service -b` for the manager,
and `sudo epistle status` for the stack. `epistle init` checks the account,
the ranges, linger and the port floor again and refuses to continue when one
is still missing.

### Rolling back an upgrade

`sudo epistle stack rollback` checks the root-owned store at
`/var/lib/epistle-rollback` before asking or stopping `mail`. Every parent must
be root-owned and protected from group or other writers, and the store must
have mode 0700. The version it selects is a directory in the store, and the
binary and its SHA-256 manifest inside it must be regular root-owned files
without group or other write permission. Links are rejected, and the digest
must match before the command proceeds. It asks for confirmation,
stops `mail`, compares the migrations in the database with those in the newest
`pre-<this version>-*.sql.gz` dump, and restores the dump only when the schema moved past it. It then copies the
kept binary over `/usr/bin/epistle` with one rename and starts `mail` on it.
Its closing message says whether the database was restored or kept.
If there is no dump from before this version, or the restore fails, nothing
is rolled back and `mail` starts again on the current binary.

The package creates the store on install or configure and saves the replaced
`/usr/bin/epistle` on upgrade as one directory per version holding the binary
and its digest. It stages that pair in an exclusive random temporary directory,
checks it, and moves it into the store with a single rename, so a copy that
fails never replaces the one already saved. It keeps the two newest versions
until the upgrade is verified: when `stack update` succeeds inside the
postinst, the postinst removes the saved generations and any staging directory
left in the store, leaving files it did not create alone, and says so on stderr.
An upgrade whose stack update failed, was skipped or found the stack switched
off keeps its copies, so a failed upgrade can still go back. A problem that
shows up after a verified upgrade has no rollback left; the dumps are gone with
it.
The version it saves has to be digits and dots, the only shape `stack rollback`
can select, so a name carrying a Debian revision, a tilde or a colon is
refused with a warning instead of taking a slot no listing can choose; so is
a part of twenty digits or more, because the command reads each part into a
64-bit integer and a part that long may not fit (the package refuses the whole
length rather than work out which ones do). A binary whose digest matches a
copy already saved is not saved again under the next name: after a manual
`stack rollback` dpkg still lists the newer version, and saving those older
bytes under it would label them with a release that is gone and push a real
copy out of the store. The upgrade says so on stderr. The same happens when you
reinstall the same binary (`apt install --reinstall`, or a package that only
changes Debian metadata): no new copy is saved and the line is the only trace.
Copies from the old `/var/lib/glyndor/epistle/rollback/` layout are ignored and
never installed, including when owned by root. If only legacy copies exist,
rollback remains unavailable until an upgrade saves a trusted copy in the new
store. The package warns when it finds legacy copies, and removes them together
with the new store's generations once a stack update has verified the upgrade.
Purging the package removes
the new store. Database dumps live under `<data_dir>/backups`, where
`stack update` can write them as the service account, and it deletes them
itself once the update is verified.

Limits:

- dpkg still lists the newer version as installed, so the next `apt
  upgrade` replaces the binary again. Hold the package with `sudo apt-mark
  hold epistle` until a fixed release, or install the older package with apt
  when the archive still has it.
- Whatever the database took after the dump (new accounts, flags, queue
  state) is gone once the dump is restored. Message files on disk are kept.
- Only the binary and the database go back; the compose file stays as
  `stack update` rendered it.
- The store is trusted only through a plain path: `/`, `/var` and `/var/lib`
  must be real directories owned by root, not links, and not writable by group
  or other. On a host where one of them fails that check (a `/var` that is a
  link, for example), the preinst does not create or fill the store. It prints `could not prepare the root-owned rollback store; rollback is
  unavailable` on stderr and the upgrade goes on, so the only trace is that
  line in the apt output. `sudo epistle stack rollback` then refuses with the
  reason. Check `/var/lib/epistle-rollback` before relying on rollback on such a
  host.

### Moving PostgreSQL to a new major

A release can pin a newer PostgreSQL major in `deploy/images/Dockerfile`. A
new major cannot open the old one's cluster, so `stack update` keeps the db
image the stack runs and says so; the move is a separate, explicit step:

```sh
sudo epistle db upgrade
```

It counts the rows of every table, stops `mail`, dumps the database into
`<data_dir>/backups/pre-db-upgrade-<old>-to-<new>-<timestamp>.sql.gz`, stops
`db`, switches its image, starts it, loads the dump in one transaction and
counts again. The images from PostgreSQL 18 on keep each major's cluster in
its own directory of the `epistle-pgdata` volume, so the new major starts
empty beside the old cluster rather than over it. When the counts match, the
whole stack starts on the new major; on any failure the old image and its
untouched cluster come back and `mail` starts again. The old cluster stays
in the volume at `/var/lib/postgresql/<old>` until it is removed by hand
after mail is verified.

### Looking at the database

```sh
epistle db status [--json]
```

Prints the PostgreSQL version, the size of the database in bytes, the number of
user tables, the connections to it and the connection limit. It runs one
`SELECT` over the server's own catalogues in the `db` container (`podup exec`),
changes nothing, reads no table, and gives up after 15 seconds. The JSON result
is `database`, `version`, `size_bytes`, `tables`, `connections` and
`max_connections`. With no `[database]` in the configuration, or no stack to ask,
it exits `3`; a query that fails or answers with something else exits `1` and
prints nothing on stdout. Maintenance that rewrites data, a manual `VACUUM` or a
second backup command next to `epistle backup`, is not offered here.

## Backup and restore

`epistle backup --config F` writes a gzip-compressed tar to stdout
(the same archive the `Backup` table at the top of this document
describes) and `epistle restore [--force] [--dry-run] [--yes|-y] --config F`
replays one back onto the data directory. `--dry-run` lists the
entries the restore would write and changes nothing. Without it,
`restore` asks on the terminal first; `--yes` answers that question and
never stands in for `--force`. Both detect the container stack by looking for
`<data_dir>/compose/compose.yaml` and route the database work
through `podup exec -T db` in that case, so the same command line
works on the host and inside the container deployment:

- **host** (no compose file): the host `pg_dump`/`psql` is invoked
  directly. The password reaches the child through the `PGPASSWORD`
  environment variable (read from `[database] url` or `[database]
  password_file`), never through argv, so the secret is never visible
  through `/proc/<pid>/cmdline`. A missing or empty `password_file`,
  a non-zero exit, empty output, or output that does not end with
  pg_dump's closing marker (`-- PostgreSQL database dump complete`) is
  a hard error: the run exits non-zero with a one-line stderr message
  that names the cause. A dump cut short with a clean exit status is
  refused too, so a truncated `database.sql` never reaches the archive.
- **container** (compose file present): the dump runs through
  `podup -f <compose> exec -T db sh -c <script>`. Restore writes the SQL
  to a host temp file and copies it into a directory that root makes in the
  `/tmp` tmpfs of `db` (`podup exec -u root db sh -c "mkdir -m 711 ..."`) with
  `podup cp <host> db:/tmp/<staged-name>/restore.sql`. The file holds the
  credential hashes of every account. `podup cp` keeps the mode and the
  numeric owner of the host file, and in `db` that owner is neither root nor
  the database user, while root, with every capability dropped, cannot change
  the mode of a file that is not its own. So the mode is set before the copy:
  the host file is `0644`, inside a directory only the operator can enter
  (`0700`), and the copy sits in a `0711` directory that only root can list.
  `psql` then runs as the container user through the same shell with `-v
  ON_ERROR_STOP=1 -1 -X -f '/tmp/<staged-name>/restore.sql'`, reading the
  copy through its `o+r`. It cannot run as root, because the password mounted
  in `db` is readable by the container user alone. A file that user can read
  adds no exposure: it already reads every one of those hashes in the
  database.
  Each
  script reads `/run/secrets/epistle_db_password` into `PGPASSWORD`
  inside `db` before executing the client. `POSTGRES_PASSWORD_FILE` is
  read by the image entrypoint during initialization, not by libpq. The
  host argv contains the shell script and secret path, never the password
  value, and the host process does not load the password. Restore
  stops at the first SQL error and rolls back the single transaction.
  The replay script runs `exec psql`, so a `SIGTERM` sent to the exec
  (Ctrl-C, a timeout, an aborted `podman exec`) reaches `psql` and
  aborts the transaction instead of the idle wrapper shell. The staged
  directory is then removed with `podup exec -T -u root db sh -c "rm -rf
  '/tmp/<staged-name>'"`, whether the replay succeeded or failed (not when
  the directory could not be made). If that removal fails, the error (or,
  when the replay worked, a warning) says which path in the container is left
  and how to remove it.

The archive's `database.sql` has to end with the closing marker `pg_dump`
writes, as the backup requires; a restore refuses one that does not before it
touches anything. The database is loaded before the files are laid down, and
the archive is checked against `data_dir` first. A dump that `psql` rejects
therefore leaves both the database and the files as they were. When the load
ends without a `psql` exit (the exec was cut), the message says it is not
known whether the dump was committed and points at `epistle db status`. If the
files fail after the database loaded, the message says so, and running the
restore again with `--force` finishes the job.

`podup exec` did not forward stdin before 5.15.0 (measured against `podup 5.10.13`
and `5.14.0`), which is why the restore path uses `podup cp` to land the SQL file
inside the `db` container rather than `psql < archive.sql`. The temp
file on the host is created in `$TMPDIR` at `0644`, inside a directory
created at `0700`, under a name unique to that restore, and a guard removes
both on every exit path, error and panic included. A `SIGINT` or `SIGTERM`
ends the process without running the guard, so a restore killed that way
leaves its host directory (mode `0700`, owned by the operator) and its copy
in the `db` container behind. The next `restore` removes the host directories
left by a process that no longer exists, and the ones in the container, saying
so with the path; if it cannot remove one it names the path and the command
(`podup exec -T -u root db rm -rf`). A restart of `db` empties them too, the
directory being in a tmpfs. The host cleanup only touches entries of the same
user, so a restore killed as root is not cleared by one run as an operator,
and the reverse.

### What lives in the tar

The archive is a faithful snapshot of `data_dir`, **including the live
private-key material**: DKIM signing keys (`dkim-*.key` / `.pem`), the
ARC seal key, the at-rest message-encryption key file, `log-pseudonym.key`,
and the per-account credential store. Treat the archive the way you would
treat the keys themselves: store it offline, encrypt it at rest, restrict
who can read it, and never leave a copy on a shared host. Delete the
archive file once `restore` has been verified.

Restore writes every credential at `0600` regardless of what the
archive recorded: the private-key material, everything under `secrets/`,
`accounts.toml`, and the per-account credential stores. An archive that
captured a permissive umask (or that was tampered with) cannot bring
one back group- or world-readable. The root `config.toml` keeps its
owner bits and loses every group and other bit, so a co-tenant on a
shared host cannot read or edit the live config. Every other file lands
at the mode the archive recorded (always masked to the lower 9 bits, so
`setuid` / `setgid` / sticky bits never survive a round-trip).

Every directory the restore creates lands at `0700`, whatever umask the
host runs with, and so does `data_dir` itself when the restore is the
one that created it. A `data_dir` the operator already had keeps the
mode they gave it.

## `epistle mta-sts-serve`

Run a second instance of the same binary for the public policy endpoint:

```sh
epistle mta-sts-serve --policy-dir /var/lib/epistle/mta-sts \
  --cert /etc/epistle/mta-sts-cert.pem --key /etc/epistle/mta-sts-key.pem \
  --listen 0.0.0.0:8443
```

`--listen` defaults to `0.0.0.0:8443`. Make this listener reachable on public
HTTPS port 443 at `mta-sts.<domain>`. The certificate must cover that hostname
for every served domain; a certificate covering only the mail hostname is
insufficient. The command needs no mail configuration or database.

`GET` and `HEAD` at `/.well-known/mta-sts.txt` read `DIR/mta-sts.txt` on each
request and return `Content-Type: text/plain; charset=utf-8` with
`Cache-Control: max-age=<policy max_age>`. Other paths and a missing policy
return an empty 404. Other methods on the policy path return 405 with
`Allow: GET, HEAD`. Invalid policy contents or read failures other than a
missing file return an empty 500.

TLS 1.2 and 1.3 are enabled. The HTTP request line and headers together are
limited to 8 KiB, and each connection has a 30-second lifetime including the
TLS handshake. Certificate and key file changes are checked on new
connections. Valid replacements take effect without restarting; an invalid
replacement retains the previous certificate and is retried on the next
connection.

Configure [`[mta_sts] policy_dir`](configuration.md#mta_sts) on the ordinary
`serve` process to write the shared policy directory at startup. After changing
the policy configuration, restart `serve` and republish the `_mta-sts` TXT
record printed by `dns-records`; its ID is derived from the policy content.

## `epistle local` (test harness)

`epistle local --dir <DIR> [--port-base 10000]` is a complete server that touches
nothing outside `--dir` and the loopback interface. It exists so anything that
needs persistent external effects (the coming `init`, DNS publishing, ACME)
can be exercised against a single `127.0.0.1` server without a domain, DNS
records or certificates. It is its own subcommand and not a flag of `serve`,
because a flag is something that gets left on in production.

What it does:

- Identity is fixed: hostname `mail.local.test`, one domain `local.test`.
  `.test` is reserved by RFC 6761 and never resolves, so nothing here can reach
  a real zone.
- Every listener binds `127.0.0.1` only. There is no option for another
  address. Ports are `port-base + {25, 587, 465, 143, 993, 8025}` for SMTP,
  submission, submissions, IMAP, IMAPS and the management API. `--port-base`
  must keep every port inside `1024..=65535`; a value outside the range is a
  usage error that names the computed port.
- The first run on an empty or missing `--dir` creates, all `0700`/`0600`:
  a marker file `.epistle-local`, a `data/` directory, a self-signed
  certificate and key for `mail.local.test`, a DKIM Ed25519 key, a
  `mail.toml` that `epistle config-check` accepts, and one account
  `user@local.test` whose password is generated from the system CSPRNG and
  stored as argon2id.
- A later run on a `--dir` that carries the marker REUSES everything byte
  for byte (same key, same certificate, same password hash). A `--dir` that
  exists, is not empty, and has no marker is refused with
  `<DIR> is not empty and was not created by "epistle local"` and no writes.
- Outbound delivery is held: mail submitted for a recipient outside
  `local.test` stays in the spool, no outbound SMTP connection is ever
  opened, and there is no `[database]` section. The flag is internal to
  `Config` (`hold_outbound`) and `serde` cannot set it; only `epistle local`
  sets it.
- On start it prints to STDERR: a first line that says `epistle local:
  starting`, followed by the directory, the six `127.0.0.1:<port>`
  endpoints, the account name, and the password ONLY on the run that
  generated it, with a line saying it is shown once. The summary uses
  `starting` because `serve` does not hook the operator from "bound" to
  "first failure" and `epistle local` does not add that hook here. stdout
  stays empty.

This is a test harness, not a deployment. There is no ACME, no DNS lookups at
startup, no DNSBL, no greylisting, no `[database]`, and the configuration
generated by `epistle local` is not a template for production.

## `epistle init` (first-run setup)

`epistle init` walks the operator through the values needed to bring a fresh
host up. The same flow drives the interactive assistant and the non-interactive
`--answers FILE` path: every question is a field on `Answers`, every answer is
validated by the same rule, and the assistant repeats a question with the same
text the file would have rejected it with.

The command shapes are:

| Command | What it does |
|---|---|
| `epistle init` | Interactive: walk through every question. |
| `epistle init --answers FILE` | Non-interactive: read the answers from a TOML file. |
| `epistle init --answers FILE --dry-run` | Print the plan, write nothing. |
| `epistle init --print-answers` | Print the answers template on stdout. |

On a terminal, setup asks inline questions in seven numbered steps. Each question
explains its purpose and what Enter selects. Options accept a number or the option
name. Invalid entries show the rejected value, the rule and a valid example, then
ask the same question again. The proposed paths are the package defaults,
`/var/lib/glyndor/epistle/data` and `/etc/epistle/mail.toml`. A review of the selected
settings and the file plan precedes an explicit confirmation. The final report
lists created or reused files, their locations and the next commands.

Accepted ordinary answers are checkpointed in
`$XDG_STATE_HOME/epistle/init-draft.json`, or
`$HOME/.local/state/epistle/init-draft.json` when the state variable is absent.
The directory is private (`0700`) and the file is `0600`. After Ctrl+C, run
`epistle init` again to accept the offer to resume. Resumed answers are validated
again, and confirmation is always asked again. Passwords are requested after
confirmation, never written into the draft or printed, and must be entered again
when resuming. Guided automatic mode accepts a DNS credential file or environment
variable reference instead of an inline token. Credential references are requested
again after interruption and are not saved in the draft. DNS publishing is still not
implemented in this build.

Without `--answers`, only a run whose stdin and stderr are both terminals and that
carries no `--json` gets the guided steps. Every other run, a pipe, a redirected
stderr or `--json`, keeps the plain questions this command shipped with: they go to
stderr and are read from stdin until it ends, so a script can still answer them and
the machine result still goes to stdout. `--answers FILE` remains the way to supply
every value up front; that path keeps its existing validation and output.
`NO_COLOR` and `TERM=dumb` suppress question colours while keeping terminal
input available. The answers file uses the TOML field names from `--print-answers`;
a missing required key fails validation before setup files are written.

Exit codes are `0` (done or nothing to
do), `1` (a step failed after effects were applied; the report names which
step), and `2` (nothing was touched, either because the answers were invalid or
because a precondition stopped the run before any effect: the existing config
could not be parsed, a required key pair was incomplete, and so on).

What this build does:

- lays the answers down under `<data_dir>/keys/` (`0700`) with mode `0600` on
  every key file: DKIM Ed25519 (`s1.pem`), DKIM RSA (`s2.pem`), and the OAuth
  public key; the at-rest storage key, the
  OAuth signing key and, with the database, the PostgreSQL admin password go to
  `secrets/` beside data_dir instead (see [the container
  stack](operations/container.md#what-each-container-may-do)); a key that already exists
  is reused, never regenerated, whatever the answers say, and one an older
  release left under `keys/` is moved; with more than one domain, the first
  signs with `s1.pem`/`s2.pem` and every other domain gets a key of its own
  under `keys/dkim/<domain>/`, named by a `[[dkim.domain]]` entry (only in a
  configuration `init` creates: running it again on one that exists keeps the
  `[[dkim.domain]]` entries the file has and adds none);
- writes the configuration file at `config_path` (also `0600`) through a
  staging path that `Config::load`s the candidate before renaming, so a config
  that does not validate never reaches its destination;
- generates a self-signed certificate under `<data_dir>/keys/cert.pem` and
  `keys/key.pem` so the produced config validates out of the box;
- creates the parent directory of `config_path` with mode `0750` when it
  does not exist (a fresh install has no `/etc/epistle/`), and prints it
  as a plan step so the operator sees it before confirming;
- creates the first mail account when one is given (the assistant asks right
  after the domains; an answers file uses an optional `[first_account]` table
  with `address`, `display_name`, `password_file` and `role_aliases`). The
  password is typed twice with echo off, or read from the first line of
  `password_file` (`-` reads it from stdin); it is never written in the
  answers file. With `role_aliases` (the default), `postmaster@` and `abuse@`
  of every domain become aliases of that account, so `config-check` no longer
  warns about the missing `postmaster@` (RFC 5321) address. The alias is
  written in the form the server stores, so a domain given with non-ASCII
  letters appears in punycode (`postmaster@xn--...`), and an address that an
  account or a masked address already holds is left alone;
- prints the plan before the confirmation, and a report on stderr listing what
  was reused, what was written, and what was skipped; the report is also
  printed when a later step fails, so the operator can see what is already
  on disk before fixing the failure.
- proposes the public addresses from the host's own interfaces, keeping only
  global ones (the rule `public_ipv4`/`public_ipv6` must pass, so no private,
  loopback, link-local, ULA, CGNAT or documentation address): the assistant
  shows a detected address as the default (empty accepts it, `none` skips the
  field, anything typed replaces it), and an answers file that leaves an
  address out gets the detected one, reported on stderr. An address the file
  names is never replaced, and `public_ipv4 = "none"` (or `public_ipv6`) says
  there is no address of that family: detection never overrides it, and with
  both families settled the interfaces are not read. Behind NAT the host has
  no global address, and a one-line hint says to set the public one by hand;
- ends with the reverse DNS (PTR) of each public address, on stderr, after a
  successful run and after `--dry-run`. Each line says whether the PTR names
  the hostname and the hostname resolves back to the address, points
  elsewhere, is missing, or could not be looked up; a missing or wrong PTR
  names what to ask the hosting provider for, since the record lives in the
  address owner's zone. The block never changes the exit code: a missing PTR
  is reported, not fatal. `epistle verify-dns` runs the same check later.

### Why a self-signed cert

In production, TLS material for the mail listeners comes from ACME (the
`[acme]` section) or from an operator-supplied PEM. `init` is the
first-run setup, before either has had a chance to run: the operator has
not yet proven control of the hostname to a CA, and they have not yet
chosen where their long-lived PEM lives. Without a cert, however, the
generated config cannot pass `epistle config-check`: the listener schema
mandates `[tls]` for every IMAP, IMAPS, ManageSieve and POP3S listener,
and `[tls]` mandates both `cert_file` and `key_file` paths. `Config::load`
does not check that those paths point to existing files, so the config
would technically validate, but the listeners would refuse to bind at
runtime with no usable material.

`init` therefore generates a self-signed pair in `<data_dir>/keys/`,
references it from the produced `[tls]`, and lists the step in the plan
so the operator sees it. The pair is generated once and reused on every
subsequent run (same never-regenerated rule as the DKIM and OAuth keys);
the operator replaces it with an ACME-issued or hand-rolled PEM when
they wire up `[acme]` or update `tls.cert_file` / `tls.key_file` to
point elsewhere.

With `[acme]` on, that pair is what the server presents until the
authority answers. The certificate the authority issues is written to
`<data_dir>/acme/cert.pem` (its key to `<data_dir>/acme/key.pem`), the
running server reloads it in memory, and the next start presents it in
place of the `[tls]` pair. `init` leaves the ACME path empty on purpose:
a self-signed certificate written there reads as valid until the year
4096, so the renewal loop would see nothing due and never ask the
authority for the real one.

Re-running with the same answers is a no-op for every file that already
matches: the keys are reused, the config is reported `identical, not touched`,
and the file mtime does not change. A run that changes every answer the
operator can change (hostname, domains, services, mode) does not regenerate a
single key.

An `init` that stops part way (killed, or a step that failed once the keys were
written) leaves what it had finished and no `mail.toml`: the keys, the
self-signed pair and the passwords are in place, because each file is written
whole under a temporary name and renamed, so none is ever half written. Run the
same command again. The keys are reused byte for byte, the missing files are
written, and nothing needs to be deleted first. Do not delete the storage key
to "start clean": it encrypts what is already stored. Every answer is checked
before the first file is written, so a refusal of the answers (an unset
variable in a path, an address already in use) leaves nothing behind; only a
failure of the disk or the process itself can stop a run after the keys.

What this build does **not** do (other parts of `init`, deliberately out of
scope here):

- DNS publishing for automatic mode: the plan still lists the `dns` step, but
  the step renders `not implemented in this build`. The operator follows it by
  hand or waits for the next part of `init` to land;
- a management-API credential: `services.api = true` writes an API listener and
  an empty `[api]` section. Create labelled keys with `epistle api-key create`.
  Operators who want a static token may set `token_hash` themselves using
  `epistle token-hash`. `epistle status` treats "no static token configured"
  as a good state. No current SCIM or OAuth route needs the static token;
  see [the API guide](api.md#turn-it-on).

## DNS records and listener probes

| Command | What it does |
|---|---|
| `epistle dns-records [--json]` | Print the DNS records this deployment should publish: SPF, DKIM, DMARC, MTA-STS, MX, and a DANE TLSA record when a certificate is present. Reads the configuration only; nothing is queried or changed. |
| `epistle verify-dns [--json]` | Look the same records up in DNS and report drift. Read-only. Exits 1 when a record is missing or differs. See [DNS](dns.md). |
| `epistle probe [--json]` | Dial each enabled listener on loopback and read its greeting. Exits 0 when every listener answers and 1 when one is down or greets wrongly. It is the container healthcheck, and the `ports` area of `status` runs the same check. |

All three take `--config FILE`.

## Keys and tokens

| Command | What it does |
|---|---|
| `epistle dkim-keygen --out F` | Generate an Ed25519 DKIM key and print the DNS record value. |
| `epistle dkim-keygen --rsa [--bits 2048\|4096] --out F` | Generate an RSA DKIM key (in process, no external program) and print the `k=rsa` record. The RSA `p=` value is large enough to need 255-octet TXT splitting; the printed record is already in the form a zone file accepts. |
| `epistle storage-keygen` | Print a fresh base64 32-byte key for at-rest message encryption (`[storage]`). |
| `epistle oauth-keygen --out F` | Generate the ES256 key pair for the built-in OAuth server: the base64 PKCS#8 private key for `[oauth] signing_key` and the matching public point for `[oauth] public_key`, written to `F` (mode 0600, an existing file is refused). The private key is never printed. |
| `epistle token-hash` | Read a bearer token on stdin, print the `sha256:<hex>` for `[api] token_hash`. |

The API keys made with `epistle api-key` open the HTTP API, described in the [HTTP API guide](api.md).

## Rotations (`epistle dkim`, `epistle tls`, `epistle api-key`)

| Command | What it does |
|---|---|
| `epistle dkim show [--json]` | The DKIM key in service (selector, key file, rotation time, next scheduled rotation, previous selector and when it retires, the RSA selector in service, from `state` or `config`, with the RSA selector a rotation retires or moves to) and whether the published TXT of each signing domain matches it. A domain with a `[[dkim.domain]]` key is listed under `overrides` and checked against that key. `stale_records` lists the records of the shared key still published at a domain that has a key of its own (an unfinished `dkim split`; the text form says `split incomplete`). `keys` (one `key <domain>: ...` line per hosted domain in the text form) names the selector each domain signs with and, for a domain on the `[dkim]` default, the other domains that sign with the same key (`shared_with`), so a shared key is visible. Reads the same rotation state as `serve`, `dns-records` and `verify-dns`; an unreadable state file is an error, never a silent fallback to the configured key. A rotation the server began and has not finished is listed with its selector (`in_progress` in JSON), or with the reason it is being withdrawn. Every time it prints (when the key rotated, when the next rotation is due, when the previous selector retires, when the rotation began, when it was requested) is an RFC 3339 UTC instant such as `2026-12-31T23:59:59Z`; `--json` keeps the epoch seconds. |
| `epistle dkim rotate [--dry-run]` | Rotate the Ed25519 key now, and with dual signing the RSA key in the same step (new selector `rsa<day>`). Refuses what the server refuses: no `[dkim]` or `[dns]`, a signing domain outside every `[dns]` zone, a provider that cannot be built, a second rotation on the same UTC day. Domains with a `[[dkim.domain]]` key are not signing domains of the default key. `--dry-run` prints the selectors and the TXT names and changes nothing. `--domain D` is always refused: a `[[dkim.domain]]` key does not rotate, and the refusal says how to replace it (or that `D` signs with the default). |
| `epistle dkim split [--dry-run] [--wait SECONDS] [--finish]` | Give every domain that signs with the `[dkim]` key a key of its own, for installs made before each domain had one. One domain keeps `[dkim]` (the first in `domains` that signs with it); each other gets an Ed25519 key (and an RSA one when `[dkim]` signs with both) under `<data_dir>/keys/dkim/<domain>/`, with the selectors `own<day>` and `ownrsa<day>`, which the shared key does not publish. The records are published through `[dns]` for the domains inside its zone and printed for the rest (`publish by hand: ...`); the command then asks a resolver (about every 5 seconds, `--wait` seconds in all, default 120, `0` asks once) until every record shows the right key. Only then does it write the `[[dkim.domain]]` entries and restart the server, so no message is ever signed with a key receivers cannot look up, and a run that stops before that changes nothing about signing: running it again reuses the keys. `--dry-run` prints the plan and makes no key, publishes nothing and writes nothing. Refused while a rotation is in progress. The shared key is still published at the domains that left it, so whoever holds it can still sign as them: the report lists those records with their full names (`stale after the switch: s1._domainkey.b.example.org ...`, and `stale_records` in `--json`; it covers the configured pair, the selector in service and the one a rotation is retiring), and `dkim show`, `status` and `check` warn `split incomplete` while any is published. `--finish` is the follow-up: after the 14-day overlap (counted from the day each domain's own key was made; before that it refuses and prints the date) it removes those records through `[dns]` where it reaches the domain, and prints the rest as `remove by hand: ...`. It only ever lists records at domains that have a `[[dkim.domain]]` entry, so the domain that kept the `[dkim]` key never loses its record; `--dry-run` lists what it would remove. `--json` gives `keeps`, `moves` and `stale_records` with `result` `split`, `waiting` (with `missing`) or `dry-run`, and for `--finish` `retired` and `manual` with `result` `retired`. |
| `epistle dkim cleanup [--dry-run] [--yes]` | List the `dkim-ed<day>.key` and `dkim-rsa<day>.key` files and `ed<day>._domainkey` and `rsa<day>._domainkey` TXT records of the signing domains that neither the active, the previous, a pending nor a configured selector (`[dkim]` or `[[dkim.domain]]`) uses (left by crashes in older releases), ask for confirmation and queue their removal. `--dry-run` only lists; `--yes` skips the question. Refused when the rotation state cannot be read, and nothing is queued when the server does not rotate keys for this configuration. |
| `epistle tls show [--json]` | The certificate the server presents (the ACME pair when `[acme]` is set and `<data_dir>/acme/{cert,key}.pem` is usable, otherwise the pair the `[tls]` section names, otherwise the bootstrap pair `init` wrote in `<data_dir>/keys/`): subject, names, issuer, expiry as an RFC 3339 UTC date (for example `2026-12-31T23:59:59Z`), days left, and `acme` or `static` as the source. JSON adds `not_after_utc` and keeps the epoch-second `not_after` field. The time a renewal was requested for is an RFC 3339 UTC instant as well. `serve`, `probe` and this command resolve it the same way. |
| `epistle tls renew [--force]` | Ask the server to renew the ACME certificate. Without `--force` nothing is queued while the ACME pair is usable, its certificate is issued by an authority, and it is outside its `renew_before_days` window. An unusable pair or a self-issued certificate is due regardless of that window. |
| `epistle api-key rotate LABEL` | Replace the secret of an API key and print the new one once. Scopes, domains, expiry and CIDR stay; the old secret stops working in the same write, when the running server's file watcher reloads `api_keys.toml`. |

`dkim rotate`, `dkim cleanup` and `tls renew` do not rotate, remove or issue
anything themselves. The running server is the only writer of DKIM keys, DNS
records and the ACME account, so these commands drop a request file in the data
directory (`dkim-rotate.request`, `dkim-cleanup.request`, `acme/renew.request`)
and the server serves it within a minute through the same code as the scheduled
rotation, removing the file on success. A cleanup removes only what is still
unused when the server serves it. A request survives a failed publication or issuance (the reason is in
`dkim-rotate.error` or `acme/renew.error` and in `show`), and a stopped server
serves it at its next start. DKIM signing switches in process as soon as the
new TXT records are published, so no restart is needed. A forced DKIM rotation
retires an older previous selector first, since the state holds only one.

## Accounts

Changes to a dynamic account (`<data_dir>/accounts.toml`) reach the running
server within seconds, no restart. A static account (`[[accounts]]` in
`mail.toml`) is refused with a hint to edit the config file.

Addresses, domains and account names are stored in lowercase whatever you type: `account add Alice` creates `alice`, with a note on stderr to use the lowercase form from now on.

### Account names and addresses are two rules

An account name and a mail address are checked by different rules, and they stay different.

- **The account name** is also the folder name under `<data_dir>/accounts/`: lowercase ASCII letters, digits and hyphens, not starting with a hyphen, at most 64 characters. A dot is refused, and so is `_`, a space or any non-ASCII character. One rule (`src/util/account_rule/mod.rs`) serves every command and endpoint that creates an account.
- **The address** follows RFC 5322 and 5321: a dot inside the local part is fine (`torre.control@example.org`), not at its start or end, not twice in a row. Stored in lowercase.

Only `epistle init` turns one into the other: it derives the name from the address, with dots becoming hyphens (`torre.control@example.org` gives the account `torre-control` and keeps the address as typed). Nothing else derives a name. `account add torre.control --address torre.control@example.org` is refused, naming the `'.'`, before the password is asked; `account add torre-control --address torre.control@example.org` works and the account sends and receives as `torre.control@example.org`.

| Where | Account name | Address, alias or member |
|---|---|---|
| `epistle init` | derived from the address (dots to hyphens); refused when the local part cannot give a name | as typed, lowercase, must be in a served domain |
| `epistle account add N --address A` | `N` must obey the name rule, refused naming the character, nothing derived | any RFC 5322 address in a served domain, dots allowed |
| `epistle account address add N A` | `N` must exist | same as above |
| `epistle alias add`, `alias member\|sender add` | an alias has no name | any RFC 5322 address; the alias address must be in a served domain and unused |
| `POST /api/v1/accounts` | `name` obeys the name rule, `400` naming the character | `addresses` as above, dots allowed |
| SCIM `POST /scim/v2/Users` | `userName` obeys the name rule, `400` naming the character, never derived from `emails` | `emails` as above, dots allowed |
| `[[accounts]]` in `mail.toml` | the loader refuses a name that breaks the rule | `addresses` as above |

| Command | What it does |
|---|---|
| `epistle account list [--json]` | List every account, static and dynamic, with its addresses. |
| `epistle account add N --address a@b [--address …] [--display-name TEXT]` | Create a dynamic account. On a terminal the password is asked twice with echo off; piped, it is read from stdin (one line). |
| `epistle account set-name N TEXT` | Set the person's name used as sender name (JMAP identity, `/api/v1/send` From), kept as written; `""` clears it. |
| `epistle account remove N --queue discard\|drain [--yes\|-y]` | Remove the account and everything it owns: mailbox, masked addresses, app passwords, per-account suppression, queued mail (`discard` drops it, `drain` leaves it for delivery). Prints the counts removed. Asks first. |
| `epistle account password N` | Change the password (asked twice with echo off, or one line from stdin). The account is checked before anything is read. |
| `epistle account disable N` / `enable N` | A disabled account keeps its mailbox but rejects authentication like an unknown login. |
| `epistle account address add\|remove N a@b` | Add or remove a delivery address. The last address cannot be removed. |
| `epistle account quota N SIZE\|none` | Storage quota (`500M`, `10G`, `1T`); `none` falls back to the domain, then the server default. |
| `epistle account protocols N LIST\|all` | Restrict sign-in to some protocols (`imap,smtp,api,webdav`); `all` clears it. |
| `epistle account set N --default-class CLASS` | The [mail class](evidence.md) granted to the account's mail when neither the request nor the credential names one: `transactional`, `marketing`, `personal`, or `none` to clear it. |
| `epistle account save-sent N on\|off` | Save a copy of every message the account sends into its `Sent` folder. Default on; `off` is the per-account opt-out. The app-password override (`app-password create --save-sent`) wins when set. |
| `epistle account show N [--json]` | Public view: log id, addresses, disabled, quota, protocols. Works for static accounts. Never a secret. |
| `epistle account find-log-id acct-…` | Map a log pseudonym back to its account. |
| `epistle account forward list\|add\|remove N [ADDR]` | Also send the account's mail to `ADDR`. Refuses the account's own addresses, an invalid address, and any forward while `srs_secret` is unset (without SRS the copy fails SPF at the next hop). |
| `epistle account catch-all list\|add\|remove N [DOMAIN]` | Deliver mail for unknown users of `DOMAIN` to the account. `DOMAIN` must be a configured domain (not an alias) that no other account catches. |
| `epistle account 2fa show N [--json]` | Whether a TOTP secret is enrolled (never the secret). |
| `epistle account 2fa disable N [--yes\|-y]` | Remove the TOTP secret; the password alone signs in again. Asks first. |
| `epistle app-password list [--account N] [--json]` | App passwords (label, expiry as an RFC 3339 UTC instant, IP restriction), never the secret. `--json` keeps the epoch second. |
| `epistle app-password create N LABEL [--expires-at EPOCH] [--ip-cidr CIDR] [--save-sent on\|off] [--class CLASS]` | Create an IMAP/SMTP app password; prints it once. The label is 1 to 64 characters without control characters. `--class` (`transactional`, `marketing` or `personal`) is the [mail class](evidence.md) granted to mail sent with this credential. `--save-sent` overrides the account-wide setting for this credential (`on` opts the credential in even if the account is off; `off` opts it out even if the account is on). Dynamic accounts only. |
| `epistle app-password rotate N LABEL [--yes\|-y] [--dry-run]` | Replace the secret and print the new one once. The label, expiry, address range and `save-sent` setting stay; the old secret stops working in the same write, and the running server picks the change up from the file within a few seconds (`reload` says `loaded`, `no-server` or `timed-out`). Asks first, because every client using the old secret stops working. `--dry-run` checks that the credential exists and prints no secret. |
| `epistle app-password rename N LABEL NEW_LABEL [--dry-run]` | Give the credential a new label; the secret and the settings stay, so clients keep working. Refuses a label that is taken (exit 2). `previous_label` in the JSON result holds the old one. |
| `epistle app-password revoke N LABEL [--yes\|-y]` | Revoke it. Asks first. |
| `epistle api-key list [--json]` | API keys: label, expiry (RFC 3339, `--json` keeps the epoch), CIDR, scopes, domains, bound account. Never the key. |
| `epistle api-key create LABEL --scope S [--scope …] [--domain D] [--account N] [--expires-at WHEN \| --expires-in 90d] [--ip-cidr CIDR] [--class CLASS]` | Create a key; prints it once. `--ip-cidr` is an allowlist of one CIDR for the client address. `--class` (`transactional`, `marketing` or `personal`) is the [mail class](evidence.md) `/api/v1/send` grants to mail the request gives none. `WHEN` is an epoch, a date, an RFC 3339 instant or a duration; no key expires unless one is given, and `status` warns about the ones that do not (see [Expiry is opt-in](api.md#expiry-is-opt-in)). Scopes: `read`, `write`, `send`, `scim`. `--domain` confines it to domains. `--account` binds it to one account (static or dynamic): it then reaches only JMAP and `/api/v1/send`, cannot hold `scim`, and takes no `--domain`. |
| `epistle api-key revoke LABEL [--yes\|-y]` | Revoke a key. Asks first. |
| `epistle api-key rotate LABEL` | New secret, same scopes; prints it once. |

## Mail in and out

| Command | What it does |
|---|---|
| `epistle export --account N [--maildir DIR]` | Export an account's mailboxes as an mbox stream on stdout, or as a Maildir tree where `Work/Project` is the Maildir++ folder `.Work.Project`. |
| `epistle import --account N [--maildir DIR]` | Import an mbox stream from stdin, or a Maildir tree. Maildir++ folders become nested folders: `.Work.Project` is `Work/Project`. |
| `epistle migrate imap --account N --host H --user U` | Copy a remote IMAP account, resumably. See [migration](operations/migration.md). |
| `epistle migrate mox --from DIR` / `migrate stalwart --from FILE` | Import domains, accounts, aliases and DKIM keys. Needs `--passwords-out FILE` (a new file, mode 0600, one `account<TAB>password` line per new account) or `--password-reset`, except with `--dry-run`. `--merge` keeps what already exists and adds the rest; `--json` prints the plan and the changes. |
| `epistle queue` | List the outbound delivery queue (same as `queue list`). See [Outbound queue](#outbound-queue). |
| `epistle delivery list [--recipient ADDR] [--account NAME] [--since WHEN] [--until WHEN] [--status S] [--limit N] [--json]` | Read the per-recipient delivery log: one record per delivered, failed, suppressed or canceled recipient, and one per deferred recipient for each distinct reply, at most eight per recipient (a retry deferred for the same reason adds none), newest day first, at most `N` records (default 100, at most 100000; a larger value is a usage error). The log is read a line at a time, so memory does not grow with the size of a day's file, and days outside `--since`/`--until` are not opened. `--since` and `--until` take an RFC 3339 time or a duration such as `24h` or `7d` counted back from now; `--since` after `--until` is refused, and so is a filter given empty (`--account ""`): it is a usage error (exit 2), never "no filter". `--status` (also `--outcome`) is `delivered`, `deferred`, `failed`, `suppressed` or `canceled`. Metadata only, never a subject or body. The time of each record is an RFC 3339 UTC instant; `--json` keeps the epoch second. `epistle delivery` alone is `delivery list`. Needs `[storage] delivery_log_days` above 0. |
| `epistle delivery show ID [--json]` | Every record of one message, oldest first. `ID` is the spool id of the `SPOOL` column of `delivery list`. The time of each record is an RFC 3339 UTC instant; `--json` keeps the epoch second. The remote host and its reply are escaped for the terminal. Exits 2 for an id that is not a UUID or that has no record. |
| `epistle delivery export [filters] [--limit N] [--json]` | The records that pass the same filters as `list` as CSV: `time,outcome,spool_id,account,from,recipient,remote,reply,attempt`, time as RFC 3339 UTC, newest day first, at most `N` records (default 10000, at most 100000). A field a spreadsheet would run as a formula (the reply of a remote server can begin with `=`) is written with a leading apostrophe. With `--json` the records are the objects `list --json` prints, `extra` included. |
| `epistle suppression list [--account SENDER] [--json]` | List suppressed (hard-bounced) recipients. A recipient suppressed by a bounce also shows, tab separated, when and the remote reply that proved the address bad. |
| `epistle suppression add ADDR [--account SENDER] [--reason TEXT]` | Suppress a recipient by hand. Mail queued for it is dropped without a bounce on the next delivery pass. With `--account` it applies to that sender only. `--reason` is kept with the entry and shown by `list`, `show` and `export` (at most 512 characters, no control characters; the default says it was added by hand). Exits 1, printing nothing, when the entry could not be written. |
| `epistle suppression remove ADDR [--account SENDER]` | Deliver to the recipient again. |
| `epistle suppression show ADDR [--account SENDER] [--json]` | One entry: the address, the list it is in, when and why. Exits 2 when the address is not suppressed in that list. |
| `epistle suppression export [--account SENDER] [--json]` | Write the list as CSV on stdout: a header `address,since,reason`, then one entry per line with the time as RFC 3339 UTC. A field that begins with `=`, `+`, `-` or `@` (after any apostrophes) is written with one more leading apostrophe so a spreadsheet does not run it as a formula, and `import` takes exactly one off, so a value that really starts with an apostrophe survives the round trip. With `--json`, one array of `{address, since, reason}`. |
| `epistle suppression import FILE [--account SENDER] [--reason TEXT] [--dry-run] [--json]` | Suppress every address of a file in the form `export` writes, or a plain list with one address per line. UTF-8 text of at most 16 MiB and 100000 entries; blank lines and lines starting with `#` are skipped. The whole file is checked first: one bad line refuses it with exit 2, naming the first ten bad lines, and nothing is written. An address that is already suppressed keeps its entry. The time must be a real RFC 3339 time (`2026-02-30T00:00:00Z` is refused); the file must be a regular file, a named pipe or a device is refused. `--reason` is the reason for lines that give none. The result counts `added`, `already` and `duplicates` (an address repeated in the file); `--dry-run` counts and writes nothing. If a write fails part way the error says how many entries were written; running the import again skips them. Run as root, the file is read through a private copy like the other input files. |
| `epistle report-abuse` | Read an offending message on stdin, print an RFC 5965 ARF report to send to the sender's abuse address. |
| `epistle reports [--days N]` | Summarise the DMARC aggregate and TLS-RPT reports that arrived for our domains over the last `N` days (default 7). Per policy domain: reporters seen, total rows, and failing rows by `source_ip` (DMARC) or failing sessions by `result_type` and `sending_mta_ip` (TLS-RPT). Reads the JSONL store under `data_dir/reports/`; never writes to it. |

For `migrate imap`, `data_dir` and its migration state must be owned by the
process's effective user, including during `--dry-run`. Run the migration as the
account that owns the data directory; group write permission alone is insufficient.
Parents of `data_dir` may be symbolic links. The final `data_dir` component and
entries under `migrate/<account>` must not be symbolic links.
One migration per account runs at a time: the run holds
`migrate/<account>/.lock` and a second run waits 30 seconds for it before it
stops with the name of that file. A dry run writes nothing, so it takes no lock
and never waits.
Recovery uses a private temporary disk index with a fixed metadata workspace, so
large local mailboxes do not require an in-memory identity set. Free disk space is
still required; an index failure retains the saved progress. Recovery bounds each
decoded local message by the configured `max_message_size`, independently of the
source response literal limit.

An interrupted batch is replayed from the first UID the folder listed, matching
pending copies against the local mailbox.
What an earlier run already confirmed is not downloaded again: every remote
folder keeps a ledger of the messages it has handed over next to its progress
file in `data_dir/migrate/<account>`, the replay skips whatever the ledger
confirms, and only the rest is matched against the local mailbox. A message you
deleted or moved after an interruption therefore does not come back, as long as
the ledger holds it. The ledger holds the identity of each confirmed message,
40 bytes per message, so two identical messages in the source still end up as
two copies here. It is written and synchronized before the checkpoint that
confirms the batch, so it never claims a message that is not stored locally, and
a copy left behind by a cut is dropped on the next run. A change in UIDVALIDITY
discards the ledger with a warning and reads the folder again from the start. A
ledger that cannot be read stops the run without removing anything, and the
message names the file to delete to copy the folder again. Already confirmed
local messages do not need fresh durability barriers unless the saved state
marks a batch in progress.

A record can only be appended above the UID the ledger already reaches, because
its records rise in UID order and a lookup binary searches them. A message a
replay confirms below that UID is therefore left out of the ledger, and from
then on only the match against the local mailbox protects it: if you delete it
there, a later replay brings it back. A message the source stops marking
`\Deleted` is confirmed that way.

A migration a version without a ledger started carries on with it: that version
kept only the progress file, so the new ledger starts empty and confirms nothing
about what was already copied. A later run that is cut and then replayed
downloads that prefix once more and matches it against the local mailbox, so a
message deleted there in the meantime can come back once. Deleting
`migrate/<account>` discards the progress and the ledgers of every folder, which
is how a full copy of the account is forced.

UID windows start at 10000 and double across empty ranges, keeping sparse UIDNEXT
values from causing a long sequence of empty queries. Each folder/run permits at
most `32 * (EXISTS + 1)` listing commands. A final bounded query checks UIDs at
and above UIDNEXT in case the source underestimated it. Without UIDNEXT, up to 16
messages arriving after EXAMINE are accepted and the discrepancy is logged;
larger counts are refused.
A limit or inconsistent-count error retains completed window checkpoints; run the
same command again to resume. While a batch is in progress every local message
stays a candidate for matching, not only the ones newer than the checkpoint.
A dry run saves no checkpoints.

## Outbound queue

`epistle queue <action>` inspects and steers the outbound spool in
`data_dir/spool`. The running server picks up every change on its next queue
pass, with no restart: the worker re-reads each entry from disk before it
decides whether to attempt it.

| Command | What it does |
|---|---|
| `epistle queue list [--json]` | One line per message (id, attempts, sender, recipients, `held`), or a JSON array with the envelope and last error. |
| `epistle queue show <id>` | Envelope, attempts, next attempt, held state and the last delivery error. The next attempt and the time the entry has been held for are RFC 3339 UTC instants. Never prints the message body. |
| `epistle queue retry <id>\|--all` | Make the next attempt happen now, skipping the backoff. The attempt count is kept, and a held entry stays held. |
| `epistle queue hold <id>\|--all` | Never attempt the entry until it is released. |
| `epistle queue release <id>\|--all` | Let a held entry be attempted again. |
| `epistle queue destinations [--json]` | The recipient domains and exchanger hosts on hold because they asked to slow down, as the spool shows them: until when (an RFC 3339 UTC instant), after how many deferrals in a row, and the reply. `epistle queue list` names them too. |
| `epistle queue release-destination <domain>\|<host>\|--all` | Make every recipient waiting for that hold due at once, its run of deferrals forgotten; the running worker picks it up at its next scan. |
| `epistle queue remove <id> [--yes\|-y]` | Delete an entry without delivering or bouncing it (same as `DELETE /api/v1/queue/{id}`). Asks first; `--yes` skips the question. |

A held entry is not attempted and its time on hold does not count toward the
give-up window below, so a message parked for a week is not bounced on its first
attempt after release. A hold that arrives while the worker is already
delivering that entry takes effect for the next attempt.

## Masked addresses

`epistle masked <action>` manages an account's masked addresses from the shell.
They are stored in `data_dir/masked.json`; the running server reloads that file
within a couple of seconds, so no restart is needed. Writes go through the same
code as the API, so the `masked_addresses_max` cap applies. An account that does
not exist is refused.

| Command | What it does |
|---|---|
| `epistle masked list <account> [--json]` | One line per address (address, label, `enabled` or `disabled`), or a JSON array. |
| `epistle masked add <account> [--label L] [--domain D]` | Mint a new address and print it. The domain defaults to that of the account's first address; `--domain` must be a configured domain. |
| `epistle masked remove <account> <address> [--yes\|-y]` | Delete the address. Asks first; `--yes` skips the question. |
| `epistle masked disable <account> <address>` | Stop delivery to the address (it is refused like an unknown user) without deleting it. |
| `epistle masked enable <account> <address>` | Deliver to it again. |

## Authentication bans

With the container stack, `ban` and `account remove` also run inside `mail`
when the configured database socket directory is absent on the host. Credentials
stay in the mounted config and password file, never in the exec arguments.

`epistle ban <action>` manages the shared authentication ban store: the client
addresses refused after repeated failed logins, plus a few operator controls.
It needs `[database]`, because the bans live in PostgreSQL
(`auth_ban`, `auth_failure`, `auth_allow`). The server reads those tables on every
authentication check, so a change made here applies to the running server at once,
with no restart. Without `[database]` the command prints that bans are kept in
memory by the running server and are not manageable from the CLI, and exits 1.

| Command | What it does |
|---|---|
| `epistle ban list [--json]` | Active bans: subject (`ip:<addr>`, where an IPv6 client appears as its /64, `cidr:<net>/<prefix>`, `pair:<login>|<client>` or `account:<login>`), reason, and when each one ends, as an RFC 3339 UTC instant. `--json` keeps the epoch second. |
| `epistle ban add <ip\|cidr> [--for 24h]` | Ban an address or network by hand. `--for` takes a number and a unit (`s`, `m`, `h`, `d`, `w`); the default is 24h. Refused for an address on the allow list. |
| `epistle ban remove <ip\|cidr\|subject>` | Lift the ban now and clear its failure counter, so the next failure starts from zero. Takes an address or network (for an IPv6 address, the /64's counter goes too) or any subject exactly as `ban list` prints it. Quote a `pair:` subject, because the shell reads `\|` as a pipe. Lifting a pair or an account clears that subject only. Exits 1 if there was neither a ban nor a failure record. |
| `epistle ban remove --account <login> --ip <addr>` | The same for a pair ban, named by its parts. An IPv6 address names its /64. |
| `epistle ban allow list [--json]` | Addresses and networks that are never banned. |
| `epistle ban allow add <ip\|cidr>` | Never ban this address or network. |
| `epistle ban allow remove <ip\|cidr>` | Take it off the allow list. |

The allow list is the table `auth_allow` (migration `0006_auth_allow.sql`), so it is
shared by every listener and editable while the server runs. An allow-listed client
is never banned, whatever bans exist, and its failed logins are not counted toward
a ban. It does not change the per-connection limit that SMTP applies to one
connection (three failed attempts close it), which keeps no state between
connections. A network ban (`add 203.0.113.0/24`) covers every address in it;
`add 203.0.113.9/32` is the same ban as `add 203.0.113.9`.

## Learning from the user's moves (`epistle learning`)

An account's Bayesian corpus learns from what its user does: a message moved
or copied into Junk is spam, a message moved out of Junk to anywhere but Trash
is ham, and `$Junk` / `$NotJunk` say the same (the rules and the limits are in
`docs/configuration.md`). `epistle learning` shows what each corpus has learned
and switches it. It needs `[database]`, because the counters and the switch live
in PostgreSQL; without it the command exits 3. A change reaches the running
server at its next lesson, with no restart. With the container stack it runs
inside `mail` like `ban`.

| Command | What it does |
|---|---|
| `epistle learning status [ACCOUNT] [--json]` | Per account: `learning` on or off, `spam` and `ham` learned (a message counts again when its verdict changed), `unlearned` (earlier verdicts taken back), `repeated` (decisions that changed nothing), `refused` (the account holds as many token rows as it may), `throttled` (it spent the day's tokens), `messages` (rows in the record), `token-rows`, `unrecorded` (messages the corpus holds that the record does not: taught before the record existed or by the server itself, they count again if the user moves them and cannot be taken back) and the `corpus-spam` and `corpus-ham` the corpus holds from any source. Without an account, every account that has learned or been switched off, at most 10000 (a note on stderr says when the list was cut); an account that never learned reads as on with zero counters. |
| `epistle learning enable ACCOUNT [--dry-run] [--json]` | Let the account's decisions teach its corpus (the default). |
| `epistle learning disable ACCOUNT [--dry-run] [--json]` | Stop them. What the corpus already learned stays. |
| `epistle learning reset ACCOUNT [--dry-run] [--yes] [--json]` | Drop the corpus and the record of the account and zero its counters; the on/off switch stays as it was, so an account switched off remains off. It scores with the shared corpus again until it holds 200 ham and 200 spam of its own. Needs `--yes` off a terminal. |

The account must exist (exit 2 otherwise), for `status` too only in the sense that
an unknown name reads as zero. Lessons dropped by the per-command, per-account queue
share, per-minute, per-day or worker-time limits are counted by the server in
`mail_bayes_training_dropped_total`, and lessons lost for another reason in
`mail_bayes_learning_unreadable_total`, `mail_bayes_learning_failed_total` and
`mail_bayes_learning_refused_total`; none of these is per account.

## Expunged-message archive

Active only when `[storage] deleted_retention_days` is set to a positive value.
With retention off, an expunge deletes the on-disk files immediately and no
archive directory is created. With retention on, an expunge moves the message
into `<account>/.archive/`, and an hourly sweeper drops entries older than the
configured window.

| Command | What it does |
|---|---|
| `epistle archive list <ACCOUNT>` | List every archived message for an account (id, mailbox, RFC 3339 time). |
| `epistle archive restore <ACCOUNT> <ID>` | Re-append an archived message to its original mailbox (or INBOX when that mailbox is gone), then remove it from the archive. |
| `epistle archive purge <ACCOUNT> [--older-than-days N] [--yes\|-y]` | Delete archived entries. Without `--older-than-days`, every entry for the account is purged; with it, only entries older than the threshold. The sweep uses the same threshold. Asks first, saying "all" when there is no threshold; `--yes` skips the question. |

## Client autodiscovery

These print documents the operator publishes so clients configure themselves
from just an email address and password. Thunderbird autoconfig and Microsoft
Autodiscover can also be served **live** by adding an `autoconfigs` listener
(HTTPS on 443, or `autoconfig` for plain HTTP behind a proxy; see the
[configuration reference](configuration.md)) and pointing the
`autoconfig.<domain>`/`autodiscover.<domain>` subdomains at it. The same
listener serves the Apple profile at `/mobileconfig?email=<address>`.

| Command | What it does |
|---|---|
| `epistle srv-records` | Print the RFC 6186 SRV records to publish in DNS. |
| `epistle autoconfig [--domain D]` | Thunderbird autoconfig XML, host at `autoconfig.<domain>/mail/config-v1.1.xml`. |
| `epistle autodiscover [--domain D]` | Microsoft Autodiscover v1 XML, host at `autodiscover.<domain>/autodiscover/autodiscover.xml`. |
| `epistle mobileconfig --account N` | Apple `.mobileconfig` profile for a user to install on iOS/macOS. |

## Outbound retry policy

The queue retries transient failures with exponential backoff (1m, 2m, 4m, …
capped at 1h). It gives up by **message age** — `queue_give_up_secs` (default 5
days) — not by attempt count, so a recipient whose server is down for hours does
not lose mail. A single "delivery delayed" warning DSN is sent at ~4h
(`queue-delay-warning`). Each
recipient has its own outcome and retry schedule: one refused or slow recipient
does not hold back or duplicate the others.

The first wait and the cap are set with `queue-retry-base` and
`queue-retry-cap`. Each wait is spread by a random ±20%, so mail for a
destination that comes back does not all retry in the same second.

The remote reply is read by its enhanced status code (RFC 3463), or by its
basic code when it has none:

| Reply | Outcome | Suppressed |
|---|---|---|
| 5.1.x (bad mailbox, bad domain, null MX), 551, 553 | bounced now | yes |
| 5.2.1 mailbox disabled, other 5.x.x, bare 550 or 554 | bounced now | no |
| X.2.2 mailbox full, bare 552 | retried until the message expires, then bounced | no |
| 5.3.4 / 5.2.3 message too big | bounced now | no |
| 5.7.x policy, authentication, spam | bounced now, counted in `mail_outbound_policy_rejected_total` and logged with the remote host | no |
| 4.x.x | retried | no |

A suppressed address is dropped without retrying (clear it with
`epistle suppression remove`). A 5.7.x refusal is about the sending side
(IP or domain reputation, SPF, DKIM, DMARC), not the address.
