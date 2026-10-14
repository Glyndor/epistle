# CLI reference

All administration is done through the `epistle` command. Every command that needs
configuration defaults to `/etc/epistle/mail.toml`. Use `--config <FILE>` to
select another file, for example `epistle account list --config /path/to/mail.toml`.
Run `epistle <command> --help` for the exact flags.

## Resources

Commands take the shape `epistle <resource> <action>`. Every `list` and `show`
accepts `--json`: a list prints one JSON array, a show one object, on stdout.
Exit codes: `0` done, `1` the operation failed (I/O, database), `2` usage
error or refused (unknown name, rejected input, a static account, a
destructive action without `--yes`).

| Resource | Actions | Older flat form (hidden, still works) |
|---|---|---|
| `account` | `list`, `show`, `add`, `remove`, `password`, `enable`, `disable`, `address add\|remove`, `quota`, `protocols`, `save-sent`, `find-log-id` | `accounts`, `account-add`, `account-remove` |
| `account forward` | `list`, `add`, `remove` | |
| `account catch-all` | `list`, `add`, `remove` | |
| `account 2fa` | `show`, `disable` | |
| `app-password` | `list`, `create`, `revoke` | `app-passwords`, `app-password-create`, `app-password-revoke` |
| `api-key` | `list`, `create`, `revoke`, `rotate` | `api-keys`, `api-key-create`, `api-key-revoke` |
| `suppression` | `list`, `add`, `remove` | `suppression`, `suppression --remove ADDR` |
| `masked`, `ban`, `queue`, `domain`, `alias`, `limits`, `relay`, `service`, `dkim`, `tls` | see each section below | |

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
| [Aliases and mailing lists](#aliases-epistle-alias) | `epistle alias …` |
| [Domains and domain aliases](#domains-epistle-domain) | `epistle domain …` |
| [Masked addresses](#masked-addresses) | `epistle masked …` |
| [Limits: quota, send rate, connections](#server-limits-epistle-limits) | `epistle limits show\|set\|unset` |
| [Bans and the IP allow list](#authentication-bans) | `epistle ban …` |
| [Outbound queue: retry, hold, release](#outbound-queue) | `epistle queue …` |
| [Antispam: DNSBL, greylisting, ClamAV](#antispam-epistle-antispam) | `epistle antispam …` |
| [Relay through a smarthost](#smarthost-relay-epistle-relay) | `epistle relay …` |
| [DNS provider for DKIM and TLSA](#dns-provider-epistle-dns-provider) | `epistle dns provider …` |
| [Webhook and alerts](#webhook-epistle-webhook) | `epistle webhook …`, `epistle alert …` |
| [Blob storage (filesystem or S3)](#blob-storage-epistle-storage-blobs) | `epistle storage blobs …` |
| [Rotate DKIM, renew TLS, rotate an API key](#rotations-epistle-dkim-epistle-tls-epistle-api-key) | `epistle dkim rotate`, `epistle dkim cleanup`, `epistle tls renew`, `epistle api-key rotate` |
| [Containers: up, logs, update](#stack-epistle-stack) | `epistle stack …` |
| [Backup and restore](#backup-and-restore) | `epistle backup`, `epistle restore` |

## Output

Every `epistle` subcommand splits its output into two streams by purpose:

- **stdout** carries command data or listings. The four data commands below
  never carry an ANSI escape sequence there, no matter the terminal, no matter
  `NO_COLOR`, no matter `CLICOLOR_FORCE`; the property is pinned by
  `tests/cli_stdout_clean.rs`. `clap`'s `--help` and `--version` also write to
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

Four commands produce binary or quoted data on stdout and would silently break if
an escape sequence or spinner frame were ever written there, so they are pinned by
`tests/cli_stdout_clean.rs`:

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
`app-password revoke`, `api-key revoke`, `archive purge`, `domain remove`, `domain alias remove`,
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
epistle service --config /path/to/mail.toml enable submission
```

`list` shows enabled or disabled state, port, and bind address. Enabled rows use
actual configured sockets, including custom ports; disabled rows show the defaults
that `enable` would use. JSON records contain `name`, `enabled`, `port`, and `bind`.

Names are `imap` (143), `imaps` (993), `submission` (587), `submissions` (465),
`pop3` (implicit TLS, 995), `managesieve` (4190), `webdav` (8090), and `api`
(loopback, 8025). IMAP and submission TLS siblings can be toggled independently.
`smtp` (25) cannot be disabled because inbound mail needs it.

Edits preserve every other configuration value, use init's comment-free TOML
formatting, and validate through the normal loader before atomically replacing
`/etc/epistle/mail.toml` (or `--config`). Existing TLS and API prerequisites must
be valid. New mail listeners inherit SMTP's bind address; API uses loopback.
An already enabled or disabled service reports no change and exits successfully.

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
| `ports` | the same check as `epistle probe`: every enabled listener answers on loopback with its greeting (SMTP `220`, IMAP `* OK`, POP3 `+OK`, ManageSieve `OK`, HTTP status line), and TLS listeners present the configured certificate | no listeners | a listener refuses, is silent, greets wrongly or presents another certificate |
| `tls` | 21 days or more left, hostname in the certificate, the TLSA record (when DNSSEC publishes one) matches it | under 21 days, under 14 days with nothing renewing it (no `[acme]`), the TLSA lookup failed | under 7 days, expired, or hostname not in the certificate; unreadable file; a TLSA record that does not match the certificate in use |
| `dns` | published records match | a lookup was inconclusive, or `dkim-rotation.json` is unreadable and the server signs with the last good state in `dkim-rotation.json.bak` | a record is missing, or the published DKIM `p=` is not the public key of the key actually signing (the rotation state in `<data_dir>/dkim-rotation.json` when present, else `[dkim] key_file`) |
| `db` | `[database]` connects and answers `SELECT 1` (or is not configured) | | cannot connect within 5 s |
| `antivirus` | clamd answers `PING` with `PONG` and reports its signature age (or is not configured) | `VERSION` fails | no `PONG` |
| `queue` | oldest queued message under 4 h | over 4 h | over 24 h |
| `disk` | 10% or more free on the filesystem holding `data_dir` | under 10% | under 5%, or under 25 MiB free (SMTP then answers 452) |
| `subid` | the ranges `glyndor-epistle` holds in `/etc/subuid` and `/etc/subgid` overlap no other account's | `glyndor-epistle` has no range in a table | a range overlaps another account's; the finding names that account and the shared interval (see [Moving an overlapping range](#moving-an-overlapping-subordinate-id-range)) |

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
| `epistle config-check` | Validate the configuration and exit. |
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
epistle limits set quota 5G
epistle limits set submission-rate 120
epistle limits set queue-give-up 12h
epistle limits set queue-retry-base 5m
epistle limits set quota --domain example.org 10G
epistle limits set submission-rate --domain example.org 50
epistle limits unset quota --domain example.org
epistle limits set quota 10G --dry-run
epistle limits unset quota
```

`show` prints each effective value with `default` or `configured`. Disabled
rate caps and the protocol-specific connection defaults are shown explicitly.
Values equal to a built-in default are marked `default`, even when configured.
`unset` removes the field so its built-in default applies again.

| Key | Value |
|---|---|
| `quota` | Bytes per account, default 5 GiB; `0` means no limit and shows as `unlimited`. |
| `submission-rate` | Messages per minute per account, default disabled. |
| `new-recipients-per-day` | New recipients per account in a rolling 24 hours, default disabled. |
| `queue-give-up` | Queue age before bouncing, default 5 days. |
| `queue-retry-base` | Wait after a recipient's first failed attempt, doubling after each failure, default 1 minute, at least 1 minute. |
| `queue-retry-cap` | Longest wait between attempts, default 1 hour, not below `queue-retry-base`. |
| `queue-delay-warning` | Message age of the "delivery delayed" DSN, default 4 hours, below `queue-give-up`. |
| `inbound-rate-per-ip` | Inbound messages per minute per client IP, default disabled. |
| `inbound-rate-per-sender` | Inbound messages per minute per envelope sender, default disabled. |
| `max-connections-per-listener` | Concurrent connections, default depends on the protocol. |
| `masked-addresses-max` | Masked addresses per account, default 100. |
| `first-time-sender-delay` | First-time sender delay, default 0 seconds. |
| `greylist-delay` | Greylist deferral window, default 0 seconds. |

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
epistle dns provider test
```

`set` rewrites the whole `[dns]` section, so switching provider never leaves an old
credential behind. The provider name and the settings it needs are checked the way
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
epistle webhook test
```

Manages the `[webhook]` section. The URL must be `https`, or `http` on a loopback
address (`127.0.0.1`, `::1`, `localhost`), and cannot carry credentials. The signing
secret arrives on stdin as one line and is stored inline in the 0600 configuration
file; `show` prints only `set` or `unset`. `set` without `--secret-stdin` keeps a
secret that is already configured. `unset` is refused while an alert still posts
to the webhook.

`test` posts one `test` event (see [configuration](configuration.md)), signed like
any other, and reports the HTTP status. It fails on a non-2xx answer, a connection
error, or no answer within 10 seconds. Supports `--dry-run` and `--config FILE`.

## Alerts (`epistle alert`)

```sh
epistle alert list [--json]
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

## Domains (`epistle domain`)

```sh
epistle domain list
epistle domain list --json
epistle domain show example.org
epistle domain show example.org --json
epistle domain add new.example.org
epistle domain add new.example.org --dry-run
epistle domain remove old.example.org [--yes|-y]
epistle domain alias add alias.example.org example.org
epistle domain alias remove alias.example.org [--yes|-y]
```

`list` writes every configured domain with the domains that target it
(`ALIASES TO`) and the domains it targets (`ALIASES FROM`). `show` writes
the alias edges plus the accounts and aliases that route mail through
the domain, so the operator can see what depends on it before removing
it. JSON records contain `domain`, `aliases_to`, `aliases_from`,
`accounts` and `aliases`.

`add` validates the name (`validate_dns_name`, same rules the loader
uses), appends it to `[domains]` and prints the DNS records the operator
must publish for the new domain (filtered to that domain only). It
refuses when the domain is already configured, when it collides with
a `domain_aliases` source or target, or when the loader rejects the
final document.

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
epistle antispam set scan-authenticated off
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

Stack requires podup 5.10.13 or newer. A failed podup command stops the
sequence and its exit code becomes epistle's exit code.

| Command | What it does |
|---|---|
| `sudo epistle stack up` | Runs `podup up -d`, then `podup autostart install` to enable and start the project's user service. It returns after starting; the service brings the stack back after reboot. |
| `sudo epistle stack down` | Runs `podup autostart uninstall`, then `podup down`. Database volumes and bind-mounted data are kept. |
| `sudo epistle stack ps [--json]` | Lists running services as a table or JSON. |
| `sudo epistle stack logs [--follow] [SERVICE]` | Streams service logs. |
| `sudo epistle stack restart [SERVICE]` | Restarts the stack or one service. |
| `sudo epistle stack stop [SERVICE]` / `sudo epistle stack start [SERVICE]` | Stop or start the whole stack, or one service, without removing containers or the autostart unit. `stack stop mail` is how to take the mail server down for `epistle restore` while the database stays up to receive the dump. |
| `sudo epistle stack update` | Renders `compose.yaml` again with this release's code, shows what changed and replaces it, then runs `podup up -d` so only changed services are recreated. In default mode it also restarts `mail` when its definition did not change, so it runs the host binary the new .deb installed; in custom image mode it runs `podup pull` first. Before any of that it dumps the stack's database to `<data_dir>/backups/pre-<version>-<timestamp>.sql.gz` (mode 0600, the newest three `pre-*` dumps kept), because the new server migrates the schema when it starts; a failed dump stops the update before anything changes. Afterwards it waits up to five minutes for `mail` to report healthy and runs the `config`, `ports` and `db` checks of `epistle status`; a failure names the area and exits non-zero, and the apt upgrade prints it framed with the rollback command. Data and volumes are kept. Before it writes the new file it moves the storage and OAuth signing keys out of data_dir, and once `db` runs it takes SUPERUSER away from an `epistle` role an older release created (see [the container stack](container.md#the-database-roles)). |
| `sudo epistle stack rollback [--to VERSION] [--yes]` | Asks before it changes anything (`--yes` skips the question; without a terminal and without `--yes` it exits 2). Puts back the binary the last upgrade replaced (the preinst keeps the two newest under `/var/lib/glyndor/epistle/rollback`) and, when the new release already migrated the schema, restores the dump `stack update` took before the restart. See [Rolling back an upgrade](#rolling-back-an-upgrade). |

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
read-only into the digest-pinned `gcr.io/distroless/static-debian12:nonroot`
base. An explicit `image` in the init answers lets the operator select a
custom mail image instead (the host binary is then not mounted). The
generated base records which mode the file is in via `x-epistle-managed-image`:
true for the default host-binary shape, false for a custom image.

Apt upgrades refresh the stack only when `podup-epistle.service` exists
and is enabled for `glyndor-epistle`. Failures print a warning and leave
the package installed; retry with `sudo epistle stack update`. Stacks
disabled with `stack down` stay disabled until `stack up`.

### Rolling back an upgrade

`sudo epistle stack rollback` asks first, then stops `mail`, compares the migrations in the
database with those in the newest `pre-<this version>-*.sql.gz` dump, and
restores the dump only when the schema moved past it. It then copies the
kept binary over `/usr/bin/epistle` with one rename and starts `mail` on it.
Its closing message says whether the database was restored or kept.
If there is no dump from before this version, or the restore fails, nothing
is rolled back and `mail` starts again on the current binary.

Limits:

- dpkg still lists the newer version as installed, so the next `apt
  upgrade` replaces the binary again. Hold the package with `sudo apt-mark
  hold epistle` until a fixed release, or install the older package with apt
  when the archive still has it.
- Whatever the database took after the dump (new accounts, flags, queue
  state) is gone once the dump is restored. Message files on disk are kept.
- Only the binary and the database go back; the compose file stays as
  `stack update` rendered it.

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
  a non-zero exit, or empty output is a hard error: the run exits
  non-zero with a one-line stderr message that names the cause.
- **container** (compose file present): the dump runs through
  `podup -f <compose> exec -T db sh -c <script>`. Restore copies the SQL
  with `podup cp <host> db:/tmp/epistle-restore.sql`, then runs `psql`
  through the same container shell with `-v ON_ERROR_STOP=1 -1 -X -f
  /tmp/epistle-restore.sql`. Each script reads
  `/run/secrets/epistle_db_password` into `PGPASSWORD` inside `db`
  before executing the client. `POSTGRES_PASSWORD_FILE` is read by
  the image entrypoint during initialization, not by libpq. The host
  argv contains the shell script and secret path, never the password
  value, and the host process does not load the password. Restore
  stops at the first SQL error and rolls back the single transaction.

`podup exec` does not forward stdin (measured against `podup 5.10.13`),
which is why the restore path uses `podup cp` to land the SQL file
inside the `db` container rather than `psql < archive.sql`. The temp
file on the host is created in `$TMPDIR` and removed after the copy.

### What lives in the tar

The archive is a faithful snapshot of `data_dir`, **including the live
private-key material**: DKIM signing keys (`dkim-*.key` / `.pem`), the
ARC seal key, the at-rest message-encryption key file, `log-pseudonym.key`,
and the per-account credential store. Treat the archive the way you would
treat the keys themselves: store it offline, encrypt it at rest, restrict
who can read it, and never leave a copy on a shared host. Delete the
archive file once `restore` has been verified.

Restore writes every private-key file at `0600` regardless of what the
archive recorded: an archive that captured a permissive umask (or that
was tampered with) cannot bring a key back group- or world-readable.
Every other file lands at the mode the archive recorded (always masked
to the lower 9 bits, so `setuid` / `setgid` / sticky bits never survive
a round-trip).

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

The TOML fields the file accepts and the assistant asks for are the same. Every
field is a key with the same name as the question, and a missing key fails the
validator before any side effect runs. Exit codes are `0` (done or nothing to
do), `1` (a step failed after effects were applied; the report names which
step), and `2` (nothing was touched, either because the answers were invalid or
because a precondition stopped the run before any effect: the existing config
could not be parsed, a required key pair was incomplete, and so on).

What this build does:

- lays the answers down under `<data_dir>/keys/` (`0700`) with mode `0600` on
  every key file: DKIM Ed25519 (`s1.pem`), DKIM RSA (`s2.pem`) via `openssl`
  when it is on `PATH`, and the OAuth public key; the at-rest storage key, the
  OAuth signing key and, with the database, the PostgreSQL admin password go to
  `secrets/` beside data_dir instead (see [the container
  stack](container.md#what-each-container-may-do)); a key that already exists
  is reused, never regenerated, whatever the answers say, and one an older
  release left under `keys/` is moved;
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
  warns about the missing `postmaster@` (RFC 5321) address;
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

Re-running with the same answers is a no-op for every file that already
matches: the keys are reused, the config is reported `identical, not touched`,
and the file mtime does not change. A run that changes every answer the
operator can change (hostname, domains, services, mode) does not regenerate a
single key.

What this build does **not** do (other parts of `init`, deliberately out of
scope here):

- DNS publishing for automatic mode: the plan still lists the `dns` step, but
  the step renders `not implemented in this build`. The operator follows it by
  hand or waits for the next part of `init` to land;
- a management-API credential: setting `services.api = true` in the answers is
  refused with a validation error. The api listener needs a bearer token whose
  hash lives in `[api] token_hash`, and `init` does not generate one. To enable
  the api service, leave `services.api` at its default (`false`) in the answers,
  run `epistle init`, and then add the `[api]` section by hand (or with
  `epistle token-hash` followed by an editor pass) before `epistle serve`.

## Keys and tokens

| Command | What it does |
|---|---|
| `epistle dkim-keygen --out F` | Generate an Ed25519 DKIM key and print the DNS record value. |
| `epistle dkim-keygen --rsa [--bits 2048\|4096] --out F` | Generate an RSA DKIM key (delegates to `openssl genpkey`) and print the `k=rsa` record. The RSA `p=` value is large enough to need 255-octet TXT splitting; the printed record is already in the form a zone file accepts. |
| `epistle storage-keygen` | Print a fresh base64 32-byte key for at-rest message encryption (`[storage]`). |
| `epistle token-hash` | Read a bearer token on stdin, print the `sha256:<hex>` for `[api] token_hash`. |

## Rotations (`epistle dkim`, `epistle tls`, `epistle api-key`)

| Command | What it does |
|---|---|
| `epistle dkim show [--json]` | The DKIM key in service (selector, key file, rotation time, next scheduled rotation, previous selector and when it retires, the RSA selector in service, from `state` or `config`, with the RSA selector a rotation retires or moves to) and whether the published TXT of each signing domain matches it. Reads the same rotation state as `serve`, `dns-records` and `verify-dns`; an unreadable state file is an error, never a silent fallback to the configured key. A rotation the server began and has not finished is listed with its selector (`in_progress` in JSON), or with the reason it is being withdrawn. |
| `epistle dkim rotate [--dry-run]` | Rotate the Ed25519 key now, and with dual signing the RSA key in the same step (new selector `rsa<day>`). Refuses what the server refuses: no `[dkim]` or `[dns]`, a signing domain outside the `[dns]` zone, a provider that cannot be built, a second rotation on the same UTC day. `--dry-run` prints the selectors and the TXT names and changes nothing. |
| `epistle dkim cleanup [--dry-run] [--yes]` | List the `dkim-ed<day>.key` and `dkim-rsa<day>.key` files and `ed<day>._domainkey` and `rsa<day>._domainkey` TXT records of the signing domains that neither the active, the previous, a pending nor a configured selector uses (left by crashes in older releases), ask for confirmation and queue their removal. `--dry-run` only lists; `--yes` skips the question. Refused when the rotation state cannot be read, and nothing is queued when the server does not rotate keys for this configuration. |
| `epistle tls show [--json]` | The certificate the server presents (the ACME pair when `[acme]` is set and `<data_dir>/acme/{cert,key}.pem` is usable, otherwise `[tls]`): subject, names, issuer, expiry as an RFC 3339 UTC date (for example `2026-12-31T23:59:59Z`), days left, and `acme` or `static` as the source. JSON adds `not_after_utc` and keeps the epoch-second `not_after` field. `serve`, `probe` and this command resolve it the same way. |
| `epistle tls renew [--force]` | Ask the server to renew the ACME certificate. Without `--force` nothing is queued while the certificate is outside its `renew_before_days` window. |
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
| `epistle account save-sent N on\|off` | Save a copy of every message the account sends into its `Sent` folder. Default on; `off` is the per-account opt-out. The app-password override (`app-password create --save-sent`) wins when set. |
| `epistle account show N [--json]` | Public view: log id, addresses, disabled, quota, protocols. Works for static accounts. Never a secret. |
| `epistle account find-log-id acct-…` | Map a log pseudonym back to its account. |
| `epistle account forward list\|add\|remove N [ADDR]` | Also send the account's mail to `ADDR`. Refuses the account's own addresses, an invalid address, and any forward while `srs_secret` is unset (without SRS the copy fails SPF at the next hop). |
| `epistle account catch-all list\|add\|remove N [DOMAIN]` | Deliver mail for unknown users of `DOMAIN` to the account. `DOMAIN` must be a configured domain (not an alias) that no other account catches. |
| `epistle account 2fa show N [--json]` | Whether a TOTP secret is enrolled (never the secret). |
| `epistle account 2fa disable N [--yes\|-y]` | Remove the TOTP secret; the password alone signs in again. Asks first. |
| `epistle app-password list [--account N] [--json]` | App passwords (label, expiry, IP restriction), never the secret. |
| `epistle app-password create N LABEL [--expires-at EPOCH] [--ip-cidr CIDR] [--save-sent on\|off]` | Create an IMAP/SMTP app password; prints it once. `--save-sent` overrides the account-wide setting for this credential (`on` opts the credential in even if the account is off; `off` opts it out even if the account is on). Dynamic accounts only. |
| `epistle app-password revoke N LABEL [--yes\|-y]` | Revoke it. Asks first. |
| `epistle api-key list [--json]` | API keys: label, expiry, CIDR, scopes, domains, bound account. Never the key. |
| `epistle api-key create LABEL --scope S [--scope …] [--domain D] [--account N]` | Create a key; prints it once. Scopes: `read`, `write`, `send`, `scim`. `--domain` confines it to domains. `--account` binds it to one account (static or dynamic): it then reaches only JMAP and `/api/v1/send`, cannot hold `scim`, and takes no `--domain`. |
| `epistle api-key revoke LABEL [--yes\|-y]` | Revoke a key. Asks first. |
| `epistle api-key rotate LABEL` | New secret, same scopes; prints it once. |

## Mail in and out

| Command | What it does |
|---|---|
| `epistle export --account N [--maildir DIR]` | Export an account's mailboxes as an mbox stream on stdout, or as a Maildir tree where `Work/Project` is the Maildir++ folder `.Work.Project`. |
| `epistle import --account N [--maildir DIR]` | Import an mbox stream from stdin, or a Maildir tree. Maildir++ folders become nested folders: `.Work.Project` is `Work/Project`. |
| `epistle migrate imap --account N --host H --user U` | Copy a remote IMAP account, resumably. See [migration](migration.md). |
| `epistle migrate mox --from DIR` / `migrate stalwart --from FILE` | Import domains, accounts, aliases and DKIM keys. |
| `epistle queue` | List the outbound delivery queue (same as `queue list`). See [Outbound queue](#outbound-queue). |
| `epistle delivery list [--recipient ADDR] [--account NAME] [--since WHEN] [--outcome O] [--limit N] [--json]` | Read the per-recipient delivery log: one record per delivered, deferred, failed, suppressed or canceled recipient, newest day first, at most `N` records (default 100). `--since` takes an RFC 3339 time or a duration such as `24h` or `7d`. Metadata only, never a subject or body. `epistle delivery` alone is `delivery list`. Needs `[storage] delivery_log_days` above 0. |
| `epistle suppression list [--account SENDER] [--json]` | List suppressed (hard-bounced) recipients. A recipient suppressed by a bounce also shows, tab separated, when and the remote reply that proved the address bad. |
| `epistle suppression add ADDR [--account SENDER]` | Suppress a recipient by hand. Mail queued for it is dropped without a bounce on the next delivery pass. With `--account` it applies to that sender only. |
| `epistle suppression remove ADDR [--account SENDER]` | Deliver to the recipient again. |
| `epistle report-abuse` | Read an offending message on stdin, print an RFC 5965 ARF report to send to the sender's abuse address. |
| `epistle reports [--days N]` | Summarise the DMARC aggregate and TLS-RPT reports that arrived for our domains over the last `N` days (default 7). Per policy domain: reporters seen, total rows, and failing rows by `source_ip` (DMARC) or failing sessions by `result_type` and `sending_mta_ip` (TLS-RPT). Reads the JSONL store under `data_dir/reports/`; never writes to it. |

## Outbound queue

`epistle queue <action>` inspects and steers the outbound spool in
`data_dir/spool`. The running server picks up every change on its next queue
pass, with no restart: the worker re-reads each entry from disk before it
decides whether to attempt it.

| Command | What it does |
|---|---|
| `epistle queue list [--json]` | One line per message (id, attempts, sender, recipients, `held`), or a JSON array with the envelope and last error. |
| `epistle queue show <id>` | Envelope, attempts, next attempt, held state and the last delivery error. Never prints the message body. |
| `epistle queue retry <id>\|--all` | Make the next attempt happen now, skipping the backoff. The attempt count is kept, and a held entry stays held. |
| `epistle queue hold <id>\|--all` | Never attempt the entry until it is released. |
| `epistle queue release <id>\|--all` | Let a held entry be attempted again. |
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
| `epistle ban list [--json]` | Active bans: subject (`ip:<addr>`, `cidr:<net>/<prefix>` or `account:<login>`), reason, and the epoch second each one ends. |
| `epistle ban add <ip\|cidr> [--for 24h]` | Ban an address or network by hand. `--for` takes a number and a unit (`s`, `m`, `h`, `d`, `w`); the default is 24h. Refused for an address on the allow list. |
| `epistle ban remove <ip\|cidr>` | Lift the ban now and clear the address's failure counter, so the next failure starts from zero. Exits 1 if there was neither a ban nor a failure record. |
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

## Expunged-message archive

Active only when `[storage] deleted_retention_days` is set to a positive value.
With retention off, an expunge deletes the on-disk files immediately and no
archive directory is created. With retention on, an expunge moves the message
into `<account>/.archive/`, and an hourly sweeper drops entries older than the
configured window.

| Command | What it does |
|---|---|
| `epistle archive list <ACCOUNT>` | List every archived message for an account (id, mailbox, unix time). |
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
