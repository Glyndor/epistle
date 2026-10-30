# Container

The supported production shape for `epistle` is a rootless Podman or Docker
container driven by `podup`. The compose file `init` writes runs the host's
`/usr/bin/epistle` (the statically linked musl binary the `.deb` ships)
bind-mounted read-only into the digest-pinned
`gcr.io/distroless/static-debian13:nonroot` base. A `ghcr.io/glyndor/epistle`
image is still built and published on every release (see "Tags" below); it
matches the `.deb` byte-for-byte and stays as the choice of an operator who
sets `image` in the answers or pulls it directly.

## What the image contains

The base is `gcr.io/distroless/static-debian13:nonroot`, pinned by digest
in the `Containerfile` and in `deploy/images/Dockerfile`, which also pins
the PostgreSQL and ClamAV images of the generated stack. The binary reads
that file at build time, so a release that moves a digest there moves it in
the compose file `epistle stack update` renders on every install; Dependabot
watches both files. The image carries the musl-statically linked
release binary, the runtime data the binary needs, and nothing else.
The list below describes the intended runtime contents. The previous Debian 12
inventory was inspected on 2026-10-04 with `podman 5.7.0`; the Debian 13
image has not yet been inspected or measured.

- `/usr/bin/epistle`, the binary. Built with the same
  `cargo build --release --locked --target <musl>` invocation the .deb
  build uses, so the .deb and the image always agree on what is running.
- A `/etc/epistle` directory owned by `uid:gid 65532:65532`, created at
  build time. The operator's `mail.toml` is bind-mounted over it; no
  file inside the image ever needs to be writable.
- `/etc/ssl/certs/ca-certificates.crt`, the merged CA
  bundle. The binary uses rustls with the system trust store, so the
  bundle is what verifies outbound TLS for SMTP submission, IMAP
  retrieval, ACME, and any other connection that pins a public CA.
- `/etc/passwd` and `/etc/group` supplied by the base. The image sets
  `USER 65532:65532`, so the binary runs as `nonroot`. The exact account
  inventory of the Debian 13 base still needs inspection.
- `/usr/share/zoneinfo/` and the tzdata package metadata under
  `/usr/share/doc/tzdata/`. The binary is single-timezone (the host's
  `TZ`), so tzdata is not exercised at runtime; it is in the base.
- No shell, no package manager, no `openssl`, no `libc` (musl is
  statically linked into the binary), no `ca-certificates` source
  tools, no editor. Nothing in the server calls `sh -c`: the keys it
  makes, the RSA DKIM key included, are made in process.
- OCI labels: `org.opencontainers.image.source`,
  `org.opencontainers.image.version`, `org.opencontainers.image.revision`,
  and `io.containers.autoupdate=registry` so `podman-auto-update(1)`
  can track the `<version>` tag.

The Debian 13 image size has not yet been measured. `USER 65532:65532`; `ENTRYPOINT
["/usr/bin/epistle"]`; `CMD ["serve", "--config", "/etc/epistle/mail.toml"]`.

## What is meant to run inside the image

`epistle serve` and only `epistle serve`. Every other subcommand is either a
one-shot operator action or a developer tool and is documented as running on
the host, not in the container. Two deserve calling out:

- `epistle dkim-keygen --rsa` makes the RSA key in process, so it does not
  need the `openssl` the distroless base does not ship. The key still belongs
  on the host: the server reads it from the data directory as the configured
  `rsa_key_file`, and the key it rotates on its own is made in process inside
  the container.
- `epistle init` is an interactive setup wizard meant to be run on the host
  once, then re-run only for structural changes (a second account, a new
  domain). It writes `/etc/epistle/mail.toml`, which is then bind-mounted
  into the container.

Anything else that is not `serve` (queue, reports, export, import, backup,
verify, mta-sts-serve, the various `*-keygen`) is documented to run on the
host with the same data directory, the same config file, and the same
`glyndor-epistle` account that the container would have used.

## Running it

Bring the stack up with `epistle stack up`, which runs the same
`podup -f <compose> up -d` you would have written by hand. The
compose file lives at `<data_dir>/compose/compose.yaml`, the path
`epistle init` writes and the only one `stack` looks at. The
`--config` flag takes the same `mail.toml` every other command
takes, and `data_dir` is read from it. The `stack` subcommand is a
thin wrapper around podup and is not a replacement: every other
`epistle` subcommand keeps working exactly the way it did, against
the same data dir, the same config file, the same `glyndor-epistle`
account.

The package keeps replaced host binaries for `sudo epistle stack rollback` in
`/var/lib/epistle-rollback` (root:root, mode 0700), outside the service account
home and container mounts. Rollback validates ownership, permissions, file type
and the saved SHA-256 digest before stopping mail. Legacy copies under the
service account home are ignored. An upgrade must save a trusted copy in the
new store before it can be used. Database dumps stay in `<data_dir>/backups`;
see [Rolling back an upgrade](cli.md#rolling-back-an-upgrade). Purge removes the
host binary store.

The minimum a Podman or Docker compose unit needs is:

```sh
podman run --rm \
  --name epistle \
  --userns=keep-id:uid=65532,gid=65532 \
  -p 25:25 -p 465:465 -p 587:587 \
  -p 143:143 -p 993:993 -p 995:995 \
  -p 8080:8080 \
  -v /etc/glyndor/epistle:/etc/epistle:ro \
  -v /var/lib/glyndor/epistle/data:/var/lib/glyndor/epistle/data \
  ghcr.io/glyndor/epistle:0.12.4
```

The `/etc/glyndor/epistle` mount carries `mail.toml`; the
`/var/lib/glyndor/epistle/data` mount carries the on-disk mail store. The account home stays outside the writable mount, keeping Podman storage and systemd user units on the host. Both are
created and owned by the `glyndor-epistle` account the `.deb` postinst sets
up (`debian/epistle.postinst`); running the container under that same uid is
what the existing rootless Podman stack under `podup` does.

### Why `--userns=keep-id` is load-bearing

`USER 65532:65532` inside the image and rootless Podman outside it do not
match by default. Without a userns mapping the container's `uid 65532` is
mapped to a subordinate uid in the operator's range (the first unused
slot, typically `100000`), and a host file owned by `glyndor-epistle`
with mode `0600` is unreadable. The default command prints:

```text
error: cannot read config file /etc/epistle/mail.toml: Permission denied (os error 13)
```

`--userns=keep-id:uid=65532,gid=65532` rewrites the container's `uid 65532`
to the operator's uid on the host, so the bind-mounted `mail.toml` is
readable and the binary reaches the parser instead of a permission error.
The compose form is the same flag under the `userns_mode:` key:

```yaml
services:
  epistle:
    image: ghcr.io/glyndor/epistle:0.12.4
    userns_mode: "keep-id:uid=65532,gid=65532"
    volumes:
      - /etc/glyndor/epistle:/etc/epistle:ro
      - /var/lib/glyndor/epistle/data:/var/lib/glyndor/epistle/data
```

Both the failing default and the working mapping were checked on this
host: a host directory with a `0600` file owned by the operator, mounted
into the image with no userns flag, returned `Permission denied (os
error 13)`. The same mount with `--userns=keep-id:uid=65532,gid=65532`
let `config-check` print
`configuration is valid` and exit 0.

## Bringing up the stack

`epistle init` lays down the operator-facing half of the stack: the
config file, the DKIM, storage and OAuth keys, the self-signed cert
pair, and, when `services.database = true`, the database passwords and
the podup compose file. Bringing the stack up is a single command:

```sh
podup -f /var/lib/glyndor/epistle/data/compose/compose.yaml up -d
```

The compose file is JSON (the repository has no YAML crate). The
`mail` service uses `network_mode: "pasta"` so an SMTP client on the
host network reaches the listener with its real address; rootless
Podman would otherwise funnel every connection through `rootlessport`
and the listener would see one internal IP for every client. The
`db` service uses `network_mode: "none"`: it does not need network
because the two services talk over a Unix-domain socket on a named
volume (`epistle-pgsock:/var/run/postgresql`), which avoids the
TCP/TLS path entirely. The `db` healthcheck queries the real database
through that socket with `psql ... -Atc 'select 1'`, so a healthy
state means the user, the role and the password file all line up;
`mail` waits on it with `depends_on: {db: {condition: service_healthy}}`.

The data directory (`<data_dir>`) and the directory holding
`mail.toml` (`<config_dir>`, the parent of the `config_path` answer)
are bind-mounted at the same path on both sides of the keep-id
mapping. A path the operator sees on the host
(`/var/lib/glyndor/epistle/data/keys/s1.pem`) is the same path inside
the container, so every entry `init` wrote into `mail.toml` resolves
the same way during a host `config-check` and during the in-container
`serve`. A different path on each side would force the operator to
keep two parallel sets of values in `mail.toml`, one for the host
and one for the container, and would silently break the moment
either side drifted.

The management API listener is not configured by `init`: the
assistant refuses `services.api = true` because there is no
credential the operator can hand the stack without editing the
generated config by hand. An operator who enables the API in
the generated config binds it on `::` inside the container
(the same dual-stack bind the mail listeners use); a loopback
listener is not reachable through the pasta mapping, so the
host-side reach is the operator's responsibility, not the
init stack's. Init keeps publishing a listener when the
operator's keep-existing-listeners merge leaves it on a
non-loopback address; where the host reaches it is the
operator's decision, made with `epistle service set
<name> --bind <address>`. For API and WebDAV I publish on loopback behind a TLS
reverse proxy; their HTTP transport is not encrypted by the mail `[tls]` section.

`epistle service enable` starts those two on loopback instead of on SMTP's
bind, which is what keeps a port they serve in plaintext off the public
interfaces, and it publishes no mapping for them: a loopback bind inside the
container is not one the pasta mapping reaches. Opening one is `epistle service
set <name> --bind 127.0.0.1`, which moves the container bind to the wildcard
and publishes that single host address.

### Publishing a port on one host address

The `ports:` array of `mail` is derived from the listeners: every non-loopback
listener is published as `<port>:<port>`, and a loopback listener gets no
entry. With no host address in the mapping the engine publishes on every
address the host has, so a listener nobody narrowed answers on the public
interfaces too. Binding the listener to a private address does not change that,
and inside the container the bind address has to be one the container owns, or
`serve` fails to start with `EADDRNOTAVAIL`. The three listeners whose transport
is HTTP without TLS (`api`, `web-dav`, plain `autoconfig`) are the exception:
they are published on `127.0.0.1` when the file names no address for them, so a
map that lost the address a `set` wrote, or an `addr` an operator edited by hand,
leaves them on loopback.

`epistle service set <name> --bind <address>` writes the host side of the
mapping for one listener and leaves the rest of the file alone:

```sh
sudo epistle service set imap --bind 127.0.0.1
```

It moves the bind the container uses to the unspecified address of the family
the operator asked for, `0.0.0.0` for IPv4 and `::` for IPv6, and publishes
`127.0.0.1:143:143` on the host. A loopback or private address inside the
container is not one the published mapping can reach, so a listener that leaves
loopback moves to that wildcard; a container bind that is already unspecified
and answers the requested family stays, which keeps the dual-stack `::` that
`init` writes. Asking for an IPv6 address with a container bound on `0.0.0.0`
is therefore not a publication on every host address: the container moves to
`::` and the mapping is `[ADDRESS]:PORT:PORT`.

Every writer of the generated map reads the host address back before rendering
it, so enabling another service, an `init` rerun or `stack update` keeps the
address on the listener that has it. A wildcard renders as `PORT:PORT` in both
families and publishes on every address the host owns either way; the family
stays in the container bind, which is where the engine needs it.
`epistle service list` shows the address in a `HOST` column.

A file from a release that published the listeners with no TLS transport wide
is different: `8090:8090`, `0.0.0.0:8090:8090` and `[::]:8090:8090` all name the
same thing, every address of the host, so any command that re-renders the map
takes them to `127.0.0.1`. That means an upgrade can be what stops WebDAV
answering on the public interface, which is why the command that does it says
so on stderr, naming the service and the port and pointing at
`compose.override.yaml`; `init` says it in its report and `stack update` in its
notes. A concrete address in the map is not a wildcard and stays where the
operator put it.

The address has to be one of the host's own: `epistle service set` refuses a
multicast group, `255.255.255.255` and a link-local IPv6 address, and it writes
`::ffff:10.0.0.5` as the `10.0.0.5` it names. Both wildcards are accepted. What
it can not know from the outside is whether the host actually owns a unicast
address it names; that surfaces as a bind refusal from the engine.

A listener the container holds on loopback, an `api` one for example, is
reported as `set` and not as `published`, because a loopback bind inside the
container gets no mapping. Naming an address for it does widen that bind to the
container wildcard, which publishes the listener on the host address named; the
reach is still only what the operator asked for, and `api` and `web-dav` only
accept loopback. When the two files describe different stacks, which is what a
command killed between its writes leaves behind, the next service command says
which ports each one published before it brings them together.

#### What was measured for the mapping form

pasta, the rootless network mode the stack uses, refuses a port mapping that
names an explicit address on Podman 5.4.2 (Debian 13): `"[::]:25:25"`, alone or
next to `"0.0.0.0:25:25"`, fails with `pasta failed ... Failed to bind port 25`,
and `"25:25"` is the form that publishes on both families. That is why a
wildcard is never written as an explicit address. Podman 5.7.0 accepts the
explicit forms, so this is a floor and not a rule of the format.

Not measured: an explicit IPv6 host address (`[ADDR]:PORT:PORT`) under pasta on
Podman 5.4.2, a rootless bridge instead of pasta, and a client connecting from
another host. Those shapes are written by the operator in
`compose.override.yaml`, where the generated map can not reach them.

The override stays the place for a mapping that has to carry every port, or
one that changes shape: `init` regenerates the base file on a rerun and `stack
update` regenerates it too, taking the published ports from the listeners. An
operator override in `compose.override.yaml`, which every stack invocation
passes after `compose.yaml`, is merged with the generated map, or replaces it
where it carries `!override`, and is never written. Lists in the override are
merged with the generated ones, so a plain `ports:` entry would be added to
`8025:8025` and the engine would refuse to bind both; the `!override` tag
replaces the list, and then it has to carry every port the stack publishes, the
mail ones included:

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

[Exposing the API on a private interface](api.md#exposing-the-api-on-a-private-interface)
covers the API case, including what `--ip-cidr` sees when the container
network does not carry the client's address.

### What each container may do

Every service starts from `cap_drop: [ALL]` with `no-new-privileges`, and
every root filesystem is read-only. Each line below was found by starting the
service without the capability, or without the writable path, and reading the
failure; the writes were listed with `podman diff` after mail in, a
submission, an IMAP read, a 20 MB message and an EICAR scan.

| Service | Runs as | Capabilities | Writable besides its volumes | Memory (8 GiB host) | Processes |
|---|---|---|---|---|---|
| `mail` | 65532 | none | nothing | `2g` | 1024 |
| `db` | 999 (postgres) | none | `/tmp` | `896m` | 256 |
| `clamav` | root, then clamav | `CHOWN`, `FOWNER`, `SETGID`, `SETUID` | `/tmp` (512 MiB) | `2g` | 128 |
| `freshclam` | 100 (clamav) | none | `/var/log/clamav` (16 MiB) | `1g` | 32 |

`clamav` keeps its root entrypoint: it chowns and chmods the socket volume and
clamd then steps down to the `clamav` user. Ports below 1024 reach `mail`
through the `ip_unprivileged_port_start` sysctl of its own network namespace,
not through `NET_BIND_SERVICE`.

The limits come from a local stack under 64 parallel SMTP sessions and 32
IMAP sessions: `mail` peaked at 47 MB of anonymous memory and 62 tasks, `db`
at 113 MB plus 148 MB of shared buffers, clamd at 1.99 GB while it reloaded
its signatures (it loads the new set before it frees the old one), and
freshclam at 860 MB while it tested a download. Podman lets each container
swap as much again.

`init` picks the memory limits from the host's `MemTotal`:

| Host memory | `mail` | `db` | `clamav` | `freshclam` |
|---|---|---|---|---|
| under 4 GiB | `1g` | `512m` | left out | left out |
| 4 GiB to under 7 GiB | `1g` | `384m` | `1152m` | `896m` |
| 7 GiB to 16 GiB | `2g` | `896m` | `2g` | `1g` |
| over 16 GiB | `4g` | `2g` | `3g` | `2g` |

Each row adds up to less than 85% of the smallest host it is given to, the
line `epistle status` warns at (under 4 GiB, 75% of a 2 GiB host). From 4 to
7 GiB clamd has room for its signatures but not for a second copy while it
reloads them, so a reload restarts the container instead. Below 4 GiB clamav
(1 GiB resident, 2 GiB while it reloads) is left out, the
config gets no `clamd_socket`, and `init` says so; `antivirus = true` under
`[services]` in the answers file keeps it. A rerun of `init` and `stack update`
keep what an install already has: the limits an older release wrote stay
(`mail 1g`, `db 1g`, `clamav 3g`, `freshclam 2g`), and the `resources` area of
`epistle status` lists the commands that adopt the new ones. See
[Sizing](#sizing) for what the limits mean under load. To change a limit, put
it in the answers file:

```toml
[resources.clamav]
memory = "4g"   # a whole number with k, m or g
pids = 256
```

`init` records the answered values in `compose.yaml` under
`x-epistle-resources`, and `stack update` keeps them. On a running install,
`sudo epistle stack resources set clamav --memory 2g` records a value the
same way, and `sudo epistle stack update` recreates the service with it. A
value in `compose.override.yaml` works too and wins over both.

### Sizing

A message in flight takes about 2.9 times its size in `mail` (measured: a
24 MiB BDAT transfer peaked at 55.7 MiB, the same over DATA and TLS at
70 MiB). The message memory budget counts message bytes only, so when
`message_memory_budget` is unset it is a fifth of the `mail` limit (at
least `max_message_size`, at most 1 GiB): full, it costs about 60% of the
limit, under the 70% line below. Past it, a new message gets `452 4.3.1` and the sender retries
later; nothing is lost. `mail` reads its limit from its cgroup, and
`epistle status` warns when a budget you set yourself, times three, is more
than 70% of it.

Worked example: 5,000 messages, each with a 10 MiB attachment, arrive in a
burst at a VPS with 8 GiB of memory and 500 GB of disk, installed with the
defaults above.

| What | On this host |
|---|---|
| Size on the wire | base64 turns 10 MiB into 13.7 MiB (4/3, plus a CRLF every 76 characters); under the 25 MiB `max_message_size` |
| Memory in flight | `mail 2g` gives a 409 MiB budget: about 29 such messages at once, 7 of them from one sending address (it may hold a quarter of the budget), about 1.2 GiB at the peak. The limits add up to 5.9 GiB of the 8 |
| Disk | 5,000 x 13.7 MiB = 67 GiB in each mailbox they land in, stored as received; the spool only holds a message until it is delivered. 500 GB (465 GiB) takes about six such bursts. `status` warns under 10% free, and SMTP refuses mail under 25 MiB free |
| Quota | the default 5 GiB per account fills after about 370 of them; the rest get `452 4.2.2` and wait in the sender's queue. Raise it with `epistle account quota alice 100G`, `epistle limits set quota --domain example.org 100G` or `epistle limits set quota 100G` |
| Time | the link is the bound: 67 GiB is about 10 minutes at 1 Gbit/s and about 1 h 40 min at 100 Mbit/s. 29 parallel transfers share the link, and `min_data_rate` only cuts a client below 10 KiB/s |

### The host clock

The containers share the host kernel's clock, and epistle does not set it.
DKIM signatures, certificate validity, token and key expiry, the timestamp
authority's seals and the [evidence log](evidence.md#the-clock) all depend on
it. `epistle status` has a `clock` area that warns when the host is not
synchronised with a time source, and `epistle init` warns about the same;
neither changes anything. The `.deb` recommends `systemd-timesyncd` or
`chrony`. To fix it on a host with systemd, run one of these:

```sh
sudo timedatectl set-ntp true
# or point systemd-timesyncd at one provider: set NTP=time.cloudflare.com
# in /etc/systemd/timesyncd.conf, then
sudo systemctl restart systemd-timesyncd
```

Or install `chrony`. Use the servers of one provider only: Google smears leap
seconds and Cloudflare steps them, so a client given both sees them disagree.

### Open files and connection caps

Every connection is a file descriptor. A rootless container starts with the
soft limit of the user that runs Podman, often 1024, and around a thousand idle
connections the SMTP and submission listeners stopped greeting. The generated
`mail` service therefore sets `ulimits: {nofile: 65536}`; the other services
keep the default. The listener caps together (SMTP 1000, IMAP and POP3 500,
ManageSieve 100, plain HTTP 1024 each) plus the spool, the database socket and
the logs fit well under it. A stack generated before this was added gets the
limit on the next `epistle init` that regenerates the compose file. The sample
unit in `docs/epistle.service` sets `LimitNOFILE=65536` for the same reason.

Podman refuses to start a container whose open-file limit is above the hard
limit of the user that runs it (`setrlimit RLIMIT_NOFILE: Operation not
permitted`), which happens on hosts with a hard limit of 4096 such as
CentOS 7 or a session without systemd. `epistle init` therefore reads its own
hard limit and asks for the lower of it and 65536, and asks for nothing when
the hard limit is 1024. It reads the limit of the process that runs `init`,
which can differ from that of the account that runs the stack; if the `mail`
container fails to start with that error, lower `nofile` in the compose file
or raise the hard limit of that account (`LimitNOFILE` in its user manager).

Each listener also caps what one client can hold of it: `max_connections_per_ip`
for SMTP (20), `max_mailbox_connections_per_ip` for IMAP, POP3 and ManageSieve
(200) and `max_http_connections_per_ip` for plain HTTP (256), all adjustable
with `epistle limits set`. The count is per client address, so it only means
something when the listener sees the real one. The `mail` service uses `pasta`
for that; a bridge network or a proxy in front shows every client as one
address, and then that address holds the whole listener's share: raise the
caps, or set them next to the listener caps, instead of letting one gateway
address be refused for everyone behind it.

### Keys outside data_dir

`mail` mounts data_dir read-write, and `epistle backup` archives it. The at-rest
storage key and the OAuth signing key therefore live in `secrets/` beside it
(`/var/lib/glyndor/epistle/secrets`, mode `0700`) and reach `mail` as
read-only compose secrets. They are mounted at their host path, not under
`/run/secrets`, because `export`, `import` and `verify` run on the host and
read the same `mail.toml`. `init` points `[storage] encryption_key_file` at the
storage key; turning `encrypt_at_rest` on stays your decision. The OAuth key
is used once `[oauth] signing_key_file` names it.

On an install from before this layout, `epistle stack update` (and a rerun of
`init`) moves both keys out of `<data_dir>/keys`, rewrites a `mail.toml` that
named the old path, and leaves both copies in place, with an error, if they
differ. Backups do not carry these keys: save `secrets/` separately.

### DNS provider token

I keep the DNS provider token in `secrets/dns_provider_token` beside `data_dir`,
with mode `0600`. `epistle dns provider set <provider> --zone <zone> --store-token`
moves an existing inline or environment token there, updates the generated
Compose file to mount it read-only only in `mail`, and recreates that service.
Supply any other settings required by your provider. For `init`, point
`dns.token_file` in the answers at this file. See [DNS token storage](dns.md#dns-provider-token-storage).

A token you already keep elsewhere is named with `--token-file /absolute/path`:
the command leaves the file where it is and mounts that path read-only into
`mail`, which is the only way the container reads a file of the host. A
credential the Compose file does not mount is a credential the container does
not have, and the provider never builds. When the source of the token changes,
the mount of the file the configuration no longer names is removed too, so the
container keeps no credential you took away.

An environment token is passed to the container and can be exposed through
`podman inspect` in `Config.Env`. A token stored inline in `mail.toml` remains
in the mounted configuration file. A token file mount exposes its path in
container metadata rather than its contents. Remove old environment entries
from Compose overrides and service configuration after migration, and save
`secrets/` separately from data backups.

### The database roles

PostgreSQL's bootstrap superuser is `epistle_admin`, whose password is in
`secrets/epistle_db_admin_password` and is mounted only into `db`. On the first
start, a script the image runs creates `epistle`, the role `mail` connects as,
with `LOGIN` and nothing else, owner of the `epistle` database, and revokes
`CONNECT` on `postgres` and `template1` from `PUBLIC`. The migrations only
create tables and indexes there, which the owner may do.

A stack initialised before this has `epistle` as the bootstrap superuser, and
PostgreSQL 16 and later refuse to remove `SUPERUSER` from that role. `stack
update` therefore renames it to `epistle_admin` and creates a new `epistle`
that takes over the database and everything in `public`, in one transaction,
once `db` runs with the admin secret mounted; then it restarts `mail` so no
session of the old role is left. The dump it took first is the way back.

To act as the admin, for example to inspect the cluster, from a root shell
(`sudo -s`):

```sh
cd /var/lib/glyndor/epistle
runuser -u glyndor-epistle -- env XDG_RUNTIME_DIR=/run/user/$(id -u glyndor-epistle) \
	podup -f data/compose/compose.yaml exec db sh -c \
	'PGPASSWORD="$(cat /run/secrets/epistle_db_admin_password)" psql -h /var/run/postgresql -U epistle_admin -d epistle'
```

## Backup and restore

`epistle backup` and `epistle restore` detect the container stack
by the presence of `<data_dir>/compose/compose.yaml` and route
the database step through `podup -f <compose> exec -T db`:

Both clients run through `sh -c` inside `db`. The shell reads the
mounted secret and sets `PGPASSWORD` only for the client process.
The scripts below are passed as one argument to `sh -c`:

```sh
# Backup script
PGPASSWORD="$(cat '/run/secrets/epistle_db_password')" exec pg_dump -Fp --no-owner --no-privileges -h '/var/run/postgresql' -U 'epistle' -d 'epistle'
# Restore script, after (as root) mkdir -m 711 '/tmp/<staged-name>',
# podup cp <host-sql> db:/tmp/<staged-name>/restore.sql (host file 0644)
PGPASSWORD="$(cat '/run/secrets/epistle_db_password')" exec psql -v ON_ERROR_STOP=1 -1 -X -f '/tmp/<staged-name>/restore.sql' -h '/var/run/postgresql' -U 'epistle' -d 'epistle'
```

`POSTGRES_PASSWORD_FILE` is consumed by the image entrypoint during
initialization. libpq does not read it, so it cannot authenticate the
clients against `local all all scram-sha-256` without `PGPASSWORD`.
The password value stays inside the container and never enters the
host argv or environment. Restore uses the copied SQL file, stops on
the first SQL error and runs in one transaction. The host temp file is
removed when the replay finishes, and the private directory holding the
copy inside `db` is removed afterwards with `podup exec -T -u root db sh -c
"rm -rf '/tmp/<staged-name>'"`, whether the replay succeeded or failed.

The `pg_dump`/`psql` host binaries are not required on the host
in this path; the database step runs entirely inside the `db`
container. The host binary is only needed when the compose file
is absent (a bare host deployment without the container stack).

## Tags

The release job pushes per-arch images plus a multi-arch manifest list with
three floating tags:

- `ghcr.io/glyndor/epistle:0.12.4-amd64`, `…:0.12.4-arm64` per-arch, built
  natively on the matching runner.
- `ghcr.io/glyndor/epistle:0.12.4` the full release.
- `ghcr.io/glyndor/epistle:0.8` the latest patch release in the `0.8` line.
- `ghcr.io/glyndor/epistle:0` the latest minor release in the `0.x` line.

`podman pull ghcr.io/glyndor/epistle:0.8` keeps getting patches;
`…:0` keeps getting minors. A consumer that wants to pin a specific build
uses `gh attestation verify oci://ghcr.io/glyndor/epistle:0.12.4 …` (below);
that command resolves the tag itself, so a separate digest lookup is
not needed. `podman pull --quiet` only prints the local image id and is
not a digest, so it has no place in the verification path.

## Verifying the build provenance

The release job signs the multi-arch manifest list with GitHub's OIDC-backed
Sigstore. The signed envelope is published as a GitHub attestation, so a
consumer does not need a separate signer key:

```sh
gh attestation verify oci://ghcr.io/glyndor/epistle:0.12.4 \
  --repo Glyndor/epistle \
  --signer-workflow Glyndor/epistle/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

A green `Verification succeeded` line proves four things and only four
things:

1. An attestation exists in `Glyndor/epistle` for the manifest list
   that resolves from `oci://ghcr.io/glyndor/epistle:0.12.4`.
2. The signer workflow is `Glyndor/epistle/.github/workflows/release.yml`,
   identified by the `SubjectAlternativeName` of the Sigstore-issued
   certificate. Not just any workflow in this repository -- specifically
   the release workflow.
3. The signer was a GitHub-hosted runner, not a self-hosted one. A
   self-hosted runner under the attacker's control could mint a key
   the Sigstore CA would still sign, so `--deny-self-hosted-runners`
   refuses the verification rather than passing it.
4. The attestation's predicate is `https://slsa.dev/provenance/v1`,
   the SLSA build provenance shape the action produces.

A pass does not prove:

- The list's bytes are what the consumer will pull. The attestation
  is bound to the manifest list's digest, not to the tag, and a
  digest-pinned reference (`oci://ghcr.io/glyndor/epistle@sha256:...`)
  is the only way to make sure the consumer pulls the same bytes
  the attestation was produced for. The tag form is convenient for
  upgrades; it is not a content-addressed handle.
- The build inputs were not tampered with on a self-hosted runner
  in some other repository. The repository and workflow are pinned;
  the runner type is GitHub-hosted; the build itself is out of scope.

The same `gh attestation verify` form works for any of the three
floating tags and for a digest-pinned
`oci://ghcr.io/glyndor/epistle@sha256:...` reference; the digest form
is what podup's update path uses.

## How the image is built and published

`Containerfile` and `.containerignore` at the repository root. The build is
exercised on every pull request that touches `Containerfile`, `.containerignore`,
`Cargo.toml`, `Cargo.lock`, `src/**`, `.sqlx/**` or the workflow file
itself, by `.github/workflows/container.yml`. The release-time publish is
appended to `.github/workflows/release.yml` and runs on every release,
because `epistle stack` pulls the image of the installed version.
