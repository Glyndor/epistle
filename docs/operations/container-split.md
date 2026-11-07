# Splitting `mail` into containers

This is the plan for the work tracked in #1399 and #1400, and the decisions that
have to hold across its phases. Phase 1 runs today, off by default; the section
"What runs today" under it says what was built and where it departs from the
plan. The later phases are intended, not built: `docs/operations/container.md`
describes the stack as it is.

## Where it starts

`mail` is the only container with a network. Its process, `epistle serve`, takes
SMTP from the internet and holds in the same memory the DKIM, ARC, evidence,
OAuth and storage keys, the DNS provider token, the ACME account key, the
password hashes and every mailbox. `db` and `clamav` already show the pattern
this plan follows: one job, one container, one Unix socket.

## Rules every phase keeps

- No network shared between components. Components talk over Unix sockets on
  volumes that only they mount, the way `db` does.
- Each container mounts only the volumes it needs and runs as its own uid in its
  own user namespace range.
- A component that receives a request checks authorization again on its side.
  Nothing is trusted because it arrived over an internal socket.
- State that has a single writer today (the evidence chain, rate limits, bans)
  stays in one place and is reached through a socket, never mounted twice.
- A phase must be removable: `epistle stack rollback` returns to the previous
  layout, and a stack that never enables the new container keeps working.

## Order

1. Certificates and DNS (this document describes it in full).
2. Signing: DKIM, ARC and evidence keys behind a service that signs a hash or a
   canonical header block and returns the signature.
3. A sandbox for parsers of hostile content (attachments, MIME walking, the
   classifier), with no network, no secrets and no mailbox.
4. The HTTP front of #1399, which holds no keys and no data and forwards every
   operation to the core.
5. Outbound delivery, webhooks and other outbound HTTP, authenticated mailbox
   access and the credential store.

The concurrency and crash consistency suite of #1426 comes before the cross
process cases of each phase: a phase adds the version of the cases it touches
before it merges.

## Phase 1: the certificates container

### What moves

The `certs` container holds the DNS provider token, the ACME account key and the
code that uses them:

- ACME issuance and renewal, with the `dns-01` challenge published through the
  `[dns]` provider;
- the TLSA record refresh when a certificate is replaced;
- the publication and withdrawal of the DKIM selectors a rotation asks for.

The DKIM keys themselves stay in `mail`: it makes them, it keeps them, it
decides when to rotate them, and it confirms that a resolver sees the new
record before the key signs. What moves is the write of the record, which
`mail` asks `certs` to perform through the hand-off directory.

`mail` stops mounting `dns_provider_token` and the ACME account key. After this
phase a compromise of the process that takes SMTP from the internet cannot
rewrite the zone: MX, SPF, DMARC and TLSA.

### What stays

`mail` keeps the TLS private key, because it terminates TLS, and the DKIM
signing keys until phase 2. It receives certificates and keys by volume, never
by request.

### Interfaces

| Volume | `certs` | `mail` | Holds |
|---|---|---|---|
| `tls/` | read and write | read only | the certificate and key of each hostname |
| `dkim/` | read and write | read only | the key files rotation produces |
| `acme-challenge/` | read and write | read only | the `http-01` and `tls-alpn-01` tokens that `mail` answers on ports 80 and 443 |
| `dns-handoff/` | read and write | read and write | the DNS writes `mail` asks `certs` to perform |
| `dns_provider_token` | read only | not mounted | the provider credential |

`serve` already watches its certificate and key files and swaps them without a
restart, so `mail` needs no new channel to learn that a certificate was
replaced. The same reload applies to a rotated DKIM key.

There is one request interface from `mail` to `certs` in this phase: the
hand-off directory. It is not a way to use the token. `mail` writes a file
that names a record to publish or to withdraw, and `certs` performs it with
the credential; `certs` checks every request and refuses anything that is not
a DKIM key record (`<selector>._domainkey.<domain>`) of a domain this
installation serves, in a zone the `[dns]` configuration covers, under a
selector this installation uses (one a rotation makes, or one the operator
configured in `[dkim]` or in a `[[dkim.domain]]` entry), and the refusal is
answered with the reason. A request the rotation would never make is
therefore the only thing that reaches the provider, and the key material
never leaves `mail`. `certs` decides by itself when to renew, and it takes
the requests it finds in the directory as it finds them.

### The hand-off

`mail` writes `<data_dir>/dns-handoff/requests/<id>` and waits for
`<data_dir>/dns-handoff/results/<id>`, which `certs` writes when it has
performed the write or refused it. A request that is not answered within a
minute is taken back: the rotation fails, withdraws what it published, and
the key in service keeps signing. A request that is older than a minute is
refused, so a write the rotation has already given up on is never performed
behind its back.

### Failure behaviour

- If `certs` is down, `mail` serves the certificate it has until it expires,
  and `epistle status` reports the container and the days left.
- DKIM rotation keeps running: the records are written by `certs`. While
  `certs` is down the rotation cannot publish, so it takes the write back and
  the key in service keeps signing; the rotation is journaled and the next
  tick finishes it when `certs` answers.
- `epistle dkim cleanup` removes the leftover key files in both layouts, but
  only `certs` can read the zone: with the split on, the TXT records are not
  checked, the command says so and exits with a failure instead of reporting
  a removal that never happens.
- `epistle dns ...` commands that write records run in `certs` through
  `podup exec`, or on the host when there is no stack, so the operator's token
  never has to reach `mail`.


### Upgrade and rollback

`epistle stack update` renders the new service, moves the token mount from `mail`
to `certs` and starts `certs` before it removes the mount from `mail`, so a
renewal in flight is not lost. `stack rollback` restores the previous Compose
file, which mounts the token in `mail` again.

### Egress

`certs` reaches the DNS provider and the CA, and `mail` no longer needs either.
The Compose file cannot filter by destination under rootless Podman, so what
this phase narrows is what each container holds and the routes each one has
out of the host.

The `certs` service runs on a network of its own: its own pasta instance, with
`network_mode: "pasta:--no-map-gw,--map-guest-addr,none"`. `--no-map-gw` keeps
pasta from remapping the host's gateway address to the host, and
`--map-guest-addr none` closes the alias podman adds for
`host.containers.internal`, which maps to the host's own address: that alias
was the route from `certs` to the host and, through it, to every port the stack
publishes. What `certs` can reach is DNS, the ACME CA and the API of the DNS
provider. What it cannot reach is the management API, the published listeners
of `mail`, and the `db` and `clamav` containers, each of which lives in its own
namespace. The addresses the host owns that are not its own global address (a
tailnet address, a second interface) are still routable from the container:
rootless Podman has no per-service filter by destination, and the only network
without a route out is `internal: true`, which would take the internet from
`certs` as well.

This was measured on Podman 5.7.0 rootless, but it is a property of the engine
and of the host, so it needs a check on the machine the stack runs on. The
check joins the network namespace of the running `certs` container and probes
the host from there; run it as the account the stack runs under:

```sh
sudo -u glyndor-epistle podman run --rm --network container:epistle-certs-1 \
  docker.io/library/alpine:3 sh -c '
  nc -w 3 169.254.1.2 8025 < /dev/null && echo "api REACHED" || echo "api BLOCKED"
  nc -w 3 169.254.1.2 25 < /dev/null && echo "published port REACHED" || echo "published port BLOCKED"
  nc -w 5 acme-v02.api.letsencrypt.org 443 < /dev/null && echo "ca REACHED" || echo "ca BLOCKED"'
```

`169.254.1.2` is the address podman maps to the host's own address for a
container, `8025` is the management API and `25` is SMTP, which the stack
publishes on every address the host has. The API is published on the host's
loopback, so it never answered from another container; the published mail port
is the one that did, and it is the one to watch. `BLOCKED` on the first two
and `REACHED` on the last is the state this phase wants.

### Tests

- The `certs` container passes the clean install and the upgrade checks on the
  Debian 13 machine, and a renewal and a rotation run there end to end against a
  test provider.
- A hostile case with `mail` compromised: it cannot read the token, cannot write
  to `tls/`, `dkim/` or `acme-challenge/`, and keeps serving after `certs` stops.
  What it can ask for is a DKIM record of a domain this installation serves, and
  nothing else.
- The concurrency suite gets the case of a certificate replaced while
  connections open, and a DKIM key replaced while messages are signed.

### What runs today

Phase 1 is implemented and off by default. `sudo epistle stack certs enable`
turns it on for a stack (see [`docs/cli.md`](../cli.md)); a stack that never
runs it renders and runs exactly as before.

- `certs` runs `epistle serve --role certs`: ACME renewal with `dns-01`
  through `[dns]`, the TLSA refresh after a new certificate and its retries,
  and the withdrawal of each challenge record when its order ends. It binds
  nothing, publishes no port and takes no request; it reads the request file
  `epistle tls renew` leaves under `<data_dir>/acme`.
- `mail` runs `epistle serve --role mail`: the listeners, the pair read from
  `<data_dir>/acme` and reloaded when it changes, no order, no DNS write and
  no TLSA state written.
- `certs` mounts the config directory read-only, `<data_dir>/acme` and the
  TLSA retry state (`<data_dir>/dns-tlsa`) read-write, the DNS credential
  read-only, and the ACME account key as a read-only secret at
  `secrets/acme_account.key` beside data_dir. It mounts nothing else of
  data_dir. It cannot mount the configuration file alone: a command that edits
  the configuration replaces the file atomically, and a container bound to the
  old file would keep reading it. The process parses only `[acme]` and `[dns]`
  out of it and never reads the account hashes, the API token hash, the OAuth
  configuration, the storage key or the DKIM key paths.
- `mail` mounts data_dir read-write as before, with three directories over it
  read-only: `<data_dir>/acme`, `<data_dir>/dns-tlsa` and `<data_dir>/compose`.
  The rule behind the list: `certs` acts on nothing `mail` can write, and the
  file that says which container holds the credential is not writable by
  `mail` either.
- The rendered Compose file is checked for the split layout: every path each
  service mounts and the mode it mounts it with, the pair and the TLSA state
  writable only in `certs`, and the read-only mounts that keep `mail` from
  writing them applied after the read-write mount of data_dir, so no later
  mount can shadow them.
- `epistle dns provider set` and `unset` put the credential in `certs` and
  recreate it when the stack runs it.
- `epistle status` reports the container in its `tls` area with the days the
  certificate has left, warns while it is down and fails when fewer than seven
  days are left. It judges the container the way `stack certs` does: two
  `podup ps` looks fifteen seconds apart, and the start has to be the same in
  both, so a container that exits at start and comes straight back is not
  reported as renewing. It reads the renewal's own traces too: the reason the
  last attempt gave under `<data_dir>/acme/renew.error`, and a pair on disk
  older than the window in which it had to be renewed, which is what a failed
  scheduled renewal leaves behind.
- `epistle stack update` waits for `certs` after it brings the stack up, with
  the same rule, and fails the update (with the rollback command) when the
  container does not settle. On a split stack it also judges the `tls` area of
  `epistle status` after the restart, since that is the area that reports the
  container.

What changed from the plan above, and why:

- **The table's `dkim/` volume does not exist yet.** DKIM rotation and key
  generation stay in `mail` for now, and with the split on they wait, since
  rotation publishes through the credential `mail` no longer holds; the key
  in use keeps signing and `status` says so. The hook is in place: the role
  check in `serve` that keeps rotation off in `--role mail`, and the `certs`
  service that already holds the credential. Moving rotation is the next step:
  each domain now has a key of its own (#1545), and the rotation of each
  domain's key on its own state (#1579) is what moves into `certs`, once.
- **The `acme-challenge/` volume does not exist.** See the first answer below.
- **`stack rollback`** turns the container off with the current binary before
  it puts an older binary back, because that binary may not know `--role`.
- **The account key is copied, never moved.** `enable` copies it to
  `secrets/`, brings the new layout up, waits for both services, and only then
  removes the copy under data_dir, and only when both copies are the same key.
  A failure writes the previous `compose.yaml` back. `disable` copies it back
  and keeps the copy in `secrets/`. Two different keys are never reconciled:
  the command stops and names both files.

## Open questions, answered

- **`http-01` and `tls-alpn-01` with the container: dropped.** `certs` answers
  only `dns-01`, and `enable` refuses another challenge. Both need ports `mail`
  owns, and keeping them would mean a channel from `certs` into `mail`, or one
  from `mail` that `certs` acts on, which is exactly what this phase removes.
  An install that renews with `http-01` keeps working with the split off.
- **Who creates the DKIM key files: the signing service of phase 2.** Creating
  them in `certs` would move them once now and again in phase 2, and the key
  that signs belongs with the service that signs. Until then they stay in
  `mail`.
- **A per-container egress rule on rootless Podman: not expressed.** Compose
  under rootless Podman cannot filter by destination, so `certs` and `mail`
  both use `pasta`. The address podman maps to the host is closed in the
  `certs` service with `pasta` options, so the host's own services are not
  reachable from it by that name. What `certs` needs is the CA's directory host (`[acme]
  directory_url`) and the provider's API host, plus the authoritative name
  servers of the zone for the visibility check; an operator who filters egress
  on the host can allow those for the account's traffic.
