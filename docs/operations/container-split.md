# The certificates container

The `certs` container holds the DNS provider token and the ACME account key,
and the process that takes SMTP from the internet holds neither. It is off by
default: `sudo epistle stack certs enable` turns it on, and a stack that never
runs it renders and runs as one `mail` container. [The container
stack](container.md) describes the rest of the stack, and "Which process holds
what" there says which process holds which secret.

## What moves

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

`mail` stops mounting `dns_provider_token` and the ACME account key. With the container on, a compromise of the process that takes SMTP from the internet cannot
rewrite the zone: MX, SPF, DMARC and TLSA.

## What stays

`mail` keeps the TLS private key, because it terminates TLS, and the DKIM
signing keys. It receives certificates and keys by volume, never
by request.

## Interfaces

`serve` already watches its certificate and key files and swaps them without a
restart, so `mail` needs no new channel to learn that a certificate was
replaced. The same reload applies to a rotated DKIM key.

There is one request interface from `mail` to `certs`: the hand-off
directory. It is not a way to use the token. `mail` writes a file a record to publish or to withdraw, and `certs` performs it with the
credential; `certs` checks every request and refuses anything that is not
a DKIM key record (`<selector>._domainkey.<domain>`) of a domain this
installation serves, in a zone the `[dns]` configuration covers, under a
selector this installation uses (one a rotation makes, or one the operator
configured in `[dkim]` or in a `[[dkim.domain]]` entry), and the refusal is
answered with the reason. A request the rotation would never make is
therefore the only thing that reaches the provider, and the key material
never leaves `mail`. `certs` decides by itself when to renew, and it takes
the requests it finds in the directory as it finds them.

## The hand-off

`mail` writes `<data_dir>/dns-handoff/requests/<id>` and waits for
`<data_dir>/dns-handoff/results/<id>`, which `certs` writes when it has
performed the write or refused it. A request that is not answered within a
minute is taken back: the rotation fails, withdraws what it published, and
the key in service keeps signing. A request that is older than a minute is
refused, so a write the rotation has already given up on is never performed
behind its back.

## Failure behaviour

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

## Upgrade and rollback

`epistle stack update` renders the new service, moves the token mount from `mail`
to `certs` and starts `certs` before it removes the mount from `mail`, so a
renewal in flight is not lost. `stack rollback` restores the previous Compose
file, which mounts the token in `mail` again.

## Egress

`certs` reaches the DNS provider and the CA, and `mail` no longer needs either.
The Compose file cannot filter by destination under rootless Podman, so what
the container narrows is what each container holds and the routes each one has
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

This is a property of the engine and of the host, so it needs a check on the
machine the stack runs on. The
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
and `REACHED` on the last is the state the container is meant to give.

## What runs today

`sudo epistle stack certs enable` turns it on for a stack (see
[`docs/cli.md`](../cli.md)).

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
  old file would keep reading it. The process drops the `[database]`,
  `[accounts]`, `[api]`, `[storage]`, `[oauth]` and `[dkim]` tables before it
  parses the file, so it never reads the account hashes, the API token hash,
  the OAuth configuration, the storage key or the DKIM key paths; the file it
  can read still carries them.
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
  recreate it when the stack runs it, and take it out of `mail` when `mail`
  still carried it: the credential belongs to the container that writes the
  zone, and `mail` is the container that takes SMTP from the internet. An
  override that hands the credential back to `mail` is named in a warning.
- `epistle stack up` puts the account key where `certs` reads it before the
  stack comes up, waits for `certs` with the same rule the switch uses, and
  only then removes the copy under data_dir, so a `stack up` after a reboot
  cannot report a stack that renews nothing. It comes up with
  `--remove-orphans`, the way the switch brings it up, so a container the
  compose file no longer names does not keep running with the credential.
- `epistle stack certs enable` checks what the container needs before it
  touches the stack: a configuration that answers `dns-01`, a DNS credential
  it can read and an ACME account key that exists. Each of them stops the
  container at start, so each of them is refused while the stack is still
  whole.
- The ACME account key is never created by a command. A key that is nowhere
  is refused, with the two places it can be, because a new key is a new
  account with the authority: the authorities rate limit new registrations
  and the operator cannot recover the old identity. The copy under data_dir
  is what `mail` renews with; the copy in `secrets/` is what `certs` renews
  with; one of them has to exist before the split is turned on.
- `epistle status` reports the container in its `tls` area with the days the
  certificate has left, warns while it is down and fails when fewer than seven
  days are left. It judges the container the way `stack certs` does: two
  `podup ps` looks fifteen seconds apart, and the start has to be the same in
  both, so a container that exits at start and comes straight back is not
  reported as renewing. It reads the renewal's own traces too: the reason the
  last attempt gave under `<data_dir>/acme/renew.error`, and a pair on disk
  older than the window in which it had to be renewed, which is what a failed
  scheduled renewal leaves behind. The `renewal` item names the container that
  renews the certificate, so it is not reported as renewed while that
  container is down, and a container the compose file does not name but that
  runs is reported: it may still hold the DNS credential and the account key.
- `epistle stack update` waits for `certs` after it brings the stack up, with
  the same rule, and fails the update (with the rollback command) when the
  container does not settle. On a split stack it also judges the `tls` area of
  `epistle status` after the restart, since that is the area that reports the
  container.

Behaviour worth knowing:

- DKIM rotation and key generation stay in `mail`, which keeps the keys, and
  with the split on the rotation keeps running: `mail` asks `certs` for each
  record through the hand-off directory, as "The hand-off" above describes.
- `certs` answers only the `dns-01` challenge, and `enable` refuses another
  challenge. `http-01` and `tls-alpn-01` need ports `mail` owns, and serving
  them would need a channel between the two containers, which the container does not have. An install that renews with `http-01` keeps working with the
  split off.
- DKIM key files are created by `mail`.
- Compose under rootless Podman cannot filter egress by destination, so `certs`
  and `mail` both use `pasta`, and the address podman maps to the host is closed
  in the `certs` service with `pasta` options (see "Egress"). `certs` needs the
  CA's directory host (`[acme] directory_url`), the provider's API host and the
  authoritative name servers of the zone for the visibility check; an operator
  who filters egress on the host can allow those for the account's traffic.
- **`stack rollback`** turns the container off with the current binary before
  it puts an older binary back, because that binary may not know `--role`.
- **The account key is copied, never moved.** `enable` copies it to
  `secrets/`, brings the new layout up, waits for both services, and only then
  removes the copy under data_dir, and only when both copies are the same key.
  A failure writes the previous `compose.yaml` back. `disable` copies it back
  and keeps the copy in `secrets/`. Two different keys are never reconciled:
  the command stops and names both files.
