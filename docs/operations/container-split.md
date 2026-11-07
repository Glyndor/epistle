# Splitting `mail` into containers

This is the plan for the work tracked in #1399 and #1400, and the decisions that
have to hold across its phases. It describes what is intended, not what runs
today: `docs/operations/container.md` describes the stack as it is.

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

## Open questions

- Whether `http-01` and `tls-alpn-01`, which need ports that `mail` owns, are
  worth keeping with the `acme-challenge/` volume or should be dropped in favour
  of `dns-01` for installs that use the `certs` container.
- Whether the DKIM key files should be created by `certs` as above or by the
  signing service of phase 2 from the start, which would remove one move.
- How the Compose generator expresses a per-container egress rule on rootless
  Podman, if it can at all: it expresses the routes of `certs` out of the host,
  but it has no filter by destination, so the addresses the host owns that are
  not its global one stay routable from the container.
