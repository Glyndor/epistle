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
- the publication and withdrawal of DKIM selectors during rotation, and the
  generation of the new key pair.

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
| `dns_provider_token` | read only | not mounted | the provider credential |

`serve` already watches its certificate and key files and swaps them without a
restart, so `mail` needs no new channel to learn that a certificate was
replaced. The same reload applies to a rotated DKIM key.

There is no request interface from `mail` to `certs` in this phase, and that is
deliberate: a channel that lets the exposed process ask for a DNS write is a way
to use the token. `certs` decides by itself when to renew and rotate, from the
clock and from what it reads on its volumes.

### Failure behaviour

- If `certs` is down, `mail` serves the certificate it has until it expires, and
  `epistle status` reports the container and the days left.
- DKIM rotation pauses and resumes from its journal; signing keeps using the
  current key.
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
The Compose file cannot filter by destination under rootless Podman, so this
phase narrows what each container holds and leaves the network policy as a
documented step for the operator, with the hosts `certs` needs listed.

### Tests

- The `certs` container passes the clean install and the upgrade checks on the
  Debian 13 machine, and a renewal and a rotation run there end to end against a
  test provider.
- A hostile case with `mail` compromised: it cannot read the token, cannot write
  to `tls/`, `dkim/` or `acme-challenge/`, and keeps serving after `certs` stops.
- The concurrency suite gets the case of a certificate replaced while
  connections open, and a DKIM key replaced while messages are signed.

## Open questions

- Whether `http-01` and `tls-alpn-01`, which need ports that `mail` owns, are
  worth keeping with the `acme-challenge/` volume or should be dropped in favour
  of `dns-01` for installs that use the `certs` container.
- Whether the DKIM key files should be created by `certs` as above or by the
  signing service of phase 2 from the start, which would remove one move.
- How the Compose generator expresses a per-container egress rule on rootless
  Podman, if it can at all.
