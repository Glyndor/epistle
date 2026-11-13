# Mesh between nodes

An optional WireGuard network between the nodes of one epistle deployment.
This page is the design. Only one part of it exists: the package depends on
`wireguard-tools`. Nothing here is configured by installing the package, and
no `epistle node` command exists yet. Each decision below names the
alternative that was rejected, and the ones that need the owner are collected
in [Decisions that need the owner](#decisions-that-need-the-owner).

## What exists today

Read from the code of this repository, not assumed:

- epistle is single-node. There is no node concept, no peer list and no
  inter-node protocol in `src/`.
- The "queue between nodes" and the "database replication" do not exist. The
  outbound queue is a local spool and the PostgreSQL container runs with
  `network_mode: "none"`, talking to `mail` over a Unix socket on a volume.
  The distributed-state model is not designed, so this page does not design it.
  It states the rule those features must follow when they arrive.
- The traffic that is internal today is the management API (`8025`), the
  metrics listener (`9090`) and the link from `epistle-panel` to the API.
- The `mail` service runs on `network_mode: "pasta"`. A listener's `addr` is
  resolved inside the container, which owns no host address, so the exposure
  of a listener is bounded by the host side of the published port
  (`src/cli/init/compose_publish/`). `epistle service set <name> --bind
  <address>` already narrows that host side to one address.
- `epistle service set` refuses any non-loopback address for the listeners that
  speak plain HTTP (`api`, `web-dav`, `autoconfig`).
- Run as root, a stateful command re-executes itself as `glyndor-epistle`
  (`src/cli/delegation.rs`). The commands that must stay root are marked
  `false` there (`rotate`, `move-subids`, `stack rollback`).
- `wireguard-tools` has only `libc6` as `Depends` and recommends `nftables |
  iptables`. It does not pull `iproute2`, and `podman` only recommends `passt`
  (measured with `apt-cache` on Ubuntu 26.04, wireguard-tools 1.0.20250521;
  Debian 13 not checked).
- `helmly-agent` can also manage WireGuard and nftables on the same host. The
  mesh must not share a name, a table or a port with it.

## The package

`wireguard-tools` is in `Depends` next to `podup`, so `dpkg -i` refuses
without it and `apt install epistle` resolves it. Installing the package
creates no interface, no key and no firewall rule, and a test reads the
maintainer scripts to keep it that way
(`tests/packaging/debian_control_depends_on_the_keyring.rs`).

Rejected: `Recommends`. apt drops an unsatisfiable Recommends without a word,
which is what happened with podup (#885).

The later pull requests add what their code uses, in the same change as the
code: `iproute2` (the commands create the link, address and routes with `ip`)
and `nftables` (the firewall). They are not added now because a dependency
nothing calls yet would be untested.

## Names

Nothing is called `wg0` or `wireguard`.

| Thing | Name |
|---|---|
| Interface | `glyndor-epistle` (15 characters, the kernel limit) |
| systemd unit | `glyndor-epistle-mesh.service` |
| Root-only directory | `/etc/glyndor/epistle-mesh/` (0700, root) |
| nftables table | `inet glyndor_epistle_mesh` |

The directory is not under `/etc/epistle`: that one belongs to the service
account and is bind-mounted into the container, and the keys must be reachable
by neither. Rejected: `wg-quick@glyndor-epistle`. It would put `wg-quick` in
the name, it needs a `.conf` carrying the private key, and its `PostUp`
scripting is exactly the shell this design avoids.

## Root against the rootless stack

An interface needs `CAP_NET_ADMIN`; the stack runs rootless as
`glyndor-epistle`. The two halves never share a process.

Root half (new commands that stay root, like `rotate` and `move-subids`):

- creates and removes the link, the address, the routes and the nftables
  table, and holds every key.
- is run by `sudo epistle node ...`. No sudoers file is shipped and the
  account is never given a capability.
- at boot it runs as `glyndor-epistle-mesh.service`, a `Type=oneshot`
  `RemainAfterExit=yes` unit whose `ExecStart` is `epistle node up` and
  `ExecStop` is `epistle node down`, with `CapabilityBoundingSet=CAP_NET_ADMIN`
  and a read-only view of the rest of the system. `node up` reads
  `/etc/glyndor/epistle-mesh/mesh.toml` and applies it, so there is no shell in
  the unit.

Account half (the existing delegation path):

- writes the `[mesh]` section of `mail.toml` (public values only) and
  re-renders the compose file with the published addresses.

The unit ships in the package, not enabled and not started
(`dh_installsystemd --no-enable --no-start`), with
`ConditionPathExists=/etc/glyndor/epistle-mesh/mesh.toml` as a second guard.
`epistle node enable` is what enables it.

### Ordering with the user manager

The stack unit `podup-epistle.service` lives in the user manager of
`glyndor-epistle` (lingering), and a user unit cannot be ordered against a
system unit. The user manager itself is a system unit, `user@<uid>.service`.
`node enable` writes
`/etc/systemd/system/user@<uid>.service.d/glyndor-epistle-mesh.conf` with
`After=glyndor-epistle-mesh.service`, so the interface exists before the stack
starts. The uid is why it is generated and not shipped: a generic
`user@.service.d` drop-in would touch every user of every host, mesh or not.

This is ordering, not safety. If the unit fails, the stack still starts and
the publish of a missing address fails, which is the fail-closed outcome
described below. Rejected: an `ExecStartPre` loop in the stack unit (podup
generates it, and a wait that never ends hides the failure).

## Prefix and port

- Prefix: `fd` plus 40 random bits from the system CSPRNG, which is a /48 per
  deployment as RFC 4193 describes. The subnet id (16 bits) and each node's
  interface identifier (64 bits) are random too, so no address looks like
  `::1` or `::2`. The node holds one `/128`. The candidate is rejected when it
  overlaps any address or route already on the host. Rejected: the RFC's
  SHA-1 of time and EUI-64, which exists to get randomness where none was
  available.
- Port: UDP, drawn from the IANA dynamic range 49152 to 65535, **outside**
  `net.ipv4.ip_local_port_range` and not in use. On a stock kernel that range
  is 32768 to 60999, so the draw is from 61000 to 65535 (measured here). A port
  inside the ephemeral range can be taken by an outgoing socket before the
  interface comes up after a reboot, and the failure would be intermittent.
  The cost is about 12 bits of choice, which is fine because the port is not a
  secret, only not the usual one.
- Both are generated once by `epistle node enable`, stored in `mesh.toml`, and
  never regenerated by an upgrade.

## Keys

- One private key per node, one pre-shared key per pair of nodes. Both are
  files of 0600 owned by root under `/etc/glyndor/epistle-mesh/`, written with
  `O_EXCL` and removed on `node disable`.
- Generated with `wg genkey`, `wg pubkey` and `wg genpsk`, with the secret on a
  pipe. Applied with `wg set <interface> private-key <file> peer <pubkey>
  preshared-key <file> ...`, where only paths appear in argv. No secret is ever
  an argument or an environment variable. Rejected: generating X25519 in
  process, which would add code to a security path to save a pipe.
- `AllowedIPs` is exactly one `/128` per peer, never `::/0`, never a prefix.
  The routes are those `/128`s.
- The new secrets are added to the registry of `epistle rotate`.
- Rotation (`epistle node rotate`): a new pre-shared key per pair, or a new
  private key, is announced to the peer **through the existing tunnel** and
  both ends switch at an agreed time. The exchange and the failure case where
  only one side switched are for that pull request to specify and test.

## Joining a node

Full mesh: every node has every other as a peer. Rejected: hub and spoke,
because a hub would need the other nodes' `/128`s in its `AllowedIPs` and
forward between them, which breaks one `/128` per peer. The price is a pair of
keys per link, which is fine for the handful of nodes this is for.

The token travels by hand, in two steps, because the API of an existing node
answers only on the tunnel address and a new node has no tunnel yet.

1. On the new node, `epistle node join-request --endpoint HOST:PORT` generates
   its key pair and prints a request: the public key and the node name. The
   request is not secret.
2. On an existing node, `epistle node invite <request>` assigns the new node an
   address, generates the pre-shared key for the pair, adds the new node as a
   peer marked pending, and prints the token.
3. On the new node, `epistle node join <token>` checks it and brings the tunnel
   up. The rest of the mesh is then learned **over the tunnel** through the API
   of the node that invited it: the other peers, and a pre-shared key for each
   pair, negotiated inside the tunnel.

The token is `epistle-mesh-1.` followed by base64url of a versioned
document: the deployment prefix, the inviter's public key and endpoint, the
joiner's public key and assigned address, the pre-shared key, an expiry and a
token id. It lives 15 minutes by default and 1 hour at most.

Single use is enforced on the inviter, not on trust:

- the pending peer is bound to the public key from the request, so the token
  is useless without the joiner's private key, and a stolen token alone does
  nothing;
- the first completed handshake with that key clears the pending flag and burns
  the token id;
- a pending peer that never handshakes is removed at its expiry.

Rejected: a token that carries the joiner's private key (a copy that never
left a clipboard is still a copy), and a bootstrap endpoint on a public address
(it is the exposure the mesh exists to remove).

## When the tunnel is down

A node refuses. It never falls back to a public address.

- **No wildcard binds.** Every mesh listener binds to the node's mesh address,
  never `::` or `0.0.0.0`. If the address does not exist at start, the bind
  fails and the service does not start.
- **Unreachable route.** `node up` installs `unreachable <prefix>/48` in the
  main table with a high metric, independent of the interface. With the tunnel
  up, the peers' `/128` routes are more specific and win. With it down, the
  traffic of a node to a peer fails at once with `ENETUNREACH`, instead of
  following the default route out through the provider.
- **Weak host model.** Linux accepts a packet for an address of the host that
  arrives on any interface. The nftables table drops anything addressed to the
  mesh address that did not arrive on the mesh interface, and anything on the
  interface that is not one of the ports below.
- **Peers are validated.** A peer address in the configuration that is not
  inside the deployment `/48` is a load error.

The firewall opens nothing on the interface except the listeners that are bound
to the mesh address: the API, metrics and, later, the ports of the features that
need it. The UDP port itself must be open on the public side. If a host firewall
(ufw, firewalld, the operator's own nftables) is active, `node enable` prints the
rule instead of editing it, because a drop in any table wins and silently
editing someone else's firewall is the wrong default.

## Binding the services

`mail.toml` gets a section written only by the node commands:

```toml
[mesh]
interface = "glyndor-epistle"
address = "fdxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
prefix = "fdxx:xxxx:xxxx::/48"
```

- A listener may say `addr = "mesh"`. It resolves to `mesh.address`, and with no
  `[mesh]` section it is a configuration error, never a wildcard.
- On the container stack the container side stays unspecified, as today, and the
  host side of the published port becomes the mesh address:
  `[fdxx:...]:8025:8025`. The generated map keeps one entry per port today, so
  an API reachable from both loopback and the mesh needs two entries and the
  reader of the map must stop keying on the port alone.
- `epistle-panel` on another node uses `EPISTLE_API_URL=http://[fdxx:...]:8025`.
  Its pasta forwards outbound traffic through the host's routing, so the tunnel
  route applies with no further change.
- API keys used by peers carry `ip_cidr` set to the deployment `/48`.
- A host install under `docs/epistle.service` binds the address directly and adds
  `Requires=` and `After=glyndor-epistle-mesh.service`.
- Future inter-node features (queue delivery, replication) bind and connect only
  to mesh addresses and refuse a peer outside the `/48`. That is a requirement on
  them, enforced at configuration load.

## Pull requests

1. This one: the dependency, the test that the package configures nothing, and
   this page.
2. `epistle node enable`, `up`, `down`, `status`, `disable`: prefix and port
   generation, key files, the unit and the user-manager drop-in, the table.
   `iproute2` and `nftables` join `Depends`.
3. `[mesh]` in the configuration, `addr = "mesh"`, the published map for the
   mesh address, the relaxation of the plain-HTTP rule for that address only.
4. `join-request`, `invite`, `join`, the sync of the other peers.
5. `rotate`, and the entries in `epistle rotate`.

Tests, by what a runner can do:

- Pure functions (prefix, port, token, rendering of `mesh.toml`, the nftables
  text, the published map) run in the ordinary suite.
- Two nodes in network namespaces, checking that traffic outside the tunnel is
  refused and that the unreachable route holds with the interface down, need
  root. Unprivileged user namespaces are blocked on this machine (AppArmor), so
  the script uses `ip netns` as root and runs on a local VM before merging, as
  the testing standard says for WireGuard, nftables, Podman and systemd.

## Not verified

These are claims the design depends on that no one has run yet:

- `pasta` publishing on a specific IPv6 host address and forwarding to the
  container, and what family it uses inside.
- Whether a published listener bound to a mesh address resumes after the
  interface is taken down and brought back.
- The `user@<uid>.service` drop-in ordering on a lingering account at boot.
- `dh_installsystemd --no-enable --no-start` leaving the unit off on install and
  upgrade.
- Debian 13 package metadata (only Ubuntu 26.04 was read).
- The weak-host drop rule on a host with other nftables tables.

## Decisions that need the owner

1. **Plain HTTP on the mesh address.** `service set` refuses a non-loopback bind
   for `api`, `web-dav` and `autoconfig`. The proposal lifts it for the mesh
   address only, since the tunnel gives confidentiality and peer authentication,
   and the keys still apply. It weakens a rule that was written on purpose.
2. **Topology.** Full mesh, with the cost of a key pair per link, or something
   else. Hub and spoke is incompatible with one `/128` per peer.
3. **Token path.** By hand in two steps, as proposed, or also through the API of
   an existing node for the second step.
4. **Firewall.** Print the UDP rule (proposed), or open it automatically in ufw or
   firewalld when one is detected.
5. **Order of work.** The queue and the replication do not exist. Proposal:
   deliver connectivity and the binding rule first, and make those features
   follow it, rather than wait for them.
6. **Port entropy.** Drawing outside the ephemeral range leaves about 4,500
   ports on a stock kernel. The alternative is the whole dynamic range plus
   `net.ipv4.ip_local_reserved_ports`, a host-wide sysctl.
