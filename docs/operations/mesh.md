# Mesh between nodes

An optional WireGuard network between the nodes of one epistle deployment.
This page is the design. Only one part of it exists: the package depends on
`wireguard-tools`. Nothing here is configured by installing the package, and
no `epistle node` command exists yet.

## Status

- epistle is single-node. There is no node concept, no peer list and no
  inter-node protocol in `src/`.
- The outbound queue is a local spool and the PostgreSQL container runs with
  `network_mode: "none"`, talking to `mail` over a Unix socket on a volume.
  Replicated queue and database state are not part of this design. This page
  states the rule such features must follow if they arrive.
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

## The package

`wireguard-tools` is in `Depends` next to `podup`, so `dpkg -i` refuses
without it and `apt install epistle` resolves it. Installing the package
creates no interface, no key and no firewall rule, and a test reads the
maintainer scripts to keep it that way
(`tests/packaging/debian_control_depends_on_the_keyring.rs`).

It is a `Depends` and not a `Recommends` because apt drops an unsatisfiable
`Recommends` without a word.

The commands will also need `iproute2` (they create the link, address and
routes with `ip`) and `nftables` (the firewall). Those join `Depends` together
with the code that calls them.

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
by neither. `wg-quick@glyndor-epistle` is not used: it needs a `.conf`
carrying the private key, and its `PostUp` scripting is the shell this design
avoids.

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
described below.

## Prefix and port

- Prefix: `fd` plus 40 random bits from the system CSPRNG, which is a /48 per
  deployment as RFC 4193 describes. The subnet id (16 bits) and each node's
  interface identifier (64 bits) are random too, so no address looks like
  `::1` or `::2`. The node holds one `/128`. The candidate is rejected when it
  overlaps any address or route already on the host.
- Port: UDP, drawn from the IANA dynamic range 49152 to 65535, **outside**
  `net.ipv4.ip_local_port_range` and not in use. On a stock kernel that range
  is 32768 to 60999, so the draw is from 61000 to 65535. A port
  inside the ephemeral range can be taken by an outgoing socket before the
  interface comes up after a reboot, and the failure would be intermittent.
  The port is not a secret, only not the usual one.
- Both are generated once by `epistle node enable`, stored in `mesh.toml`, and
  never regenerated by an upgrade.

## Keys

- One private key per node, one pre-shared key per pair of nodes. Both are
  files of 0600 owned by root under `/etc/glyndor/epistle-mesh/`, written with
  `O_EXCL` and removed on `node disable`.
- Generated with `wg genkey`, `wg pubkey` and `wg genpsk`, with the secret on a
  pipe. Applied with `wg set <interface> private-key <file> peer <pubkey>
  preshared-key <file> ...`, where only paths appear in argv. No secret is ever
  an argument or an environment variable.
- `AllowedIPs` is exactly one `/128` per peer, never `::/0`, never a prefix.
  The routes are those `/128`s.
- The new secrets are added to the registry of `epistle rotate`.
- Rotation (`epistle node rotate`): a new pre-shared key per pair, or a new
  private key, is announced to the peer **through the existing tunnel** and
  both ends switch at an agreed time.

## Joining a node

Full mesh: every node has every other as a peer. A hub-and-spoke topology
would need the hub to hold the other nodes' `/128`s in its `AllowedIPs` and
forward between them, which breaks one `/128` per peer. The price of a full
mesh is a pair of keys per link, which suits the handful of nodes this is for.

The token travels by hand, in three steps, because the API of an existing node
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

The token never carries the joiner's private key, and there is no bootstrap
endpoint on a public address, which is the exposure the mesh exists to remove.

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
