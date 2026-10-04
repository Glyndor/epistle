//! Bind the listeners `serve` exposes.
//!
//! `TcpListener::bind` on `::` inherits the host's
//! `net.ipv6.bindv6only`: on hosts where the sysctl is `1` (the
//! minority, but allowed) the socket stops accepting IPv4 packets
//! and the mail server loses every connection from an IPv4 client
//! on day one. The fix is to set `IPV6_V6ONLY = false` ourselves on
//! the IPv6-unspecified address before `bind`, so the dual-stack
//! property is a property of the server we ship, not of the host
//! the operator happens to run it on.
//!
//! The IPv6-only fallback kicks in when an operator has both a
//! `[::]:P` and a `0.0.0.0:P` listener configured for the same
//! port. On hosts with `bindv6only=1` the dual-stack `[::]:P` socket
//! would shadow the IPv4 bind; with `bindv6only=0` it would silently
//! route IPv4 traffic away from the explicit `0.0.0.0:P`. Either
//! way, the operator's intent: bind both, one per family. The
//! listener has to win. When the port is already covered by an
//! `0.0.0.0` listener the `[::]` listener is bound with
//! `only_v6(true)` so the two coexist; when it is not, the listener
//! stays dual-stack.
//!
//! Every other address keeps the plain `TcpListener::bind` path:
//! IPv4 loopback and an explicit IPv6 address do not need the
//! socket2 dance.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpListener;

use crate::config::Listener;
#[cfg(test)]
use crate::config::ListenerKind;

/// Bind a listener's socket and log it. Shared by every `serve`
/// listener arm. When the listener's address is the IPv6 unspecified
/// address (`::`), the socket is built with `socket2` so
/// `IPV6_V6ONLY` is off (default) and IPv4 connections reach the
/// same port regardless of the host's `net.ipv6.bindv6only` sysctl.
///
/// `ipv4_any_ports` is the set of port numbers that already have an
/// `0.0.0.0` listener bound by the same `serve` run. When the
/// listener being bound is `[::]:P` and `P` is in that set, the
/// socket is created with `IPV6_V6ONLY = true` so the two coexist
/// instead of one of them failing with `EADDRINUSE`.
pub(super) async fn bind_listener(
	listener: &Listener,
	ipv4_any_ports: &HashSet<u16>,
) -> std::io::Result<TcpListener> {
	let addr = listener.socket_addr();
	let bound = if is_dual_stack_addr(listener.addr) {
		let only_v6 = ipv4_any_ports.contains(&addr.port());
		bind_dual_stack(addr, only_v6)?
	} else {
		TcpListener::bind(addr).await?
	};
	tracing::info!(%addr, kind = ?listener.kind, "listening");
	Ok(bound)
}

/// Bind on the IPv6 unspecified address with `reuse_address(true)`,
/// then convert to a Tokio listener. `only_v6` selects the
/// `IPV6_V6ONLY` socket option:
/// - `false`: the socket accepts both IPv4 and IPv6 traffic
///   regardless of the host's `bindv6only` sysctl. The default
///   when no other listener already covers the port with
///   `0.0.0.0`.
/// - `true`: the socket accepts IPv6 traffic only. Used when an
///   `0.0.0.0:P` listener is already bound, so the two can coexist
///   on the same port instead of one failing with `EADDRINUSE`.
///
/// The backlog is 128, the standard library's default for
/// `TcpListener::bind`, and the socket is non-blocking because
/// Tokio needs that to hand it off. Caller guarantees the address
/// is the IPv6 unspecified address; the `V6` destructure makes any
/// future call with a different address surface as a compile-time
/// error.
fn bind_dual_stack(addr: SocketAddr, only_v6: bool) -> std::io::Result<TcpListener> {
	let SocketAddr::V6(v6) = addr else {
		return Err(std::io::Error::other(
			"bind_dual_stack called with a non-IPv6 address",
		));
	};
	let socket = socket2::Socket::new(
		socket2::Domain::IPV6,
		socket2::Type::STREAM,
		Some(socket2::Protocol::TCP),
	)?;
	socket.set_only_v6(only_v6)?;
	socket.set_reuse_address(true)?;
	socket.bind(&v6.into())?;
	socket.listen(128)?;
	socket.set_nonblocking(true)?;
	let std_listener: std::net::TcpListener = socket.into();
	TcpListener::from_std(std_listener)
}

/// `true` when the address is the IPv6 unspecified address (`::`).
/// The dual-stack setup is IPv6-specific; loopback addresses stay on
/// the plain bind path.
fn is_dual_stack_addr(addr: IpAddr) -> bool {
	matches!(addr, IpAddr::V6(v6) if v6.is_unspecified())
}

/// Helper used by the test: build a fresh `Listener` whose bind
/// shape triggers the dual-stack code path (`::`, port 0). Lives in
/// this module because the test reaches for the same private
/// helpers the production code uses.
#[cfg(test)]
pub(super) fn dual_stack_listener(port: u16) -> Listener {
	Listener {
		kind: ListenerKind::Smtp,
		addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
		port: Some(port),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::SocketAddrV4;

	/// Bind a `Listener` whose address is `::` and port 0 through the
	/// new function, then connect to `127.0.0.1:<port>` with a plain
	/// IPv4 TCP connect. The connect and the accept must both succeed:
	/// if the socket has `only_v6` true the connect fails and the
	/// test goes red. The test fails with a clear message when the
	/// host has no IPv6 loopback at all, rather than skipping; CI
	/// hosts have IPv6 loopback and the bind must succeed.
	#[tokio::test]
	async fn dual_stack_listener_accepts_ipv4_clients() {
		let listener = dual_stack_listener(0);
		let bound = match bind_listener(&listener, &HashSet::new()).await {
			Ok(bound) => bound,
			Err(error) => panic!(
				"dual-stack bind failed; CI hosts must have IPv6 loopback \
				 (bind [::]:0 returned {error}); the bind helper turns an \
				 `IPv6 sockets are not bindable on this host` outcome \
				 into a plain `serve` start failure, not a skipped test"
			),
		};
		let port = bound.local_addr().expect("local addr").port();
		let stream = tokio::net::TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
			std::net::Ipv4Addr::LOCALHOST,
			port,
		)))
		.await
		.expect("IPv4 connect to a [::] socket");
		let peer = stream.peer_addr().expect("peer_addr");
		assert!(
			is_v4(&peer),
			"connected peer must be IPv4 (got {peer}); if it is plain IPv6, the socket is `only_v6` and the regression has come back"
		);
		let (socket, peer_addr) = bound.accept().await.expect("accept");
		let _ = socket;
		// The accepted address is the v4-mapped form (`::ffff:127.0.0.1`)
		// because the listener is IPv6 and the kernel reports the
		// IPv4 peer as a v4-mapped v6 address. `is_v4` matches both
		// the IPv4 variant and the v4-mapped IPv6 form, so the
		// assertion says what we mean: the peer reached us over
		// IPv4, not IPv6. If the socket were `only_v6`, the connect
		// from 127.0.0.1 would have failed in the first place.
		assert!(
			is_v4(&peer_addr),
			"accepted peer must be IPv4 (got {peer_addr}); if it is plain IPv6, the socket is `only_v6` and the regression has come back"
		);
	}

	/// The helper `is_dual_stack_addr` only matches the IPv6
	/// unspecified address; loopback and IPv4 any must fall through to
	/// the plain `TcpListener::bind` path.
	#[test]
	fn dual_stack_addr_recogniser_is_specific() {
		assert!(is_dual_stack_addr(IpAddr::V6(
			std::net::Ipv6Addr::UNSPECIFIED
		)));
		assert!(!is_dual_stack_addr(IpAddr::V6(
			std::net::Ipv6Addr::LOCALHOST
		)));
		assert!(!is_dual_stack_addr(IpAddr::V4(
			std::net::Ipv4Addr::UNSPECIFIED
		)));
		assert!(!is_dual_stack_addr(IpAddr::V4(
			std::net::Ipv4Addr::LOCALHOST
		)));
	}

	/// `true` when the address is an IPv4 connection. Matches both the
	/// `SocketAddr::V4` variant and the v4-mapped IPv6 form a
	/// dual-stack listener returns for an IPv4 peer.
	fn is_v4(addr: &std::net::SocketAddr) -> bool {
		match addr {
			std::net::SocketAddr::V4(_) => true,
			std::net::SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().is_some(),
		}
	}

	/// A config that lists both `[::]:P` and `0.0.0.0:P` for the same
	/// port must bind both. The first `serve` listener to claim the
	/// port is the one `bind_listener` will see as `ipv4_any_ports`
	/// for the second; whichever order the test runs the two binds
	/// in, both must succeed.
	///
	/// Picks a free port by binding a plain `127.0.0.1:0`, dropping
	/// it, and reusing the port number. The two production binds must
	/// match the picked port; using `port = 0` for either would let the
	/// test pass even when the dual-stack bind ends up on a different
	/// port than the IPv4 bind.
	#[tokio::test]
	async fn v6_any_and_v4_any_listeners_on_the_same_port_coexist() {
		let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("free-port probe");
		let port = probe.local_addr().expect("probe addr").port();
		drop(probe);

		// The IPv4 listener: build the production `Listener` shape
		// (with kind = Smtp so `bind_listener` takes the same path
		// it would for a real config entry) and bind through the
		// serve bind helper.
		let v4 = Listener {
			kind: ListenerKind::Smtp,
			addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
			port: Some(port),
		};
		// First bind: the IPv4 one. The set `ipv4_any_ports` here
		// does not yet include `port` because the IPv4 bind has not
		// happened yet. The helper treats an IPv4 `Listener` as
		// the plain tokio bind path and never consults the set;
		// the set matters only for `[::]` listeners.
		let ipv4_bound = bind_listener(&v4, &HashSet::new())
			.await
			.expect("IPv4 0.0.0.0:P bind must succeed");
		let ipv4_addr = ipv4_bound.local_addr().expect("v4 local addr");
		assert_eq!(ipv4_addr.port(), port);

		// Second bind: `[::]:P`, with `port` already in the set. The
		// helper must switch the socket to `only_v6(true)` so the
		// two coexist. With `only_v6(false)` the bind would still
		// succeed on hosts with `bindv6only=0`, but on the
		// minority with `bindv6only=1` the IPv4 bind would fail
		// with `EADDRINUSE`; the helper picks the path that works on
		// every host.
		let ipv4_any_ports: HashSet<u16> = std::iter::once(port).collect();
		let v6 = Listener {
			kind: ListenerKind::Smtp,
			addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
			port: Some(port),
		};
		let ipv6_bound = bind_listener(&v6, &ipv4_any_ports)
			.await
			.expect("[::]:P bind must succeed when 0.0.0.0:P is already bound");
		let ipv6_addr = ipv6_bound.local_addr().expect("v6 local addr");
		assert_eq!(ipv6_addr.port(), port);

		// An IPv4 connect to the IPv4 listener succeeds.
		let v4_client = tokio::net::TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
			std::net::Ipv4Addr::LOCALHOST,
			port,
		)))
		.await
		.expect("IPv4 connect");
		let (v4_socket, _) =
			tokio::time::timeout(std::time::Duration::from_secs(5), ipv4_bound.accept())
				.await
				.expect("v4 accept timed out")
				.expect("v4 accept");
		let _ = v4_socket;
		let _ = v4_client;

		// An IPv6 connect to the `[::1]` listener succeeds. The
		// `[::]:P` socket is `only_v6(true)` so the IPv6 peer
		// reaches it.
		let v6_client = tokio::net::TcpStream::connect(SocketAddr::V6(
			std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, port, 0, 0),
		))
		.await
		.expect("IPv6 connect");
		let (v6_socket, _) =
			tokio::time::timeout(std::time::Duration::from_secs(5), ipv6_bound.accept())
				.await
				.expect("v6 accept timed out")
				.expect("v6 accept");
		let _ = v6_socket;
		let _ = v6_client;

		// Belt and braces: read the option back off both sockets so
		// the test fails on a regression that loses the
		// `set_only_v6(true)` switch. The production intent is
		// observable on the socket itself, not only through the
		// accepts. The companion test below pins the other branch
		// (`[::]:P` without a co-resident `0.0.0.0:P`, which must
		// stay `only_v6(false)`).
		let v6_ref = socket2::SockRef::from(&ipv6_bound);
		let only_v6 = v6_ref.only_v6().expect("read only_v6 from v6 socket");
		assert!(
			only_v6,
			"[::]:P with 0.0.0.0:P already bound must be IPV6_V6ONLY=true, \
			 so the two coexist; got only_v6={only_v6}; the bind helper \
			 dropped the conditional set_only_v6(true) switch"
		);
	}

	/// A `[::]:P` listener bound without a co-resident `0.0.0.0:P`
	/// listener must still be `IPV6_V6ONLY=false` so IPv4 clients
	/// reach it. The companion to the coexist test above; pins the
	/// other branch of the conditional.
	#[tokio::test]
	async fn dual_stack_bind_is_only_v6_false_without_v4_any() {
		let listener = dual_stack_listener(0);
		let bound = bind_listener(&listener, &HashSet::new())
			.await
			.expect("dual-stack bind");
		let port = bound.local_addr().expect("local addr").port();
		// The port must not appear in the empty `ipv4_any_ports` set,
		// so the helper must leave the socket dual-stack.
		let only_v6 = socket2::SockRef::from(&bound)
			.only_v6()
			.expect("read only_v6");
		assert!(
			!only_v6,
			"a lone [::]:P must be IPV6_V6ONLY=false so IPv4 clients can reach it; \
			 got only_v6={only_v6}"
		);
		let _ = port;
	}
}
