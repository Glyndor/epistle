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
	let port = crate::test_fixtures::free_port();

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
	let v6_client = tokio::net::TcpStream::connect(SocketAddr::V6(std::net::SocketAddrV6::new(
		std::net::Ipv6Addr::LOCALHOST,
		port,
		0,
		0,
	)))
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
