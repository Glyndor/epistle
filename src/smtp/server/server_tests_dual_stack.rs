//! End-to-end check that the SMTP `serve()` loop canonicalises the peer
//! of an IPv4 client arriving through a dual-stack `::` listener. With
//! the dual-stack bind, the kernel reports the peer of an IPv4 connection
//! as the v4-mapped IPv6 form `::ffff:127.0.0.1`. Without the
//! canonicalisation at the SMTP accept, that v4-mapped form reaches SPF
//! as `IpAddr::V6(...)`; the `ip4:192.0.2.0/24` mechanism in the test
//! record never matches, the outcome flips from `pass` to `fail`, and
//! the operator's legitimate senders are rejected with `550 5.7.23`.
//!
//! The test binds the SMTP listener on `[::]:0` with the same socket2
//! `only_v6(false)` switch the production `serve_bind::bind_listener`
//! uses, runs a real `Server::serve` on it, opens a TCP connection from
//! `127.0.0.1`, walks an EHLO + MAIL FROM + RCPT TO + DATA + QUIT
//! script, and asserts the `Received-SPF` header the SMTP server
//! stamps carries `client-ip=127.0.0.1` (an `IpAddr::V4`), not
//! `client-ip=::ffff:127.0.0.1`. The header is the wire the SPF outcome
//! reaches the message body with, so a v4-mapped form there is
//! proof that every consumer downstream of `serve()` (the audit log,
//! the DNSBL lookups, the inbound rate limit, the greylist key, the ban
//! table) sees the same wrong form.
//!
//! Lives in a sibling to `server_tests.rs` because the canonicalisation
//! invariant deserves its own focused coverage rather than sitting as
//! one more case in the long `server_tests` file.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::smtp::sink::MemorySink;

/// Build a directory with two accounts used by the dual-stack tests.
/// Mirrors the helper in `server_tests.rs` so this file compiles without
/// reaching into the private helper of the sibling test module.
fn test_directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("b@example.org".to_string(), "bob".to_string()),
		],
	))
}

/// DNS stub whose `txt` answers the `sender.example` SPF policy the
/// test uses. The mechanism `ip4:127.0.0.0/8` matches the IPv4
/// loopback the test client connects from. The mechanism is IPv4-only
/// by design: any SPF evaluation that receives the peer as the
/// v4-mapped IPv6 form `::ffff:127.0.0.1` instead of `127.0.0.1`
/// evaluates the rule against `IpAddr::V6(_)` and the `ip4:` mechanism
/// short-circuits to `false`. The subsequent `-all` fails the message
/// with the same `5.7.23` an attacker would. The shape is what
/// `server_tests` already uses; re-stated here so this file compiles
/// without importing the existing file's private helpers.
struct Ipv4SpfDns;

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for Ipv4SpfDns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let result = if name == "sender.example" {
			vec!["v=spf1 ip4:127.0.0.0/8 -all".to_string()]
		} else {
			Vec::new()
		};
		Box::pin(async move { Ok(result) })
	}

	fn addresses(&self, _name: &str) -> DnsFuture<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// Build the same dual-stack `::` listener the production
/// `serve_bind::bind_listener` builds: socket2 `set_only_v6(false)` so
/// IPv4 packets reach the same port regardless of the
/// `net.ipv6.bindv6only` sysctl. The helper exists so the test mirrors
/// the production path byte-for-byte without going through the private
/// cli module.
fn dual_stack_listener() -> std::io::Result<TcpListener> {
	let socket = socket2::Socket::new(
		socket2::Domain::IPV6,
		socket2::Type::STREAM,
		Some(socket2::Protocol::TCP),
	)?;
	socket.set_only_v6(false)?;
	socket.set_reuse_address(true)?;
	socket.bind(&std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0).into())?;
	socket.listen(1024)?;
	socket.set_nonblocking(true)?;
	let std_listener: std::net::TcpListener = socket.into();
	TcpListener::from_std(std_listener)
}

/// Open a connection to `addr` from the IPv4 loopback. With the
/// dual-stack listener, the kernel reports the peer of this
/// connection as `::ffff:127.0.0.1` unless the server canonicalises.
async fn connect_ipv4_loopback(addr: SocketAddr) -> tokio::net::TcpStream {
	let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr.port()));
	tokio::net::TcpStream::connect(target)
		.await
		.expect("IPv4 connect to dual-stack listener")
}

/// The SMTP server passes the peer address to SPF as the second
/// argument of `spf::check_host`. With the dual-stack bind, an
/// unfixed accept loop hands SPF `::ffff:127.0.0.1`; the
/// `ip4:127.0.0.0/8` mechanism in `sender.example`'s record never
/// matches (the mechanism is IPv4-only and the peer arrived as
/// `IpAddr::V6(_)`), the `-all` returns `SpfOutcome::Fail`, and the
/// message is rejected with `550 5.7.23 SPF validation failed` before
/// any DATA is accepted. The fix canonicalises the peer to `127.0.0.1`,
/// the mechanism matches, the outcome is `pass`, and the body carries
/// `Received-SPF: pass (domain of sender.example) client-ip=127.0.0.1`.
///
/// Asserted end-to-end on the wire: a real TCP listener, a real
/// `Server::serve` loop, a real client over the kernel, the full
/// conversation. Without the fix the test fails because the
/// `Received-SPF` line says `client-ip=::ffff:127.0.0.1` (or the
/// conversation is terminated with `550` before DATA).
#[tokio::test]
async fn dual_stack_listener_canonicalises_peer_for_spf() {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_spf(Arc::new(Ipv4SpfDns)),
	);
	let listener = dual_stack_listener().expect("dual-stack bind");
	let addr = listener.local_addr().expect("local addr");
	let serve = tokio::spawn({
		let server = Arc::clone(&server);
		async move { server.serve(listener).await }
	});

	let mut client = connect_ipv4_loopback(addr).await;
	// Read the greeting so the next write is not blocked on a full
	// kernel buffer if the server side is slow.
	let mut greeting = [0u8; 64];
	let _ = client.read(&mut greeting).await.expect("greeting read");

	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<eve@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
	client.write_all(script).await.expect("client write");
	client.shutdown().await.expect("client shutdown");

	let mut output = Vec::new();
	client.read_to_end(&mut output).await.expect("client read");
	serve.abort();

	let output = String::from_utf8(output).expect("ascii output");
	assert!(
		!output.contains("550"),
		"server must not reject the legitimate IPv4 sender; got: {output}"
	);
	let messages = sink.messages();
	assert_eq!(
		messages.len(),
		1,
		"expected one delivered message, got {messages:?}"
	);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii body");
	assert!(
		data.contains("Received-SPF: pass (domain of sender.example) client-ip=127.0.0.1"),
		"SPF must evaluate against the IPv4 peer 127.0.0.1; \
		 a v4-mapped form (::ffff:127.0.0.1) here is the bug being fixed; \
		 got body: {data}"
	);
	// Belt and braces: explicitly check no v4-mapped form leaks into
	// the Received-SPF header. Catches a regression that drops the
	// canonicalisation at the SMTP accept.
	assert!(
		!data.contains("client-ip=::ffff:"),
		"v4-mapped form leaked into Received-SPF; the canonical_peer \
		 call at listener.accept() has been removed; got body: {data}"
	);
}

/// Belt and braces for the message-level property: the peer IP the
/// SMTP session carries must be the IPv4 form `127.0.0.1`, never the
/// v4-mapped IPv6 form. The `Received:` header the SMTP server stamps
/// records `[127.0.0.1]` for an IPv4 peer and `[::ffff:127.0.0.1]`
/// for a v4-mapped peer, so this is a second independent check that
/// the canonicalisation happened before the session was built.
#[tokio::test]
async fn dual_stack_listener_canonicalises_peer_for_received_header() {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory()),
	);
	let listener = dual_stack_listener().expect("dual-stack bind");
	let addr = listener.local_addr().expect("local addr");
	let serve = tokio::spawn({
		let server = Arc::clone(&server);
		async move { server.serve(listener).await }
	});

	let mut client = connect_ipv4_loopback(addr).await;
	let mut greeting = [0u8; 64];
	let _ = client.read(&mut greeting).await.expect("greeting read");

	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
	client.write_all(script).await.expect("client write");
	client.shutdown().await.expect("client shutdown");

	let mut output = Vec::new();
	client.read_to_end(&mut output).await.expect("client read");
	serve.abort();

	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii body");
	assert!(
		data.contains("Received: from client.example.org ([127.0.0.1])"),
		"the peer IP the session stamps in `Received:` must be the \
		 IPv4 form, not the v4-mapped IPv6 form; got body: {data}"
	);
	assert!(
		!data.contains("[::ffff:"),
		"the v4-mapped IPv6 form must not appear in any peer annotation; \
		 got body: {data}"
	);
	// Reference the type so the IpAddr import is used; the second test
	// in this file uses `IpAddr` only transitively.
	let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
}
