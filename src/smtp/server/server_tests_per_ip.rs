//! The per-IP connection cap: a peer over `max_connections_per_ip`
//! is answered `421 4.7.0 too many connections from your address` and
//! the connection is closed. The cap is per-listener: two SMTP
//! listeners each have their own count for the same IP. A peer in a
//! trusted CIDR bypasses the cap; the per-listener semaphore still
//! bounds the total.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::sync::Mutex;

use super::*;
use crate::net::accept::Accept;
use crate::smtp::sink::MemorySink;

/// A test accept loop that hands out a fixed number of pre-connected
/// streams, all attributed to the same peer. Once the script is
/// empty, the accept loop parks forever (the listener's `serve_on`
/// then keeps running on the active connections, which is the only
/// state the test cares about).
struct Scripted {
	streams: Mutex<Vec<DuplexStream>>,
	peer: SocketAddr,
}

impl Scripted {
	fn new(streams: Vec<DuplexStream>, peer: SocketAddr) -> Self {
		Scripted {
			streams: Mutex::new(streams),
			peer,
		}
	}
}

impl Accept for Scripted {
	type Stream = DuplexStream;

	fn accept(
		&self,
	) -> impl std::future::Future<Output = std::io::Result<(DuplexStream, SocketAddr)>> + Send {
		let next = self.streams.try_lock().ok().and_then(|mut g| g.pop());
		let peer = self.peer;
		async move {
			match next {
				Some(stream) => Ok((stream, peer)),
				None => std::future::pending().await,
			}
		}
	}
}

/// Wire a server with `max_connections` and `max_connections_per_ip`
/// to a scripted accept loop, returning the server's `Arc` so the
/// test can spawn the loop alongside the client connections. Returns
/// the client-side duplex streams so the test can read each
/// connection's greeting or 421 reply.
fn server_with_caps(
	max_connections: usize,
	max_connections_per_ip: usize,
) -> (Arc<Server>, Scripted, Vec<DuplexStream>) {
	let (a1, a2) = tokio::io::duplex(64 * 1024);
	let (b1, b2) = tokio::io::duplex(64 * 1024);
	let (c1, c2) = tokio::io::duplex(64 * 1024);
	let (d1, d2) = tokio::io::duplex(64 * 1024);
	let (e1, e2) = tokio::io::duplex(64 * 1024);
	let client_streams = vec![a1, b1, c1, d1, e1];
	let server_streams = vec![a2, b2, c2, d2, e2];
	let peer: SocketAddr = "203.0.113.1:4000".parse().expect("peer");
	let accept = Scripted::new(server_streams, peer);
	let sink = Arc::new(MemorySink::new());
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(directory)
			.with_max_connections(max_connections)
			.with_max_connections_per_ip(max_connections_per_ip),
	);
	(server, accept, client_streams)
}

/// Spawn the server's accept loop in a tokio task. The server holds
/// the work itself; cancelling the JoinHandle tears down the accept
/// loop and the in-flight connection tasks.
fn spawn_serve(server: Arc<Server>, accept: Scripted) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let _ = server.serve_on(accept).await;
	})
}

/// Drive one client: wait for the 220 banner and a 421 (or 250, in
/// the trusted path) reply, then return the bytes the server wrote.
async fn expect_greeting_or_421(client: &mut DuplexStream) -> String {
	let mut out = Vec::new();
	let mut buf = [0u8; 512];
	// Read whatever the server sends within two seconds; a refused
	// connection writes the 421 and closes, an admitted one writes
	// the 220 banner and parks waiting for EHLO.
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
	loop {
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		if remaining.is_zero() {
			break;
		}
		let read = match tokio::time::timeout(remaining, client.read(&mut buf)).await {
			Ok(Ok(0)) => break,
			Ok(Ok(n)) => n,
			Ok(Err(_)) => break,
			Err(_) => break,
		};
		out.extend_from_slice(&buf[..read]);
		if out.windows(3).any(|w| w == b"421") || out.windows(3).any(|w| w == b"220") {
			break;
		}
	}
	String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn per_ip_cap_refuses_excess_connections_with_421() {
	let (server, accept, mut clients) = server_with_caps(100, 2);
	let _serve = spawn_serve(server, accept);
	// Five clients open from the same IP; the cap is 2, so the third,
	// fourth and fifth are refused.
	let mut refused = 0;
	let mut admitted = 0;
	for client in clients.iter_mut() {
		// Each client waits for the 220 banner (admitted) or the 421
		// reply (refused); a 2-second ceiling catches a hang.
		let reply = tokio::time::timeout(
			std::time::Duration::from_secs(2),
			expect_greeting_or_421(client),
		)
		.await
		.unwrap_or_default();
		if reply.contains("421 ") {
			refused += 1;
			assert!(
				reply.contains("too many connections from your address"),
				"refusal reply missing the exact wording: {reply}"
			);
		} else if reply.starts_with("220 ") {
			admitted += 1;
		}
	}
	// The cap is 2; the test produced 5 clients, so 2 are admitted and
	// 3 are refused. Anything else means the cap is not holding.
	assert_eq!(admitted, 2, "expected 2 admitted under the per-IP cap");
	assert_eq!(refused, 3, "expected 3 refused with 421");
}

#[tokio::test]
async fn trusted_cidr_bypasses_the_per_ip_cap() {
	// Cap is 1, but the peer is in a trusted CIDR; the cap is skipped
	// and every connection from the trusted network is admitted. The
	// per-listener semaphore (here 100) is still the real upper bound.
	let (a, _b) = tokio::io::duplex(64 * 1024);
	let (c, _d) = tokio::io::duplex(64 * 1024);
	let (e, _f) = tokio::io::duplex(64 * 1024);
	let peer: SocketAddr = "10.0.0.5:4000".parse().expect("peer");
	let accept = Scripted::new(vec![a, c, e], peer);
	let mut clients = [_b, _d, _f];
	let sink = Arc::new(MemorySink::new());
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(directory)
			.with_max_connections(100)
			.with_max_connections_per_ip(1)
			.with_trusted_networks(vec![crate::cidr::Cidr::parse("10.0.0.0/8").unwrap()]),
	);
	let _serve = spawn_serve(server, accept);
	let mut admitted = 0;
	for client in clients.iter_mut() {
		let reply = tokio::time::timeout(
			std::time::Duration::from_secs(2),
			expect_greeting_or_421(client),
		)
		.await
		.unwrap_or_default();
		if reply.starts_with("220 ") {
			admitted += 1;
		}
	}
	assert_eq!(admitted, 3, "a trusted peer is exempt from the per-IP cap");
}

/// An accept loop fed one stream at a time by the test.
struct Fed {
	streams: Mutex<tokio::sync::mpsc::UnboundedReceiver<DuplexStream>>,
	peer: SocketAddr,
}

impl Accept for Fed {
	type Stream = DuplexStream;

	async fn accept(&self) -> std::io::Result<(DuplexStream, SocketAddr)> {
		match self.streams.lock().await.recv().await {
			Some(stream) => Ok((stream, self.peer)),
			None => std::future::pending().await,
		}
	}
}

#[tokio::test]
async fn a_failed_tls_handshake_gives_the_per_ip_slot_back() {
	// Cap 1 on an implicit-TLS listener. A client that sends garbage
	// instead of a ClientHello fails the handshake; the next connection
	// from the same address must still get in.
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let (feed, streams) = tokio::sync::mpsc::unbounded_channel();
	let accept = Fed {
		streams: Mutex::new(streams),
		peer: "203.0.113.9:4000".parse().expect("peer"),
	};
	let server = Arc::new(
		Server::new(
			"mail.example.org",
			Arc::new(MemorySink::new()) as Arc<dyn MessageSink>,
		)
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Implicit,
		)
		.with_max_connections_per_ip(1),
	);
	let _serve = tokio::spawn(async move {
		let _ = server.serve_on(accept).await;
	});
	for _ in 0..3 {
		let (mut client, server_side) = tokio::io::duplex(64 * 1024);
		feed.send(server_side).expect("feed");
		tokio::io::AsyncWriteExt::write_all(&mut client, b"EHLO not-a-client-hello\r\n\r\n")
			.await
			.expect("garbage");
		let mut rest = Vec::new();
		let _ = tokio::time::timeout(
			std::time::Duration::from_secs(5),
			client.read_to_end(&mut rest),
		)
		.await;
	}
	tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	let (client, server_side) = tokio::io::duplex(64 * 1024);
	feed.send(server_side).expect("feed");
	let name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = super::tests_auth::connector(cert)
		.connect(name, client)
		.await
		.expect("the slot is free again, so the handshake is served");
	let banner = super::tests_auth::reply(&mut tls).await;
	assert!(
		banner.starts_with("220 "),
		"admitted after failed handshakes"
	);
}

#[tokio::test]
async fn excessive_listener_cap_still_sends_the_smtp_greeting() {
	let (server, accept, mut clients) = server_with_caps(usize::MAX, 20);
	let task = spawn_serve(server, accept);
	let mut greeting = [0; 512];
	let n = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		clients[0].read(&mut greeting),
	)
	.await
	.expect("greeting deadline")
	.expect("greeting");
	assert!(String::from_utf8_lossy(&greeting[..n]).starts_with("220 "));
	task.abort();
}
