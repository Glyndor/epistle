//! A local NTS-KE stand-in, so the authenticated probe can be driven
//! without touching a public server.
//!
//! The server speaks the RFC 8915 record layer over a throwaway TLS 1.3
//! session with ALPN `ntske/1`: it reads the key exchange request,
//! answers with Next Protocol, AEAD Algorithm, eight cookies, an
//! optional Server and Port record, and End of Message. It then keeps
//! the connection open instead of closing it, which is the shape
//! `time.cloudflare.com` uses and the reason the third delivery was
//! sent back.
//!
//! Two properties are pinned here:
//!
//! 1. The key exchange does not need the peer to close the connection.
//!    The probe must reach its second leg, which is where the NTS-NTS
//!    datagram goes, and send the poll inside its budget.
//! 2. The deadline bounds the whole probe. A server that answers the
//!    key exchange after part of the budget leaves the authenticated
//!    exchange only what is left, not a fresh copy of the deadline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::clock::external::adapter::{ProbeError, ke_then_ntp_with_roots};
use crate::clock::external::source::Source;

/// Record type numbers from RFC 8915 section 6. The high bit marks a
/// critical record and is part of the type on the wire.
const RECORD_END_OF_MESSAGE: u16 = 0x8000;
const RECORD_NEXT_PROTOCOL: u16 = 0x8001;
const RECORD_AEAD_ALGORITHM: u16 = 0x8004;
const RECORD_NEW_COOKIE: u16 = 0x0005;
const RECORD_SERVER: u16 = 0x8006;
const RECORD_PORT: u16 = 0x8007;

/// AEAD_AES_SIV_CMAC_256, the id every public server picked over the
/// wire when we measured them.
const AEAD_AES_SIV_CMAC_256: u16 = 15;

const COOKIE_COUNT: usize = 8;
const COOKIE_LEN: usize = 96;
const COOKIE_SEED: u8 = 0x5a;

/// The four octets an End of Message record starts with: the type with
/// its critical bit, then a body length of zero.
const END_OF_MESSAGE_HEADER: [u8; 4] = [0x80, 0x00, 0x00, 0x00];

/// One NTS record: type, body length and body. RFC 8915 section 6 sizes
/// the record by its body alone, unlike the NTP extension field of
/// RFC 5905, which counts its own header.
fn record(kind: u16, body: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(body.len() + 4);
	out.extend_from_slice(&kind.to_be_bytes());
	out.extend_from_slice(&(body.len() as u16).to_be_bytes());
	out.extend_from_slice(body);
	out
}

fn response_bytes(server: Option<&str>, port: Option<u16>) -> Vec<u8> {
	let mut out = Vec::new();
	out.extend_from_slice(&record(RECORD_NEXT_PROTOCOL, &0u16.to_be_bytes()));
	out.extend_from_slice(&record(
		RECORD_AEAD_ALGORITHM,
		&AEAD_AES_SIV_CMAC_256.to_be_bytes(),
	));
	for index in 0..COOKIE_COUNT {
		let mut cookie = vec![COOKIE_SEED.wrapping_add(index as u8); COOKIE_LEN];
		cookie[0] = COOKIE_SEED;
		out.extend_from_slice(&record(RECORD_NEW_COOKIE, &cookie));
	}
	if let Some(name) = server {
		out.extend_from_slice(&record(RECORD_SERVER, name.as_bytes()));
	}
	if let Some(value) = port {
		out.extend_from_slice(&record(RECORD_PORT, &value.to_be_bytes()));
	}
	out.extend_from_slice(&record(RECORD_END_OF_MESSAGE, &[]));
	out
}

/// A loopback NTS-KE server that holds the connection open after the
/// response.
struct KeServer {
	addr: std::net::SocketAddr,
	root: CertificateDer<'static>,
	join: tokio::task::JoinHandle<()>,
}

async fn spawn_ke_server(answer_delay: Duration, server: &str, port: u16) -> KeServer {
	crate::tls::ensure_crypto_provider();
	let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
		.expect("generate certificate");
	let mut config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(
			vec![certified.cert.der().clone()],
			PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
				certified.signing_key.serialize_der(),
			)),
		)
		.expect("server config");
	config.alpn_protocols = vec![b"ntske/1".to_vec()];
	let acceptor = TlsAcceptor::from(Arc::new(config));
	let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
		.await
		.expect("loopback bind");
	let addr = listener.local_addr().expect("address");
	let payload = response_bytes(Some(server), Some(port));
	let join = tokio::spawn(async move {
		let (tcp, _) = match listener.accept().await {
			Ok(pair) => pair,
			Err(_) => return,
		};
		let mut tls = match acceptor.accept(tcp).await {
			Ok(stream) => stream,
			Err(_) => return,
		};
		let mut request: Vec<u8> = Vec::new();
		let mut chunk = vec![0u8; 256];
		for _ in 0..16 {
			match tls.read(&mut chunk).await {
				Ok(0) | Err(_) => break,
				Ok(n) => {
					request.extend_from_slice(&chunk[..n]);
					if request.windows(4).any(|w| w == END_OF_MESSAGE_HEADER) {
						break;
					}
				}
			}
		}
		if !request.windows(4).any(|w| w == END_OF_MESSAGE_HEADER) {
			return;
		}
		tokio::time::sleep(answer_delay).await;
		if tls.write_all(&payload).await.is_err() {
			return;
		}
		let _ = tls.flush().await;
		// Hold the session open well past any deadline the client sets.
		tokio::time::sleep(Duration::from_secs(30)).await;
	});
	KeServer {
		addr,
		root: certified.cert.der().clone(),
		join,
	}
}

impl KeServer {
	/// A source pointing at this stand-in. The NTS-KE port is the
	/// ephemeral one the listener landed on, never 4460.
	fn source(&self) -> Source {
		let mut source = Source::nts("localhost");
		source.port = Some(self.addr.port());
		source
	}
	fn shutdown(self) {
		self.join.abort();
	}
}

/// Bind a UDP socket that receives the NTS-NTS poll and never answers,
/// which is what a silent server looks like from here. The oneshot
/// fires as soon as the datagram lands, so a test can tell "the key
/// exchange finished and we sent the poll" from "the probe stalled in
/// the key exchange and never got that far".
async fn silent_udp_port() -> (u16, tokio::sync::oneshot::Receiver<usize>) {
	let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
		.await
		.expect("bind udp");
	let port = socket.local_addr().expect("address").port();
	let (tx, rx) = tokio::sync::oneshot::channel();
	tokio::spawn(async move {
		let mut buf = vec![0u8; 1024];
		if let Ok((n, _)) = socket.recv_from(&mut buf).await {
			let _ = tx.send(n);
		}
	});
	(port, rx)
}

/// The key exchange completes against a server that never closes the
/// connection: the probe reaches the NTS-NTS leg and sends the poll
/// inside the budget. A reader that waited for EOF or close_notify
/// would sit on the key exchange until the deadline expired and the
/// datagram would never arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_exchange_completes_when_the_server_keeps_the_connection_open() {
	const DEADLINE: Duration = Duration::from_millis(700);
	const TOLERANCE: Duration = Duration::from_millis(100);

	let (port, poll_seen) = silent_udp_port().await;
	let server = spawn_ke_server(Duration::from_millis(0), "127.0.0.1", port).await;
	let started = Instant::now();
	let result = ke_then_ntp_with_roots(
		&server.source(),
		DEADLINE,
		std::slice::from_ref(&server.root),
		true,
	)
	.await;
	let elapsed = started.elapsed();
	let observed = tokio::time::timeout(Duration::from_millis(200), poll_seen).await;
	server.shutdown();
	let observed = observed
		.expect("the probe must send its NTS-NTS poll inside the budget")
		.expect("the peer must have received the NTS-NTS poll");
	assert!(
		observed >= 48,
		"the datagram the peer saw must carry at least the NTP header; \
		 got {observed} bytes"
	);
	assert!(
		matches!(result, Err(ProbeError::Timeout)),
		"a peer that never answers the poll must surface as Timeout; got {result:?}"
	);
	assert!(
		elapsed <= DEADLINE + TOLERANCE,
		"the probe must stop at the deadline it was given, not later; \
		 elapsed={elapsed:?} budget={DEADLINE:?}"
	);
}

/// The deadline bounds the whole probe, not each stage of it. The
/// server answers the key exchange after 300 ms of a 700 ms budget; the
/// authenticated leg then meets a server that never answers. A probe
/// that re-armed the full deadline at every stage would spend 300 ms in
/// the key exchange and then another 700 ms waiting for the reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_deadline_bounds_the_whole_probe_not_each_stage() {
	const ANSWER_DELAY: Duration = Duration::from_millis(300);
	const DEADLINE: Duration = Duration::from_millis(700);
	const SLACK: Duration = Duration::from_millis(150);

	let (port, _poll_seen) = silent_udp_port().await;
	let server = spawn_ke_server(ANSWER_DELAY, "127.0.0.1", port).await;
	let started = Instant::now();
	let result = ke_then_ntp_with_roots(
		&server.source(),
		DEADLINE,
		std::slice::from_ref(&server.root),
		true,
	)
	.await;
	let elapsed = started.elapsed();
	server.shutdown();
	assert!(
		matches!(result, Err(ProbeError::Timeout)),
		"a silent NTS-NTS peer must surface as Timeout; got {result:?}"
	);
	assert!(
		elapsed <= DEADLINE + SLACK,
		"a {DEADLINE:?} deadline spent {ANSWER_DELAY:?} in the key \
		 exchange must still return inside the budget; elapsed={elapsed:?}"
	);
}
