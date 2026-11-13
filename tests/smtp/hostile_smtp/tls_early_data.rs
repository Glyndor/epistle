//! 0-RTT data after `STARTTLS`. Early data can be replayed by anyone who
//! recorded it, and it would reach the SMTP parser before the session has
//! said a word, so the listener must never offer it: the tickets it hands
//! out carry no early data allowance, and a resumed session starts clean.
//!
//! The client here cannot send early data even when allowed (that needs a
//! feature of tokio-rustls this crate does not enable), so the check is on
//! what the server offers, which is the whole of the defence.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::{ClientSessionMemoryCache, ClientSessionStore};
use tokio_rustls::rustls::client::{Tls12ClientSessionValue, Tls13ClientSessionValue};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{HandshakeKind, NamedGroup};

use super::harness::*;
use super::tls::Tls;
use crate::common::TLS_PROBE_IO_TIMEOUT;

/// A session store that remembers the early data size of every ticket the
/// server issued, and otherwise behaves like the in-memory one.
#[derive(Debug)]
struct Recorder {
	inner: ClientSessionMemoryCache,
	/// Largest `max_early_data_size` among the tickets seen.
	allowance: AtomicU32,
	tickets: AtomicU32,
}

impl Recorder {
	fn new() -> Arc<Self> {
		Arc::new(Self {
			inner: ClientSessionMemoryCache::new(8),
			allowance: AtomicU32::new(0),
			tickets: AtomicU32::new(0),
		})
	}
}

impl ClientSessionStore for Recorder {
	fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
		self.inner.set_kx_hint(name, group);
	}
	fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
		self.inner.kx_hint(name)
	}
	fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
		self.inner.set_tls12_session(name, value);
	}
	fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
		self.inner.tls12_session(name)
	}
	fn remove_tls12_session(&self, name: &ServerName<'static>) {
		self.inner.remove_tls12_session(name);
	}
	fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
		self.tickets.fetch_add(1, Ordering::Relaxed);
		self.allowance
			.fetch_max(value.max_early_data_size(), Ordering::Relaxed);
		self.inner.insert_tls13_ticket(name, value);
	}
	fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
		self.inner.take_tls13_ticket(name)
	}
}

/// STARTTLS, then the handshake with `connector`.
async fn upgrade(
	server: &Harness,
	connector: &TlsConnector,
) -> tokio_rustls::client::TlsStream<TcpStream> {
	let mut tcp = server.connect().await;
	ehlo(&mut tcp).await;
	send(&mut tcp, b"STARTTLS\r\n").await;
	expect(&mut tcp, "220 ready to start TLS\r\n").await;
	let name = ServerName::try_from("mx.epistle.test").expect("server name");
	timeout(TLS_PROBE_IO_TIMEOUT, connector.connect(name, tcp))
		.await
		.expect("TLS deadline")
		.expect("TLS handshake")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumed_session_never_carries_early_data() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::start(|s| tls.server(s)).await;
	let store = Recorder::new();
	let connector = tls.resuming(store.clone());

	// A full handshake first, so the client holds a ticket to resume with.
	let mut first = upgrade(&server, &connector).await;
	ehlo(&mut first).await;
	quit(&mut first).await;
	assert!(
		store.tickets.load(Ordering::Relaxed) > 0,
		"the listener issued no ticket, so nothing was resumed"
	);
	assert_eq!(
		store.allowance.load(Ordering::Relaxed),
		0,
		"a ticket allows early data: a recorded 0-RTT command could be replayed"
	);

	// The client asks for 0-RTT whenever a ticket allows it. The resumed
	// session must be an ordinary one: no early data accepted, and the
	// listener answers the client's own EHLO first.
	let mut second = upgrade(&server, &connector).await;
	ehlo(&mut second).await;
	assert_eq!(
		second.get_ref().1.handshake_kind(),
		Some(HandshakeKind::Resumed),
		"the second handshake did not resume the first session"
	);
	assert!(
		!second.get_ref().1.is_early_data_accepted(),
		"the listener accepted 0-RTT data"
	);
	quit(&mut second).await;
	assert!(server.sink.messages().is_empty());
	server.healthy().await;
}
