//! One ban store serves every listener: failed sign-ins on IMAP and on SMTP
//! submission are counted against the same client, and the ban they earn
//! together holds on both, even for the right password. Both listeners are real
//! sockets on one shared directory.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine;
use epistle::antispam::bans::{BanInfo, BanStore};
use epistle::directory_store::DirectoryHandle;
use epistle::smtp::server::{Server as SmtpServer, TlsMode};
use epistle::smtp::sink::MemorySink;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::harness::*;

/// The failures the store has seen, per subject. It bans a subject at the
/// default threshold of the real store (5, and 20 for an account), for an hour.
#[derive(Debug, Default)]
struct CountingStore {
	failures: Mutex<HashMap<String, u32>>,
}

type Future<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl BanStore for CountingStore {
	fn record_failure(&self, subject: &str, _protocol: &str, _now: u64) -> Future<'_, ()> {
		*self
			.failures
			.lock()
			.expect("failures")
			.entry(subject.to_string())
			.or_default() += 1;
		Box::pin(async {})
	}

	fn is_banned(&self, subject: &str, now: u64) -> Future<'_, Option<BanInfo>> {
		let limit = if subject.starts_with("account:") {
			20
		} else {
			5
		};
		let count = self
			.failures
			.lock()
			.expect("failures")
			.get(subject)
			.copied();
		Box::pin(async move {
			count.filter(|n| *n >= limit).map(|_| BanInfo {
				until_secs: now + 3600,
				reason: "test".to_string(),
			})
		})
	}

	fn clear_success(&self, subject: &str, _now: u64) -> Future<'_, ()> {
		// A success clears the account and the pair, never the client address.
		if !subject.starts_with("ip:") {
			self.failures.lock().expect("failures").remove(subject);
		}
		Box::pin(async {})
	}

	fn sweep(&self, _now: u64) -> Future<'_, ()> {
		Box::pin(async {})
	}

	fn remove_account(&self, _account: &str) -> Future<'_, ()> {
		Box::pin(async {})
	}
}

struct Listeners {
	imap: Harness,
	smtp: SocketAddr,
	connector: TlsConnector,
	_smtp_task: AbortOnDrop,
}

impl Listeners {
	async fn start() -> Self {
		let directory = DirectoryHandle::new(
			Harness::fixture_directory().with_ban_store(Arc::new(CountingStore::default())),
		);
		let imap = Harness::with_directory(directory.clone(), |s| s).await;
		let cert = rcgen::generate_simple_self_signed(vec!["mx.epistle.test".into()])
			.expect("self-signed certificate");
		let acceptor = epistle::tls::acceptor_from_pem(
			cert.cert.pem().as_bytes(),
			cert.signing_key.serialize_pem().as_bytes(),
		)
		.expect("TLS acceptor");
		let mut roots = RootCertStore::empty();
		roots
			.add(cert.cert.der().clone())
			.expect("trust certificate");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		let server = SmtpServer::new("mx.epistle.test", Arc::new(MemorySink::new()))
			.with_directory(directory)
			.with_tls(
				epistle::tls::ReloadableAcceptor::new(acceptor),
				TlsMode::Opportunistic,
			);
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind smtp");
		let smtp = listener.local_addr().expect("smtp address");
		let task = tokio::spawn(Arc::new(server).serve(listener));
		Self {
			imap,
			smtp,
			connector: TlsConnector::from(Arc::new(config)),
			_smtp_task: AbortOnDrop(task.abort_handle()),
		}
	}

	/// One LOGIN on a fresh IMAP connection; true when it signed in.
	async fn imap_login(&self, password: &str) -> bool {
		let mut client = self.imap.encrypted().await;
		send(
			&mut client,
			format!("L LOGIN tester {password}\r\n").as_bytes(),
		)
		.await;
		match line(&mut client).await.expect("LOGIN reply").as_deref() {
			Some("L OK LOGIN completed\r\n") => true,
			Some("L NO LOGIN failed\r\n") => false,
			other => panic!("unexpected LOGIN reply {other:?}"),
		}
	}

	/// One AUTH PLAIN on a fresh SMTP connection; true when it signed in.
	async fn smtp_login(&self, password: &str) -> bool {
		let mut tcp = TcpStream::connect(self.smtp).await.expect("connect smtp");
		smtp_expect(&mut tcp, "220 mx.epistle.test ESMTP ready\r\n").await;
		send(&mut tcp, b"EHLO client.remote.test\r\n").await;
		while !smtp_line(&mut tcp).await.starts_with("250 ") {}
		send(&mut tcp, b"STARTTLS\r\n").await;
		smtp_expect(&mut tcp, "220 ready to start TLS\r\n").await;
		let name = ServerName::try_from("mx.epistle.test").expect("server name");
		let mut tls = self.connector.connect(name, tcp).await.expect("TLS");
		send(&mut tls, b"EHLO client.remote.test\r\n").await;
		while !smtp_line(&mut tls).await.starts_with("250 ") {}
		let credentials =
			base64::engine::general_purpose::STANDARD.encode(format!("\0tester\0{password}"));
		send(&mut tls, format!("AUTH PLAIN {credentials}\r\n").as_bytes()).await;
		match smtp_line(&mut tls).await.as_str() {
			"235 2.7.0 authentication successful\r\n" => true,
			"535 5.7.8 authentication credentials invalid\r\n" => false,
			other => panic!("unexpected AUTH reply {other:?}"),
		}
	}
}

async fn smtp_line<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
	line(stream).await.expect("SMTP reply").expect("open")
}

async fn smtp_expect<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, expected: &str) {
	assert_eq!(smtp_line(stream).await, expected);
}

fn wrong() -> String {
	format!("{PASSWORD}-wrong")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failures_split_over_imap_and_smtp_add_up_to_one_ban_that_holds_on_both() {
	let listeners = Listeners::start().await;
	let wrong = wrong();
	for _ in 0..3 {
		assert!(!listeners.imap_login(&wrong).await);
	}
	for _ in 0..2 {
		assert!(!listeners.smtp_login(&wrong).await);
	}
	// Five failures from one client, none of them five on one listener.
	assert!(
		!listeners.imap_login(&PASSWORD).await,
		"IMAP signed in a client the two listeners together had banned"
	);
	assert!(
		!listeners.smtp_login(&PASSWORD).await,
		"SMTP signed in a client the two listeners together had banned"
	);
	listeners.imap.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_failure_short_of_the_threshold_is_not_a_ban() {
	let listeners = Listeners::start().await;
	let wrong = wrong();
	for _ in 0..3 {
		assert!(!listeners.imap_login(&wrong).await);
	}
	assert!(!listeners.smtp_login(&wrong).await);
	// Four failures: the same shape as above, and the right password signs in on both.
	assert!(listeners.imap_login(&PASSWORD).await);
	assert!(listeners.smtp_login(&PASSWORD).await);
}
