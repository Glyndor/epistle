//! The worker journals one TLS-RPT session per direct MX delivery attempt.

use std::net::{IpAddr, Ipv4Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;

use super::*;
use crate::queue::resolver::{BoxedStream, ConnectFuture, Connection};
use crate::smtp::session::AcceptedMessage;

/// 2024-01-01T12:00:00Z, so the journal lands under `20240101`.
const NOW: u64 = 1_704_110_400;
const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

/// What the fake exchanger does after the greeting.
#[derive(Clone, Copy)]
enum Remote {
	/// Offers STARTTLS with a self-signed certificate (no public root).
	SelfSignedStartTls,
	/// The in-process SMTP server with no TLS: STARTTLS is not offered.
	Plaintext,
}

struct FakeMx(Remote);

impl Connector for FakeMx {
	fn connect(&self, _domain: &str, _policy: Option<&crate::mtasts::Policy>) -> ConnectFuture<'_> {
		let remote = self.0;
		Box::pin(async move {
			let (client, server) = tokio::io::duplex(64 * 1024);
			match remote {
				Remote::SelfSignedStartTls => {
					tokio::spawn(self_signed_mta(server));
				}
				Remote::Plaintext => {
					let directory = crate::directory_store::DirectoryHandle::new(
						crate::smtp::directory::Directory::new(
							["remote.example".to_string()],
							[("bob@remote.example".to_string(), "bob".to_string())],
						),
					);
					let sink = Arc::new(crate::smtp::sink::MemorySink::new());
					let smtp = crate::smtp::server::Server::new("mx.remote.example", sink)
						.with_directory(directory);
					tokio::spawn(async move { smtp.handle(server, None).await });
				}
			}
			Ok(Connection {
				stream: Box::new(client) as BoxedStream,
				host: "mx.remote.example".to_string(),
				local_ip: Some(LOCAL),
				peer_ip: Some(PEER),
				mx: crate::queue::resolver::MxSecurity::Secure,
			})
		})
	}
}

async fn read_line(stream: &mut tokio::io::DuplexStream) {
	let mut byte = [0u8; 1];
	let mut last = 0u8;
	while stream.read_exact(&mut byte).await.is_ok() {
		if last == b'\r' && byte[0] == b'\n' {
			return;
		}
		last = byte[0];
	}
}

/// Greet, offer STARTTLS, and present a self-signed certificate.
async fn self_signed_mta(mut stream: tokio::io::DuplexStream) {
	crate::tls::ensure_crypto_provider();
	let certified = rcgen::generate_simple_self_signed(vec!["mx.remote.example".to_string()])
		.expect("certificate");
	let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).expect("key");
	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![certified.cert.der().clone()], key)
		.expect("server config");
	let _ = stream.write_all(b"220 mx.remote.example ESMTP\r\n").await;
	read_line(&mut stream).await;
	let _ = stream
		.write_all(b"250-mx.remote.example\r\n250 STARTTLS\r\n")
		.await;
	read_line(&mut stream).await;
	let _ = stream.write_all(b"220 go ahead\r\n").await;
	let _ = TlsAcceptor::from(Arc::new(config)).accept(stream).await;
}

/// Run one pass delivering to bob@remote.example and return the journal
/// lines recorded for remote.example that day.
async fn journal_after_one_pass(remote: Remote) -> Vec<serde_json::Value> {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(&AcceptedMessage {
			reverse_path: "alice@sender.example".into(),
			recipients: vec!["bob@remote.example".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("store");
	let worker =
		Worker::new(spool, Arc::new(FakeMx(remote)), "mail.sender.example").with_tlsrpt(dir.path());
	worker.set_now(NOW);
	worker.pass().await.expect("pass");
	let path = dir
		.path()
		.join("reports/tlsrpt-outbound/20240101/remote.example.jsonl");
	std::fs::read_to_string(path)
		.unwrap_or_default()
		.lines()
		.map(|line| serde_json::from_str(line).expect("json line"))
		.collect()
}

#[tokio::test]
async fn certificate_validation_failure_is_recorded_with_its_result_type() {
	let journal = journal_after_one_pass(Remote::SelfSignedStartTls).await;
	assert_eq!(journal.len(), 1, "one session per attempt");
	let session = &journal[0];
	assert_eq!(session["result"], "certificate-not-trusted");
	assert_eq!(session["policy_type"], "no-policy-found");
	assert_eq!(session["policy_domain"], "remote.example");
	assert_eq!(session["receiving_mx_hostname"], "mx.remote.example");
	assert_eq!(session["sending_mta_ip"], "203.0.113.5");
	assert_eq!(session["receiving_ip"], "198.51.100.7");
	assert_eq!(session["timestamp"], NOW);
}

#[tokio::test]
async fn missing_starttls_is_recorded_even_when_the_mail_goes_through() {
	let journal = journal_after_one_pass(Remote::Plaintext).await;
	assert_eq!(journal.len(), 1, "one session per attempt");
	assert_eq!(journal[0]["result"], "starttls-not-supported");
}
