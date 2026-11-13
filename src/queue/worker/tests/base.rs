//! Outbound queue worker tests.

use super::*;
use crate::queue::SuppressionList;
use crate::queue::resolver::{BoxedStream, ConnectFuture};
use crate::smtp::directory::Directory;
use crate::smtp::server::Server;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use std::collections::BTreeMap;

/// Connector that hands out duplex pipes served by an in-process server.
struct LoopbackConnector {
	sink: Arc<MemorySink>,
	/// Domains the fake remote server accepts mail for.
	domain: String,
}

impl Connector for LoopbackConnector {
	fn connect(&self, _domain: &str, _policy: Option<&crate::mtasts::Policy>) -> ConnectFuture<'_> {
		Box::pin(async move {
			let directory = crate::directory_store::DirectoryHandle::new(Directory::new(
				[self.domain.clone()],
				[(format!("bob@{}", self.domain), "bob".to_string())],
			));
			let server = Server::new(
				"mx.remote.example",
				self.sink.clone() as Arc<dyn MessageSink>,
			)
			.with_directory(directory);
			let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
			tokio::spawn(async move { server.handle(server_stream, None).await });
			Ok(crate::queue::resolver::Connection::new(
				Box::new(client_stream) as BoxedStream,
				"mx.remote.example".to_string(),
			)
			.with_mx(crate::queue::resolver::MxSecurity::Secure))
		})
	}
}

/// A resolver that publishes one (already DNSSEC-validated) TLSA record for
/// every `_25._tcp.<host>` query, simulating an MX with a DANE policy.
struct DaneDns {
	record: crate::dane::tlsa::TlsaRecord,
}

impl crate::spf::DnsLookup for DaneDns {
	fn txt(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>,
	> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, crate::spf::DnsFailure>> + Send + '_>,
	> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>,
	> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn tlsa(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<
			dyn Future<Output = Result<crate::dane::rrset::TlsaRrset, crate::spf::DnsFailure>>
				+ Send
				+ '_,
		>,
	> {
		let record = self.record.clone();
		Box::pin(async move { Ok(crate::dane::rrset::TlsaRrset::Usable(vec![record])) })
	}
}

/// A resolver whose TLSA lookup fails transiently (e.g. resolver timeout),
/// while every other query succeeds with no records. Models the case where a
/// host *may* publish DANE but the lookup cannot be completed right now.
struct TlsaTempFailDns;

impl crate::spf::DnsLookup for TlsaTempFailDns {
	fn txt(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>,
	> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, crate::spf::DnsFailure>> + Send + '_>,
	> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>,
	> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn tlsa(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<
			dyn Future<Output = Result<crate::dane::rrset::TlsaRrset, crate::spf::DnsFailure>>
				+ Send
				+ '_,
		>,
	> {
		Box::pin(async { Err(crate::spf::DnsFailure::Temporary) })
	}
}

/// Connector that always fails with a transient error.
pub(in super::super) struct DownConnector;

impl Connector for DownConnector {
	fn connect(&self, _domain: &str, _policy: Option<&crate::mtasts::Policy>) -> ConnectFuture<'_> {
		Box::pin(async { Err(DeliveryError::Transient("connection refused".into())) })
	}
}

fn spool_with_message(dir: &std::path::Path, recipient: &str) -> FsSpool {
	let spool = FsSpool::open(dir).expect("open spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec![recipient.to_string()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	spool
}

#[tokio::test]
async fn delivers_and_clears_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});

	let worker = Worker::new(spool, connector, "mail.sender.example");
	let delivered = worker.pass().await.expect("pass");

	assert_eq!(delivered, 1);
	assert!(worker.spool.list().expect("list").is_empty());
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(
		messages[0].recipients,
		vec!["bob@remote.example".to_string()]
	);
}

#[tokio::test]
async fn permanent_rejection_drops_and_bounces() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The loopback server only knows bob@; carol@ gets 550.
	let spool = spool_with_message(dir.path(), "carol@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});
	let bounce_sink = Arc::new(MemorySink::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());

	let worker = Worker::new(spool, connector, "mail.sender.example")
		.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>)
		.with_metrics(metrics.clone());
	let delivered = worker.pass().await.expect("pass");

	assert_eq!(delivered, 0);
	assert!(metrics.render().contains("mail_bounced_total 1\n"));
	// Dropped, not retried: the spool is empty and nothing arrived.
	assert!(worker.spool.list().expect("list").is_empty());
	assert!(sink.messages().is_empty());

	// The sender got a bounce with the null reverse-path.
	let bounces = bounce_sink.messages();
	assert_eq!(bounces.len(), 1);
	assert_eq!(bounces[0].reverse_path, "");
	assert_eq!(
		bounces[0].recipients,
		vec!["alice@sender.example".to_string()]
	);
	let body = String::from_utf8(bounces[0].data.clone()).expect("ascii");
	assert!(body.contains("carol@remote.example"), "{body}");
}

#[tokio::test]
async fn dane_present_but_no_starttls_defers_and_keeps_message() {
	// The loopback MX speaks plaintext (offers no STARTTLS). With a DANE policy
	// published for it, delivery must never downgrade: the message is deferred
	// (kept in the spool) and nothing is delivered (fail closed, RFC 7672).
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});
	// Any TLSA record makes STARTTLS mandatory for that MX.
	let record = crate::dane::tlsa::TlsaRecord::from_parts(3, 1, 1, vec![0u8; 32]).expect("record");
	let dns: Arc<dyn crate::spf::DnsLookup> = Arc::new(DaneDns { record });

	let worker = Worker::new(spool, connector, "mail.sender.example").with_dane(Arc::clone(&dns));
	let delivered = worker.pass().await.expect("pass");

	assert_eq!(delivered, 0);
	// Deferred, not dropped: the message stays in the spool for retry.
	assert_eq!(worker.spool.list().expect("list").len(), 1);
	// Nothing crossed the wire to the (plaintext) remote.
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn transient_tlsa_failure_defers_rather_than_downgrading() {
	// A host that may publish DANE, but the TLSA lookup fails transiently. The
	// worker must NOT treat that as "no DANE" and deliver over a (plaintext or
	// opportunistic) connection — that would be a silent downgrade. It must
	// defer (keep the message, deliver nothing) and retry later (RFC 7672 §2.1).
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});
	let dns: Arc<dyn crate::spf::DnsLookup> = Arc::new(TlsaTempFailDns);

	let worker = Worker::new(spool, connector, "mail.sender.example").with_dane(Arc::clone(&dns));
	let delivered = worker.pass().await.expect("pass");

	assert_eq!(delivered, 0);
	// Deferred for retry: the message is still in the spool.
	assert_eq!(worker.spool.list().expect("list").len(), 1);
	// Nothing was delivered over a connection that bypassed DANE.
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn without_dane_plaintext_mx_still_delivers() {
	// The same plaintext loopback MX, but no DANE policy: opportunistic TLS
	// applies and delivery succeeds (the regression guard for the DANE gate).
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});

	let worker = Worker::new(spool, connector, "mail.sender.example");
	assert_eq!(worker.pass().await.expect("pass"), 1);
	assert_eq!(sink.messages().len(), 1);
}

mod operator;

/// Creation epoch of the single spooled message, from its UUIDv7 id.
fn created_at(spool: &FsSpool) -> u64 {
	let id = spool.list().expect("list")[0];
	id.get_timestamp().expect("v7 timestamp").to_unix().0
}

mod expiry;
