//! Inbound trusted-replies fast path (plan 4.6): a sender known to any
//! local recipient account of the message skips greylisting and the
//! reputation first-time delay. The remaining inbound stack (DNSBL,
//! SPF, DKIM, DMARC, the scanner and the LLM band) keeps running.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::directory::Directory;
use crate::smtp::server::Server;
use crate::smtp::sink::MemorySink;

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

fn test_directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	))
}

/// Drive one scripted client conversation through a server built with
/// the supplied configuration helpers. The greylist is shared by
/// `with_greylist`; this helper does not wire one in by default so
/// the test that exercises the fast path can build the server itself.
async fn run_with(
	server: Arc<Server>,
	input: &[u8],
	peer: Option<std::net::IpAddr>,
) -> (String, Arc<MemorySink>) {
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(input).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	let output = String::from_utf8(output).expect("ascii");
	// The sink is held inside `Server`; for the assertions we just
	// return a placeholder; tests that need it pass a custom
	// `Arc<MemorySink>` through `Server::new`.
	(output, Arc::new(MemorySink::new()))
}

/// DNS stub listing 192.0.2.7 on `bl.example` so the DNSBL reject fires.
struct ListingDns;

impl crate::spf::DnsLookup for ListingDns {
	fn txt(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn addresses(&self, name: &str) -> DnsFuture<'_, Vec<std::net::IpAddr>> {
		let listed = name == "7.2.0.192.bl.example";
		Box::pin(async move {
			Ok(if listed {
				vec!["127.0.0.2".parse().expect("ip")]
			} else {
				Vec::new()
			})
		})
	}
	fn mx(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A fresh triplet from an unknown sender is greylisted (451). The
/// greylist is in-memory; a real MTA retries and is then accepted.
#[tokio::test]
async fn unknown_sender_is_greylisted() {
	let greylist = Arc::new(crate::antispam::greylist::MemoryGreylist::new());
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_greylist(Arc::clone(&greylist), 60),
	);

	let script = b"EHLO c.example.org\r\n\
MAIL FROM:<unknown@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
hi\r\n\
.\r\n\
QUIT\r\n";
	let peer = Some("203.0.113.7".parse().expect("ip"));
	let (output, _) = run_with(server, script, peer).await;
	assert!(
		output.contains("451") && output.contains("greylisted"),
		"unknown sender must be greylisted: {output}"
	);
}

/// A known correspondent (the recipient account has previously written
/// to the envelope sender) skips greylisting on the first attempt:
/// the message is accepted even though the greylist has never seen
/// the triplet before.
#[tokio::test]
async fn a_known_correspondent_skips_greylisting() {
	let dir = tempfile::tempdir().expect("tempdir");
	let correspondents =
		Arc::new(crate::storage::CorrespondentStore::open(dir.path()).expect("store"));
	// `bob` previously wrote to `correspondent@sender.example`.
	correspondents
		.record("bob", &["correspondent@sender.example"])
		.expect("seed marker");

	let greylist = Arc::new(crate::antispam::greylist::MemoryGreylist::new());
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_greylist(Arc::clone(&greylist), 60)
			.with_correspondents(Arc::clone(&correspondents)),
	);

	let script = b"EHLO c.example.org\r\n\
MAIL FROM:<correspondent@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
hi\r\n\
.\r\n\
QUIT\r\n";
	let peer = Some("203.0.113.7".parse().expect("ip"));
	let (output, _) = run_with(server, script, peer).await;
	assert!(
		!output.contains("451"),
		"known correspondent must not be greylisted: {output}"
	);
	assert!(output.contains("250"), "{output}");
}

/// The fast path skips *only* greylisting and the first-time delay.
/// DNSBL still runs: a known correspondent whose client IP is on a
/// blocklist is still refused with `554 DNS blocklist`, because a
/// known correspondent's account can itself be compromised.
#[tokio::test]
async fn a_known_correspondent_is_still_checked_by_dnsbl() {
	let dir = tempfile::tempdir().expect("tempdir");
	let correspondents =
		Arc::new(crate::storage::CorrespondentStore::open(dir.path()).expect("store"));
	correspondents
		.record("bob", &["correspondent@sender.example"])
		.expect("seed marker");

	let greylist = Arc::new(crate::antispam::greylist::MemoryGreylist::new());
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_spf(Arc::new(ListingDns))
			.with_dnsbl(crate::dnsbl::Dnsbl::new(["bl.example".to_string()]))
			.with_greylist(Arc::clone(&greylist), 60)
			.with_correspondents(Arc::clone(&correspondents)),
	);

	let script = b"EHLO c.example.org\r\n\
MAIL FROM:<correspondent@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
hi\r\n\
.\r\n\
QUIT\r\n";
	let (output, _) = run_with(server, script, Some("192.0.2.7".parse().expect("ip"))).await;
	assert!(
		output.contains("554") && output.contains("DNS blocklist"),
		"DNSBL must still refuse the listed IP, even for a known correspondent: {output}"
	);
}
