//! SMTP-level tests for the domain & URL DNSBL screens.
//!
//! Lives in a sibling file because `server_tests.rs` is already close to the
//! 450-line ceiling and these tests bring their own scripted DNS stubs.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[
			("bob@example.org".to_string(), "bob".to_string()),
			("alice@example.org".to_string(), "alice".to_string()),
		],
	))
}

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

/// DNS stub that lists `sender.example` on the RHSBL zone.
struct DomainListingDns;

impl crate::spf::DnsLookup for DomainListingDns {
	fn txt(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(&self, name: &str) -> DnsFuture<'_, Vec<IpAddr>> {
		let listed = name == "sender.example.dnsbl.example";
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

/// DNS stub that lists `spam.example` on the URIBL zone.
struct UrlListingDns;

impl crate::spf::DnsLookup for UrlListingDns {
	fn txt(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(&self, name: &str) -> DnsFuture<'_, Vec<IpAddr>> {
		let listed = name == "spam.example.urlbl.example";
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

const URL_SCRIPT: &[u8] = b"EHLO c.example.org\r\n\
MAIL FROM:<eve@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
visit http://spam.example/offer for details\r\n\
.\r\n\
QUIT\r\n";

const PLAIN_SCRIPT: &[u8] = b"EHLO c.example.org\r\n\
MAIL FROM:<eve@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";

/// Same body as `URL_SCRIPT` but the envelope sender is the authenticated
/// account so MAIL FROM's ownership check (which would otherwise reject
/// `eve@sender.example` for an `alice@example.org` session) does not fire
/// before `screen_dnsbl` gets a chance to run.
const URL_AUTH_SCRIPT: &[u8] = b"EHLO c.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
visit http://spam.example/offer for details\r\n\
.\r\n\
QUIT\r\n";

async fn run_script(
	server: Server,
	peer: Option<IpAddr>,
	script: &[u8],
) -> (String, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server {
		sink: sink.clone(),
		..server
	};
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	(String::from_utf8(output).expect("ascii"), sink)
}

#[tokio::test]
async fn a_listed_sender_domain_is_refused() {
	let server = Server::new("mail.example.org", Arc::new(MemorySink::new()))
		.with_directory(directory())
		.with_spf(Arc::new(DomainListingDns))
		.with_dnsbl(
			crate::dnsbl::Dnsbl::default().with_domain_zones(["dnsbl.example".to_string()]),
		);
	let (output, sink) = run_script(server, None, PLAIN_SCRIPT).await;
	assert!(
		output.contains("554") && output.contains("sender domain"),
		"sender-domain reject not in reply: {output}"
	);
	assert!(sink.messages().is_empty(), "listed domain must not deliver");
}

#[tokio::test]
async fn a_listed_url_host_in_the_body_is_refused() {
	let server = Server::new("mail.example.org", Arc::new(MemorySink::new()))
		.with_directory(directory())
		.with_spf(Arc::new(UrlListingDns))
		.with_dnsbl(crate::dnsbl::Dnsbl::default().with_url_zones(["urlbl.example".to_string()]));
	let (output, sink) = run_script(server, None, URL_SCRIPT).await;
	assert!(
		output.contains("554") && output.contains("body links"),
		"url-host reject not in reply: {output}"
	);
	assert!(
		sink.messages().is_empty(),
		"listed URL host must not deliver"
	);
}

#[tokio::test]
async fn authenticated_mail_is_not_screened() {
	// Drive a session directly so we can mark it authenticated without going
	// through SASL. The screen gates on `session.authenticated() == None`, so
	// an authenticated session must let the same URL through.
	let server = Server::new("mail.example.org", Arc::new(MemorySink::new()))
		.with_directory(directory())
		.with_spf(Arc::new(UrlListingDns))
		.with_dnsbl(crate::dnsbl::Dnsbl::default().with_url_zones(["urlbl.example".to_string()]));
	let mut session = server.new_session();
	session.mark_authenticated_for_test("alice");
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task =
		tokio::spawn(async move { server.run(Box::new(server_stream), session, None).await });
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write
		.write_all(URL_AUTH_SCRIPT)
		.await
		.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	let output = String::from_utf8(output).expect("ascii");
	assert!(
		!(output.contains("554") && output.contains("body links")),
		"authenticated mail must not be URIBL-rejected: {output}"
	);
}
