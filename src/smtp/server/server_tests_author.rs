//! Inbound DMARC against the From field a reader sees (RFC 7489 section
//! 6.6.1): a message with two From fields fails, and an address tucked in
//! a comment does not stand in for the author.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

/// SPF passes 192.0.2.7 for sender.example; bank.example publishes
/// `p=reject`; every other name is empty.
struct BankDns;

impl crate::spf::DnsLookup for BankDns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let records = match name {
			"sender.example" => vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
			"_dmarc.bank.example" => vec!["v=DMARC1; p=reject".to_string()],
			_ => Vec::new(),
		};
		Box::pin(async move { Ok(records) })
	}

	fn addresses(&self, _name: &str) -> DnsFuture<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// Deliver `headers` from eve@sender.example to bob@example.org; return
/// the server output and the stored messages.
async fn receive(headers: &str) -> (String, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory)
		.with_spf(Arc::new(BankDns));
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let script = format!(
		"EHLO client.sender.example\r\nMAIL FROM:<eve@sender.example>\r\n\
		 RCPT TO:<bob@example.org>\r\nDATA\r\n{headers}Subject: hi\r\n\r\nhello\r\n.\r\nQUIT\r\n"
	);
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(script.as_bytes()).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	(String::from_utf8(output).expect("ascii"), sink)
}

fn stored(sink: &MemorySink) -> String {
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	String::from_utf8(messages[0].data.clone()).expect("ascii")
}

#[tokio::test]
async fn two_from_fields_fail_dmarc() {
	let (output, sink) = receive("From: eve@sender.example\r\nFrom : ceo@bank.example\r\n").await;
	assert!(output.contains("250 2.0.0"), "{output}");
	let data = stored(&sink);
	assert!(data.contains("\tdmarc=fail\r\n"), "{data}");
}

#[tokio::test]
async fn an_address_in_a_comment_does_not_dodge_the_author_policy() {
	let (output, sink) = receive("From: ceo@bank.example (eve@sender.example)\r\n").await;
	assert!(
		output.contains("550 5.7.1 rejected by DMARC policy"),
		"{output}"
	);
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn the_author_domain_is_recorded() {
	let (_, sink) = receive("From: Eve <eve@sender.example>\r\n").await;
	let data = stored(&sink);
	assert!(
		data.contains("\tdmarc=none header.from=sender.example"),
		"{data}"
	);
}
