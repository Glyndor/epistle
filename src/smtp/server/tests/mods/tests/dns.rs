//! SMTP server tests that resolve SPF and DNSBL through a stubbed resolver.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

/// DNS stub serving one SPF TXT record for `sender.example`.
struct OneRecordDns {
	record: &'static str,
}

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for OneRecordDns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let result = if name == "sender.example" {
			vec![self.record.to_string()]
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

async fn converse_with_spf(record: &'static str) -> (String, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_spf(Arc::new(OneRecordDns { record }));

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });

	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<eve@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(script).await.expect("client write");
	client_write.shutdown().await.expect("client shutdown");
	let mut output = Vec::new();
	client_read
		.read_to_end(&mut output)
		.await
		.expect("client read");
	task.await.expect("task").expect("server result");
	(String::from_utf8(output).expect("ascii"), sink)
}

/// DNS stub that lists 192.0.2.7 on the `bl.example` blocklist.
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

#[tokio::test]
async fn dnsbl_listed_client_is_rejected() {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_spf(Arc::new(ListingDns))
		.with_dnsbl(crate::dnsbl::Dnsbl::new(["bl.example".to_string()]));

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });

	let script = b"EHLO c.example.org\r\n\
MAIL FROM:<eve@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
hi\r\n\
.\r\n\
QUIT\r\n";
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");

	let output = String::from_utf8(output).expect("ascii");
	assert!(
		output.contains("554") && output.contains("DNS blocklist"),
		"{output}"
	);
	assert!(sink.messages().is_empty(), "listed client must not deliver");
}

#[tokio::test]
async fn spf_fail_rejects_the_message() {
	let (output, sink) = converse_with_spf("v=spf1 -all").await;
	assert!(output.contains("550 5.7.23"), "{output}");
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn spf_pass_stamps_received_spf_header() {
	let (output, sink) = converse_with_spf("v=spf1 ip4:192.0.2.0/24 -all").await;
	assert!(!output.contains("550"), "{output}");
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
	assert!(
		data.contains("Received-SPF: pass (domain of sender.example) client-ip=192.0.2.7"),
		"{data}"
	);
}

#[tokio::test]
async fn unsigned_message_records_dkim_none() {
	let (_, sink) = converse_with_spf("v=spf1 ip4:192.0.2.0/24 -all").await;
	let data = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
	assert!(
		data.contains(
			"Authentication-Results: mail.example.org;\r\n\tspf=pass smtp.mailfrom=sender.example;\r\n\tdkim=none;\r\n\tdmarc="
		),
		"{data}"
	);
}

#[tokio::test]
async fn spf_softfail_is_accepted_and_recorded() {
	let (output, sink) = converse_with_spf("v=spf1 ~all").await;
	assert!(!output.contains("550"), "{output}");
	let data = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
	assert!(data.contains("Received-SPF: softfail"), "{data}");
}
