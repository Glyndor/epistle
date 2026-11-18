//! The DMARC journal the aggregate reports are built from records the
//! policy the evaluated record published, not placeholders.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::dmarc::report::DeliveryRecord;
use crate::smtp::sink::MemorySink;

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

/// SPF passes 192.0.2.7 for sender.example, which publishes
/// `p=quarantine; pct=30`; bank.example publishes `p=reject; sp=none;
/// pct=20`; every other name is empty.
struct PolicyDns;

impl crate::spf::DnsLookup for PolicyDns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let records = match name {
			"sender.example" => vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
			"_dmarc.sender.example" => vec!["v=DMARC1; p=quarantine; pct=30".to_string()],
			"_dmarc.bank.example" => vec!["v=DMARC1; p=reject; sp=none; pct=20".to_string()],
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

/// Deliver a message with `from` as its From field from eve@sender.example
/// to bob@example.org, journaling under `data_dir`; return the one record
/// the journal holds for `from_domain`.
async fn journal(data_dir: &std::path::Path, from: &str, from_domain: &str) -> DeliveryRecord {
	let sink = Arc::new(MemorySink::new());
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory)
		.with_spf(Arc::new(PolicyDns))
		.with_report_dir(data_dir.to_path_buf());
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let script = format!(
		"EHLO client.sender.example\r\nMAIL FROM:<eve@sender.example>\r\n\
		 RCPT TO:<bob@example.org>\r\nDATA\r\nFrom: {from}\r\nSubject: hi\r\n\r\nhello\r\n.\r\nQUIT\r\n"
	);
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(script.as_bytes()).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	let output = String::from_utf8(output).expect("ascii");
	assert!(output.contains("250 2.0.0"), "{output}");

	let days: Vec<_> = std::fs::read_dir(data_dir.join("dmarc-reports"))
		.expect("journal root")
		.flatten()
		.collect();
	assert_eq!(days.len(), 1, "one day directory");
	let file = days[0].path().join(format!("{from_domain}.jsonl"));
	let text = std::fs::read_to_string(&file).expect("journal file");
	let lines: Vec<&str> = text.lines().collect();
	assert_eq!(lines.len(), 1, "{text}");
	serde_json::from_str(lines[0]).expect("journal line")
}

#[tokio::test]
async fn the_journal_records_the_policy_of_the_from_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = journal(dir.path(), "eve@sender.example", "sender.example").await;
	assert_eq!(record.dmarc, "pass");
	assert_eq!(record.published_policy, "quarantine");
	assert_eq!(record.published_subdomain_policy, "quarantine");
	assert_eq!(record.pct, 30);
}

#[tokio::test]
async fn the_journal_records_both_policies_of_an_inherited_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = journal(dir.path(), "ceo@news.bank.example", "news.bank.example").await;
	// The organizational `sp=none` applied, so the message was accepted.
	assert_eq!(record.dmarc, "fail");
	assert_eq!(record.published_policy, "reject");
	assert_eq!(record.published_subdomain_policy, "none");
	assert_eq!(record.pct, 20);
}

#[tokio::test]
async fn without_a_record_nothing_is_journaled_as_published() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = journal(dir.path(), "eve@nowhere.example", "nowhere.example").await;
	assert_eq!(record.dmarc, "none");
	assert_eq!(record.published_policy, "");
	assert_eq!(record.published_subdomain_policy, "");
	assert_eq!(record.pct, 100);
}
