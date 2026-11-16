//! What an inbound refusal says: the address, the domain and the result
//! that were evaluated, the policy and the list that matched, and a
//! temporary SPF or DMARC error under `4.7.24` (RFC 7372), never `4.4.3`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

/// A resolver with a fixed set of TXT records and listed names. A TXT name
/// in `broken` fails temporarily.
#[derive(Default)]
pub(super) struct Dns {
	pub(super) txt: Vec<(&'static str, &'static str)>,
	pub(super) broken: Vec<&'static str>,
	pub(super) listed: Vec<&'static str>,
}

impl crate::spf::DnsLookup for Dns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let result = if self.broken.contains(&name) {
			Err(crate::spf::DnsFailure::Temporary)
		} else {
			Ok(self
				.txt
				.iter()
				.filter(|(owner, _)| *owner == name)
				.map(|(_, record)| (*record).to_string())
				.collect())
		};
		Box::pin(async move { result })
	}

	fn addresses(&self, name: &str) -> DnsFuture<'_, Vec<std::net::IpAddr>> {
		let listed = self.listed.contains(&name);
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

/// Deliver one message with the given `From` header and body from
/// `eve@sender.example` at 192.0.2.7 to the hosted bob@example.org, and
/// return the one refusal line the server answered at the end of DATA.
async fn refusal(dns: Dns, dnsbl: crate::dnsbl::Dnsbl, from: &str, body: &str) -> String {
	refusal_with(Setup::default(), dns, dnsbl, from, body).await
}

/// How the server under test is set: what a refusal says and whether it
/// carries a reference.
pub(super) struct Setup {
	pub(super) detail: crate::config::RefusalDetail,
	pub(super) reference: bool,
}

impl Default for Setup {
	fn default() -> Self {
		Self {
			detail: crate::config::RefusalDetail::Standard,
			reference: false,
		}
	}
}

/// [`refusal`] on a server set as `setup` says.
pub(super) async fn refusal_with(
	setup: Setup,
	dns: Dns,
	dnsbl: crate::dnsbl::Dnsbl,
	from: &str,
	body: &str,
) -> String {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(DirectoryHandle::new(Directory::new(
			["example.org".to_string()],
			[("bob@example.org".to_string(), "bob".to_string())],
		)))
		.with_spf(Arc::new(dns))
		.with_dnsbl(dnsbl)
		.with_refusal(setup.detail, setup.reference);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let script = format!(
		"EHLO client.example.org\r\nMAIL FROM:<eve@sender.example>\r\n\
		 RCPT TO:<bob@example.org>\r\nDATA\r\nFrom: {from}\r\nSubject: hi\r\n\r\n{body}\r\n.\r\nQUIT\r\n"
	);
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(script.as_bytes()).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	assert!(
		sink.messages().is_empty(),
		"a refused message is not stored"
	);
	let output = String::from_utf8(output).expect("ascii");
	let line = output
		.lines()
		.find(|line| line.starts_with("550") || line.starts_with("451") || line.starts_with("554"))
		.unwrap_or_else(|| panic!("no refusal in {output}"))
		.to_string();
	// Only what the sender supplied or its own check produced: nothing of
	// the hosted domain, its recipient or this server.
	for private in ["example.org", "bob", "mail."] {
		assert!(!line.contains(private), "{line} names {private}");
	}
	line
}

#[tokio::test]
async fn an_spf_failure_names_the_address_the_domain_and_the_result() {
	let dns = Dns {
		txt: vec![("sender.example", "v=spf1 -all")],
		..Dns::default()
	};
	let line = refusal(
		dns,
		crate::dnsbl::Dnsbl::default(),
		"eve@sender.example",
		"hi",
	)
	.await;
	assert_eq!(
		line,
		"550 5.7.23 SPF validation failed for 192.0.2.7 as sender of sender.example (result: fail)"
	);
}

#[tokio::test]
async fn a_temporary_spf_error_is_4_7_24_and_stays_temporary() {
	let dns = Dns {
		broken: vec!["sender.example"],
		..Dns::default()
	};
	let line = refusal(
		dns,
		crate::dnsbl::Dnsbl::default(),
		"eve@sender.example",
		"hi",
	)
	.await;
	assert_eq!(
		line,
		"451 4.7.24 SPF check temporarily failed for 192.0.2.7 as sender of sender.example (result: temperror)"
	);
}

#[tokio::test]
async fn a_dmarc_refusal_names_the_from_domain_the_policy_and_the_result() {
	let dns = Dns {
		txt: vec![
			("sender.example", "v=spf1 ip4:192.0.2.0/24 -all"),
			("_dmarc.bank.example", "v=DMARC1; p=reject"),
		],
		..Dns::default()
	};
	let line = refusal(
		dns,
		crate::dnsbl::Dnsbl::default(),
		"ceo@bank.example",
		"hi",
	)
	.await;
	assert_eq!(
		line,
		"550 5.7.1 rejected by DMARC policy of bank.example (p=reject, result: fail)"
	);
}

#[tokio::test]
async fn a_temporary_dmarc_error_is_4_7_24_and_stays_temporary() {
	let dns = Dns {
		txt: vec![("sender.example", "v=spf1 ip4:192.0.2.0/24 -all")],
		broken: vec!["_dmarc.bank.example"],
		..Dns::default()
	};
	let line = refusal(
		dns,
		crate::dnsbl::Dnsbl::default(),
		"ceo@bank.example",
		"hi",
	)
	.await;
	assert_eq!(
		line,
		"451 4.7.24 DMARC check temporarily failed for bank.example (result: temperror)"
	);
}

#[tokio::test]
async fn a_blocklisted_client_is_named_with_its_address_and_the_list() {
	let dns = Dns {
		listed: vec!["7.2.0.192.bl.example"],
		..Dns::default()
	};
	let dnsbl = crate::dnsbl::Dnsbl::new(["bl.example".to_string()]);
	let line = refusal(dns, dnsbl, "eve@sender.example", "hi").await;
	assert_eq!(
		line,
		"554 5.7.1 client host 192.0.2.7 blocked by DNS blocklist bl.example (result: listed)"
	);
}

#[tokio::test]
async fn a_blocklisted_sender_domain_is_named_with_the_list() {
	let dns = Dns {
		listed: vec!["sender.example.dbl.example"],
		..Dns::default()
	};
	let dnsbl = crate::dnsbl::Dnsbl::default().with_domain_zones(["dbl.example".to_string()]);
	let line = refusal(dns, dnsbl, "eve@sender.example", "hi").await;
	assert_eq!(
		line,
		"554 5.7.1 sender domain sender.example blocked by DNS blocklist dbl.example (result: listed)"
	);
}

#[tokio::test]
async fn a_blocklisted_link_names_the_list() {
	let dns = Dns {
		listed: vec!["spam.example.uri.example"],
		..Dns::default()
	};
	let dnsbl = crate::dnsbl::Dnsbl::default().with_url_zones(["uri.example".to_string()]);
	let line = refusal(
		dns,
		dnsbl,
		"eve@sender.example",
		"see http://spam.example/x",
	)
	.await;
	assert_eq!(
		line,
		"554 5.7.1 message body links blocked by DNS blocklist uri.example (result: listed)"
	);
}

#[tokio::test]
async fn a_zone_with_a_key_in_its_name_is_never_quoted_in_the_reply() {
	let dns = Dns {
		listed: vec![
			"7.2.0.192.abcd1234efgh5678.zen.dq.spamhaus.net",
			"sender.example.abcd1234efgh5678.dbl.dq.spamhaus.net",
			"spam.example.abcd1234efgh5678.dbl.dq.spamhaus.net",
		],
		..Dns::default()
	};
	let ip = crate::dnsbl::Dnsbl::new(["abcd1234efgh5678.zen.dq.spamhaus.net".to_string()]);
	let line = refusal(dns, ip, "eve@sender.example", "hi").await;
	assert_eq!(
		line,
		"554 5.7.1 client host 192.0.2.7 blocked by DNS blocklist spamhaus.net (result: listed)"
	);
	assert!(!line.contains("abcd1234efgh5678"), "{line}");

	let dns = Dns {
		listed: vec!["sender.example.abcd1234efgh5678.dbl.dq.spamhaus.net"],
		..Dns::default()
	};
	let domain = crate::dnsbl::Dnsbl::default()
		.with_domain_zones(["abcd1234efgh5678.dbl.dq.spamhaus.net".to_string()]);
	let line = refusal(dns, domain, "eve@sender.example", "hi").await;
	assert!(line.ends_with("blocked by DNS blocklist spamhaus.net (result: listed)"));
	assert!(!line.contains("abcd1234efgh5678"), "{line}");

	let dns = Dns {
		listed: vec!["spam.example.abcd1234efgh5678.dbl.dq.spamhaus.net"],
		..Dns::default()
	};
	let url = crate::dnsbl::Dnsbl::default()
		.with_url_zones(["abcd1234efgh5678.dbl.dq.spamhaus.net".to_string()]);
	let line = refusal(dns, url, "eve@sender.example", "see http://spam.example/x").await;
	assert!(line.ends_with("blocked by DNS blocklist spamhaus.net (result: listed)"));
	assert!(!line.contains("abcd1234efgh5678"), "{line}");
}

#[tokio::test]
async fn a_zone_without_a_public_name_is_a_dns_blocklist() {
	for zone in ["blocklist", "127.0.0"] {
		let name = format!("7.2.0.192.{zone}");
		let dns = Dns {
			listed: vec![Box::leak(name.into_boxed_str())],
			..Dns::default()
		};
		let dnsbl = crate::dnsbl::Dnsbl::new([zone.to_string()]);
		let line = refusal(dns, dnsbl, "eve@sender.example", "hi").await;
		assert_eq!(
			line,
			"554 5.7.1 client host 192.0.2.7 blocked by a DNS blocklist (result: listed)"
		);
	}
}
