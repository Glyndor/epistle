//! A peer in `[smtp] trusted_networks` skips the checks of the connecting
//! address and nothing else.

use super::*;

/// DNS that publishes an SPF record that refuses everyone for
/// `example.net` and lists the test client on `bl.example`.
struct StrictDns;

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for StrictDns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let records = if name == "example.net" {
			vec!["v=spf1 -all".to_string()]
		} else {
			Vec::new()
		};
		Box::pin(async move { Ok(records) })
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

fn strict(sink: &Arc<MemorySink>) -> crate::smtp::server::Server {
	server(sink, None)
		.with_spf(Arc::new(StrictDns))
		.with_dnsbl(crate::dnsbl::Dnsbl::new(["bl.example".to_string()]))
}

#[tokio::test]
async fn control_a_stranger_is_refused_by_the_blocklist() {
	let sink = Arc::new(MemorySink::new());
	let run = deliver_to(strict(&sink), &sink, &["bob@example.org"]).await;
	assert!(run.output.contains("554"), "{}", run.output);
	assert!(run.messages.is_empty());
}

fn trusted(server: crate::smtp::server::Server) -> crate::smtp::server::Server {
	server.with_inbound_policy(policy(TRUST_CLIENT))
}

#[tokio::test]
async fn a_trusted_relay_skips_the_blocklist_of_the_client_address() {
	let sink = Arc::new(MemorySink::new());
	let run = deliver_to(trusted(strict(&sink)), &sink, &["bob@example.org"]).await;
	assert!(
		!run.output.contains("DNS blocklist"),
		"the client's listing is not held against a relay: {}",
		run.output
	);
}

#[tokio::test]
async fn a_trusted_relay_skips_spf_dkim_and_dmarc_and_is_never_verified() {
	// Control: a stranger whose domain refuses everyone is refused by SPF.
	let sink = Arc::new(MemorySink::new());
	let server = server(&sink, None).with_spf(Arc::new(StrictDns));
	let refused = deliver_to(server, &sink, &["bob@example.org"]).await;
	assert!(refused.output.contains("550 5.7.23"), "{}", refused.output);
	// The same message from a relay is taken, with nothing claimed for it.
	let sink = Arc::new(MemorySink::new());
	let server = trusted(server_with_spf(&sink));
	let run = deliver_to(server, &sink, &["bob@example.org"]).await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
	let data = String::from_utf8_lossy(&run.messages[0].data);
	assert!(
		!data.contains("Received-SPF"),
		"a relay is not authenticated: {data}"
	);
	assert!(
		!run.messages[0].sender_verified,
		"and never marked verified"
	);
}

fn server_with_spf(sink: &Arc<MemorySink>) -> crate::smtp::server::Server {
	server(sink, None).with_spf(Arc::new(StrictDns))
}

#[tokio::test]
async fn a_trusted_relay_is_never_greylisted() {
	let sink = Arc::new(MemorySink::new());
	let server = trusted(server(&sink, None).with_greylist(greylist(), 600));
	let run = deliver_to(server, &sink, &["bob@example.org"]).await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
}

#[tokio::test]
async fn a_network_that_does_not_hold_the_client_trusts_nobody() {
	let sink = Arc::new(MemorySink::new());
	let elsewhere = policy("[smtp]\ntrusted_networks = [\"198.51.100.0/24\"]\n");
	let server = strict(&sink).with_inbound_policy(elsewhere);
	let run = deliver_to(server, &sink, &["bob@example.org"]).await;
	assert!(run.output.contains("554"), "{}", run.output);
}

#[tokio::test]
async fn a_trusted_relay_still_meets_the_sender_lists() {
	let sink = Arc::new(MemorySink::new());
	let lists = super::super::scopes::scopes("[antispam.senders]\ndeny = [\"example.net\"]\n");
	let server = server(&sink, Some(lists))
		.with_spf(dns(&[]))
		.with_inbound_policy(policy(TRUST_CLIENT));
	let run = deliver_to(server, &sink, &["bob@example.org"]).await;
	assert!(run.output.contains("550 5.7.1"), "{}", run.output);
	assert!(run.messages.is_empty());
}
