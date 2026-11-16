//! `[antispam_scope.checks]`: DKIM, ARC and the reverse DNS of the
//! connecting address, each `off`, `annotate` or `reject`. Only example data.

use std::collections::HashMap;
use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;
use crate::arc::chain::ChainValidation;
use crate::arc::sealer::ArcSealer;
use crate::dkim::canon;
use crate::dkim::signature::{Algorithm, Canon};
use crate::spf::{DnsFailure, DnsLookup};

type DnsFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

const PEER: &str = "192.0.2.7";
const SENDER: &str = "a@partner.example.net";
const REJECT_DKIM: &str =
	"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\ndkim = \"reject\"\n";

/// A resolver with fixed TXT, PTR and address answers; the names in
/// `broken` and the PTR of `ptr_broken` fail temporarily.
#[derive(Default)]
struct Dns {
	txt: HashMap<String, Vec<String>>,
	broken: Vec<String>,
	ptr: HashMap<IpAddr, Vec<String>>,
	ptr_broken: bool,
	addresses: HashMap<String, Vec<IpAddr>>,
}

impl DnsLookup for Dns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let result = if self.broken.iter().any(|broken| broken == name) {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.txt.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn addresses(&self, name: &str) -> DnsFuture<'_, Vec<IpAddr>> {
		let found = self.addresses.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(found) })
	}

	fn mx(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn ptr(&self, ip: IpAddr) -> DnsFuture<'_, Vec<String>> {
		let result = if self.ptr_broken {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.ptr.get(&ip).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}
}

/// A resolver whose reverse DNS of the peer names a host that resolves back.
fn confirmed_dns() -> Dns {
	let ip: IpAddr = PEER.parse().expect("ip");
	Dns {
		ptr: HashMap::from([(ip, vec!["mail.partner.example.net".to_string()])]),
		addresses: HashMap::from([("mail.partner.example.net".to_string(), vec![ip])]),
		..Dns::default()
	}
}

/// Deliver `data` to `recipients` through a server with `scopes` and `dns`.
async fn deliver(scopes: &str, dns: Dns, recipients: &[&str], data: &str) -> Run {
	let sink = Arc::new(MemorySink::new());
	let server = server(&sink, Some(super::scopes(scopes))).with_spf(Arc::new(dns));
	run(server, &sink, &script(SENDER, recipients, data)).await
}

async fn to_bob(scopes: &str, dns: Dns, data: &str) -> Run {
	deliver(scopes, dns, &["bob@example.org"], data).await
}

fn headers(run: &Run) -> String {
	assert_eq!(run.messages.len(), 1, "accepted once: {}", run.output);
	String::from_utf8_lossy(&run.messages[0].data).into_owned()
}

/// Whether `result` (`arc=pass`) is a method of the header, and not the tail
/// of another one (`dmarc=pass`). The header may fold before it.
fn has(headers: &str, result: &str) -> bool {
	headers.match_indices(result).any(|(at, _)| {
		!headers[..at]
			.chars()
			.next_back()
			.is_some_and(|before| before.is_ascii_alphanumeric())
	})
}

fn refused_with(run: &Run, line: &str) {
	assert!(run.output.contains(line), "{line:?} not in {}", run.output);
	assert!(run.messages.is_empty(), "a refused message is not stored");
}

fn scope(table: &str) -> String {
	format!("[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\n{table}\n")
}

/// `data` signed by `partner.example.net` with a good signature, and the
/// DNS that publishes its key.
fn signed(key: &Ed25519KeyPair, good_body_hash: bool) -> String {
	let body = b"hello\r\n";
	let hash = match good_body_hash {
		true => ring::digest::digest(&ring::digest::SHA256, &canon::body(Canon::Relaxed, body)),
		false => ring::digest::digest(&ring::digest::SHA256, b"another body"),
	};
	let from = format!(" {SENDER}");
	let value = format!(
		" v=1; a=ed25519-sha256; c=relaxed/relaxed; d=partner.example.net; s=sel; h=from; bh={}; b=",
		BASE64.encode(hash)
	);
	let mut input = canon::header(Canon::Relaxed, "From", &from);
	let mut line = canon::header(Canon::Relaxed, "DKIM-Signature", &value);
	line.truncate(line.len() - 2);
	input.push_str(&line);
	let signature = key.sign(
		Algorithm::Ed25519Sha256
			.signed_bytes(input.as_bytes())
			.as_ref(),
	);
	format!(
		"From:{from}\r\nTo: bob@example.org\r\nDKIM-Signature:{value}{}\r\n\r\nhello\r\n",
		BASE64.encode(signature.as_ref())
	)
}

fn key() -> (Ed25519KeyPair, Dns) {
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("key");
	let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load");
	let dns = Dns {
		txt: HashMap::from([(
			"sel._domainkey.partner.example.net".to_string(),
			vec![format!(
				"v=DKIM1; k=ed25519; p={}",
				BASE64.encode(key.public_key().as_ref())
			)],
		)]),
		..Dns::default()
	};
	(key, dns)
}

/// A message whose only signature has a body hash that does not match.
fn failing() -> (String, Dns) {
	let (key, dns) = key();
	(signed(&key, false), dns)
}

/// A signature that is good, but whose key the domain does not publish.
fn keyless() -> String {
	let (key, _) = key();
	signed(&key, true)
}

#[tokio::test]
async fn dkim_without_a_scope_off_and_annotate_never_refuse() {
	for scopes in [
		String::new(),
		scope("dkim = \"off\""),
		scope("dkim = \"annotate\""),
	] {
		let (data, dns) = failing();
		let run = to_bob(&scopes, dns, &data).await;
		assert!(headers(&run).contains("dkim=fail"), "{scopes}");
	}
}

#[tokio::test]
async fn dkim_reject_refuses_a_failed_signature_with_5_7_21() {
	let (data, dns) = failing();
	let run = to_bob(REJECT_DKIM, dns, &data).await;
	refused_with(
		&run,
		"550 5.7.21 DKIM validation failed for partner.example.net: no acceptable signature (result: fail)",
	);
}

#[tokio::test]
async fn dkim_reject_lets_a_good_signature_through() {
	let (key, dns) = key();
	let run = to_bob(REJECT_DKIM, dns, &signed(&key, true)).await;
	assert!(headers(&run).contains("dkim=pass"));
}

#[tokio::test]
async fn dkim_reject_never_refuses_a_sender_with_no_key_or_no_signature() {
	let unsigned = plain(SENDER);
	for data in [unsigned, keyless()] {
		let run = to_bob(REJECT_DKIM, Dns::default(), &data).await;
		assert_eq!(run.messages.len(), 1, "{}", run.output);
	}
}

#[tokio::test]
async fn dkim_reject_with_a_required_signature_refuses_both_with_5_7_20() {
	let scopes = scope("dkim = \"reject\"\ndkim_require_signature = true");
	for data in [plain(SENDER), keyless()] {
		let run = to_bob(&scopes, Dns::default(), &data).await;
		assert!(
			run.output
				.contains("550 5.7.20 no passing DKIM signature found for "),
			"{}",
			run.output
		);
		assert!(run.messages.is_empty());
	}
}

#[tokio::test]
async fn dkim_reject_defers_when_the_key_lookup_fails() {
	let dns = Dns {
		broken: vec!["sel._domainkey.partner.example.net".to_string()],
		..Dns::default()
	};
	let run = to_bob(REJECT_DKIM, dns, &keyless()).await;
	refused_with(
		&run,
		"451 4.7.20 DKIM check temporarily failed for partner.example.net (result: temperror)",
	);
}

/// A message sealed by a forwarder, and the DNS that publishes its key.
fn sealed() -> (String, Dns) {
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("key");
	let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load");
	let record = format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	let message = plain(SENDER);
	let headers = ArcSealer::new(key, "fwd.example.net", "arc1")
		.seal(message.as_bytes(), "spf=pass", &[], ChainValidation::None)
		.expect("sealed");
	let dns = Dns {
		txt: HashMap::from([("arc1._domainkey.fwd.example.net".to_string(), vec![record])]),
		..Dns::default()
	};
	(format!("{headers}{message}"), dns)
}

/// A chain that cannot be read: one seal and nothing else.
fn broken_chain() -> String {
	format!(
		"ARC-Seal: i=1; a=ed25519-sha256; cv=none; d=fwd.example.net; s=arc1; b=AAAA\r\n{}",
		plain(SENDER)
	)
}

#[tokio::test]
async fn arc_is_not_looked_at_without_a_scope_or_when_off() {
	for scopes in [String::new(), scope("arc = \"off\"")] {
		let run = to_bob(&scopes, Dns::default(), &broken_chain()).await;
		assert!(!has(&headers(&run), "arc="), "{scopes}");
	}
}

#[tokio::test]
async fn arc_annotate_records_the_result_and_never_refuses() {
	let run = to_bob(
		&scope("arc = \"annotate\""),
		Dns::default(),
		&broken_chain(),
	)
	.await;
	assert!(has(&headers(&run), "arc=fail"));
}

#[tokio::test]
async fn arc_reject_refuses_a_broken_chain_with_5_7_29() {
	let run = to_bob(&scope("arc = \"reject\""), Dns::default(), &broken_chain()).await;
	refused_with(
		&run,
		"550 5.7.29 ARC validation failed: the chain of the message is broken (result: fail)",
	);
}

#[tokio::test]
async fn arc_reject_accepts_no_chain_and_a_good_chain() {
	let scopes = scope("arc = \"reject\"");
	let run = to_bob(&scopes, Dns::default(), &plain(SENDER)).await;
	assert!(has(&headers(&run), "arc=none"));
	let (data, dns) = sealed();
	let run = to_bob(&scopes, dns, &data).await;
	assert!(has(&headers(&run), "arc=pass"));
}

#[tokio::test]
async fn arc_reject_defers_when_the_key_lookup_fails() {
	let (data, mut dns) = sealed();
	dns.broken = vec!["arc1._domainkey.fwd.example.net".to_string()];
	let run = to_bob(&scope("arc = \"reject\""), dns, &data).await;
	refused_with(
		&run,
		"451 4.7.29 ARC check temporarily failed (result: temperror)",
	);
}

#[tokio::test]
async fn reverse_dns_is_not_looked_up_without_a_scope_or_when_off() {
	for scopes in [String::new(), scope("reverse_dns = \"off\"")] {
		let run = to_bob(&scopes, Dns::default(), &plain(SENDER)).await;
		assert!(!headers(&run).contains("iprev="), "{scopes}");
	}
}

#[tokio::test]
async fn reverse_dns_annotate_records_the_result_and_never_refuses() {
	let scopes = scope("reverse_dns = \"annotate\"");
	let run = to_bob(&scopes, Dns::default(), &plain(SENDER)).await;
	assert!(headers(&run).contains("iprev=none policy.iprev=192.0.2.7"));
	let run = to_bob(&scopes, confirmed_dns(), &plain(SENDER)).await;
	assert!(headers(&run).contains("iprev=pass policy.iprev=192.0.2.7"));
}

#[tokio::test]
async fn reverse_dns_reject_refuses_a_missing_or_unconfirmed_name_with_5_7_25() {
	let scopes = scope("reverse_dns = \"reject\"");
	let ip: IpAddr = PEER.parse().expect("ip");
	let unconfirmed = Dns {
		ptr: HashMap::from([(ip, vec!["mail.partner.example.net".to_string()])]),
		addresses: HashMap::from([(
			"mail.partner.example.net".to_string(),
			vec!["198.51.100.1".parse().expect("ip")],
		)]),
		..Dns::default()
	};
	for dns in [Dns::default(), unconfirmed] {
		let run = to_bob(&scopes, dns, &plain(SENDER)).await;
		refused_with(
			&run,
			"550 5.7.25 reverse DNS validation failed for 192.0.2.7 (result: fail)",
		);
	}
	let run = to_bob(&scopes, confirmed_dns(), &plain(SENDER)).await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
}

#[tokio::test]
async fn reverse_dns_reject_defers_when_the_lookup_fails() {
	let dns = Dns {
		ptr_broken: true,
		..Dns::default()
	};
	let run = to_bob(&scope("reverse_dns = \"reject\""), dns, &plain(SENDER)).await;
	refused_with(
		&run,
		"451 4.7.25 reverse DNS check temporarily failed for 192.0.2.7 (result: temperror)",
	);
}

#[tokio::test]
async fn one_domain_refusing_changes_nothing_for_another() {
	let (data, dns) = failing();
	let run = deliver(REJECT_DKIM, dns, &["carol@example.com"], &data).await;
	assert!(headers(&run).contains("dkim=fail"));
}

#[tokio::test]
async fn the_account_scope_wins_over_the_domain_and_the_strictest_recipient_decides() {
	let scopes = format!(
		"{REJECT_DKIM}[[antispam_scope]]\naccount = \"alice\"\n[antispam_scope.checks]\ndkim = \"annotate\"\n"
	);
	let (data, dns) = failing();
	let run = deliver(&scopes, dns, &["alice@example.org"], &data).await;
	assert!(headers(&run).contains("dkim=fail"), "alice opted out");
	let (data, dns) = failing();
	let run = deliver(
		&scopes,
		dns,
		&["alice@example.org", "bob@example.org"],
		&data,
	)
	.await;
	assert!(
		run.output.contains("550 5.7.21"),
		"bob's domain refuses it: {}",
		run.output
	);
}

#[tokio::test]
async fn a_mapped_ipv4_peer_is_checked_as_its_ipv4_address() {
	use crate::smtp::server::run_checks::{Iprev, iprev};
	let mapped: IpAddr = "::ffff:192.0.2.7".parse().expect("ip");
	assert_eq!(iprev(&confirmed_dns(), mapped).await, Iprev::Pass);
	assert_eq!(iprev(&Dns::default(), mapped).await, Iprev::None);
}
