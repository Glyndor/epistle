use super::*;
use std::collections::HashMap;
use std::pin::Pin;

/// Scripted resolver: maps of name → records.
#[derive(Default)]
struct FakeDns {
	txt: HashMap<String, Vec<String>>,
	addresses: HashMap<String, Vec<IpAddr>>,
	mx: HashMap<String, Vec<String>>,
	fail_txt: bool,
	fail_addresses: bool,
	fail_mx: bool,
}

impl DnsLookup for FakeDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail_txt {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.txt.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn addresses(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		let result = if self.fail_addresses {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.addresses.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn mx(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail_mx {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.mx.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}
}

fn dns_with(records: &[(&str, &str)]) -> FakeDns {
	let mut dns = FakeDns::default();
	for (name, record) in records {
		dns.txt
			.entry(name.to_string())
			.or_default()
			.push(record.to_string());
	}
	dns
}

fn ip(text: &str) -> IpAddr {
	text.parse().expect("ip")
}

async fn outcome(dns: &FakeDns, from_ip: &str, domain: &str) -> SpfOutcome {
	check_host(dns, ip(from_ip), domain, "test@example.org", "example.org").await
}

// ── Core SPF evaluation tests ──────────────────────────────────────────────

#[tokio::test]
async fn no_record_is_none() {
	let dns = FakeDns::default();
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::None
	);
}

#[tokio::test]
async fn ip4_match_passes_and_all_fails() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:192.0.2.0/24 -all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.99", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn ip6_match() {
	let dns = dns_with(&[("example.org", "v=spf1 ip6:2001:db8::/32 ~all")]);
	assert_eq!(
		outcome(&dns, "2001:db8::1", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "2001:db9::1", "example.org").await,
		SpfOutcome::SoftFail
	);
}

#[tokio::test]
async fn a_mechanism_resolves_the_domain() {
	let mut dns = dns_with(&[("example.org", "v=spf1 a -all")]);
	dns.addresses
		.insert("example.org".into(), vec![ip("192.0.2.10")]);
	assert_eq!(
		outcome(&dns, "192.0.2.10", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "192.0.2.11", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn mx_mechanism_resolves_exchangers() {
	let mut dns = dns_with(&[("example.org", "v=spf1 mx -all")]);
	dns.mx
		.insert("example.org".into(), vec!["mx.example.org".into()]);
	dns.addresses
		.insert("mx.example.org".into(), vec![ip("192.0.2.20")]);
	assert_eq!(
		outcome(&dns, "192.0.2.20", "example.org").await,
		SpfOutcome::Pass
	);
}

#[tokio::test]
async fn include_passes_through() {
	let dns = dns_with(&[
		("example.org", "v=spf1 include:_spf.example.org -all"),
		("_spf.example.org", "v=spf1 ip4:192.0.2.0/24 -all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.5", "example.org").await,
		SpfOutcome::Pass
	);
	// A fail inside the include does not match; outer -all decides.
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn include_of_missing_record_is_permerror() {
	let dns = dns_with(&[("example.org", "v=spf1 include:missing.example -all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn redirect_is_followed() {
	let dns = dns_with(&[
		("example.org", "v=spf1 redirect=_spf.example.org"),
		("_spf.example.org", "v=spf1 ip4:192.0.2.0/24 -all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.5", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn lookup_loop_hits_the_budget() {
	let dns = dns_with(&[
		("a.example", "v=spf1 include:b.example -all"),
		("b.example", "v=spf1 include:a.example -all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "a.example").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn malformed_record_is_permerror() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:notanip -all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn multiple_records_are_permerror() {
	let dns = dns_with(&[
		("example.org", "v=spf1 -all"),
		("example.org", "v=spf1 +all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn dns_failure_is_temperror() {
	let mut dns = dns_with(&[("example.org", "v=spf1 -all")]);
	dns.fail_txt = true;
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::TempError
	);
}

#[tokio::test]
async fn no_match_without_all_is_neutral() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:192.0.2.0/24")]);
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Neutral
	);
}

#[tokio::test]
async fn zero_prefix_matches_everything() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:0.0.0.0/0 -all")]);
	assert_eq!(
		outcome(&dns, "203.0.113.7", "example.org").await,
		SpfOutcome::Pass
	);
}

// ── exists: and ptr: mechanism tests ──────────────────────────────────────────

#[tokio::test]
async fn exists_matches_when_domain_has_an_a_record() {
	let mut dns = dns_with(&[("example.org", "v=spf1 exists:_spf.example.org -all")]);
	dns.addresses
		.insert("_spf.example.org".into(), vec![ip("192.0.2.1")]);
	assert_eq!(
		outcome(&dns, "198.51.100.7", "example.org").await,
		SpfOutcome::Pass
	);
}

#[tokio::test]
async fn exists_does_not_match_when_domain_is_empty() {
	let dns = dns_with(&[("example.org", "v=spf1 exists:_absent.example.org -all")]);
	assert_eq!(
		outcome(&dns, "198.51.100.7", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn ptr_does_not_match_and_falls_through() {
	let dns = dns_with(&[(
		"example.org",
		"v=spf1 ptr:example.org ip4:192.0.2.0/24 -all",
	)]);
	assert_eq!(
		outcome(&dns, "192.0.2.5", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "198.51.100.5", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn bare_ptr_does_not_match_and_falls_through() {
	let dns = dns_with(&[("example.org", "v=spf1 ptr ~all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.5", "example.org").await,
		SpfOutcome::SoftFail
	);
}

#[test]
fn outcome_keywords_cover_all_variants() {
	assert_eq!(SpfOutcome::None.as_str(), "none");
	assert_eq!(SpfOutcome::Neutral.as_str(), "neutral");
	assert_eq!(SpfOutcome::Pass.as_str(), "pass");
	assert_eq!(SpfOutcome::Fail.as_str(), "fail");
	assert_eq!(SpfOutcome::SoftFail.as_str(), "softfail");
	assert_eq!(SpfOutcome::TempError.as_str(), "temperror");
	assert_eq!(SpfOutcome::PermError.as_str(), "permerror");
}

#[tokio::test]
async fn ip4_mechanism_ignores_ipv6_connection() {
	// An ip4 directive cannot match an IPv6 client; evaluation falls to -all.
	let dns = dns_with(&[("example.org", "v=spf1 ip4:192.0.2.0/24 -all")]);
	assert_eq!(
		outcome(&dns, "2001:db8::1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn ip6_mechanism_ignores_ipv4_connection() {
	let dns = dns_with(&[("example.org", "v=spf1 ip6:2001:db8::/32 -all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn a_mechanism_dns_failure_is_temperror() {
	let mut dns = dns_with(&[("example.org", "v=spf1 a -all")]);
	dns.fail_addresses = true;
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::TempError
	);
}

#[tokio::test]
async fn mx_mechanism_dns_failure_is_temperror() {
	let mut dns = dns_with(&[("example.org", "v=spf1 mx -all")]);
	dns.fail_mx = true;
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::TempError
	);
}

#[tokio::test]
async fn mx_exchanger_address_failure_is_temperror() {
	let mut dns = dns_with(&[("example.org", "v=spf1 mx -all")]);
	dns.mx.insert(
		"example.org".to_string(),
		vec!["mail.example.org".to_string()],
	);
	dns.fail_addresses = true;
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::TempError
	);
}

#[tokio::test]
async fn exhausting_the_dns_budget_is_permerror() {
	// More than MAX_DNS_MECHANISMS (10) DNS-consuming `a` terms → permerror.
	let many_a = "v=spf1 a a a a a a a a a a a -all";
	let dns = dns_with(&[("example.org", many_a)]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::PermError
	);
}
