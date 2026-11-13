//! What `check_domain_for_role` expects of a domain that sends nothing or
//! accepts nothing: the null SPF, no DKIM key, the null MX.

use super::drift_duplicates::FakeDns;
use super::*;

const HOST: &str = "mail.example.org";

fn status(checks: &[Check], kind: &str) -> Status {
	checks
		.iter()
		.find(|c| c.kind == kind)
		.map(|c| c.status.clone())
		.unwrap_or_else(|| panic!("no {kind} check in {checks:?}"))
}

fn zone(spf: &str, mx: &str) -> FakeDns {
	let mut dns = FakeDns::default();
	dns.mx.insert("example.org".into(), vec![mx.into()]);
	dns.txt.insert("example.org".into(), vec![spf.into()]);
	dns
}

async fn check(role: DomainRole, dns: &FakeDns) -> Vec<Check> {
	check_domain_for_role("example.org", HOST, &["sel".to_string()], role, dns).await
}

#[tokio::test]
async fn the_dkim_key_of_a_domain_that_sends_nothing_is_skipped_not_missing() {
	let dns = zone("v=spf1 -all", HOST);
	for role in [DomainRole::ReceiveOnly, DomainRole::Disabled] {
		let checks = check(role, &dns).await;
		assert_eq!(status(&checks, "DKIM sel"), Status::Skipped, "{role:?}");
	}
	for role in [DomainRole::Full, DomainRole::SendOnly] {
		let checks = check(role, &dns).await;
		assert_eq!(status(&checks, "DKIM sel"), Status::Missing, "{role:?}");
	}
}

#[tokio::test]
async fn a_domain_that_sends_nothing_must_carry_the_null_spf() {
	let null = check(DomainRole::ReceiveOnly, &zone("v=spf1 -all", HOST)).await;
	assert_eq!(status(&null, "SPF"), Status::Ok);
	let stale = check(DomainRole::ReceiveOnly, &zone("v=spf1 mx -all", HOST)).await;
	assert_eq!(status(&stale, "SPF"), Status::Missing);
	let detail = &stale.iter().find(|c| c.kind == "SPF").unwrap().detail;
	assert!(detail.contains("expected v=spf1 -all"), "{detail}");
	// The same record is right for a domain that sends.
	let sends = check(DomainRole::Full, &zone("v=spf1 mx -all", HOST)).await;
	assert_eq!(status(&sends, "SPF"), Status::Ok);
}

#[tokio::test]
async fn a_switched_off_domain_must_carry_the_null_mx_and_nothing_else() {
	// The resolver trims the trailing dot, so the root name arrives empty.
	let null = check(DomainRole::Disabled, &zone("v=spf1 -all", "")).await;
	assert_eq!(status(&null, "MX"), Status::Ok);
	let host = check(DomainRole::Disabled, &zone("v=spf1 -all", HOST)).await;
	assert_eq!(status(&host, "MX"), Status::Missing);
	let mut both = zone("v=spf1 -all", "");
	both.mx
		.get_mut("example.org")
		.unwrap()
		.push(HOST.to_string());
	let both = check(DomainRole::Disabled, &both).await;
	assert_eq!(status(&both, "MX"), Status::Missing);
	let none = check(DomainRole::Disabled, &FakeDns::default()).await;
	assert_eq!(status(&none, "MX"), Status::Missing);
}

#[tokio::test]
async fn a_domain_that_receives_must_still_name_the_mail_host() {
	let host = check(DomainRole::ReceiveOnly, &zone("v=spf1 -all", HOST)).await;
	assert_eq!(status(&host, "MX"), Status::Ok);
	let null = check(DomainRole::ReceiveOnly, &zone("v=spf1 -all", "")).await;
	assert_eq!(status(&null, "MX"), Status::Missing);
}
