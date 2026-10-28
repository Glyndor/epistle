//! Reproduction tests for the SPF §4.6.4 shared-budget violation.
//!
//! When `check_host_inner` descends through `include:` or `redirect=`,
//! it must propagate the child's DNS-term and void counters back into the
//! caller's `Budget`. The earlier revisions handed the child a copy of
//! the parent budget and never copied the consumed counts back: a void
//! that happened inside an `include` vanished from the parent's budget,
//! so the third void across an `include` boundary stayed `Fail` instead
//! of `PermError`, and the eleventh `exists:` term inside an `include`
//! stopped tripping at the outer boundary.
//!
//! These tests pin the corrected behaviour. Each test is shaped so that
//! a regression to the copy-and-discard bug trips it immediately, and a
//! sabotage of the constant limits (the reviewer tried
//! `MAX_VOID_LOOKUPS = 1` and `MAX_DNS_MECHANISMS = 100` in a separate
//! harness) trips the boundary tests below it.
//!
//! The DNS mock returns empty addresses for every name. Empty addresses
//! are how `exists:` mechanisms contribute to the void counter (one
//! void per empty response), so the void tests are easy to drive.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

use super::*;

/// Scripted resolver: per-name TXT records. Addresses return empty
/// vectors so any `exists:` counts as a void lookup.
#[derive(Default)]
struct VoidDns {
	txt: HashMap<String, Vec<String>>,
}

impl DnsLookup for VoidDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = Ok(self.txt.get(name).cloned().unwrap_or_default());
		Box::pin(async move { result })
	}
	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		let result = Ok(Vec::<IpAddr>::new());
		Box::pin(async move { result })
	}
	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = Ok(Vec::<String>::new());
		Box::pin(async move { result })
	}
}

/// One void before the include, one inside it, one after it. The
/// shared budget must see all three voids and answer `PermError`. The
/// bug returned `Fail` because the parent's copy of the budget never
/// saw the include's void.
#[tokio::test]
async fn void_before_include_and_after_include_share_the_budget() {
	let mut dns = VoidDns::default();
	dns.txt.insert(
		"example.org".to_string(),
		vec![
			"v=spf1 exists:o1.example.org include:inc.example.org exists:o2.example.org -all"
				.to_string(),
		],
	);
	dns.txt.insert(
		"inc.example.org".to_string(),
		vec!["v=spf1 exists:a.example.org -all".to_string()],
	);
	let outcome = check_host(
		&dns,
		"192.0.2.1".parse().unwrap(),
		"example.org",
		"alice@example.org",
		"example.org",
	)
	.await;
	assert_eq!(
		outcome,
		SpfOutcome::PermError,
		"three voids across an include boundary must exhaust the §4.6.4 budget"
	);
}

/// A `redirect=` after an `include` shares the same budget. One void
/// before the include, one inside it, one inside the redirect: the
/// third void lives in the redirect and must trip the shared budget.
/// The outer record has no `-all` so the redirect is actually reached
/// after the include mechanism fails to match.
#[tokio::test]
async fn include_then_redirect_voids_share_one_budget() {
	let mut dns = VoidDns::default();
	dns.txt.insert(
		"example.org".to_string(),
		vec![
			"v=spf1 exists:o.example.org include:inc.example.org redirect=_r.example.org"
				.to_string(),
		],
	);
	dns.txt.insert(
		"inc.example.org".to_string(),
		vec!["v=spf1 exists:a.example.org -all".to_string()],
	);
	dns.txt.insert(
		"_r.example.org".to_string(),
		vec!["v=spf1 exists:r.example.org -all".to_string()],
	);
	let outcome = check_host(
		&dns,
		"192.0.2.1".parse().unwrap(),
		"example.org",
		"alice@example.org",
		"example.org",
	)
	.await;
	assert_eq!(
		outcome,
		SpfOutcome::PermError,
		"include + redirect voids share the §4.6.4 budget"
	);
}

/// Eleven `ptr:` terms inside one record must exhaust the
/// `MAX_DNS_MECHANISMS` budget and answer `PermError`. The `ptr:`
/// mechanism always evaluates to non-matching (RFC 7208 §5.5
/// deprecates reverse-DNS lookups) but it still draws budget, which is
/// exactly the property we want to pin: the loop runs through all
/// eleven before reaching the `consume` that fails.
#[tokio::test]
async fn the_eleventh_dns_term_in_a_single_record_is_permerror() {
	let mut dns = VoidDns::default();
	let mut record = String::from("v=spf1");
	for i in 0..11 {
		record.push_str(&format!(" ptr:ptr{i}.example.org"));
	}
	record.push_str(" -all");
	dns.txt.insert("example.org".to_string(), vec![record]);
	let outcome = check_host(
		&dns,
		"192.0.2.1".parse().unwrap(),
		"example.org",
		"alice@example.org",
		"example.org",
	)
	.await;
	assert_eq!(
		outcome,
		SpfOutcome::PermError,
		"the eleventh `ptr:` term must exhaust the §4.6.4 DNS budget"
	);
}

/// Ten `ptr:` terms in a single record stay within the budget. The
/// evaluation falls through to `-all` and answers `Fail`. A regression
/// that lowers the cap by 1 (or one that lowers the budget
/// propagation through `include`) trips this test.
#[tokio::test]
async fn the_tenth_dns_term_in_a_single_record_still_fails() {
	let mut dns = VoidDns::default();
	let mut record = String::from("v=spf1");
	for i in 0..10 {
		record.push_str(&format!(" ptr:ptr{i}.example.org"));
	}
	record.push_str(" -all");
	dns.txt.insert("example.org".to_string(), vec![record]);
	let outcome = check_host(
		&dns,
		"192.0.2.1".parse().unwrap(),
		"example.org",
		"alice@example.org",
		"example.org",
	)
	.await;
	assert_eq!(
		outcome,
		SpfOutcome::Fail,
		"ten `ptr:` terms are within tolerance; -all fails the evaluation"
	);
}

/// One void from the outer's `exists:`, one from the include's
/// `exists:`, then `-all`. Two voids total, within the §4.6.4
/// tolerance, so the include mechanism is what decides the result.
/// The include's `-all` fails, the include returns `Fail`, the outer
/// include mechanism does not match, the outer's `-all` fails.
#[tokio::test]
async fn two_voids_total_with_one_inside_the_include_still_fails() {
	let mut dns = VoidDns::default();
	dns.txt.insert(
		"example.org".to_string(),
		vec!["v=spf1 exists:o.example.org include:inc.example.org -all".to_string()],
	);
	dns.txt.insert(
		"inc.example.org".to_string(),
		vec!["v=spf1 exists:a.example.org -all".to_string()],
	);
	let outcome = check_host(
		&dns,
		"192.0.2.1".parse().unwrap(),
		"example.org",
		"alice@example.org",
		"example.org",
	)
	.await;
	assert_eq!(
		outcome,
		SpfOutcome::Fail,
		"two voids are within the §4.6.4 tolerance; -all in the include then -all in the outer fails the evaluation"
	);
}

/// Raising `MAX_DNS_MECHANISMS` to 100
/// would make this test return `Fail` instead of `PermError`, because
/// eleven terms would fit the loosened budget. The default budget is
/// `10`, and the test pins that boundary: eleven is one over. The
/// `ptr:` mechanism always evaluates to non-matching, so the loop
/// walks through every term before tripping the cap; the resolver never
/// runs.
#[tokio::test]
async fn eleven_dns_terms_trip_the_budget_in_isolation() {
	let mut dns = VoidDns::default();
	let mut record = String::from("v=spf1");
	for i in 0..11 {
		record.push_str(&format!(" ptr:ptr{i}.example.org"));
	}
	record.push_str(" -all");
	dns.txt.insert("example.org".to_string(), vec![record]);
	let outcome = check_host(
		&dns,
		"192.0.2.1".parse().unwrap(),
		"example.org",
		"alice@example.org",
		"example.org",
	)
	.await;
	assert_eq!(
		outcome,
		SpfOutcome::PermError,
		"the eleventh DNS term must exhaust the §4.6.4 cap"
	);
}

/// Lowering `MAX_VOID_LOOKUPS` to 1
/// would make a two-void record answer `PermError`, and a one-void
/// record answer `None`/`Neutral`. This test pins the two-void
/// tolerance: one void from the outer's `exists:`, one from an
/// `include`'s `exists:`, and no third.
#[tokio::test]
async fn two_voids_total_with_one_inside_the_include_stays_under_the_cap() {
	let mut dns = VoidDns::default();
	dns.txt.insert(
		"example.org".to_string(),
		vec!["v=spf1 exists:o.example.org include:inc.example.org".to_string()],
	);
	dns.txt.insert(
		"inc.example.org".to_string(),
		vec!["v=spf1 exists:a.example.org -all".to_string()],
	);
	let outcome = check_host(
		&dns,
		"192.0.2.1".parse().unwrap(),
		"example.org",
		"alice@example.org",
		"example.org",
	)
	.await;
	// Two voids are within the §4.6.4 tolerance; the include's
	// `-all` fails the include, the outer has no further mechanism
	// to match, so the result is the default `Neutral` per §4.7.
	assert_eq!(
		outcome,
		SpfOutcome::Neutral,
		"two voids are within tolerance; no outer mechanism matches"
	);
}

/// Inspect the returned budget because redirect terminates its caller.
#[tokio::test]
async fn redirect_alone_propagates_consumed_terms_and_voids() {
	let mut dns = VoidDns::default();
	dns.txt.insert(
		"example.org".into(),
		vec!["v=spf1 redirect=target.example.org".into()],
	);
	dns.txt.insert(
		"target.example.org".into(),
		vec!["v=spf1 exists:empty.example.org ptr:unused.example.org -all".into()],
	);
	let ctx = CheckContext {
		dns: &dns,
		ip: "192.0.2.1".parse().unwrap(),
		sender: "alice@example.org",
		helo: "example.org",
	};
	let mut budget = Budget::default();
	assert_eq!(
		check_host_inner(&ctx, "example.org", &mut budget).await,
		SpfOutcome::Fail
	);
	assert_eq!(budget.remaining, MAX_DNS_MECHANISMS - 3);
	assert_eq!(budget.voids, 1);
	assert_eq!(budget.depth, 0);
}
