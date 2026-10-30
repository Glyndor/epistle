//! Void-lookup budget tests (RFC 7208 §4.6.4). The default `MAX_VOID_LOOKUPS`
//! is 2; the third void lookup must turn the evaluation into `permerror`,
//! which the evaluator answers `permerror` for (vs the previous behaviour of
//! `none`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

use super::*;

#[derive(Default)]
struct EmptyDns;

impl DnsLookup for EmptyDns {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[derive(Default)]
struct ScriptedDns {
	txt: HashMap<String, Vec<String>>,
}

impl DnsLookup for ScriptedDns {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = Ok(self.txt.get(_name).cloned().unwrap_or_default());
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

#[tokio::test]
async fn two_void_lookups_remain_a_soft_none() {
	// RFC 7208 §4.6.4 says two voids are tolerated. Drive exactly two
	// voids (one empty A on the outer's `exists:`, one empty A on the
	// `exists:` inside the include) and confirm the evaluation does not
	// become `permerror`. The first revision of this test only had one
	// void (an empty TXT at the outer fetch) and therefore could not
	// distinguish the boundary from a single-void record.
	let mut dns = ScriptedDns::default();
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
	// Two voids are within tolerance; the include's `-all` fails the
	// include (so the include mechanism does not match), the outer's
	// `-all` then fails the evaluation.
	assert_eq!(
		outcome,
		SpfOutcome::Fail,
		"two voids are within §4.6.4 tolerance; -all fails the evaluation"
	);
}

#[tokio::test]
async fn three_void_lookups_become_permerror() {
	// Build a record that issues more than two void DNS lookups via the
	// `exists:` mechanism (which queries `dns.addresses`). The result
	// must be `permerror`.
	let mut dns = ScriptedDns::default();
	dns.txt.insert(
		"example.org".to_string(),
		vec![
			"v=spf1 exists:one.example.org exists:two.example.org exists:three.example.org -all"
				.to_string(),
		],
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
		"the third void lookup must force permerror per §4.6.4"
	);
}

#[tokio::test]
async fn the_tenth_lookup_beyond_budget_is_permerror_too() {
	// Even when the budget is exhausted on a non-void lookups path, the
	// legacy §4.6.4 limit (10 DNS-querying mechanisms) still applies and
	// returns `permerror`. This test protects the older limit from
	// regression while the void-lookup budget is added. The first
	// revision of this test shipped two `v=spf1` records, which trips
	// the duplicate-record check (§4.5) before the budget check ever
	// runs; the test was rewritten with a single record so the trip is
	// the budget itself.
	let mut dns = ScriptedDns::default();
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
	assert_eq!(outcome, SpfOutcome::PermError);
}

#[tokio::test]
async fn a_void_lookups_does_not_overflow_with_no_record() {
	// Sanity check: no TXT record means one void (the record fetch),
	// not three — and definitely not permerror.
	let dns = EmptyDns;
	assert_eq!(
		check_host(
			&dns,
			"192.0.2.1".parse().unwrap(),
			"example.org",
			"alice@example.org",
			"example.org",
		)
		.await,
		SpfOutcome::None
	);
}
