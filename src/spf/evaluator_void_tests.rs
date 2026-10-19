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
	// RFC 7208 §4.6.4 says two voids are tolerated. With the domain
	// returning an empty TXT (one void) and one `exists:` mechanism also
	// returning an empty A (a second void), the result must still be the
	// soft `None` outcome, not `permerror`.
	let dns = ScriptedDns::default();
	// no record → empty TXT → one void; the outer record is `None`.
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
	// regression while the void-lookup budget is added.
	let mut dns = ScriptedDns::default();
	let mut record = String::from("v=spf1");
	for i in 0..11 {
		record.push_str(&format!(" exists:void{i}.example.org"));
	}
	dns.txt.insert(
		"example.org".to_string(),
		vec![record, "v=spf1 -all".to_string()],
	);
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
