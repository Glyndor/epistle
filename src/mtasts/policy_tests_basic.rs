//! Parsing, basic discovery, and "first fetch + cache hit" coverage. The
//! caching semantics for refresh-failure, id-aware refetch, and the
//! no-cache-fallback path live in [`super::tests_cache`] and the
//! id-aware sibling next to it.

use super::*;
use std::collections::HashMap as Map;
use std::sync::atomic::{AtomicU32, Ordering};

const SAMPLE: &str = "version: STSv1\nmode: enforce\nmx: mx1.example.org\nmx: *.backup.example.org\nmax_age: 86400\n";

#[test]
fn parses_policy_and_matches_mx() {
	let policy = parse(SAMPLE).expect("valid policy");
	assert_eq!(policy.mode, Mode::Enforce);
	assert_eq!(policy.max_age, 86400);
	assert!(policy.permits_mx("mx1.example.org"));
	assert!(policy.permits_mx("MX1.EXAMPLE.ORG"));
	assert!(policy.permits_mx("a.backup.example.org"));
	assert!(!policy.permits_mx("deep.a.backup.example.org"));
	assert!(!policy.permits_mx("backup.example.org"));
	assert!(!policy.permits_mx("evil.example"));
}

#[test]
fn parses_crlf_and_ignores_unknown_keys() {
	let policy = parse(
		"version: STSv1\r\nmode: testing\r\nmx: a.example\r\nmax_age: 60\r\nfuture: x\r\n",
	)
	.expect("valid policy");
	assert_eq!(policy.mode, Mode::Testing);
}

#[test]
fn rejects_malformed_policies() {
	assert!(parse("mode: enforce\nmx: a.example\nmax_age: 60").is_err());
	assert!(parse("version: STSv1\nmx: a.example\nmax_age: 60").is_err());
	assert!(parse("version: STSv1\nmode: enforce\nmax_age: 60").is_err());
	assert!(parse("version: STSv1\nmode: enforce\nmx: a.example").is_err());
	assert!(parse("version: STSv1\nmode: bogus\nmx: a.example\nmax_age: 1").is_err());
	assert!(parse("version: STSv1\nmode: enforce\nmx: a.example\nmax_age: x").is_err());
	assert!(parse("not a policy").is_err());
}

#[test]
fn mode_none_needs_no_mx() {
	let policy = parse("version: STSv1\nmode: none\nmax_age: 60").expect("valid");
	assert_eq!(policy.mode, Mode::None);
}

struct FakeDns {
	txt: Map<String, Vec<String>>,
}

impl DnsLookup for FakeDns {
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
	) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>>
	{
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

struct CountingFetcher {
	calls: std::sync::Arc<AtomicU32>,
}

impl PolicyFetcher for CountingFetcher {
	fn fetch(&self, _domain: &str) -> FetchFuture<'_> {
		self.calls.fetch_add(1, Ordering::Relaxed);
		Box::pin(async { Ok(SAMPLE.to_string()) })
	}
}

#[tokio::test]
async fn discovery_fetch_and_cache() {
	let mut txt = Map::new();
	txt.insert(
		"_mta-sts.example.org".to_string(),
		vec!["v=STSv1; id=2026a".to_string()],
	);
	let dns = FakeDns { txt };
	let calls = std::sync::Arc::new(AtomicU32::new(0));
	let store = PolicyStore::new(Box::new(CountingFetcher {
		calls: calls.clone(),
	}));

	let policy = store
		.policy(&dns, "example.org")
		.await
		.expect("ok")
		.expect("policy");
	assert_eq!(policy.mode, Mode::Enforce);

	// Second lookup (case-insensitive) is served from the cache.
	let _ = store.policy(&dns, "EXAMPLE.org").await.expect("ok");
	assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn no_txt_record_means_no_policy() {
	let dns = FakeDns { txt: Map::new() };
	let store = PolicyStore::new(Box::new(CountingFetcher {
		calls: std::sync::Arc::new(AtomicU32::new(0)),
	}));
	let policy = store.policy(&dns, "example.org").await.expect("ok");
	assert!(policy.is_none());
}

struct FailingFetcher;
impl PolicyFetcher for FailingFetcher {
	fn fetch(&self, _domain: &str) -> FetchFuture<'_> {
		Box::pin(async { Err(PolicyError::Temporary("unreachable".into())) })
	}
}

/// A DnsLookup whose TXT query always fails temporarily.
struct TempFailDns;
impl DnsLookup for TempFailDns {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Err(DnsFailure::Temporary) })
	}
	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>>
	{
		Box::pin(async { Ok(Vec::new()) })
	}
	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn txt_lookup_failure_is_temporary_error() {
	let store = PolicyStore::new(Box::new(CountingFetcher {
		calls: std::sync::Arc::new(AtomicU32::new(0)),
	}));
	let result = store.policy(&TempFailDns, "example.org").await;
	assert!(matches!(result, Err(PolicyError::Temporary(_))));
	// Exercise the unused resolver methods so the stub stays covered.
	assert!(TempFailDns.addresses("x").await.unwrap().is_empty());
	assert!(TempFailDns.mx("x").await.unwrap().is_empty());
}

#[tokio::test]
async fn fetch_failure_propagates() {
	let mut txt = Map::new();
	txt.insert(
		"_mta-sts.example.org".to_string(),
		vec!["v=STSv1; id=1".to_string()],
	);
	let dns = FakeDns { txt };
	let store = PolicyStore::new(Box::new(FailingFetcher));
	assert!(store.policy(&dns, "example.org").await.is_err());
}
