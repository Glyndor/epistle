//! A cached policy outlives a failed refresh until its max_age runs out
//! (RFC 8461 section 3.3 and 5.1): neither an unreachable policy host nor
//! a missing TXT record takes an enforce policy away early. RFC 8461
//! section 3.3 also requires refetching when the TXT id changes before
//! max_age runs out.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use super::*;

const ENFORCE: &str = "version: STSv1\nmode: enforce\nmx: mx.example.org\nmax_age: 604800\n";

/// What the next TXT lookup and policy fetch do.
const OK: u8 = 0;
const TXT_GONE: u8 = 1;
const TXT_TEMPFAIL: u8 = 2;
const FETCH_FAILS: u8 = 3;
/// TXT is published with a new policy id (different from the cached one).
const TXT_ID_B: u8 = 4;

struct World(Arc<AtomicU8>);

impl DnsLookup for World {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = match self.0.load(Ordering::Relaxed) {
			TXT_GONE => Ok(Vec::new()),
			TXT_TEMPFAIL => Err(DnsFailure::Temporary),
			TXT_ID_B => Ok(vec!["v=STSv1; id=2026b".to_string()]),
			_ => Ok(vec!["v=STSv1; id=1".to_string()]),
		};
		Box::pin(async move { result })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

struct Fetcher(Arc<AtomicU8>);

impl PolicyFetcher for Fetcher {
	fn fetch(&self, _domain: &str) -> FetchFuture<'_> {
		let result = match self.0.load(Ordering::Relaxed) {
			FETCH_FAILS => Err(PolicyError::Temporary("connection refused".into())),
			_ => Ok(ENFORCE.to_string()),
		};
		Box::pin(async move { result })
	}
}

/// A store holding a week-long enforce policy that is now due for refresh,
/// with the refresh failing the way `failure` says.
async fn after_failed_refresh(failure: u8) -> Result<Option<Policy>, PolicyError> {
	let state = Arc::new(AtomicU8::new(OK));
	let dns = World(Arc::clone(&state));
	let store = PolicyStore::new(Box::new(Fetcher(Arc::clone(&state))));
	let first = store
		.policy(&dns, "example.org")
		.await
		.expect("first fetch");
	assert_eq!(first.map(|policy| policy.mode), Some(Mode::Enforce));
	store.due_for_refresh("example.org");
	state.store(failure, Ordering::Relaxed);
	store.policy(&dns, "example.org").await
}

#[tokio::test]
async fn an_unreachable_policy_host_keeps_the_cached_policy() {
	let policy = after_failed_refresh(FETCH_FAILS).await;
	assert_eq!(policy.map(|p| p.map(|p| p.mode)), Ok(Some(Mode::Enforce)));
}

#[tokio::test]
async fn a_failed_txt_lookup_keeps_the_cached_policy() {
	let policy = after_failed_refresh(TXT_TEMPFAIL).await;
	assert_eq!(policy.map(|p| p.map(|p| p.mode)), Ok(Some(Mode::Enforce)));
}

#[tokio::test]
async fn a_missing_txt_record_keeps_the_cached_policy() {
	let policy = after_failed_refresh(TXT_GONE).await;
	assert_eq!(policy.map(|p| p.map(|p| p.mode)), Ok(Some(Mode::Enforce)));
}

#[tokio::test]
async fn without_a_cached_policy_a_failed_fetch_is_temporary() {
	let state = Arc::new(AtomicU8::new(FETCH_FAILS));
	let store = PolicyStore::new(Box::new(Fetcher(Arc::clone(&state))));
	let result = store.policy(&World(state), "example.org").await;
	assert!(
		matches!(result, Err(PolicyError::Temporary(_))),
		"{result:?}"
	);
}

/// RFC 8461 section 3.3: when the published TXT id differs from the
/// cached one, the sender must refetch the policy before its max_age
/// runs out. Today the cached policy is used until the refresh window
/// elapses, so a domain that rolled its id is silently served the old
/// policy. This test pins the corrected behaviour.
#[tokio::test]
async fn a_new_txt_id_refetches_before_max_age() {
	let state = Arc::new(AtomicU8::new(OK));
	let dns = World(Arc::clone(&state));
	let calls = Arc::new(AtomicU32::new(0));
	let store = PolicyStore::new(Box::new(CountingIdFetcher(Arc::clone(&calls))));

	// First lookup: cache miss, fetch and remember id=1.
	let _ = store
		.policy(&dns, "example.org")
		.await
		.expect("ok")
		.expect("policy");
	assert_eq!(calls.load(Ordering::Relaxed), 1, "first call fetches");

	// Second lookup: same id, still within max_age, no fetch.
	let _ = store.policy(&dns, "example.org").await.expect("ok");
	assert_eq!(calls.load(Ordering::Relaxed), 1, "same id is a cache hit");

	// Domain publishes a new id.
	state.store(TXT_ID_B, Ordering::Relaxed);

	// Third lookup: id changed, must refetch.
	let _ = store.policy(&dns, "example.org").await.expect("ok");
	assert_eq!(
		calls.load(Ordering::Relaxed),
		2,
		"id change forces a refetch"
	);
}

/// A fetcher that always succeeds and counts how many times it was hit.
struct CountingIdFetcher(Arc<AtomicU32>);

impl PolicyFetcher for CountingIdFetcher {
	fn fetch(&self, _domain: &str) -> FetchFuture<'_> {
		self.0.fetch_add(1, Ordering::Relaxed);
		Box::pin(async move { Ok(ENFORCE.to_string()) })
	}
}
