use super::*;

fn triplet() -> Triplet<'static> {
	Triplet {
		client_ip: "192.0.2.10".parse().unwrap(),
		sender: "Sender@Example.org",
		recipient: "Bob@Example.net",
	}
}

const DELAY: u64 = 60;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	runtime.block_on(future)
}

/// Run the same decision cases against every implementation of the
/// store trait. Returns them so the per-test assertion can target a
/// specific outcome (deferred, recorded, accepted...) without only
/// asserting "did not panic" or "returned something".
fn run_against(store: &dyn GreylistStore) {
	let t = triplet();
	let key = t.key();
	// First sighting: defer and remember it.
	assert_eq!(block_on(decide(store, &t, 1000, DELAY)), Decision::Defer);
	assert_eq!(block_on(store.first_seen(&key)), Ok(Some(1000)));
	// Retry too soon: still defer (first_seen unchanged).
	assert_eq!(block_on(decide(store, &t, 1030, DELAY)), Decision::Defer);
	assert_eq!(block_on(store.first_seen(&key)), Ok(Some(1000)));
	// Retry past the delay: accept.
	assert_eq!(block_on(decide(store, &t, 1060, DELAY)), Decision::Accept);
}

#[test]
fn first_attempt_is_deferred_and_recorded() {
	let store = MemoryGreylist::new();
	let t = triplet();
	assert_eq!(block_on(decide(&store, &t, 1000, DELAY)), Decision::Defer);
	assert_eq!(block_on(store.first_seen(&t.key())), Ok(Some(1000)));
}

#[test]
fn retry_before_delay_is_deferred() {
	let store = MemoryGreylist::new();
	block_on(decide(&store, &triplet(), 1000, DELAY));
	assert_eq!(
		block_on(decide(&store, &triplet(), 1030, DELAY)),
		Decision::Defer
	);
}

#[test]
fn retry_after_delay_is_accepted() {
	let store = MemoryGreylist::new();
	block_on(decide(&store, &triplet(), 1000, DELAY));
	assert_eq!(
		block_on(decide(&store, &triplet(), 1060, DELAY)),
		Decision::Accept
	);
}

#[test]
fn key_is_case_insensitive() {
	let lower = Triplet {
		client_ip: "192.0.2.10".parse().unwrap(),
		sender: "sender@example.org",
		recipient: "bob@example.net",
	};
	assert_eq!(triplet().key(), lower.key());
}

#[test]
fn memory_store_roundtrips_and_prunes() {
	let store = MemoryGreylist::new();
	assert_eq!(
		block_on(decide(&store, &triplet(), 1000, DELAY)),
		Decision::Defer
	);
	// Recorded, so a later retry past the delay is accepted.
	assert_eq!(
		block_on(decide(&store, &triplet(), 1100, DELAY)),
		Decision::Accept
	);
	// Pruning old entries forgets the triplet; it is new again.
	block_on(store.sweep(1000 + 86_400, 3600));
	assert_eq!(block_on(store.first_seen(&triplet().key())), Ok(None));
}

#[test]
fn distinct_triplets_are_independent() {
	let store = MemoryGreylist::new();
	block_on(decide(&store, &triplet(), 1000, DELAY));
	let other = Triplet {
		client_ip: "198.51.100.1".parse().unwrap(),
		sender: "sender@example.org",
		recipient: "bob@example.net",
	};
	// A different client is still on its first attempt.
	assert_eq!(
		block_on(decide(&store, &other, 1100, DELAY)),
		Decision::Defer
	);
}

/// A store that cannot answer (the database is down) never stands in for a
/// first sighting: deferring there would defer every retry for the whole
/// outage. The attempt is accepted and nothing is recorded.
#[test]
fn unavailable_store_accepts_and_records_nothing() {
	struct Down(std::sync::atomic::AtomicUsize);
	impl GreylistStore for Down {
		fn first_seen(&self, _key: &str) -> StoreFuture<'_, Result<Option<u64>, StoreUnavailable>> {
			Box::pin(async { Err(StoreUnavailable) })
		}
		fn record(&self, _key: &str, _now: u64) -> StoreFuture<'_, ()> {
			self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
			Box::pin(async {})
		}
	}
	let store = Down(std::sync::atomic::AtomicUsize::new(0));
	assert_eq!(
		block_on(decide(&store, &triplet(), 1000, DELAY)),
		Decision::Accept
	);
	assert_eq!(
		store.0.load(std::sync::atomic::Ordering::SeqCst),
		0,
		"an unavailable store must not be written to"
	);
}

/// The memory store is the production default. Pinning it to the
/// shared contract catches divergence even before the SQL store test
/// runs (and the SQL test is gated on a live database).
#[test]
fn memory_store_matches_the_decision_contract() {
	let store = MemoryGreylist::new();
	run_against(&store);
}
