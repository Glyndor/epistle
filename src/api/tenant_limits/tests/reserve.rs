//! The aggregate storage cap reserves the size it admits: uploads that check
//! at the same moment share the room under the cap.

use super::base::store_with;
use super::*;
use crate::config::Tenant;

fn limits(cap: u64) -> TenantLimits {
	TenantLimits::from_config(&[Tenant {
		name: Some("acme".to_string()),
		domains: vec!["acme.example".to_string()],
		quota_bytes: Some(cap),
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: None,
		encryption_key_file: None,
		webhook: None,
	}])
}

fn reserve(
	limits: &TenantLimits,
	store: &AccountStore,
	dir: &std::path::Path,
	size: u64,
) -> Result<AggregateReservation, String> {
	limits.reserve_aggregate_quota(
		store,
		dir,
		&crate::storage::MessageCrypto::disabled(),
		&["ann@acme.example".to_string()],
		size,
	)
}

#[test]
fn uploads_at_the_same_moment_share_the_cap() {
	const THREADS: usize = 16;
	let dir = tempfile::tempdir().expect("tempdir");
	let limits = limits(100);
	let store = store_with(&["acme.example"], &[("ann", &["ann@acme.example"])]);
	let start = std::sync::Barrier::new(THREADS);
	let done = std::sync::Barrier::new(THREADS);
	let admitted: usize = std::thread::scope(|scope| {
		let threads: Vec<_> = (0..THREADS)
			.map(|_| {
				scope.spawn(|| {
					start.wait();
					let held = reserve(&limits, &store, dir.path(), 80);
					// Every admitted upload stays reserved until all have decided.
					done.wait();
					usize::from(held.is_ok())
				})
			})
			.collect();
		threads.into_iter().map(|t| t.join().expect("upload")).sum()
	});
	assert_eq!(admitted, 1, "a cap of 100 holds one upload of 80");
}

#[test]
fn a_released_reservation_frees_its_room() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limits = limits(100);
	let store = store_with(&["acme.example"], &[("ann", &["ann@acme.example"])]);
	let held = reserve(&limits, &store, dir.path(), 80).expect("fits");
	let refused = reserve(&limits, &store, dir.path(), 80).expect_err("room is taken");
	assert!(refused.contains("aggregate storage cap"), "{refused}");
	drop(held);
	reserve(&limits, &store, dir.path(), 80).expect("the room came back");
}

#[test]
fn a_refused_reservation_leaves_nothing_held() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limits = limits(100);
	let store = store_with(&["acme.example"], &[("ann", &["ann@acme.example"])]);
	for _ in 0..4 {
		reserve(&limits, &store, dir.path(), 101).expect_err("larger than the cap");
	}
	reserve(&limits, &store, dir.path(), 100).expect("nothing stayed reserved");
}
