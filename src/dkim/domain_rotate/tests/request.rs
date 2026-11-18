//! An operator's request rotates one domain now, through the same steps,
//! and never cuts a replaced selector's overlap short.

use std::sync::Arc;

use super::*;

use super::support::{INTERVAL, OVERLAP, Zone, domain};

#[tokio::test]
async fn a_request_rotates_the_domain_on_the_next_cycle_and_is_consumed() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + 60;
	request_rotation(&d.data_dir, "b.example", now).expect("request");
	assert!(pending_request(&d.data_dir, "b.example").is_some());
	d.rotator(&zone).cycle(now, false).await.expect("cycle");
	assert_ne!(d.signer.current().selector(), "own1");
	assert!(d.verifies(&zone).await);
	assert!(pending_request(&d.data_dir, "b.example").is_none());
}

#[tokio::test]
async fn a_request_inside_the_overlap_is_refused_and_kept() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let first = d.made_at + INTERVAL;
	d.rotator(&zone).tick(first).await.expect("first");
	d.rotator(&zone)
		.tick(first + INTERVAL)
		.await
		.expect("second");
	let retiring = d.state().previous.expect("retiring").selector;
	let now = first + INTERVAL + OVERLAP / 2;
	request_rotation(&d.data_dir, "b.example", now).expect("request");
	let error = d
		.rotator(&zone)
		.serve_request(now)
		.await
		.expect_err("refused");
	assert!(error.to_string().contains("overlap short"), "{error}");
	assert!(zone.record(&d.name(&retiring)).is_some(), "still published");
	assert!(pending_request(&d.data_dir, "b.example").is_some());
	let reason = last_error(&d.data_dir, "b.example").expect("reason kept");
	assert!(reason.contains(&retiring), "{reason}");
	// Once the overlap is over the request retires it and rotates.
	let later = first + INTERVAL + OVERLAP + 1;
	d.rotator(&zone).serve_request(later).await.expect("served");
	assert!(zone.record(&d.name(&retiring)).is_none());
	assert!(d.verifies(&zone).await);
}

#[test]
fn a_request_for_a_name_that_cannot_be_a_directory_is_refused() {
	let dir = tempfile::tempdir().expect("dir");
	assert!(request_rotation(dir.path(), "../escape", 0).is_err());
	assert!(!dir.path().join("keys").exists());
}

/// Every cycle asks the publisher to build its provider again, whether or
/// not it writes anything, so a credential that changed is picked up.
#[tokio::test]
async fn every_cycle_builds_the_provider_again() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let rotator = d.rotator(&zone);
	rotator.cycle(d.made_at + 60, false).await.expect("cycle");
	rotator.cycle(d.made_at + 120, false).await.expect("cycle");
	assert_eq!(zone.refreshes.load(std::sync::atomic::Ordering::Relaxed), 2);
}
