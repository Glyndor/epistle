//! A domain's key rotates on its own schedule: published, confirmed, then
//! switched, with the replaced selector kept through its overlap and the
//! configured key never retired.

use std::sync::Arc;

use super::support::{DAY, INTERVAL, OVERLAP, Zone, domain};
use crate::dkim::rotate::Decision;

#[tokio::test]
async fn a_key_just_made_is_not_replaced_on_the_first_tick() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let decision = d.rotator(&zone).tick(d.made_at + DAY).await.expect("tick");
	assert_eq!(decision, crate::dkim::rotate::Decision::Idle);
	assert!(
		zone.log().is_empty(),
		"nothing is published: {:?}",
		zone.log()
	);
	assert_eq!(d.signer.current().selector(), "own1");
}

#[tokio::test]
async fn the_key_rotates_once_its_interval_has_passed_and_new_mail_verifies() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + INTERVAL;
	let decision = d.rotator(&zone).tick(now).await.expect("tick");
	assert_eq!(decision, Decision::Rotate);
	let selector = format!("own{}", now / DAY);
	assert_eq!(
		d.signer.current().selector(),
		selector,
		"the live signer switched"
	);
	assert_eq!(
		zone.record(&d.name(&selector)),
		Some(d.signer.current().dns_record_value()),
		"the record of the new selector holds the key that now signs"
	);
	assert!(d.verifies(&zone).await, "mail signed now verifies");
	let state = d.state();
	assert_eq!(state.selector, selector);
	assert_eq!(state.rotated_at, now);
	assert!(
		state.previous.is_none(),
		"the configured key is not put up for retirement"
	);
	assert!(
		zone.record(&d.name("own1")).is_some(),
		"the configured record stays published"
	);
}

#[tokio::test]
async fn a_replaced_selector_stays_published_through_its_overlap_then_retires() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let first = d.made_at + INTERVAL;
	d.rotator(&zone).tick(first).await.expect("first rotation");
	let first_selector = d.state().selector;
	let first_file = d.state().key_file;
	let second = first + INTERVAL;
	d.rotator(&zone)
		.tick(second)
		.await
		.expect("second rotation");
	let previous = d
		.state()
		.previous
		.expect("the first rotated key is retiring");
	assert_eq!(previous.selector, first_selector);
	assert_eq!(previous.retire_at, second + OVERLAP);
	// Inside the overlap: nothing is withdrawn.
	let decision = d
		.rotator(&zone)
		.tick(second + OVERLAP - 1)
		.await
		.expect("tick");
	assert_eq!(decision, Decision::Idle);
	assert!(zone.record(&d.name(&first_selector)).is_some());
	assert!(first_file.exists());
	// After it: the record and the key file go, the configured ones stay.
	let decision = d.rotator(&zone).tick(second + OVERLAP).await.expect("tick");
	assert_eq!(decision, Decision::Retire(first_selector.clone()));
	assert!(zone.record(&d.name(&first_selector)).is_none());
	assert!(!first_file.exists(), "the retired key file is removed");
	assert!(d.state().previous.is_none());
	assert!(zone.record(&d.name("own1")).is_some());
	assert!(d.entry.key_file.exists(), "the configured key file is kept");
	assert!(d.verifies(&zone).await);
}

#[tokio::test]
async fn an_entry_whose_key_lives_elsewhere_rotates_into_the_domain_key_directory() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let mut d = domain(dir.path(), "b.example", &zone);
	let elsewhere = dir.path().join("etc").join("b.pem");
	std::fs::create_dir_all(elsewhere.parent().expect("parent")).expect("mkdir");
	std::fs::rename(&d.entry.key_file, &elsewhere).expect("move");
	std::fs::remove_dir_all(d.dir()).expect("no key directory");
	d.entry.key_file = elsewhere.clone();
	d.rotator(&zone)
		.tick(d.made_at + INTERVAL)
		.await
		.expect("rotates");
	assert!(d.state().key_file.starts_with(d.dir()));
	assert!(d.verifies(&zone).await);
	assert!(elsewhere.exists());
}

#[tokio::test]
async fn the_next_rotation_waits_for_the_replaced_selector_to_retire() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	// An overlap longer than the interval: the second rotation comes due
	// while the first rotated key is still retiring.
	let rotator = || d.rotator(&zone).with_windows(INTERVAL, 3 * INTERVAL);
	let first = d.made_at + INTERVAL;
	rotator().tick(first).await.expect("first");
	rotator().tick(first + INTERVAL).await.expect("second");
	let retiring = d.state().previous.expect("retiring").selector;
	let in_service = d.state().selector;
	let decision = rotator().tick(first + 2 * INTERVAL).await.expect("tick");
	assert_eq!(decision, Decision::Idle);
	assert_eq!(d.state().selector, in_service, "no third key");
	assert_eq!(
		d.state().previous.map(|p| p.selector),
		Some(retiring),
		"the retiring selector is still the one the state will retire"
	);
}
