//! A process killed at any step of a domain's rotation leaves a state the
//! next tick completes, with the same key and one record.

use std::sync::Arc;

use super::*;

use super::support::{DAY, INTERVAL, OVERLAP, Zone, domain};
use crate::dkim::rotate::Step;

#[tokio::test]
async fn a_rotation_killed_at_any_step_is_finished_by_the_next_tick() {
	for step in [
		Step::Journaled,
		Step::KeyWritten,
		Step::Published(0),
		Step::Confirmed,
		Step::Committed,
	] {
		let dir = tempfile::tempdir().expect("dir");
		let zone = Arc::new(Zone::default());
		let d = domain(dir.path(), "b.example", &zone);
		let now = d.made_at + INTERVAL;
		let selector = format!("own{}", now / DAY);
		d.crashing(&zone, step).tick(now).await.expect_err("killed");
		let key_before = std::fs::read(d.dir().join(format!("{selector}.pem"))).ok();
		// A new process: the signer is the one startup builds from disk.
		let restarted = super::support::Domain {
			signer: ReloadableSigner::new(Arc::new(
				{
					let active = active_keys(&d.entry, &d.data_dir).expect("active");
					crate::dkim::Signer::load(&active.ed.selector, &active.ed.key_file)
				}
				.expect("load"),
			)),
			..d.clone()
		};
		restarted
			.rotator(&zone)
			.tick(now + 60)
			.await
			.unwrap_or_else(|error| panic!("{step:?}: {error}"));
		assert_eq!(
			restarted.signer.current().selector(),
			selector,
			"{step:?}: the domain signs with the rotated key"
		);
		if let Some(key) = key_before {
			assert_eq!(
				std::fs::read(d.dir().join(format!("{selector}.pem"))).expect("key"),
				key,
				"{step:?}: the key a killed run wrote is the one kept"
			);
		}
		assert!(restarted.verifies(&zone).await, "{step:?}");
		assert!(d.state().pending.is_none(), "{step:?}");
		let published = zone
			.log()
			.iter()
			.filter(|line| line.starts_with("publish"))
			.count();
		assert!(published <= 2, "{step:?}: {:?}", zone.log());
	}
}

#[tokio::test]
async fn a_withdrawal_killed_halfway_is_finished_and_publishes_nothing_again() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + INTERVAL;
	let name = d.name(&format!("own{}", now / DAY));
	zone.hidden.lock().unwrap().insert(name.clone());
	d.crashing(&zone, Step::Withdrawing)
		.tick(now)
		.await
		.expect_err("killed");
	assert!(d.state().pending.expect("journaled").withdrawing.is_some());
	// The record shows now, but the rotation is already being taken back.
	zone.hidden.lock().unwrap().clear();
	d.rotator(&zone)
		.tick(now + 60)
		.await
		.expect_err("withdrawn");
	assert_eq!(d.signer.current().selector(), "own1");
	assert!(zone.record(&name).is_none());
	assert_eq!(zone.log().last(), Some(&format!("withdraw {name}")));
	assert_eq!(
		zone.log()
			.iter()
			.filter(|l| l.starts_with("publish"))
			.count(),
		1,
		"{:?}",
		zone.log()
	);
}

#[tokio::test]
async fn a_retirement_killed_before_its_state_is_saved_is_repeated() {
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
	let due = first + INTERVAL + OVERLAP;
	d.crashing(&zone, Step::RetiredKey)
		.tick(due)
		.await
		.expect_err("killed");
	assert!(d.state().previous.is_some(), "still named until the save");
	d.rotator(&zone).tick(due + 60).await.expect("retired");
	assert!(d.state().previous.is_none());
	assert!(zone.record(&d.name(&retiring)).is_none());
}
