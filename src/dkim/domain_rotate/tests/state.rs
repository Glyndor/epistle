//! Which key a domain signs with after a restart, and what a damaged state
//! may and may not make the rotation do.

use std::sync::Arc;

use super::*;

use super::support::{INTERVAL, OVERLAP, Zone, domain};
use crate::dkim::rotate::{Previous, RotationState};

#[tokio::test]
async fn after_a_rotation_startup_signs_with_the_rotated_key() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let before = active_keys(&d.entry, &d.data_dir).expect("active");
	assert_eq!(before.ed.selector, "own1");
	assert_eq!(before.ed.key_file, d.entry.key_file);
	d.rotator(&zone)
		.tick(d.made_at + INTERVAL)
		.await
		.expect("rotates");
	let after = active_keys(&d.entry, &d.data_dir).expect("active");
	assert_eq!(after.ed.selector, d.signer.current().selector());
	let loaded = crate::dkim::Signer::load(&after.ed.selector, &after.ed.key_file).expect("load");
	assert_eq!(
		loaded.dns_record_value(),
		d.signer.current().dns_record_value()
	);
}

#[tokio::test]
async fn an_unreadable_state_falls_back_to_the_last_good_copy_and_stops_rotating() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let first = d.made_at + INTERVAL;
	d.rotator(&zone).tick(first).await.expect("first");
	d.rotator(&zone)
		.tick(first + INTERVAL)
		.await
		.expect("second");
	let in_service = d.state().selector;
	std::fs::write(d.dir().join(STATE_FILE), b"{ not json").expect("damage");
	// The copy is one save behind, and every key it names is published.
	let fallback = active_keys(&d.entry, &d.data_dir).expect("the copy reads");
	assert!(zone.record(&d.name(&fallback.ed.selector)).is_some());
	let writes = zone.log().len();
	d.rotator(&zone)
		.tick(first + 3 * INTERVAL)
		.await
		.expect_err("an unreadable state stops the rotation");
	assert_eq!(zone.log().len(), writes, "nothing is written over it");
	assert!(zone.record(&d.name(&in_service)).is_some());
	std::fs::remove_file(d.dir().join(STATE_BACKUP_FILE)).expect("remove copy");
	assert!(
		active_keys(&d.entry, &d.data_dir).is_err(),
		"with no good copy the start is refused, never the configured key"
	);
}

/// Save a state whose replaced selector is `previous`, due for retirement.
fn damaged(d: &super::support::Domain, previous: Previous) {
	let state = RotationState {
		selector: "own9".into(),
		key_file: d.entry.key_file.clone(),
		rotated_at: d.made_at,
		previous: Some(previous),
		pending: None,
		rsa: None,
	};
	std::fs::write(
		d.dir().join(STATE_FILE),
		serde_json::to_vec(&state).expect("json"),
	)
	.expect("write");
}

#[tokio::test]
async fn a_state_that_retires_the_configured_selector_is_refused() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	damaged(
		&d,
		Previous {
			selector: "own1".into(),
			key_file: Default::default(),
			retire_at: d.made_at,
			rsa: None,
		},
	);
	let error = d
		.rotator(&zone)
		.tick(d.made_at + OVERLAP)
		.await
		.expect_err("refused");
	assert!(
		error.to_string().contains("refusing to retire own1"),
		"{error}"
	);
	assert!(zone.record(&d.name("own1")).is_some());
	assert!(zone.log().is_empty(), "{:?}", zone.log());
}

#[tokio::test]
async fn retiring_never_removes_a_key_file_the_rotation_did_not_make() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let outside = dir.path().join("operator.pem");
	std::fs::write(&outside, b"kept").expect("write");
	for key_file in [d.entry.key_file.clone(), outside.clone()] {
		damaged(
			&d,
			Previous {
				selector: "own5".into(),
				key_file,
				retire_at: d.made_at,
				rsa: None,
			},
		);
		d.rotator(&zone)
			.tick(d.made_at + OVERLAP)
			.await
			.expect("retired");
	}
	assert!(d.entry.key_file.exists(), "the configured key file is kept");
	assert!(outside.exists(), "a file outside the key directory is kept");
}
