//! Unit tests for the (pure) rotation decision and the reloadable signer.

use super::*;

const DAY: u64 = 86_400;

fn state(selector: &str, rotated_at: u64, previous: Option<Previous>) -> RotationState {
	RotationState {
		selector: selector.to_string(),
		key_file: "dkim.key".into(),
		rotated_at,
		previous,
	}
}

#[test]
fn empty_state_rotates_to_bootstrap() {
	assert_eq!(
		decide(&RotationState::default(), 1_000, 30 * DAY, DAY),
		Decision::Rotate
	);
}

#[test]
fn rotates_once_interval_elapses() {
	let s = state("ed1", 1_000_000, None);
	// Before the interval: idle.
	assert_eq!(decide(&s, 1_000_000 + DAY, 30 * DAY, DAY), Decision::Idle);
	// After the interval: rotate.
	assert_eq!(
		decide(&s, 1_000_000 + 30 * DAY, 30 * DAY, DAY),
		Decision::Rotate
	);
}

#[test]
fn retires_previous_after_overlap_takes_precedence() {
	let previous = Previous {
		selector: "ed-old".into(),
		retire_at: 2_000,
	};
	let s = state("ed-new", 0, Some(previous));
	// Overlap not elapsed: still idle (interval not reached either).
	assert_eq!(decide(&s, 1_999, 30 * DAY, DAY), Decision::Idle);
	// Overlap elapsed: retire the old selector, even though rotation is also due.
	let due = state(
		"ed-new",
		0,
		Some(Previous {
			selector: "ed-old".into(),
			retire_at: 2_000,
		}),
	);
	assert_eq!(
		decide(&due, 100 * DAY, 30 * DAY, DAY),
		Decision::Retire("ed-old".into())
	);
}

#[test]
fn selector_is_day_unique_and_stable() {
	assert_eq!(selector_for(0), "ed0");
	assert_eq!(selector_for(DAY), "ed1");
	// Same day → same selector; next day → different.
	assert_eq!(selector_for(5 * DAY + 10), selector_for(5 * DAY + 20));
	assert_ne!(selector_for(5 * DAY), selector_for(6 * DAY));
}

#[test]
fn reloadable_signer_swaps_the_active_signer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem1, _) = super::super::generate_key().expect("key1");
	let path1 = dir.path().join("a.key");
	std::fs::write(&path1, pem1).expect("write");
	let signer1 = std::sync::Arc::new(Signer::load("ed-a", &path1).expect("load1"));

	let handle = ReloadableSigner::new(signer1);
	assert!(!handle.current().dns_record_value().is_empty());

	let (pem2, _) = super::super::generate_key().expect("key2");
	let path2 = dir.path().join("b.key");
	std::fs::write(&path2, pem2).expect("write");
	let signer2 = std::sync::Arc::new(Signer::load("ed-b", &path2).expect("load2"));
	let before = handle.current().dns_record_value();
	handle.reload(signer2);
	// A fresh key changes the published public key.
	assert_ne!(handle.current().dns_record_value(), before);
}
