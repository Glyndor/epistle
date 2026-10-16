use super::*;
use crate::evidence::audit::tests::{DAY, Fixture, reason};
use crate::evidence::audit::{Options, Report, verify};
use crate::evidence::checkpoint::Checkpoint;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::record::sha256;
use crate::evidence::test_support::{accepted, at};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

/// The fixture's three days are sealed by the first key. A fourth day gets
/// a record at `hour`, then the rotation happens.
fn rotated() -> (Fixture, String) {
	let fixture = Fixture::new();
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("append");
	let new = rotate(fixture.root(), true, at(DAY + 3, 5)).expect("rotate");
	(fixture, new)
}

/// Seal what is closed with the key now in force, and stamp it.
fn seal(fixture: &mut Fixture, now: u64) {
	let key = EvidenceKey::load_or_create(fixture.root()).expect("key");
	seal_with(fixture.dir.path(), &mut fixture.tsa, &key, now);
}

/// Seal what is closed with `key`, and stamp it.
fn seal_with(root: &Path, tsa: &mut FakeTsa, key: &EvidenceKey, now: u64) {
	seal_closed_days(root, key, true, now).expect("seal");
	tsa.gen_time = now + 3600;
	for offset in 0..6 {
		let paths = files(root, Day(DAY + offset));
		if paths.json.exists() && !paths.tsr.exists() {
			let json = std::fs::read(&paths.json).expect("json");
			let token = tsa.respond(&build(&sha256(&json), random_nonce()).der);
			std::fs::write(&paths.tsr, token).expect("tsr");
		}
	}
}

fn verified(fixture: &Fixture, now: u64) -> Report {
	verify(
		fixture.root(),
		&Options {
			from: None,
			to: None,
			anchors: vec![fixture.tsa.anchor],
			now,
		},
	)
	.expect("verify")
}

#[test]
fn a_rotation_hands_over_and_every_day_still_verifies() {
	let (mut fixture, new) = rotated();
	seal(&mut fixture, at(DAY + 4, 0));
	let report = verified(&fixture, at(DAY + 4, 12));
	assert_eq!(report.first_break, None);
	assert_eq!((report.sealed, report.stamped), (4, 4));
	let old = fixture.key.id();
	assert_ne!(old, new);
	assert_eq!(
		key::pinned_id(fixture.root()).expect("pin"),
		Some(new.clone())
	);
	assert_eq!(
		lineage(fixture.root()).expect("lineage"),
		vec![new.clone(), old.clone()]
	);
	assert_eq!(
		EvidenceKey::load_or_create(fixture.root())
			.expect("key")
			.id(),
		new
	);
	let statement = ancestry(fixture.root(), &new);
	assert_eq!(statement.len(), 1);
	assert_eq!(
		(statement[0].old.as_str(), statement[0].new.as_str()),
		(old.as_str(), new.as_str())
	);
}

#[test]
fn rotating_seals_the_closed_days_with_the_old_key_first() {
	let fixture = Fixture::new();
	// A day that closed and was never sealed.
	std::fs::remove_file(files(fixture.root(), Day(DAY + 2)).tsr).expect("tsr");
	std::fs::remove_file(files(fixture.root(), Day(DAY + 2)).sig).expect("sig");
	std::fs::remove_file(files(fixture.root(), Day(DAY + 2)).json).expect("json");
	let new = rotate(fixture.root(), true, at(DAY + 3, 5)).expect("rotate");
	let sealed: Checkpoint = serde_json::from_slice(
		&std::fs::read(files(fixture.root(), Day(DAY + 2)).json).expect("json"),
	)
	.expect("parse");
	assert_eq!(
		sealed.key,
		fixture.key.id(),
		"sealed before the key changed"
	);
	assert_ne!(sealed.key, new);
}

#[test]
fn a_key_change_no_record_explains_is_a_break() {
	let (mut fixture, _new) = rotated();
	// The chain forgets the rotation record: the day is rewritten without it.
	let chain = Chain::open(fixture.root()).expect("chain");
	let path = chain.day_file(Day(DAY + 3));
	let text = std::fs::read_to_string(&path).expect("read");
	let kept: Vec<&str> = text
		.lines()
		.filter(|l| !l.contains("key_rotated"))
		.collect();
	std::fs::write(&path, format!("{}\n", kept.join("\n"))).expect("write");
	seal(&mut fixture, at(DAY + 4, 0));
	let text = reason(&verified(&fixture, at(DAY + 4, 12)));
	assert_eq!(
		text,
		"2026-10-14: checkpoint: signed with a key another took over from, with no rotation record in the chain"
	);
}

#[test]
fn a_key_taken_without_a_rotation_record_is_a_break() {
	let mut fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("key");
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("append");
	// A signed statement and a promoted key, but no record in the chain.
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	let rotation = Rotation::signed(&old, &new.id(), "2026-10-17");
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&rotation).expect("json"),
	)
	.expect("statement");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	seal(&mut fixture, at(DAY + 4, 0));
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 4, 12))),
		"2026-10-14: checkpoint: signed with a key another took over from, with no rotation record in the chain"
	);
}

#[test]
fn a_statement_the_old_key_did_not_sign_is_not_followed() {
	let fixture = Fixture::new();
	let other_root = tempfile::tempdir().expect("tempdir");
	let other = EvidenceKey::load_or_create(other_root.path()).expect("other");
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	let forged = Rotation {
		old: fixture.key.id(),
		new: new.id(),
		day: "2026-10-17".into(),
		signature: to_hex(&other.sign(&statement(&fixture.key.id(), &new.id(), "2026-10-17"))),
	};
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&forged).expect("json"),
	)
	.expect("statement");
	assert!(ancestry(fixture.root(), &new.id()).is_empty());
	assert!(!took_over(fixture.root(), &fixture.key.id(), &new.id()));
	// Moving the key under the pin is refused: the statement is not followed.
	std::fs::rename(
		fixture.root().join("key.next.pk8"),
		fixture.root().join("key.pk8"),
	)
	.expect("rename");
	let error = EvidenceKey::load_or_create(fixture.root()).expect_err("refused");
	assert_eq!(
		error.to_string(),
		"the evidence key does not match the pinned key: refusing to sign with it"
	);
}

#[test]
fn a_rotation_that_stopped_before_the_replacement_keeps_the_old_key_and_can_finish() {
	let fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("key");
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	// Stopped after staging: the old key stays in force.
	assert_eq!(
		EvidenceKey::load_or_create(fixture.root())
			.expect("key")
			.id(),
		old.id()
	);
	assert_eq!(lineage(fixture.root()).expect("lineage"), vec![old.id()]);
	let finished = rotate(fixture.root(), true, at(DAY + 3, 5)).expect("rotate");
	assert_eq!(
		finished,
		new.id(),
		"the staged key is the one that takes over"
	);
}

#[test]
fn a_rotation_that_stopped_before_the_pin_moved_is_repaired() {
	let fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("key");
	let new = rotate(fixture.root(), true, at(DAY + 3, 5)).expect("rotate");
	// As if the process died after the replacement and before the pin.
	std::fs::write(key::pin_path(fixture.root()), format!("{}\n", old.id())).expect("pin");
	assert_eq!(
		EvidenceKey::load_or_create(fixture.root())
			.expect("key")
			.id(),
		new
	);
	assert_eq!(key::pinned_id(fixture.root()).expect("pin"), Some(new));
}

#[test]
fn a_rotation_record_without_its_statement_is_a_break() {
	let mut fixture = Fixture::new();
	let rotation = Rotation {
		old: fixture.key.id(),
		new: "ab".repeat(32),
		day: "2026-10-17".into(),
		signature: "cd".repeat(64),
	};
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), Entry::KeyRotated(rotation))
		.expect("append");
	seal(&mut fixture, at(DAY + 4, 0));
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 4, 12))),
		"2026-10-17 line 1: checkpoint: the key rotation statement is missing or not signed by the old key"
	);
}

#[test]
fn the_old_key_cannot_seal_the_day_of_its_own_hand_over() {
	// The rotation record sits in DAY+3; that day is sealed after it ends, by
	// the key in force then.
	let (mut fixture, _new) = rotated();
	let Fixture { dir, key, tsa } = &mut fixture;
	seal_with(dir.path(), tsa, key, at(DAY + 4, 0));
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 4, 12))),
		"2026-10-17: checkpoint: signed with a key that had already handed over to another: only the key now in force signs after a rotation"
	);
}

#[test]
fn a_key_that_handed_over_cannot_sign_a_later_day() {
	let (mut fixture, _new) = rotated();
	seal(&mut fixture, at(DAY + 4, 0));
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 4, 1), accepted(8))
		.expect("append");
	// A leaked old key seals the next day.
	let Fixture { dir, key, tsa } = &mut fixture;
	seal_with(dir.path(), tsa, key, at(DAY + 5, 0));
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 5, 12))),
		"2026-10-18: checkpoint: signed with a key that had already handed over to another: only the key now in force signs after a rotation"
	);
}

#[test]
fn an_oldest_key_cannot_sign_once_the_chain_reached_the_third() {
	let (mut fixture, _b) = rotated();
	seal(&mut fixture, at(DAY + 4, 0));
	let c = rotate(fixture.root(), true, at(DAY + 4, 5)).expect("second rotation");
	seal(&mut fixture, at(DAY + 5, 0));
	assert_eq!(verified(&fixture, at(DAY + 5, 12)).first_break, None);
	assert_eq!(lineage(fixture.root()).expect("lineage").len(), 3);
	assert_eq!(key::pinned_id(fixture.root()).expect("pin"), Some(c));
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 5, 1), accepted(8))
		.expect("append");
	let Fixture { dir, key, tsa } = &mut fixture;
	seal_with(dir.path(), tsa, key, at(DAY + 6, 0));
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 6, 12))),
		"2026-10-19: checkpoint: signed with a key that had already handed over to another: only the key now in force signs after a rotation"
	);
}

#[test]
fn a_pinned_key_that_took_over_without_a_record_is_a_break() {
	let fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("key");
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	let rotation = Rotation::signed(&old, &new.id(), "2026-10-17");
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&rotation).expect("json"),
	)
	.expect("statement");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 3, 12))),
		"2026-10-14: checkpoint: signed with a key another took over from, with no rotation record in the chain"
	);
}

#[test]
fn hand_overs_that_lead_back_to_a_key_already_met_stop_the_walk() {
	let fixture = Fixture::new();
	let a = EvidenceKey::load_or_create(fixture.root()).expect("key");
	let b = EvidenceKey::stage_next(fixture.root()).expect("stage");
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	for (old, new) in [(&a, &b), (&b, &a)] {
		let rotation = Rotation::signed(&old, &new.id(), "2026-10-17");
		std::fs::write(
			path(fixture.root(), &new.id()),
			serde_json::to_vec(&rotation).expect("json"),
		)
		.expect("statement");
	}
	EvidenceKey::promote_next(fixture.root(), &b.id()).expect("promote");
	assert_eq!(
		lineage(fixture.root()).expect("lineage"),
		vec![b.id(), a.id()]
	);
	assert_eq!(ancestry(fixture.root(), &b.id()).len(), 1);
}

#[test]
fn a_record_whose_statement_does_not_verify_is_not_believed() {
	let fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("key");
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	let genuine = Rotation::signed(&old, &new.id(), "2026-10-17");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&genuine).expect("json"),
	)
	.expect("statement");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	// The chain carries the hand-over with another signature than the file's.
	let altered = Rotation {
		signature: "00".repeat(64),
		..genuine
	};
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), Entry::KeyRotated(altered))
		.expect("append");
	let timeline = Timeline::load(fixture.root()).expect("timeline");
	assert_eq!(
		timeline.check(&old.id(), (Day(DAY), 1)),
		Err(Fault::Unrecorded),
		"an altered record was taken as the hand-over"
	);
}

#[test]
fn more_verified_rotations_than_the_cap_are_an_error_not_a_truncation() {
	let fixture = Fixture::new();
	for _ in 0..=MAX_ROTATIONS {
		rotate(fixture.root(), true, at(DAY + 3, 1)).expect("rotate");
	}
	let error = Timeline::load(fixture.root()).expect_err("over the cap");
	assert_eq!(
		error.to_string(),
		"more key rotations than the evidence follows"
	);
}

#[test]
fn a_bounded_audit_still_needs_a_record_for_a_change_of_signer() {
	let mut fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("key");
	let chain = Chain::open(fixture.root()).expect("chain");
	for offset in [3, 4] {
		chain
			.append_at(at(DAY + offset, 1), accepted(offset as u32 + 10))
			.expect("append");
	}
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	let rotation = Rotation::signed(&old, &new.id(), "2026-10-17");
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&rotation).expect("json"),
	)
	.expect("statement");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	// Two days sealed by the new key, with no record in the chain.
	seal(&mut fixture, at(DAY + 5, 0));
	let report = verify(
		fixture.root(),
		&Options {
			from: Some(Day(DAY + 2)),
			to: Some(Day(DAY + 3)),
			anchors: vec![fixture.tsa.anchor],
			now: at(DAY + 5, 12),
		},
	)
	.expect("verify");
	assert_eq!(
		reason(&report),
		"2026-10-17: checkpoint: signed with a different evidence key than the day before, and no rotation record explains it"
	);
}

#[test]
fn a_rotation_record_names_the_day_it_sits_in() {
	let mut fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("key");
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	// Signed for another day than the one the record lands in.
	let rotation = Rotation::signed(&old, &new.id(), "2026-10-20");
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&rotation).expect("json"),
	)
	.expect("statement");
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), Entry::KeyRotated(rotation))
		.expect("append");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	seal(&mut fixture, at(DAY + 4, 0));
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 4, 12))),
		"2026-10-17 line 1: checkpoint: the key rotation record names another day than the one it sits in"
	);
}
