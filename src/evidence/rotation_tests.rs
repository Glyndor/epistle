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
		"2026-10-17: checkpoint: signed with a different evidence key than the day before, and no rotation record explains it"
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
	let rotation = Rotation {
		old: old.id(),
		new: new.id(),
		signature: to_hex(&old.sign(&statement(&old.id(), &new.id()))),
	};
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
		"2026-10-17: checkpoint: signed with a different evidence key than the day before, and no rotation record explains it"
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
		signature: to_hex(&other.sign(&statement(&fixture.key.id(), &new.id()))),
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
		signature: "cd".repeat(64),
	};
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), Entry::KeyRotated(rotation))
		.expect("append");
	seal(&mut fixture, at(DAY + 4, 0));
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 4, 12))),
		"2026-10-18: checkpoint: the key rotation statement is missing or not signed by the old key"
	);
}

#[test]
fn a_key_that_handed_over_cannot_sign_a_later_day() {
	let (mut fixture, _new) = rotated();
	// The rotation record sits in DAY+3, which the old key may still seal.
	let Fixture { dir, key, tsa } = &mut fixture;
	seal_with(dir.path(), tsa, key, at(DAY + 4, 0));
	Chain::open(dir.path())
		.expect("chain")
		.append_at(at(DAY + 4, 1), accepted(8))
		.expect("append");
	// A leaked old key seals the next day too: the same signer as the day before.
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
	let rotation = Rotation {
		old: old.id(),
		new: new.id(),
		signature: to_hex(&old.sign(&statement(&old.id(), &new.id()))),
	};
	super::super::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&rotation).expect("json"),
	)
	.expect("statement");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	assert_eq!(
		reason(&verified(&fixture, at(DAY + 3, 12))),
		"2026-10-17: checkpoint: the pinned evidence key took over with no rotation record in the chain"
	);
}
