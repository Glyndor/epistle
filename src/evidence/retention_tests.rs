use super::*;
use crate::evidence::audit::{Options, verify};
use crate::evidence::checkpoint::seal_closed_days;
use crate::evidence::test_support::{accepted_for, at, delivered};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

const DAY: i64 = 20_740;

/// Days DAY..DAY+3 with short retentions, sealed and stamped.
fn fixture() -> (tempfile::TempDir, EvidenceKey, FakeTsa) {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let mut tsa = FakeTsa::new(at(DAY + 10, 0));
	let chain = Chain::open(dir.path()).expect("chain");
	for offset in 0..4 {
		let n = offset as u32;
		chain
			.append_at(at(DAY + offset, 1), accepted_for(n, 2))
			.expect("append");
		chain
			.append_at(at(DAY + offset, 2), delivered(n))
			.expect("append");
	}
	stamp_all(dir.path(), &key, &mut tsa, at(DAY + 4, 0));
	(dir, key, tsa)
}

fn stamp_all(root: &Path, key: &EvidenceKey, tsa: &mut FakeTsa, now: u64) {
	tsa.gen_time = now + 60;
	seal_closed_days(root, key, true, now).expect("seal");
	for day in Chain::open(root).expect("chain").days().expect("days") {
		let paths = files(root, day);
		if paths.json.exists() && !paths.tsr.exists() {
			let json = std::fs::read(&paths.json).expect("json");
			std::fs::write(
				&paths.tsr,
				tsa.respond(&build(&sha256(&json), random_nonce()).der),
			)
			.expect("tsr");
		}
	}
}

fn verified(root: &Path, tsa: &FakeTsa, now: u64) -> crate::evidence::audit::Report {
	verify(
		root,
		&Options {
			from: None,
			to: None,
			anchors: vec![tsa.anchor],
			now,
		},
	)
	.expect("verify")
}

#[test]
fn nothing_is_purged_while_any_record_of_the_day_must_be_kept() {
	let (dir, key, _) = fixture();
	// delivered() keeps a year: no day is purgeable.
	let swept = sweep(dir.path(), &key, at(DAY + 30, 0)).expect("sweep");
	assert_eq!(swept, Sweep::default());
	assert_eq!(
		Chain::open(dir.path())
			.expect("chain")
			.days()
			.expect("days")
			.len(),
		4
	);
}

#[test]
fn a_purge_keeps_the_rest_of_the_chain_verifiable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let mut tsa = FakeTsa::new(at(DAY + 30, 0));
	let chain = Chain::open(dir.path()).expect("chain");
	for offset in 0..4 {
		chain
			.append_at(at(DAY + offset, 1), accepted_for(offset as u32, 2))
			.expect("append");
	}
	stamp_all(dir.path(), &key, &mut tsa, at(DAY + 4, 0));
	// Two days later the first days' two-day retention has passed.
	let now = at(DAY + 5, 12);
	let swept = sweep(dir.path(), &key, now).expect("sweep");
	assert_eq!(
		swept.days, 3,
		"every closed day before yesterday whose retention passed"
	);
	let days = chain.days().expect("days");
	assert!(
		days.iter().all(|day| *day >= Day(DAY + 3)),
		"purged days are gone"
	);
	assert!(
		!files(dir.path(), Day(DAY)).json.exists(),
		"the checkpoint went with its day"
	);
	// The chain verifies from the anchor, and the purge record is sealed later.
	let later = at(DAY + 7, 0);
	chain
		.append_at(at(DAY + 6, 1), accepted_for(9, 2))
		.expect("append after");
	stamp_all(dir.path(), &key, &mut tsa, later);
	let report = verified(dir.path(), &tsa, later);
	assert_eq!(report.first_break.as_ref().map(ToString::to_string), None);
	// The statement is signed by the evidence key.
	let statement = std::fs::read(
		dir.path()
			.join(PURGES_DIR)
			.join(format!("{}.json", Day(DAY + 2).name())),
	)
	.expect("statement");
	let signature = std::fs::read(
		dir.path()
			.join(PURGES_DIR)
			.join(format!("{}.sig", Day(DAY + 2).name())),
	)
	.expect("sig");
	assert!(crate::evidence::key::verify(
		&key.public_key(),
		&statement,
		&signature
	));
}

#[test]
fn an_anchor_moved_without_its_purge_record_is_a_break() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let mut tsa = FakeTsa::new(at(DAY + 30, 0));
	let chain = Chain::open(dir.path()).expect("chain");
	for offset in 0..4 {
		chain
			.append_at(at(DAY + offset, 1), accepted_for(offset as u32, 2))
			.expect("append");
	}
	stamp_all(dir.path(), &key, &mut tsa, at(DAY + 4, 0));
	// Delete the oldest day by hand and write an anchor: no purge record.
	let (cp, bytes) = checkpoint::load(dir.path(), Day(DAY))
		.expect("load")
		.expect("cp");
	let position = Position {
		hash: hash_from_hex(&cp.last_hash).expect("hash"),
		seq: cp.last_seq,
		time: cp.last_time,
	};
	super::super::anchor::write(
		&dir.path().join(CHAIN_DIR),
		&Day(DAY).name(),
		&position,
		&sha256(&bytes),
	)
	.expect("anchor");
	std::fs::remove_file(chain.day_file(Day(DAY))).expect("rm");
	let report = verified(dir.path(), &tsa, at(DAY + 4, 12));
	assert_eq!(
		report.first_break.map(|b| b.to_string()).as_deref(),
		Some("2026-10-18: checkpoint: days were purged without a purge record")
	);
}

#[test]
fn kept_messages_go_when_their_retention_passes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let old = dir
		.path()
		.join(MESSAGES_DIR)
		.join(Day(DAY).name())
		.join("2");
	let young = dir
		.path()
		.join(MESSAGES_DIR)
		.join(Day(DAY).name())
		.join("30");
	std::fs::create_dir_all(&old).expect("mkdir");
	std::fs::create_dir_all(&young).expect("mkdir");
	std::fs::write(old.join("a.eml"), b"x").expect("write");
	let swept = sweep(dir.path(), &key, at(DAY + 3, 0)).expect("sweep");
	assert_eq!(swept.message_dirs, 1);
	assert!(!old.exists());
	assert!(young.exists());
}

#[test]
fn a_day_sealed_after_every_older_checkpoint_was_purged_names_the_anchor() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let mut tsa = FakeTsa::new(at(DAY, 0));
	let chain = Chain::open(dir.path()).expect("chain");
	chain
		.append_at(at(DAY, 1), accepted_for(1, 1))
		.expect("append");
	stamp_all(dir.path(), &key, &mut tsa, at(DAY + 1, 0));
	let swept = sweep(dir.path(), &key, at(DAY + 3, 0)).expect("sweep");
	assert_eq!(swept.days, 1);
	// The purge record sits on DAY+3; seal it two days later with nothing
	// older left.
	stamp_all(dir.path(), &key, &mut tsa, at(DAY + 4, 1));
	let report = verified(dir.path(), &tsa, at(DAY + 4, 2));
	assert_eq!(report.first_break.as_ref().map(ToString::to_string), None);
	assert_eq!(report.sealed, 1);
}
