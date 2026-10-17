//! A purge deletes only what a verified purge says, whatever a planted file
//! says, and a break an operator acknowledged does not stop it.

use super::tests::{DAY, verified};
use super::tests_crash::old_days;
use super::*;
use crate::evidence::ack::{Operator, acknowledge_at};
use crate::evidence::test_support::{accepted_for, at};

fn statement_file(root: &Path, day: Day) -> PathBuf {
	root.join(PURGES_DIR).join(format!("{}.json", day.name()))
}

use std::path::PathBuf;

#[test]
fn a_planted_statement_cannot_name_a_path_to_delete() {
	for through in [
		"../checkpoints/VICTIM",
		"/etc/passwd",
		"a/b",
		"..",
		"２０２６-１０-１７",
		"2026-10-17\u{0}",
		"2026-10-17/../../x",
	] {
		let (dir, key, tsa, now) = old_days();
		let victim = Day(DAY + 3);
		let victim_files = files(dir.path(), victim);
		let through = through.replace("VICTIM", &victim.name());
		let statement = Statement {
			v: 1,
			from: "x".into(),
			through,
			records: 0,
			days: vec![],
			last_hash: "00".repeat(32),
			last_seq: 0,
			last_time: 0,
			checkpoint: "00".repeat(32),
			retain_until: "x".into(),
			time: 0,
			key: key.id(),
		};
		std::fs::create_dir_all(dir.path().join(PURGES_DIR)).expect("dir");
		let planted = dir.path().join(PURGES_DIR).join("2099-01-01.json");
		std::fs::write(
			&planted,
			serde_json::to_vec_pretty(&statement).expect("json"),
		)
		.expect("plant");
		let error = sweep(dir.path(), &key, &[tsa.anchor], now).expect_err("kept");
		assert!(error.to_string().contains("another day"), "{error}");
		assert!(victim_files.json.exists() && victim_files.sig.exists());
		assert!(planted.exists(), "the planted file is not ours to remove");
	}
}

#[test]
fn an_anchor_that_parses_is_not_a_purge() {
	let (dir, key, tsa, now) = old_days();
	let swept = sweep(dir.path(), &key, &[tsa.anchor], now).expect("sweep");
	assert_eq!(swept.days, 3, "{:?}", swept.refused);
	let chain = Chain::open(dir.path()).expect("chain");
	let before = chain.days().expect("days");
	// An anchor naming a later day: a flipped digit, a hand edit.
	let path = dir.path().join(CHAIN_DIR).join("anchor.json");
	let mut anchor: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&path).expect("anchor")).expect("json");
	anchor["through"] = Day(DAY + 3).name().into();
	std::fs::write(&path, serde_json::to_vec(&anchor).expect("json")).expect("edit");
	sweep(dir.path(), &key, &[tsa.anchor], now + 300).expect_err("kept");
	assert_eq!(
		chain.days().expect("days"),
		before,
		"days went on an anchor nothing backed"
	);
}

#[test]
fn days_the_statement_does_not_name_are_kept() {
	let (dir, key, tsa, now) = old_days();
	sweep_steps(dir.path(), &key, &[tsa.anchor], now, |step| {
		step == Step::Anchored
	})
	.expect_err("cut after the anchor");
	// The statement is edited to drop a day it purged: the record no longer
	// names it, which the verification reports; the days stay.
	let path = statement_file(dir.path(), Day(DAY + 2));
	let mut statement: Statement =
		serde_json::from_slice(&std::fs::read(&path).expect("statement")).expect("json");
	statement.days.remove(0);
	std::fs::write(&path, serde_json::to_vec_pretty(&statement).expect("json")).expect("edit");
	let chain = Chain::open(dir.path()).expect("chain");
	let before = chain.days().expect("days");
	sweep(dir.path(), &key, &[tsa.anchor], now + 300).expect_err("kept");
	assert_eq!(chain.days().expect("days"), before);
}

#[test]
fn a_manipulated_statement_after_its_record_is_kept_and_nothing_is_deleted() {
	for edit in ["append", "signature", "removed"] {
		let (dir, key, tsa, now) = old_days();
		sweep_steps(dir.path(), &key, &[tsa.anchor], now, |step| {
			step == Step::Recorded
		})
		.expect_err("cut");
		let json = statement_file(dir.path(), Day(DAY + 2));
		let sig = json.with_extension("sig");
		match edit {
			"append" => {
				let mut bytes = std::fs::read(&json).expect("json");
				bytes.push(b'\n');
				std::fs::write(&json, bytes).expect("edit");
			}
			"signature" => std::fs::write(&sig, b"bad").expect("edit"),
			_ => std::fs::remove_file(&json).expect("remove"),
		}
		let chain = Chain::open(dir.path()).expect("chain");
		let before = chain.days().expect("days");
		let swept = sweep(dir.path(), &key, &[tsa.anchor], now + 300);
		assert!(
			swept.is_err() || swept.is_ok_and(|swept| swept.refused.is_some() && swept.days == 0),
			"{edit}: the sweep went on"
		);
		assert_eq!(chain.days().expect("days"), before, "{edit}: days went");
		assert!(
			!dir.path().join(CHAIN_DIR).join("anchor.json").exists(),
			"{edit}: an anchor was written on a statement that does not verify"
		);
	}
}

/// Three records in the open day with the middle one cut out, acknowledged.
fn acknowledged_break(dir: &Path, key: &EvidenceKey, tsa: &FakeTsa, now: u64) {
	let chain = Chain::open(dir).expect("chain");
	for n in 0..3 {
		chain
			.append_at(at(DAY + 5, 2 + n), accepted_for(20 + n as u32, 2))
			.expect("append");
	}
	let file = chain.day_file(Day(DAY + 5));
	let text = std::fs::read_to_string(&file).expect("day");
	let lines: Vec<&str> = text.lines().collect();
	std::fs::write(&file, format!("{}\n{}\n", lines[0], lines[2])).expect("cut a line");
	let first = verified(dir, tsa, now).first_break.expect("a break");
	acknowledge_at(
		dir,
		key,
		&first,
		"test",
		&Operator::named("uid=0 sudo_user=a host=h"),
		now,
	)
	.expect("ack");
	assert_eq!(verified(dir, tsa, now).first_break, None);
}

use crate::evidence::tsa::fake::FakeTsa;

#[test]
fn a_purge_cut_short_is_finished_though_a_break_was_acknowledged() {
	let (dir, key, tsa, now) = old_days();
	sweep_steps(dir.path(), &key, &[tsa.anchor], now, |step| {
		step == Step::Statement
	})
	.expect_err("cut before the record");
	acknowledged_break(dir.path(), &key, &tsa, now);
	let swept = sweep(dir.path(), &key, &[tsa.anchor], now + 300).expect("not stuck");
	assert!(swept.refused.is_none(), "{:?}", swept.refused);
	let again = sweep(dir.path(), &key, &[tsa.anchor], now + 600).expect("and again");
	assert_eq!(again.days, 0);
	assert_eq!(super::tests_crash::purge_records(dir.path()), 1);
}

#[test]
fn a_day_that_cannot_be_read_is_unknown_and_an_acknowledged_break_is_not() {
	let (dir, key, tsa, now) = old_days();
	let chain = Chain::open(dir.path()).expect("chain");
	// Nothing names this digest.
	assert_eq!(recorded(dir.path(), &chain, "ab").expect("read"), Named::No);
	acknowledged_break(dir.path(), &key, &tsa, now);
	assert_eq!(
		recorded(dir.path(), &chain, "ab").expect("read"),
		Named::No,
		"an acknowledged break hid the rest of the chain"
	);
	// A break nobody acknowledged: the day cannot be relied on.
	let file = chain.day_file(Day(DAY + 5));
	let text = std::fs::read_to_string(&file).expect("day");
	std::fs::write(&file, format!("{text}not a record\n")).expect("damage");
	assert_eq!(
		recorded(dir.path(), &chain, "ab").expect("read"),
		Named::Unknown
	);
}

#[test]
fn a_break_elsewhere_keeps_the_days_the_anchor_covers() {
	let (dir, key, tsa, now) = old_days();
	sweep_steps(dir.path(), &key, &[tsa.anchor], now, |step| {
		step == Step::Anchored
	})
	.expect_err("cut after the anchor");
	// A record of a kept day is changed: nothing is deleted on an anchor
	// while the evidence does not verify.
	let chain = Chain::open(dir.path()).expect("chain");
	let file = chain.day_file(Day(DAY + 3));
	let text = std::fs::read_to_string(&file).expect("day");
	std::fs::write(&file, text.replacen("Notice", "Notiće", 1)).expect("edit");
	let before = chain.days().expect("days");
	let error = sweep(dir.path(), &key, &[tsa.anchor], now + 300).expect_err("kept");
	assert!(error.to_string().contains("does not verify"), "{error}");
	assert_eq!(chain.days().expect("days"), before);
}

#[test]
fn a_cut_purge_is_not_decided_while_a_day_of_the_chain_cannot_be_read() {
	let (dir, key, mut tsa, now) = old_days();
	sweep(dir.path(), &key, &[tsa.anchor], now).expect("first purge");
	// A second purge, cut before its record.
	let later = at(DAY + 9, 12);
	crate::evidence::retention::tests::stamp_all(dir.path(), &key, &mut tsa, at(DAY + 9, 0));
	sweep_steps(dir.path(), &key, &[tsa.anchor], later, |step| {
		step == Step::Statement
	})
	.expect_err("cut");
	let statement = statement_file(dir.path(), Day(DAY + 5));
	assert!(statement.exists(), "the second purge wrote its statement");
	let signed = std::fs::read(&statement).expect("statement");
	// A day before the anchor, out of the verification's reach, that is
	// not a chain: it is not known whether it names the statement.
	let chain = Chain::open(dir.path()).expect("chain");
	std::fs::write(chain.day_file(Day(DAY)), b"not a record\n").expect("plant");
	let error = sweep(dir.path(), &key, &[tsa.anchor], later + 300).expect_err("kept");
	assert!(error.to_string().contains("cannot be read"), "{error}");
	assert_eq!(std::fs::read(&statement).expect("kept"), signed);
}
