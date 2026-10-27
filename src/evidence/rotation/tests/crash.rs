//! A rotation that is cut short can be finished, once, from any step.

use super::*;
use crate::evidence::audit::tests::base::{DAY, Fixture};
use crate::evidence::audit::{Options, verify};
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::record::sha256;
use crate::evidence::test_support::{accepted, at};
use crate::evidence::tsa::request::{build, random_nonce};

fn seal_with_current_key(fixture: &mut Fixture, now: u64) {
	let key = EvidenceKey::load_or_create(fixture.root()).expect("key");
	seal_closed_days(fixture.root(), &key, true, now).expect("seal");
	fixture.tsa.gen_time = now + 3600;
	for offset in 0..8 {
		let paths = files(fixture.root(), Day(DAY + offset));
		if paths.json.exists() && !paths.tsr.exists() {
			let json = std::fs::read(&paths.json).expect("json");
			let token = fixture
				.tsa
				.respond(&build(&sha256(&json), random_nonce()).der);
			std::fs::write(&paths.tsr, token).expect("tsr");
		}
	}
}

fn first_break(fixture: &Fixture, now: u64) -> Option<String> {
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
	.first_break
	.map(|at| at.to_string())
}

/// How many `key_rotated` records the chain holds.
fn records(root: &Path) -> usize {
	let mut count = 0;
	for day in Chain::open(root).expect("chain").days().expect("days") {
		let _ = crate::evidence::verify::walk_day(root, day, None, |_, record, _| {
			count += usize::from(matches!(record.entry, Entry::KeyRotated(_)));
		});
	}
	count
}

const STEPS: [Step; 4] = [Step::Sealed, Step::Staged, Step::Statement, Step::Recorded];

/// A server with one record on `DAY + 3`, whose rotation is cut after `step`.
fn cut_after(step: Step) -> Fixture {
	let fixture = Fixture::new();
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("append");
	let cut = rotate_steps(fixture.root(), at(DAY + 3, 5), |at_step| at_step == step);
	assert_eq!(cut.expect_err("cut").to_string(), "stopped", "{step:?}");
	fixture
}

/// What must hold once the rotation is finished, however it was cut.
fn finished(fixture: &mut Fixture, step: Step) {
	let root = fixture.root().to_path_buf();
	assert_eq!(records(&root), 1, "{step:?}: one hand-over in the chain");
	let periods = periods(&root).expect("periods");
	assert_eq!(periods.len(), 2, "{step:?}: {periods:?}");
	assert_eq!(
		key::pinned_id(&root).expect("pin"),
		Some(periods[0].0.clone()),
		"{step:?}"
	);
	seal_with_current_key(fixture, at(DAY + 5, 0));
	assert_eq!(first_break(fixture, at(DAY + 5, 1)), None, "{step:?}");
}

#[test]
fn running_rotate_again_finishes_a_rotation_cut_at_any_step_once() {
	for step in STEPS {
		let mut fixture = cut_after(step);
		let new = rotate_at(fixture.root(), at(DAY + 4, 1)).expect("rotate again");
		assert_eq!(
			EvidenceKey::load_or_create(fixture.root())
				.expect("key")
				.id(),
			new,
			"{step:?}"
		);
		finished(&mut fixture, step);
	}
}

#[test]
fn a_restart_finishes_a_rotation_that_was_recorded_before_anything_signs_again() {
	let mut fixture = cut_after(Step::Recorded);
	let before = key::pinned_id(fixture.root()).expect("pin");
	// The server's next tick loads the key to seal with.
	let key = EvidenceKey::load_or_create(fixture.root()).expect("key");
	assert_ne!(
		Some(key.id()),
		before,
		"still signing with the key that handed over"
	);
	finished(&mut fixture, Step::Recorded);
}

#[test]
fn a_rotation_cut_before_the_record_keeps_the_old_key_and_breaks_nothing() {
	for step in [Step::Sealed, Step::Staged, Step::Statement] {
		let mut fixture = cut_after(step);
		let before = key::pinned_id(fixture.root()).expect("pin");
		assert_eq!(
			EvidenceKey::load_or_create(fixture.root())
				.map(|k| Some(k.id()))
				.expect("key"),
			before,
			"{step:?}"
		);
		seal_with_current_key(&mut fixture, at(DAY + 4, 0));
		assert_eq!(first_break(&fixture, at(DAY + 4, 1)), None, "{step:?}");
	}
}

#[test]
fn a_second_process_promoting_the_same_key_ends_the_same() {
	let fixture = cut_after(Step::Recorded);
	let root = fixture.root();
	let new = EvidenceKey::staged(root).expect("staged").id();
	EvidenceKey::promote_next(root, &new).expect("first");
	EvidenceKey::promote_next(root, &new).expect("second, nothing left to move");
	assert_eq!(key::pinned_id(root).expect("pin"), Some(new));
}

#[test]
fn a_rotation_at_a_clock_the_log_does_not_agree_with_seals_nothing() {
	let fixture = Fixture::new();
	let before = std::fs::read_dir(fixture.root().join("checkpoints"))
		.expect("dir")
		.count();
	let refused = rotate(fixture.root(), at(DAY + 400, 5)).expect_err("a clock far ahead");
	assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
	assert!(refused.to_string().contains("not confirmed"), "{refused}");
	assert_eq!(
		std::fs::read_dir(fixture.root().join("checkpoints"))
			.expect("dir")
			.count(),
		before,
		"a day was sealed at a doubtful time"
	);
	assert!(!fixture.root().join("rotations").exists());
}

#[test]
fn a_rotation_after_a_quiet_week_needs_the_running_servers_word() {
	let fixture = Fixture::new();
	let now = at(DAY + 10, 5);
	// Nobody confirmed that clock: a month ahead would look the same.
	rotate(fixture.root(), now).expect_err("not confirmed");
	// The server's last tick believed it.
	crate::evidence::test_support::running_server(fixture.root(), now);
	rotate(fixture.root(), now).expect("the server's word");
}

#[test]
fn a_rotation_in_the_first_half_hour_of_a_day_waits_for_the_day_before_to_be_sealed() {
	let fixture = Fixture::new();
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("record");
	let early = at(DAY + 4, 0) + 30;
	let refused = rotate_at(fixture.root(), early).expect_err("too soon");
	assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
	assert!(
		refused.to_string().contains("too soon after midnight"),
		"{refused}"
	);
	assert!(!fixture.root().join("rotations").exists());
	assert!(!files(fixture.root(), Day(DAY + 3)).json.exists());
	// Half an hour in, the day before is sealed by the old key and the
	// hand-over names the day it sits in.
	rotate_at(fixture.root(), at(DAY + 4, 0) + 1900).expect("rotate");
	assert!(files(fixture.root(), Day(DAY + 3)).json.exists());
}

#[test]
fn a_rotation_recorded_after_an_acknowledged_break_is_still_found_and_finished() {
	use crate::evidence::ack::{Operator, acknowledge_at};
	let fixture = Fixture::new();
	let root = fixture.root().to_path_buf();
	let chain = Chain::open(&root).expect("chain");
	for hour in 1..=3 {
		chain
			.append_at(at(DAY + 3, hour), accepted(20 + hour as u32))
			.expect("append");
	}
	rotate_steps(&root, at(DAY + 3, 5), |step| step == Step::Recorded).expect_err("cut");
	// A line before the hand-over is cut out of the day, and an operator
	// acknowledges the break.
	let file = chain.day_file(Day(DAY + 3));
	let text = std::fs::read_to_string(&file).expect("day");
	let lines: Vec<&str> = text.lines().collect();
	let kept: Vec<&str> = lines
		.iter()
		.enumerate()
		.filter(|(index, _)| *index != 1)
		.map(|(_, line)| *line)
		.collect();
	std::fs::write(&file, format!("{}\n", kept.join("\n"))).expect("cut a line");
	let report = verify(
		&root,
		&Options {
			from: None,
			to: None,
			anchors: vec![fixture.tsa.anchor],
			now: at(DAY + 3, 6),
		},
	)
	.expect("verify");
	let first = report.first_break.expect("a break");
	let key = EvidenceKey::load_or_create(&root).expect("key");
	acknowledge_at(
		&root,
		&key,
		&first,
		"test",
		&Operator::named("uid=0 sudo_user=a host=h"),
		at(DAY + 3, 6),
	)
	.expect("ack");
	assert!(
		resume(&root).expect("resume").is_some(),
		"the hand-over after the acknowledged break was not found"
	);
}
