use super::*;
use crate::evidence::key::EvidenceKey;
use crate::evidence::test_support::{accepted, at, delivered};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

pub(crate) const DAY: i64 = 20_740;

pub(crate) struct Fixture {
	pub(crate) dir: tempfile::TempDir,
	pub(crate) key: EvidenceKey,
	pub(crate) tsa: FakeTsa,
}

impl Fixture {
	/// Three sealed and stamped days.
	pub(crate) fn new() -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let key = EvidenceKey::load_or_create(dir.path()).expect("key");
		let tsa = FakeTsa::new(at(DAY + 3, 1));
		let fixture = Fixture { dir, key, tsa };
		let chain = Chain::open(fixture.root()).expect("open");
		for offset in 0..3 {
			let n = offset as u32;
			chain
				.append_at(at(DAY + offset, 1), accepted(n))
				.expect("append");
			chain
				.append_at(at(DAY + offset, 2), delivered(n))
				.expect("append");
		}
		fixture.seal_and_stamp();
		// A server is running, and believes the clock: commands may date by it.
		crate::evidence::test_support::running_server(
			fixture.root(),
			crate::storage::delivery_log::now_epoch(),
		);
		fixture
	}

	pub(crate) fn root(&self) -> &Path {
		self.dir.path()
	}

	fn seal_and_stamp(&self) {
		checkpoint::seal_closed_days(self.root(), &self.key, true, at(DAY + 3, 0)).expect("seal");
		for offset in 0..3 {
			let paths = files(self.root(), Day(DAY + offset));
			if paths.tsr.exists() {
				continue;
			}
			let json = std::fs::read(&paths.json).expect("json");
			let response = self.tsa.respond(&build(&sha256(&json), random_nonce()).der);
			std::fs::write(&paths.tsr, response).expect("tsr");
		}
	}

	pub(crate) fn verify(&self) -> Report {
		verify(
			self.root(),
			&Options {
				from: None,
				to: None,
				anchors: vec![self.tsa.anchor],
				now: at(DAY + 3, 12),
			},
		)
		.expect("verify")
	}

	/// Rewrite the records of `offset` consistently and re-seal it, as an
	/// operator holding the key could.
	fn rewrite_day(&self, offset: i64, keep_token: bool) {
		let day = Day(DAY + offset);
		let chain = Chain::open(self.root()).expect("open");
		std::fs::remove_file(chain.day_file(day)).expect("remove day");
		let paths = files(self.root(), day);
		std::fs::remove_file(&paths.json).expect("remove json");
		std::fs::remove_file(&paths.sig).expect("remove sig");
		if !keep_token {
			std::fs::remove_file(&paths.tsr).expect("remove tsr");
		}
		// Written by hand, as the writer never goes back to a past day.
		let (before, _) = checkpoint::load(self.root(), Day(DAY + offset - 1))
			.expect("load")
			.expect("the day before is sealed");
		let line = crate::evidence::record::Record {
			v: crate::evidence::record::FORMAT_VERSION,
			seq: before.last_seq + 1,
			prev: before.last_hash.clone(),
			time: at(DAY + offset, 1),
			entry: accepted(90),
		}
		.to_line()
		.expect("line");
		std::fs::write(chain.day_file(day), [line, b"\n".to_vec()].concat()).expect("write");
		checkpoint::seal(self.root(), day, &self.key, true, at(DAY + 3, 0)).expect("re-seal");
	}
}

pub(crate) fn reason(report: &Report) -> String {
	plain(report.first_break.as_ref().expect("a break").to_string())
}

/// A break's words without the state it names (`[..]` at the end), which
/// holds hashes that differ from run to run.
pub(crate) fn plain(text: String) -> String {
	match text.rsplit_once(" [") {
		Some((words, state)) if state.ends_with(']') => words.to_string(),
		_ => text,
	}
}

#[test]
fn intact_evidence_verifies_end_to_end() {
	let fixture = Fixture::new();
	let report = fixture.verify();
	assert_eq!(report.first_break, None);
	assert_eq!(
		(report.days, report.records, report.sealed, report.stamped),
		(3, 6, 3, 3)
	);
}

#[test]
fn a_re_signed_last_day_without_its_token_is_found() {
	let fixture = Fixture::new();
	fixture.rewrite_day(2, false);
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-16: checkpoint: not timestamped: the token is missing (still being requested, or the day was re-signed)"
	);
}

#[test]
fn a_re_signed_day_keeping_the_old_token_is_found() {
	let fixture = Fixture::new();
	fixture.rewrite_day(2, true);
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-16: checkpoint: timestamp: the token stamps a different digest"
	);
}

#[test]
fn a_re_signed_middle_day_is_named_by_the_next_checkpoint() {
	let fixture = Fixture::new();
	// The middle day is rewritten and re-stamped; the day after still chains
	// onto (and its checkpoint names) the original.
	fixture.rewrite_day(1, false);
	let paths = files(fixture.root(), Day(DAY + 1));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		fixture
			.tsa
			.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	let report = fixture.verify();
	let text = reason(&report);
	assert!(
		text.starts_with("2026-10-16 line 1: the day does not follow the day before"),
		"{text}"
	);
}

#[test]
fn an_edited_checkpoint_or_signature_is_found() {
	let fixture = Fixture::new();
	let paths = files(fixture.root(), Day(DAY));
	let original = std::fs::read_to_string(&paths.json).expect("json");
	std::fs::write(
		&paths.json,
		original.replace("\"records\": 2", "\"records\": 1"),
	)
	.expect("edit");
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-14: checkpoint: the record count does not match the day's records"
	);
	std::fs::write(
		&paths.json,
		original.replace("\"created\": ", "\"created\": 1"),
	)
	.expect("edit");
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-14: checkpoint: the signature does not verify"
	);
}

#[test]
fn a_missing_checkpoint_is_a_break_after_the_grace() {
	let fixture = Fixture::new();
	std::fs::remove_file(files(fixture.root(), Day(DAY)).json).expect("remove");
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-14: checkpoint: missing: the day was never sealed"
	);
}

#[test]
fn today_and_a_just_closed_day_are_open_not_broken() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	chain.append_at(at(DAY, 23), accepted(1)).expect("append");
	chain
		.append_at(at(DAY + 1, 0), accepted(2))
		.expect("append");
	let report = verify(
		dir.path(),
		&Options {
			from: None,
			to: None,
			anchors: Vec::new(),
			now: at(DAY + 1, 0) + 60,
		},
	)
	.expect("verify");
	assert_eq!(report.first_break, None);
	assert_eq!(report.open, vec![Day(DAY), Day(DAY + 1)]);
}

#[test]
fn a_token_from_an_unpinned_authority_is_refused() {
	let fixture = Fixture::new();
	let report = verify(
		fixture.root(),
		&Options {
			from: None,
			to: None,
			anchors: vec![[7; 32]],
			now: at(DAY + 3, 12),
		},
	)
	.expect("verify");
	assert_eq!(
		reason(&report),
		"2026-10-14: checkpoint: timestamp: the token does not verify: the chain does not reach a pinned anchor"
	);
}

/// Re-sign `day`'s checkpoint after `edit`, with `key`.
fn resign(fixture: &Fixture, day: Day, key: &EvidenceKey, edit: impl FnOnce(&mut Checkpoint)) {
	let paths = files(fixture.root(), day);
	let mut checkpoint: Checkpoint =
		serde_json::from_slice(&std::fs::read(&paths.json).expect("json")).expect("parse");
	edit(&mut checkpoint);
	let bytes = serde_json::to_vec_pretty(&checkpoint).expect("encode");
	std::fs::write(&paths.sig, key.sign(&bytes)).expect("sig");
	std::fs::write(&paths.json, &bytes).expect("json");
}

#[test]
fn a_deleted_latest_day_is_a_rollback() {
	let fixture = Fixture::new();
	let day = Day(DAY + 2);
	std::fs::remove_file(Chain::open(fixture.root()).expect("open").day_file(day)).expect("rm");
	for path in [
		files(fixture.root(), day).json,
		files(fixture.root(), day).sig,
		files(fixture.root(), day).tsr,
	] {
		std::fs::remove_file(path).expect("rm");
	}
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-14: checkpoint: rollback: the chain ends before its recorded head (a truncated tail or a deleted latest day)"
	);
}

#[test]
fn a_truncated_tail_is_a_rollback() {
	let fixture = Fixture::new();
	let chain = Chain::open(fixture.root()).expect("open");
	chain
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("append");
	let path = chain.day_file(Day(DAY + 3));
	let kept = std::fs::read(&path).expect("read");
	chain
		.append_at(at(DAY + 3, 2), delivered(7))
		.expect("append");
	std::fs::write(&path, kept).expect("truncate");
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-14: checkpoint: rollback: the chain ends before its recorded head (a truncated tail or a deleted latest day)"
	);
}

#[test]
fn a_missing_head_is_a_break() {
	let fixture = Fixture::new();
	std::fs::remove_file(crate::evidence::head::path(fixture.root())).expect("rm head");
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-14: checkpoint: the head is missing: the evidence may have been restored from an older copy"
	);
}

#[test]
fn a_checkpoint_downgraded_to_no_timestamp_is_a_break() {
	let fixture = Fixture::new();
	resign(&fixture, Day(DAY + 2), &fixture.key, |checkpoint| {
		checkpoint.timestamp = "disabled".into();
	});
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-16: checkpoint: timestamping is marked disabled while the chain has it enabled: a downgrade"
	);
}

#[test]
fn a_checkpoint_signed_by_another_key_is_a_break() {
	let fixture = Fixture::new();
	let other_root = tempfile::tempdir().expect("tempdir");
	let other = EvidenceKey::load_or_create(other_root.path()).expect("key");
	std::fs::copy(
		crate::evidence::key::public_key_path(other_root.path(), &other.id()),
		crate::evidence::key::public_key_path(fixture.root(), &other.id()),
	)
	.expect("publish");
	resign(&fixture, Day(DAY + 1), &other, |checkpoint| {
		checkpoint.key = other.id()
	});
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-15: checkpoint: signed with a key other than the pinned evidence key, or one it took over from by a signed rotation"
	);
}

#[test]
fn a_deleted_middle_day_is_a_gap() {
	let fixture = Fixture::new();
	let day = Day(DAY + 1);
	std::fs::remove_file(Chain::open(fixture.root()).expect("open").day_file(day)).expect("rm");
	let text = reason(&fixture.verify());
	assert!(
		text.starts_with("2026-10-16 line 1: the day does not follow the day before"),
		"{text}"
	);
}

#[test]
fn a_token_issued_long_after_its_checkpoint_is_refused() {
	let fixture = Fixture::new();
	let late = FakeTsa::new(at(DAY + 10, 0));
	let paths = files(fixture.root(), Day(DAY + 2));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		late.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	let report = verify(
		fixture.root(),
		&Options {
			from: None,
			to: None,
			anchors: vec![fixture.tsa.anchor, late.anchor],
			now: at(DAY + 10, 12),
		},
	)
	.expect("verify");
	assert_eq!(
		reason(&report),
		"2026-10-16: checkpoint: timestamp: the token was issued more than 3 days after the checkpoint"
	);
}
