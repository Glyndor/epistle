use crate::evidence::ack::{Acknowledged, Operator, acknowledge_at, is_acknowledged, statement};
use crate::evidence::audit::tests::{DAY, Fixture, reason};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::files;
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{Entry, to_hex};
use crate::evidence::test_support::at;

fn operator() -> Operator {
	Operator::named("uid=0 sudo_user=admin host=mail")
}

fn break_on_first_day(fixture: &Fixture) -> crate::evidence::verify::Break {
	std::fs::remove_file(files(fixture.root(), Day(DAY)).tsr).expect("rm token");
	fixture.verify().first_break.expect("a break")
}

#[test]
fn an_acknowledged_break_is_reported_and_the_walk_goes_on() {
	let fixture = Fixture::new();
	let first = break_on_first_day(&fixture);
	acknowledge_at(
		fixture.root(),
		&fixture.key,
		&first,
		"token lost in a disk failure",
		&operator(),
		at(DAY + 3, 13),
	)
	.expect("acknowledge");
	let report = fixture.verify();
	assert_eq!(report.acknowledged, vec![first]);
	assert_eq!(report.first_break, None);
	assert_eq!(
		report.sealed, 2,
		"the days after the acknowledged one are still checked"
	);
}

#[test]
fn an_acknowledgement_covers_only_its_own_break() {
	let fixture = Fixture::new();
	let first = break_on_first_day(&fixture);
	acknowledge_at(
		fixture.root(),
		&fixture.key,
		&first,
		"lost",
		&operator(),
		at(DAY + 3, 13),
	)
	.expect("ack");
	std::fs::remove_file(files(fixture.root(), Day(DAY + 1)).tsr).expect("rm second token");
	assert_eq!(
		reason(&fixture.verify()),
		"2026-10-15: checkpoint: not timestamped: the token is missing (still being requested, or the day was re-signed)"
	);
}

#[test]
fn a_forged_acknowledgement_lifts_nothing() {
	let fixture = Fixture::new();
	let first = break_on_first_day(&fixture);
	let mut forged = Acknowledged {
		break_day: first.day.name(),
		break_line: first.line,
		break_id: crate::evidence::ack::id(&first),
		reason: "forged".into(),
		operator: "uid=1001".into(),
		key: fixture.key.id(),
		signature: "00".repeat(64),
	};
	Chain::open(fixture.root())
		.expect("open")
		.append_at(at(DAY + 3, 13), Entry::Acknowledged(forged.clone()))
		.expect("append");
	assert!(!is_acknowledged(fixture.root(), &first));
	// Signed by a key that is not the pinned one: refused too.
	let other_root = tempfile::tempdir().expect("tempdir");
	let other = EvidenceKey::load_or_create(other_root.path()).expect("key");
	forged.key = other.id();
	forged.signature = to_hex(&other.sign(&statement(&forged)));
	Chain::open(fixture.root())
		.expect("open")
		.append_at(at(DAY + 3, 14), Entry::Acknowledged(forged))
		.expect("append");
	assert!(!is_acknowledged(fixture.root(), &first));
	assert_eq!(reason(&fixture.verify()), first.to_string());
}

#[test]
fn an_acknowledgement_before_the_break_it_names_does_not_count() {
	let fixture = Fixture::new();
	let first = break_on_first_day(&fixture);
	acknowledge_at(
		fixture.root(),
		&fixture.key,
		&first,
		"ok",
		&operator(),
		at(DAY + 3, 13),
	)
	.expect("ack");
	// The same break, claimed to be later in the chain than the record.
	let later = crate::evidence::verify::Break {
		day: Day(DAY + 3),
		line: 99,
		problem: first.problem.clone(),
	};
	assert!(!is_acknowledged(fixture.root(), &later));
}

#[test]
fn only_root_or_the_data_owner_may_acknowledge() {
	let dir = tempfile::tempdir().expect("tempdir");
	let operator = Operator::current(dir.path()).expect("the owner may");
	assert!(operator.as_str().starts_with("uid="), "the uid is recorded");
	// SAFETY: geteuid has no preconditions.
	if unsafe { libc::geteuid() } != 0 {
		let error = Operator::current(std::path::Path::new("/")).expect_err("not the owner of /");
		assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
	} else {
		eprintln!(
			"SKIPPED the refusal half of only_root_or_the_data_owner_may_acknowledge: running as root"
		);
	}
}

#[test]
fn a_replaced_evidence_key_is_refused() {
	let fixture = Fixture::new();
	std::fs::remove_file(fixture.root().join("key.pk8")).expect("rm key");
	let error =
		EvidenceKey::load_or_create(fixture.root()).expect_err("a new key is not the pinned one");
	assert_eq!(
		error.to_string(),
		"the evidence key does not match the pinned key: refusing to sign with it"
	);
}

#[test]
fn an_acknowledgement_signed_before_a_rotation_still_counts() {
	let fixture = Fixture::new();
	let first = break_on_first_day(&fixture);
	acknowledge_at(
		fixture.root(),
		&fixture.key,
		&first,
		"token lost in a disk failure",
		&operator(),
		at(DAY + 3, 13),
	)
	.expect("acknowledge");
	crate::evidence::rotation::rotate(fixture.root(), true, at(DAY + 3, 14)).expect("rotate");
	let report = crate::evidence::audit::verify(
		fixture.root(),
		&crate::evidence::audit::Options {
			from: None,
			to: None,
			anchors: vec![fixture.tsa.anchor],
			now: at(DAY + 3, 15),
		},
	)
	.expect("verify");
	assert_eq!(report.first_break, None);
	assert_eq!(report.acknowledged, vec![first]);
}

/// A break on the first day, a rotation, then an acknowledgement written
/// after it and signed by `signer`.
fn acknowledged_after_a_rotation(
	fixture: &Fixture,
	signer: &EvidenceKey,
) -> crate::evidence::audit::Report {
	let first = break_on_first_day(fixture);
	crate::evidence::rotation::rotate(fixture.root(), true, at(DAY + 3, 13)).expect("rotate");
	acknowledge_at(
		fixture.root(),
		signer,
		&first,
		"token lost in a disk failure",
		&operator(),
		at(DAY + 3, 14),
	)
	.expect("acknowledge");
	crate::evidence::audit::verify(
		fixture.root(),
		&crate::evidence::audit::Options {
			from: None,
			to: None,
			anchors: vec![fixture.tsa.anchor],
			now: at(DAY + 3, 15),
		},
	)
	.expect("verify")
}

#[test]
fn an_acknowledgement_after_a_rotation_must_be_signed_by_the_key_in_force() {
	let fixture = Fixture::new();
	let report = acknowledged_after_a_rotation(&fixture, &fixture.key);
	assert!(report.acknowledged.is_empty(), "the old key acknowledged");
	assert_eq!(
		report.first_break.map(|at| at.to_string()).as_deref(),
		Some(
			"2026-10-14: checkpoint: not timestamped: the token is missing (still being requested, or the day was re-signed)"
		)
	);
}

#[test]
fn an_acknowledgement_after_a_rotation_signed_by_the_key_in_force_counts() {
	let fixture = Fixture::new();
	let rotated_key = {
		// The key in force after the rotation the helper performs.
		crate::evidence::rotation::rotate(fixture.root(), true, at(DAY + 3, 12)).expect("rotate");
		EvidenceKey::load_or_create(fixture.root()).expect("key")
	};
	let first = break_on_first_day(&fixture);
	acknowledge_at(
		fixture.root(),
		&rotated_key,
		&first,
		"token lost in a disk failure",
		&operator(),
		at(DAY + 3, 14),
	)
	.expect("acknowledge");
	let report = crate::evidence::audit::verify(
		fixture.root(),
		&crate::evidence::audit::Options {
			from: None,
			to: None,
			anchors: vec![fixture.tsa.anchor],
			now: at(DAY + 3, 15),
		},
	)
	.expect("verify");
	assert_eq!(report.first_break, None);
	assert_eq!(report.acknowledged, vec![first]);
}

#[test]
fn an_acknowledgement_signed_by_a_key_before_its_rotation_record_does_not_count() {
	use crate::evidence::rotation::{ROTATIONS_DIR, Rotation, path};
	let fixture = Fixture::new();
	let first = break_on_first_day(&fixture);
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	let rotation = Rotation::signed(&fixture.key, &new.id(), "2026-10-17");
	crate::evidence::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&rotation).expect("json"),
	)
	.expect("statement");
	// The next key signs before the record that introduces it.
	acknowledge_at(
		fixture.root(),
		&new,
		&first,
		"token lost in a disk failure",
		&operator(),
		at(DAY + 3, 13),
	)
	.expect("acknowledge");
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 14), Entry::KeyRotated(rotation))
		.expect("record");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	assert!(!is_acknowledged(fixture.root(), &first));
}

#[test]
fn a_break_found_only_after_the_whole_walk_can_be_acknowledged() {
	// A day sealed by a key that had handed over: the walk finds it last.
	let mut fixture = Fixture::new();
	fixture.tsa.gen_time = at(DAY + 4, 1);
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), crate::evidence::test_support::accepted(7))
		.expect("append");
	crate::evidence::rotation::rotate(fixture.root(), true, at(DAY + 3, 5)).expect("rotate");
	crate::evidence::checkpoint::seal_closed_days(
		fixture.root(),
		&fixture.key,
		true,
		at(DAY + 4, 0),
	)
	.expect("seal with the old key");
	let paths = files(fixture.root(), Day(DAY + 3));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		fixture.tsa.respond(
			&crate::evidence::tsa::request::build(
				&crate::evidence::record::sha256(&json),
				crate::evidence::tsa::request::random_nonce(),
			)
			.der,
		),
	)
	.expect("token");
	let verify_at = |now| {
		crate::evidence::audit::verify(
			fixture.root(),
			&crate::evidence::audit::Options {
				from: None,
				to: None,
				anchors: vec![fixture.tsa.anchor],
				now,
			},
		)
		.expect("verify")
	};
	let found = verify_at(at(DAY + 4, 1)).first_break.expect("a break");
	assert!(found.to_string().contains("already handed over"), "{found}");
	let current = EvidenceKey::load_or_create(fixture.root()).expect("current key");
	acknowledge_at(
		fixture.root(),
		&current,
		&found,
		"sealed by the old key before the rotation finished",
		&operator(),
		at(DAY + 4, 2),
	)
	.expect("acknowledge");
	let report = verify_at(at(DAY + 4, 3));
	assert_eq!(report.first_break, None);
	assert_eq!(report.acknowledged, vec![found]);
}
