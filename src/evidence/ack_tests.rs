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
