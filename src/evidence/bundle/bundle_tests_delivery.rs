//! A bundle that verifies says what became of the message: a reader who sees
//! "the bundle verifies" must not take a bounce, an expiry or a message that
//! was never sent for a delivery.

use super::check::{CheckReport, Delivery};
use super::tests::{failures, resum};
use super::tests_complete::{drop_records, export_of, fixture};
use super::*;
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{Entry, OutcomeKind, sha256};
use crate::evidence::test_support::{accepted, at, delivered};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

fn delivery_of(fixture: &Fixture, n: u32) -> Delivery {
	let (_out, bundle) = export_of(fixture, n);
	let report = check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check");
	assert!(report.passed(), "{:?}", report.findings);
	report.delivery.expect("the delivery is told")
}

#[test]
fn what_became_of_each_ending_is_told_apart() {
	let fixture = fixture();
	let abandoned = delivery_of(&fixture, 1);
	assert_eq!((abandoned.abandoned, abandoned.delivered), (1, 0));
	assert!(!abandoned.all_delivered());
	assert!(abandoned.words().contains("nothing was sent"));
	let sent = delivery_of(&fixture, 2);
	assert_eq!((sent.delivered, sent.total()), (1, 1));
	assert!(sent.all_delivered());
	let bounced = delivery_of(&fixture, 3);
	assert_eq!((bounced.bounced, bounced.delivered), (1, 0));
	assert!(!bounced.all_delivered());
	assert!(bounced.words().contains("refused by the receiving server"));
}

#[test]
fn an_expiry_and_a_suppression_are_not_a_delivery_either() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let tsa = FakeTsa::new(at(DAY + 1, 1));
	let fixture = Fixture { dir, key, tsa };
	let chain = Chain::open(fixture.root()).expect("chain");
	for (n, result) in [(4, OutcomeKind::Expired), (5, OutcomeKind::Suppressed)] {
		chain.append_at(at(DAY, 1), accepted(n)).expect("accepted");
		let Entry::Outcome(mut outcome) = delivered(n) else {
			unreachable!()
		};
		outcome.result = result;
		chain
			.append_at(at(DAY, 2), Entry::Outcome(outcome))
			.expect("outcome");
	}
	seal_closed_days(fixture.root(), &fixture.key, true, at(DAY + 1, 0)).expect("seal");
	let paths = files(fixture.root(), Day(DAY));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		fixture
			.tsa
			.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	let expired = delivery_of(&fixture, 4);
	assert_eq!((expired.expired, expired.delivered), (1, 0));
	assert!(!expired.all_delivered());
	let suppressed = delivery_of(&fixture, 5);
	assert_eq!((suppressed.suppressed, suppressed.delivered), (1, 0));
	assert!(!suppressed.all_delivered());
}

/// Message 6 is delivered and then bounced, for the same recipient; message
/// 7 shares its day. One day, sealed and stamped.
fn delivered_then_bounced() -> Fixture {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let tsa = FakeTsa::new(at(DAY + 1, 1));
	let fixture = Fixture { dir, key, tsa };
	let chain = Chain::open(fixture.root()).expect("chain");
	chain.append_at(at(DAY, 1), accepted(6)).expect("accepted");
	chain
		.append_at(at(DAY, 2), delivered(6))
		.expect("delivered");
	let Entry::Outcome(mut bounced) = delivered(6) else {
		unreachable!()
	};
	bounced.result = OutcomeKind::Bounced;
	chain
		.append_at(at(DAY, 3), Entry::Outcome(bounced))
		.expect("bounced");
	chain.append_at(at(DAY, 4), accepted(7)).expect("accepted");
	chain
		.append_at(at(DAY, 5), delivered(7))
		.expect("delivered");
	seal_closed_days(fixture.root(), &fixture.key, true, at(DAY + 1, 0)).expect("seal");
	let paths = files(fixture.root(), Day(DAY));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		fixture
			.tsa
			.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	fixture
}

fn checked(fixture: &Fixture, bundle: &std::path::Path) -> CheckReport {
	check(bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check")
}

#[test]
fn a_recipient_with_two_different_endings_is_not_called_delivered() {
	let fixture = delivered_then_bounced();
	let (_out, bundle) = export_of(&fixture, 6);
	let report = checked(&fixture, &bundle);
	assert!(
		failures(&report)
			.iter()
			.any(|why| why.contains("contradictory outcomes for student6@example.net")),
		"{:?}",
		failures(&report)
	);
	assert!(!report.passed());
}

#[test]
fn leaving_out_the_later_bounce_passes_only_with_the_warning_that_records_are_missing() {
	let fixture = delivered_then_bounced();
	let (_out, bundle) = export_of(&fixture, 6);
	drop_records(&bundle, "\"result\":\"bounced\"");
	let report = checked(&fixture, &bundle);
	assert!(report.passed(), "{:?}", failures(&report));
	let delivery = report.delivery.expect("told");
	assert!(delivery.all_delivered());
	assert!(
		delivery.records_left_out > 0,
		"the bundle does not say it holds only some of the day"
	);
	assert!(
		report
			.notes
			.iter()
			.any(|note| note.contains("a selection of the log")
				&& note.contains("cannot be ruled out")),
		"{:?}",
		report.notes
	);
}

#[test]
fn a_bundle_of_one_message_says_the_rest_of_its_day_is_not_there() {
	let fixture = fixture();
	let (_out, bundle) = export_of(&fixture, 2);
	let report = checked(&fixture, &bundle);
	// Message 2 shares its day with 1 and 3, whose records are not here.
	assert!(report.delivery.expect("told").records_left_out > 0);
}

#[test]
fn records_and_proofs_moved_together_are_refused_not_read_another_way() {
	let fixture = delivered_then_bounced();
	let (_out, bundle) = export_of(&fixture, 6);
	let records = bundle.join(format!("records/{}.jsonl", Day(DAY).name()));
	let proofs = bundle.join(format!("proofs/{}.json", Day(DAY).name()));
	let text = std::fs::read_to_string(&records).expect("read");
	let mut lines: Vec<&str> = text.lines().collect();
	lines.swap(1, 2);
	std::fs::write(&records, format!("{}\n", lines.join("\n"))).expect("write");
	let mut proof: crate::evidence::bundle::DayProof =
		serde_json::from_slice(&std::fs::read(&proofs).expect("proofs")).expect("parse");
	proof.entries.swap(1, 2);
	std::fs::write(&proofs, serde_json::to_vec_pretty(&proof).expect("json")).expect("write");
	resum(&bundle);
	let failed = failures(&checked(&fixture, &bundle));
	assert!(
		failed
			.iter()
			.any(|why| why.contains("does not come after the record before it")),
		"{failed:?}"
	);
}

#[test]
fn a_canceled_recipient_is_counted_and_is_not_a_delivery() {
	let delivery = Delivery {
		canceled: 1,
		..Delivery::default()
	};
	assert!(!delivery.all_delivered());
	assert_eq!(delivery.total(), 1);
	assert!(
		delivery
			.words()
			.contains("canceled (an operator removed it")
	);
}
