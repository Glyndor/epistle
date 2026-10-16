//! A bundle that verifies says what became of the message: a reader who sees
//! "the bundle verifies" must not take a bounce, an expiry or a message that
//! was never sent for a delivery.

use super::check::Delivery;
use super::tests_complete::{export_of, fixture};
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
