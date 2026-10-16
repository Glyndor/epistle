//! A bundle cannot drop the record that contradicts its story: a message
//! accepted and then abandoned, or bounced, shows the abandonment or the
//! bounce, or the bundle does not verify.

use uuid::Uuid;

use super::tests::{failures, resum};
use super::*;
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{Abandoned, Entry, Outcome, OutcomeKind, sha256};
use crate::evidence::test_support::{accepted, at, delivered};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

/// Messages 1 (abandoned), 2 (delivered) and 3 (bounced) on one day.
pub(super) fn fixture() -> Fixture {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let tsa = FakeTsa::new(at(DAY + 1, 1));
	let fixture = Fixture { dir, key, tsa };
	let chain = Chain::open(fixture.root()).expect("chain");
	chain.append_at(at(DAY, 1), accepted(1)).expect("a1");
	chain
		.append_at(
			at(DAY, 2),
			Entry::Abandoned(Abandoned {
				spool_id: Uuid::from_u128(1),
				reason: "the server stopped before the message was queued".into(),
				retain_days: 365,
			}),
		)
		.expect("abandoned");
	chain.append_at(at(DAY, 3), accepted(2)).expect("a2");
	chain.append_at(at(DAY, 4), delivered(2)).expect("d2");
	chain.append_at(at(DAY, 5), accepted(3)).expect("a3");
	let Entry::Outcome(mut bounced) = delivered(3) else {
		unreachable!()
	};
	bounced.result = OutcomeKind::Bounced;
	bounced.reply = Some("550 5.1.1 no such user".into());
	chain
		.append_at(at(DAY, 6), Entry::Outcome(Outcome { ..bounced }))
		.expect("bounced");
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

pub(super) fn export_of(fixture: &Fixture, n: u32) -> (tempfile::TempDir, std::path::PathBuf) {
	super::tests::exported(fixture, &super::tests::by_id(n))
}

pub(super) fn checked(fixture: &Fixture, bundle: &std::path::Path) -> Vec<String> {
	failures(&check(bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"))
}

/// Take every line naming `kind` out of the day's records and the matching
/// entries out of the proofs, and make the checksums agree.
pub(super) fn drop_records(bundle: &std::path::Path, kind: &str) {
	let records = bundle.join(format!("records/{}.jsonl", Day(DAY).name()));
	let text = std::fs::read_to_string(&records).expect("read");
	let proofs = bundle.join(format!("proofs/{}.json", Day(DAY).name()));
	let mut proof: DayProof =
		serde_json::from_slice(&std::fs::read(&proofs).expect("proofs")).expect("parse");
	let mut kept = Vec::new();
	let mut entries = Vec::new();
	for (line, entry) in text.lines().zip(proof.entries.clone()) {
		if !line.contains(kind) {
			kept.push(line);
			entries.push(entry);
		}
	}
	proof.entries = entries;
	let body = match kept.is_empty() {
		true => String::new(),
		false => format!("{}\n", kept.join("\n")),
	};
	std::fs::write(&records, body).expect("write");
	std::fs::write(&proofs, serde_json::to_vec_pretty(&proof).expect("json")).expect("write");
	resum(bundle);
}

#[test]
fn a_complete_bundle_of_each_ending_passes() {
	let fixture = fixture();
	for n in [1, 2, 3] {
		let (_out, bundle) = export_of(&fixture, n);
		assert_eq!(
			checked(&fixture, &bundle),
			Vec::<String>::new(),
			"message {n}"
		);
	}
}

#[test]
fn leaving_out_the_abandonment_does_not_verify() {
	let fixture = fixture();
	let (_out, bundle) = export_of(&fixture, 1);
	drop_records(&bundle, "\"kind\":\"abandoned\"");
	let failed = checked(&fixture, &bundle);
	assert_eq!(
		failed,
		vec![format!(
			"every message is accounted for: {}: no outcome for student1@example.net, and not abandoned: a record is missing, or the message is still in the queue",
			Uuid::from_u128(1)
		)]
	);
}

#[test]
fn leaving_out_a_bounce_does_not_verify() {
	let fixture = fixture();
	let (_out, bundle) = export_of(&fixture, 3);
	drop_records(&bundle, "\"result\":\"bounced\"");
	let failed = checked(&fixture, &bundle);
	assert_eq!(failed.len(), 1, "{failed:?}");
	assert!(
		failed[0].contains("no outcome for student3@example.net"),
		"{failed:?}"
	);
}

#[test]
fn a_record_that_names_a_message_whose_acceptance_is_not_there_does_not_verify() {
	let fixture = fixture();
	let (_out, bundle) = export_of(&fixture, 2);
	drop_records(&bundle, "\"kind\":\"accepted\"");
	let failed = checked(&fixture, &bundle);
	assert!(
		failed.iter().any(|f| f.contains("without its acceptance")),
		"{failed:?}"
	);
}

#[test]
fn a_bundle_without_its_manifest_does_not_verify() {
	let fixture = fixture();
	let (_out, bundle) = export_of(&fixture, 2);
	std::fs::remove_file(bundle.join("manifest.json")).expect("remove");
	resum(&bundle);
	let failed = checked(&fixture, &bundle);
	assert!(
		failed.iter().any(|f| f.contains("manifest.json: missing")),
		"{failed:?}"
	);
}

#[test]
fn a_bundle_for_one_recipient_needs_that_recipients_outcome_and_not_the_others() {
	use crate::evidence::record::Entry::Accepted as Acc;
	let fixture = fixture();
	let chain = Chain::open(fixture.root()).expect("chain");
	// Message 4 goes to two students; both are delivered.
	let Acc(mut two) = accepted(4) else {
		unreachable!()
	};
	two.recipients = vec!["ana@example.net".into(), "bea@example.net".into()];
	two.message_id = Some("<4@example.org>".into());
	// A day later, so it is its own sealed day.
	chain.append_at(at(DAY + 1, 1), Acc(two)).expect("accepted");
	for recipient in ["ana@example.net", "bea@example.net"] {
		let Entry::Outcome(mut outcome) = delivered(4) else {
			unreachable!()
		};
		outcome.recipient = recipient.into();
		chain
			.append_at(at(DAY + 1, 2), Entry::Outcome(outcome))
			.expect("outcome");
	}
	let mut fixture = fixture;
	seal_closed_days(fixture.root(), &fixture.key, true, at(DAY + 2, 0)).expect("seal");
	fixture.tsa.gen_time = at(DAY + 2, 1);
	let paths = files(fixture.root(), Day(DAY + 1));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		fixture
			.tsa
			.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	let out = tempfile::tempdir().expect("tempdir");
	let bundle = out.path().join("bundle");
	export(
		fixture.root(),
		&crate::storage::MessageCrypto::disabled(),
		&Selector::Recipient {
			address: "ANA@example.net".into(),
			from: Day(DAY + 1),
			to: Day(DAY + 1),
		},
		&bundle,
	)
	.expect("export");
	let records =
		std::fs::read_to_string(bundle.join(format!("records/{}.jsonl", Day(DAY + 1).name())))
			.expect("records");
	assert!(
		!records.contains("bea@example.net\",\"result"),
		"bea's outcome was exported"
	);
	assert_eq!(checked(&fixture, &bundle), Vec::<String>::new());
	// Her outcome taken out: the message is no longer accounted for her.
	let proofs = bundle.join(format!("proofs/{}.json", Day(DAY + 1).name()));
	let mut proof: DayProof =
		serde_json::from_slice(&std::fs::read(&proofs).expect("proofs")).expect("parse");
	let path = bundle.join(format!("records/{}.jsonl", Day(DAY + 1).name()));
	let text = std::fs::read_to_string(&path).expect("read");
	let mut kept = Vec::new();
	let mut entries = Vec::new();
	for (line, entry) in text.lines().zip(proof.entries.clone()) {
		if !line.contains("\"kind\":\"outcome\"") {
			kept.push(line);
			entries.push(entry);
		}
	}
	proof.entries = entries;
	std::fs::write(&path, format!("{}\n", kept.join("\n"))).expect("write");
	std::fs::write(&proofs, serde_json::to_vec_pretty(&proof).expect("json")).expect("write");
	resum(&bundle);
	let failed = checked(&fixture, &bundle);
	assert_eq!(failed.len(), 1, "{failed:?}");
	assert!(
		failed[0].contains("no outcome for ana@example.net"),
		"{failed:?}"
	);
}
