//! What a bundle covers: the manifest, the scope the reader asked for, and
//! what is shown of both.

use super::tests::{failures, resum};
use super::tests_complete::{checked, drop_records, export_of, fixture};
use super::*;
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::record::{Entry, OutcomeKind, sha256};
use crate::evidence::test_support::{accepted, at, delivered};
use crate::evidence::tsa::request::{build, random_nonce};

/// Message 4 to two students, one delivered and one bounced, sealed.
fn two_recipients() -> Fixture {
	let mut fixture = fixture();
	let chain = Chain::open(fixture.root()).expect("chain");
	let crate::evidence::record::Entry::Accepted(mut two) = accepted(4) else {
		unreachable!()
	};
	two.recipients = vec!["ana@example.net".into(), "bea@example.net".into()];
	two.message_id = Some("<4@example.org>".into());
	chain
		.append_at(at(DAY + 1, 1), Entry::Accepted(two))
		.expect("accepted");
	for (recipient, result) in [
		("ana@example.net", OutcomeKind::Delivered),
		("bea@example.net", OutcomeKind::Bounced),
	] {
		let Entry::Outcome(mut outcome) = delivered(4) else {
			unreachable!()
		};
		outcome.recipient = recipient.into();
		outcome.result = result;
		chain
			.append_at(at(DAY + 1, 2), Entry::Outcome(outcome))
			.expect("outcome");
	}
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
	fixture
}

/// The bundle of message 4 with the manifest of a bundle for `address`, the
/// outcome of every other recipient taken out.
fn narrowed_to(fixture: &Fixture, address: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	let (out, bundle) =
		super::tests::exported(fixture, &Selector::MessageId("<4@example.org>".into()));
	std::fs::write(
		bundle.join("manifest.json"),
		format!(
			"{{\"v\":1,\"scope\":\"recipient\",\"address\":\"{address}\",\"from\":\"{0}\",\"to\":\"{0}\"}}",
			Day(DAY + 1).name()
		),
	)
	.expect("manifest");
	let records = bundle.join(format!("records/{}.jsonl", Day(DAY + 1).name()));
	let proofs = bundle.join(format!("proofs/{}.json", Day(DAY + 1).name()));
	let text = std::fs::read_to_string(&records).expect("read");
	let mut proof: DayProof =
		serde_json::from_slice(&std::fs::read(&proofs).expect("proofs")).expect("parse");
	let (mut kept, mut entries) = (Vec::new(), Vec::new());
	for (line, entry) in text.lines().zip(proof.entries.clone()) {
		let other = line.contains("\"kind\":\"outcome\"") && !line.contains(address);
		if !other {
			kept.push(line);
			entries.push(entry);
		}
	}
	proof.entries = entries;
	std::fs::write(&records, format!("{}\n", kept.join("\n"))).expect("write");
	std::fs::write(&proofs, serde_json::to_vec_pretty(&proof).expect("json")).expect("write");
	resum(&bundle);
	(out, bundle)
}

fn expecting(
	fixture: &Fixture,
	bundle: &std::path::Path,
	expected: &Expectation,
) -> (Vec<String>, Vec<String>) {
	let report = check_expecting(bundle, &[fixture.tsa.anchor], &[fixture.key.id()], expected)
		.expect("check");
	(failures(&report), report.notes.clone())
}

#[test]
fn a_narrowed_manifest_hides_a_bounce_unless_the_reader_expects_the_whole_message() {
	let fixture = two_recipients();
	let (_out, bundle) = narrowed_to(&fixture, "ana@example.net");
	// Taken on its own word, the bundle says what it covers and what it does not.
	let (failed, notes) = expecting(&fixture, &bundle, &Expectation::default());
	assert_eq!(failed, Vec::<String>::new());
	assert!(
		notes.iter().any(|n| n.contains("recipient ana@example.net")
			&& n.contains("outcomes of the other recipients were NOT checked")
			&& n.contains("messages to this recipient that are not in the bundle")),
		"{notes:?}"
	);
	// A reader who asks about the message is not given the narrowed bundle.
	let (failed, _) = expecting(
		&fixture,
		&bundle,
		&Expectation {
			message_id: Some("<4@example.org>".into()),
			recipient: None,
			..Expectation::default()
		},
	);
	assert_eq!(
		failed,
		vec!["every message in the bundle has an outcome for each recipient it covers: the bundle was made for recipient ana@example.net, not for message <4@example.org>".to_string()]
	);
}

#[test]
fn the_scope_must_name_the_message_and_the_recipient_the_records_are_about() {
	let fixture = two_recipients();
	// A recipient the message was never sent to.
	let (_out, bundle) = narrowed_to(&fixture, "carl@example.net");
	let (failed, _) = expecting(&fixture, &bundle, &Expectation::default());
	assert!(
		failed
			.iter()
			.any(|f| f.contains("was not sent to carl@example.net")),
		"{failed:?}"
	);
	// A message id that is not the message's.
	let (_out, whole) =
		super::tests::exported(&fixture, &Selector::MessageId("<4@example.org>".into()));
	std::fs::write(
		whole.join("manifest.json"),
		"{\"v\":1,\"scope\":\"message\",\"message_id\":\"<other@example.org>\"}",
	)
	.expect("manifest");
	resum(&whole);
	let (failed, _) = expecting(&fixture, &whole, &Expectation::default());
	assert!(
		failed
			.iter()
			.any(|f| f.contains("is not the Message-ID the manifest names")),
		"{failed:?}"
	);
}

#[test]
fn the_expected_scope_is_checked_and_the_report_lists_the_scope() {
	let fixture = two_recipients();
	let (_out, bundle) =
		super::tests::exported(&fixture, &Selector::MessageId("<4@example.org>".into()));
	let (failed, notes) = expecting(
		&fixture,
		&bundle,
		&Expectation {
			message_id: Some("<4@example.org>".into()),
			recipient: Some("BEA@example.net".into()),
			..Expectation::default()
		},
	);
	assert_eq!(failed, Vec::<String>::new());
	assert!(
		notes
			.iter()
			.any(|n| n.contains("the records of all the recipients it names were looked at")),
		"{notes:?}"
	);
	let (failed, _) = expecting(
		&fixture,
		&bundle,
		&Expectation {
			message_id: Some("<5@example.org>".into()),
			recipient: None,
			..Expectation::default()
		},
	);
	assert_eq!(
		failed,
		vec!["every message in the bundle has an outcome for each recipient it covers: the bundle was made for message <4@example.org>, not for message <5@example.org>".to_string()]
	);
}

#[test]
fn a_bundle_with_no_acceptance_of_what_was_asked_checks_nothing_and_says_so() {
	let fixture = fixture();
	let (_out, bundle) = export_of(&fixture, 2);
	for kind in [
		"\"kind\":\"accepted\"",
		"\"kind\":\"outcome\"",
		"\"kind\":\"abandoned\"",
	] {
		drop_records(&bundle, kind);
	}
	let (failed, notes) = expecting(
		&fixture,
		&bundle,
		&Expectation {
			message_id: Some("<2@example.org>".into()),
			recipient: None,
			..Expectation::default()
		},
	);
	assert!(
		failed
			.iter()
			.any(|f| f.ends_with("the bundle holds no acceptance of message <2@example.org>")),
		"{failed:?}"
	);
	assert!(
		!notes.iter().any(|n| n.contains("was checked")),
		"{notes:?}"
	);
	// The same without being asked: its own manifest names a message.
	let (failed, _) = expecting(&fixture, &bundle, &Expectation::default());
	assert!(
		failed
			.iter()
			.any(|f| f.contains("holds no acceptance of message <2@example.org>")),
		"{failed:?}"
	);
}

#[test]
fn only_the_records_of_a_day_that_verified_count() {
	let fixture = fixture();
	let (_out, bundle) = export_of(&fixture, 2);
	// The day's signature broken: nothing of it counts as checked.
	let sig = bundle.join(format!("checkpoints/{}.sig", Day(DAY).name()));
	std::fs::write(&sig, [0u8; 64]).expect("write");
	resum(&bundle);
	let failed = checked(&fixture, &bundle);
	assert!(
		failed
			.iter()
			.any(|f| f.contains("holds no acceptance of message <2@example.org>")),
		"{failed:?}"
	);
}

#[test]
fn a_record_outside_the_range_the_manifest_names_does_not_verify() {
	let fixture = two_recipients();
	let (_out, bundle) = narrowed_to(&fixture, "ana@example.net");
	// The manifest says the acceptances are from a day before the real one.
	std::fs::write(
		bundle.join("manifest.json"),
		format!(
			"{{\"v\":1,\"scope\":\"recipient\",\"address\":\"ana@example.net\",\"from\":\"{0}\",\"to\":\"{0}\"}}",
			Day(DAY).name()
		),
	)
	.expect("manifest");
	resum(&bundle);
	let (failed, _) = expecting(&fixture, &bundle, &Expectation::default());
	assert!(
		failed.iter().any(|f| f.contains(&format!(
			"accepted on {}, outside the days the manifest names ({} to {})",
			Day(DAY + 1).name(),
			Day(DAY).name(),
			Day(DAY).name()
		))),
		"{failed:?}"
	);
	// And the reader's own range must be inside what the manifest covers.
	let (_out, bundle) = narrowed_to(&fixture, "ana@example.net");
	let (failed, _) = expecting(
		&fixture,
		&bundle,
		&Expectation {
			from: Some(Day(DAY)),
			to: Some(Day(DAY + 1)),
			..Expectation::default()
		},
	);
	assert!(
		failed
			.iter()
			.any(|f| f.contains("does not cover the days asked")),
		"{failed:?}"
	);
}

#[test]
fn nothing_in_a_manifest_is_taken_that_could_move_a_terminal() {
	let fixture = two_recipients();
	for hostile in [
		"\u{1b}[31mred",
		"a\u{1b}]0;title\u{7}b",
		"a\rb",
		"a\nb",
		"a\u{202e}b",
		"a\u{61c}b",
		"a\u{3164}b",
		"a\u{e0041}b",
	] {
		let (_out, bundle) = narrowed_to(&fixture, "ana@example.net");
		std::fs::write(
			bundle.join("manifest.json"),
			serde_json::json!({
				"v": 1, "scope": "recipient", "address": hostile,
				"from": Day(DAY + 1).name(), "to": Day(DAY + 1).name()
			})
			.to_string(),
		)
		.expect("manifest");
		resum(&bundle);
		let (failed, notes) = expecting(&fixture, &bundle, &Expectation::default());
		assert!(
			failed
				.iter()
				.any(|f| f.contains("manifest.json: not a manifest")),
			"{hostile:?}: {failed:?}"
		);
		assert!(
			!notes.iter().any(|n| n.contains(hostile)),
			"{hostile:?}: {notes:?}"
		);
	}
}
