use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::*;
use crate::evidence::MailClass;
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{Accepted, Entry, Retention, RetentionMode, sha256, to_hex};
use crate::evidence::test_support::at;
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};
use crate::storage::MessageCrypto;

/// The id of the evidence key under `root`.
pub(super) fn key_of(root: &Path) -> String {
	EvidenceKey::load_or_create(root).expect("key").id()
}

pub(super) fn by_id(n: u32) -> Selector {
	Selector::MessageId(format!("<{n}@example.org>"))
}

pub(super) fn exported(fixture: &Fixture, selector: &Selector) -> (tempfile::TempDir, PathBuf) {
	let out = tempfile::tempdir().expect("tempdir");
	let bundle = out.path().join("bundle");
	export(
		fixture.root(),
		&MessageCrypto::disabled(),
		selector,
		&bundle,
	)
	.expect("export");
	(out, bundle)
}

pub(super) fn failures(report: &CheckReport) -> Vec<String> {
	report
		.findings
		.iter()
		.filter_map(|finding| match &finding.result {
			Ok(()) => None,
			Err(why) => Some(format!("{}: {why}", finding.name)),
		})
		.collect()
}

pub(super) fn resum(bundle: &Path) {
	std::fs::remove_file(bundle.join("SHA256SUMS")).expect("remove sums");
	super::sums::write(bundle).expect("sums");
}

#[test]
fn an_exported_message_checks_offline_after_the_server_is_gone() {
	let fixture = Fixture::new();
	let anchor = fixture.tsa.anchor;
	let key = fixture.key.id();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	// Nothing of the server is left: only the bundle and the anchor.
	drop(fixture);
	let report = check(&bundle, &[anchor], &[key]).expect("check");
	assert!(report.passed(), "{:?}", failures(&report));
	let records =
		std::fs::read_to_string(bundle.join("records/2026-10-15.jsonl")).expect("records");
	assert_eq!(records.lines().count(), 2, "the acceptance and its outcome");
	assert!(
		report
			.findings
			.iter()
			.any(|f| f.name.contains("(a) the signer chains"))
	);
	assert!(report.notes.iter().any(|note| note.contains("not checked")));
}

#[test]
fn a_recipient_export_spans_days_and_takes_only_that_recipient() {
	let fixture = Fixture::new();
	let selector = Selector::Recipient {
		address: "STUDENT2@example.net".into(),
		from: Day(DAY),
		to: Day(DAY + 2),
	};
	let (_out, bundle) = exported(&fixture, &selector);
	let report = check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check");
	assert!(report.passed(), "{:?}", failures(&report));
	let days: Vec<_> = std::fs::read_dir(bundle.join("records"))
		.expect("records")
		.collect();
	assert_eq!(days.len(), 1, "student2 only appears on one day");
}

#[test]
fn an_unknown_message_and_an_existing_output_are_refused() {
	let fixture = Fixture::new();
	let out = tempfile::tempdir().expect("tempdir");
	let none = export(
		fixture.root(),
		&MessageCrypto::disabled(),
		&by_id(77),
		&out.path().join("b"),
	);
	assert!(matches!(none, Err(BundleError::Refused(_))));
	let exists = export(
		fixture.root(),
		&MessageCrypto::disabled(),
		&by_id(1),
		out.path(),
	);
	assert!(matches!(exists, Err(BundleError::Refused(_))));
}

#[test]
fn an_edited_record_fails_even_with_fresh_checksums() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let path = bundle.join("records/2026-10-15.jsonl");
	let edited = std::fs::read_to_string(&path)
		.expect("read")
		.replace("student1", "student9");
	std::fs::write(&path, edited).expect("write");
	assert!(
		!check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()])
			.expect("check")
			.passed()
	);
	resum(&bundle);
	let report = check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check");
	let failed = failures(&report);
	assert!(
		failed
			.iter()
			.any(|f| f.contains("included under the signed root")),
		"{failed:?}"
	);
	// The proof file names the new hash too: only the Merkle path catches it.
	let proofs = bundle.join("proofs/2026-10-15.json");
	let mut proof: DayProof =
		serde_json::from_slice(&std::fs::read(&proofs).expect("proofs")).expect("parse");
	let lines = std::fs::read_to_string(&path).expect("read");
	for (entry, line) in proof.entries.iter_mut().zip(lines.lines()) {
		entry.sha256 = to_hex(&sha256(line.as_bytes()));
	}
	std::fs::write(&proofs, serde_json::to_vec_pretty(&proof).expect("json")).expect("write");
	resum(&bundle);
	let failed =
		failures(&check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed
			.iter()
			.any(|f| f.contains("included under the signed root")),
		"{failed:?}"
	);
}

#[test]
fn an_edited_checkpoint_fails_its_signature_and_its_token() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let path = bundle.join("checkpoints/2026-10-15.json");
	let edited = std::fs::read_to_string(&path)
		.expect("read")
		.replace("\"records\": 2", "\"records\": 3");
	std::fs::write(&path, edited).expect("write");
	resum(&bundle);
	let failed =
		failures(&check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed
			.iter()
			.any(|f| f.contains("signed by the evidence key")),
		"{failed:?}"
	);
	assert!(
		failed.iter().any(|f| f.contains("(e) the imprint")),
		"{failed:?}"
	);
}

#[test]
fn a_substituted_key_is_refused_by_its_id() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let other = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(other.path()).expect("key");
	let id = fixture.key.id();
	let pem = crate::evidence::key::public_pem(&key.public_key());
	std::fs::write(bundle.join("keys").join(format!("{id}.pem")), pem).expect("write");
	resum(&bundle);
	let failed =
		failures(&check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed
			.iter()
			.any(|f| f.contains("signed by the evidence key")),
		"{failed:?}"
	);
}

#[test]
fn a_token_from_an_authority_not_trusted_by_the_reader_fails() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let stranger = FakeTsa::new(0);
	let failed = failures(&check(&bundle, &[stranger.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed.iter().any(|f| f.contains("(a) the signer chains")),
		"{failed:?}"
	);
}

#[test]
fn unlisted_files_and_links_are_refused() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	std::fs::write(bundle.join("extra.txt"), "added later").expect("write");
	let failed =
		failures(&check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed.iter().any(|f| f.contains("extra.txt: not listed")),
		"{failed:?}"
	);
	std::fs::remove_file(bundle.join("extra.txt")).expect("remove");
	// A link to an identical file outside the bundle is still refused.
	let key = bundle
		.join("keys")
		.join(format!("{}.pem", fixture.key.id()));
	let outside = bundle.with_file_name("outside.pem");
	std::fs::rename(&key, &outside).expect("move key");
	std::os::unix::fs::symlink(&outside, &key).expect("link key");
	let failed =
		failures(&check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed.iter().any(|f| f.contains("not a regular file")),
		"{failed:?}"
	);
	std::fs::remove_file(&key).expect("unlink");
	std::fs::rename(&outside, &key).expect("restore key");
	let records = bundle.join("records/2026-10-15.jsonl");
	let moved = bundle.join("elsewhere.jsonl");
	std::fs::rename(&records, &moved).expect("move");
	std::os::unix::fs::symlink(&moved, &records).expect("link");
	let failed =
		failures(&check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed.iter().any(|f| f.contains("not a regular file")),
		"{failed:?}"
	);
}

#[test]
fn a_bundle_without_any_checkpoint_does_not_pass() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	for entry in std::fs::read_dir(bundle.join("checkpoints")).expect("dir") {
		std::fs::remove_file(entry.expect("entry").path()).expect("remove");
	}
	resum(&bundle);
	let report = check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check");
	assert!(!report.passed());
	assert!(
		failures(&report)
			.iter()
			.any(|f| f.contains("at least one sealed day"))
	);
}

/// One transactional message kept in full, sealed and stamped.
pub(super) struct Kept {
	pub(super) dir: tempfile::TempDir,
	pub(super) tsa: FakeTsa,
	pub(super) id: Uuid,
	pub(super) crypto: MessageCrypto,
}

const BODY: &[u8] = b"Subject: notice\r\n\r\nYou were withdrawn from the course.\r\n";

fn kept(encrypted: bool) -> Kept {
	kept_stamped_at(encrypted, at(DAY + 1, 1))
}

pub(super) fn kept_stamped_at(encrypted: bool, gen_time: u64) -> Kept {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let tsa = FakeTsa::new(gen_time);
	let id = Uuid::from_u128(5);
	let crypto = match encrypted {
		true => MessageCrypto::for_test(&crate::test_fixtures::bytes::<32>()),
		false => MessageCrypto::disabled(),
	};
	let chain = Chain::open(dir.path()).expect("open");
	chain
		.append_at(
			at(DAY, 1),
			Entry::Accepted(Accepted {
				spool_id: id,
				account: "notices".into(),
				tenant: None,
				class: MailClass::Transactional,
				from: "notices@example.org".into(),
				recipients: vec!["student5@example.net".into()],
				message_id: Some("<kept@example.org>".into()),
				date: None,
				subject: None,
				sha256: to_hex(&sha256(BODY)),
				size: BODY.len() as u64,
				retention: Retention {
					mode: RetentionMode::Full,
					days: 30,
				},
			}),
		)
		.expect("append");
	let stored = dir.path().join("messages").join(Day(DAY).name()).join("30");
	std::fs::create_dir_all(&stored).expect("dir");
	let bytes = match encrypted {
		true => crypto
			.encode_with_aad(BODY, id.as_bytes())
			.expect("encrypt"),
		false => BODY.to_vec(),
	};
	std::fs::write(stored.join(format!("{id}.eml")), bytes).expect("write");
	seal_closed_days(dir.path(), &key, true, at(DAY + 1, 0)).expect("seal");
	let paths = files(dir.path(), Day(DAY));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		tsa.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	Kept {
		dir,
		tsa,
		id,
		crypto,
	}
}

#[test]
fn a_kept_message_goes_in_the_bundle_decrypted_and_is_checked() {
	for encrypted in [false, true] {
		let kept = kept(encrypted);
		let out = tempfile::tempdir().expect("tempdir");
		let bundle = out.path().join("bundle");
		let selector = Selector::MessageId("<kept@example.org>".into());
		export(kept.dir.path(), &kept.crypto, &selector, &bundle).expect("export");
		let message = bundle.join("messages").join(format!("{}.eml", kept.id));
		assert_eq!(std::fs::read(&message).expect("message"), BODY);
		let report = check(&bundle, &[kept.tsa.anchor], &[key_of(kept.dir.path())]).expect("check");
		assert!(report.passed(), "{:?}", failures(&report));
		std::fs::write(&message, b"Subject: notice\r\n\r\nSomething else.\r\n").expect("write");
		resum(&bundle);
		let failed = failures(
			&check(&bundle, &[kept.tsa.anchor], &[key_of(kept.dir.path())]).expect("check"),
		);
		assert!(
			failed
				.iter()
				.any(|f| f.contains("does not match its record")),
			"{failed:?}"
		);
	}
}

#[test]
fn a_day_sealed_without_timestamps_is_reported_as_such() {
	let kept = kept(false);
	let paths = files(kept.dir.path(), Day(DAY));
	for path in [&paths.json, &paths.sig, &paths.tsr] {
		std::fs::remove_file(path).expect("remove");
	}
	let key = EvidenceKey::load_or_create(kept.dir.path()).expect("key");
	seal_closed_days(kept.dir.path(), &key, false, at(DAY + 1, 0)).expect("seal");
	let out = tempfile::tempdir().expect("tempdir");
	let bundle = out.path().join("bundle");
	let selector = Selector::MessageId("<kept@example.org>".into());
	export(kept.dir.path(), &kept.crypto, &selector, &bundle).expect("export");
	let report = check(&bundle, &[kept.tsa.anchor], &[key_of(kept.dir.path())]).expect("check");
	let failed = failures(&report);
	assert!(
		failed
			.iter()
			.any(|f| f.contains("timestamps were disabled")),
		"{failed:?}"
	);
	assert!(
		report
			.findings
			.iter()
			.any(|f| f.name.contains("included") && f.result.is_ok())
	);
}

#[test]
fn a_key_id_that_is_a_path_is_refused() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let path = bundle.join("checkpoints/2026-10-15.json");
	let id = fixture.key.id();
	let edited = std::fs::read_to_string(&path)
		.expect("read")
		.replace(&id, "../../outside");
	std::fs::write(&path, edited).expect("write");
	resum(&bundle);
	let failed =
		failures(&check(&bundle, &[fixture.tsa.anchor], &[fixture.key.id()]).expect("check"));
	assert!(
		failed.iter().any(|f| f.contains("not a key id")),
		"{failed:?}"
	);
}

#[test]
fn a_token_dated_before_the_day_ended_fails() {
	// Stamped during the day it seals: it cannot cover the day's later records.
	let kept = kept_stamped_at(false, at(DAY, 20));
	let out = tempfile::tempdir().expect("tempdir");
	let bundle = out.path().join("bundle");
	let selector = Selector::MessageId("<kept@example.org>".into());
	export(kept.dir.path(), &kept.crypto, &selector, &bundle).expect("export");
	let failed =
		failures(&check(&bundle, &[kept.tsa.anchor], &[key_of(kept.dir.path())]).expect("check"));
	assert!(
		failed
			.iter()
			.any(|f| f.contains("stamped after the day ended")),
		"{failed:?}"
	);
}
