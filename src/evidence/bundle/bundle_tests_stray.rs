//! A bundle holds only what the checks vouch for.

use std::os::unix::fs::symlink;

use super::tests::{by_id, exported, failures, resum};
use super::*;
use crate::evidence::audit::tests::Fixture;

const DAY_NAME: &str = "2026-10-15";

fn stray_failures(fixture: &Fixture, bundle: &std::path::Path) -> Vec<String> {
	failures(&check(bundle, &[fixture.tsa.anchor]).expect("check"))
}

#[test]
fn a_bundle_as_exported_has_no_stray_file() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	assert_eq!(stray_failures(&fixture, &bundle), Vec::<String>::new());
}

#[test]
fn a_file_planted_in_any_directory_fails_even_with_fresh_checksums() {
	let fixture = Fixture::new();
	for dir in [
		"records",
		"proofs",
		"messages",
		"keys",
		"tsa",
		"checkpoints",
	] {
		let (_out, bundle) = exported(&fixture, &by_id(1));
		let planted = bundle.join(dir).join("planted.bin");
		std::fs::create_dir_all(planted.parent().expect("parent")).expect("dir");
		std::fs::write(&planted, "added later").expect("write");
		resum(&bundle);
		assert_eq!(
			stray_failures(&fixture, &bundle),
			vec![format!(
				"every file belongs to a verified day or an accepted record: {dir}/planted.bin: not vouched for by any check"
			)],
			"{dir}"
		);
	}
}

#[test]
fn a_file_named_like_a_real_one_but_of_another_day_or_message_fails() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let records = bundle.join("records");
	std::fs::copy(
		records.join(format!("{DAY_NAME}.jsonl")),
		records.join("2026-10-16.jsonl"),
	)
	.expect("copy");
	std::fs::create_dir_all(bundle.join("messages")).expect("dir");
	std::fs::write(
		bundle
			.join("messages")
			.join("00000000-0000-0000-0000-000000000000.eml"),
		"not a message of this bundle",
	)
	.expect("write");
	resum(&bundle);
	// Sorted by name, the message comes first; the copied day is the other.
	assert_eq!(
		stray_failures(&fixture, &bundle),
		vec![
			"every file belongs to a verified day or an accepted record: messages/00000000-0000-0000-0000-000000000000.eml: not vouched for by any check (and 1 more)"
				.to_string()
		]
	);
}

#[test]
fn a_link_nobody_listed_is_not_vouched_for_either() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	symlink("/etc/hostname", bundle.join("keys").join("link.pem")).expect("link");
	let failed = stray_failures(&fixture, &bundle);
	assert!(
		failed
			.iter()
			.any(|f| f.contains("keys/link.pem: not vouched for")),
		"{failed:?}"
	);
}

#[test]
fn the_files_of_a_day_that_fails_are_not_vouched_for() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let proofs = bundle.join("proofs").join(format!("{DAY_NAME}.json"));
	std::fs::write(&proofs, "{}").expect("write");
	resum(&bundle);
	let failed = stray_failures(&fixture, &bundle);
	assert_eq!(
		failed.last().map(String::as_str),
		Some(
			"every file belongs to a verified day or an accepted record: checkpoints/2026-10-15.json: not vouched for by any check (and 6 more)"
		),
		"{failed:?}"
	);
}

#[test]
fn an_altered_certificate_chain_file_fails_even_with_fresh_checksums() {
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let chain = bundle.join("tsa").join(format!("{DAY_NAME}-chain.pem"));
	let text = std::fs::read_to_string(&chain).expect("chain");
	std::fs::write(&chain, text.replacen('A', "B", 1)).expect("write");
	resum(&bundle);
	let failed = stray_failures(&fixture, &bundle);
	assert_eq!(
		failed.first().map(String::as_str),
		Some(
			"2026-10-15: the certificate chain file is the one the token carries: differs from the certificates in the token"
		),
		"{failed:?}"
	);
	std::fs::remove_file(&chain).expect("remove");
	resum(&bundle);
	let failed = stray_failures(&fixture, &bundle);
	assert_eq!(
		failed.first().map(String::as_str),
		Some("2026-10-15: the certificate chain file is the one the token carries: missing"),
		"{failed:?}"
	);
}
