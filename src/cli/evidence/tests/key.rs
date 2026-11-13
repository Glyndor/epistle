//! The evidence key as a third party anchors it, and its rotation.

use std::path::{Path, PathBuf};

use super::base::{Server, now, text};
use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::Checkpoint;
use crate::evidence::key::{self, EvidenceKey};
use crate::evidence::record::{sha256, to_hex};
use crate::evidence::test_support::{accepted, at};

pub(super) fn export(server: &Server, message: u32) -> (tempfile::TempDir, PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let bundle = dir.path().join("bundle");
	let selector = crate::evidence::bundle::Selector::MessageId(format!("<{message}@example.org>"));
	let code = crate::cli::evidence::bundle::export(
		server.root(),
		&crate::storage::MessageCrypto::disabled(),
		&selector,
		&bundle,
		(false, false),
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::SUCCESS);
	(dir, bundle)
}

pub(super) fn check(
	server: &Server,
	bundle: &Path,
	keys: &[String],
) -> (ExitCode, serde_json::Value) {
	let action = EvidenceCli::Check {
		bundle: bundle.to_path_buf(),
		message_id: None,
		recipient: None,
		from: None,
		to: None,
		keys: keys.to_vec(),
		anchors: vec![to_hex(&server.tsa.anchor)],
		require_delivered: false,
		json: true,
	};
	let mut out = Vec::new();
	let code = run(Path::new("/nonexistent.toml"), action, now(), &mut out);
	(code, serde_json::from_slice(&out).unwrap_or_default())
}

pub(super) fn failed(report: &serde_json::Value) -> Vec<String> {
	report["findings"]
		.as_array()
		.map(|findings| {
			findings
				.iter()
				.filter(|finding| finding["ok"] == false)
				.map(|finding| finding["check"].as_str().unwrap_or_default().to_string())
				.collect()
		})
		.unwrap_or_default()
}

pub(super) fn resum(bundle: &Path) {
	let mut lines = Vec::new();
	let mut pending = vec![bundle.to_path_buf()];
	while let Some(dir) = pending.pop() {
		for entry in std::fs::read_dir(dir).expect("read") {
			let path = entry.expect("entry").path();
			if path.is_dir() {
				pending.push(path);
			} else if path.file_name().is_some_and(|name| name != "SHA256SUMS") {
				let relative = path.strip_prefix(bundle).expect("inside");
				let digest = to_hex(&sha256(&std::fs::read(&path).expect("read")));
				lines.push(format!("{digest}  {}\n", relative.display()));
			}
		}
	}
	lines.sort();
	std::fs::write(bundle.join("SHA256SUMS"), lines.concat()).expect("sums");
}

pub(super) fn key_of(server: &Server) -> String {
	EvidenceKey::load_or_create(server.root())
		.expect("key")
		.id()
}

#[test]
fn a_check_without_a_key_fails_because_the_bundle_cannot_vouch_for_its_own_key() {
	let server = Server::new();
	let (_dir, bundle) = export(&server, 1);
	let (code, report) = check(&server, &bundle, &[]);
	assert_eq!(code, ExitCode::FAILURE);
	assert_eq!(failed(&report)[0], "the evidence key is anchored");
}

#[test]
fn a_bundle_re_signed_with_another_key_fails_against_the_real_one() {
	let server = Server::new();
	let real = key_of(&server);
	let (_dir, bundle) = export(&server, 1);
	assert_eq!(
		check(&server, &bundle, std::slice::from_ref(&real)).0,
		ExitCode::SUCCESS
	);
	// The operator re-signs every checkpoint with a key of their own and
	// publishes it in the bundle.
	let other_root = tempfile::tempdir().expect("tempdir");
	let other = EvidenceKey::load_or_create(other_root.path()).expect("other");
	for entry in std::fs::read_dir(bundle.join("checkpoints")).expect("read") {
		let path = entry.expect("entry").path();
		if path.extension().is_some_and(|ext| ext == "json") {
			let mut checkpoint: Checkpoint =
				serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
			checkpoint.key = other.id();
			let bytes = serde_json::to_vec_pretty(&checkpoint).expect("encode");
			std::fs::write(path.with_extension("sig"), other.sign(&bytes)).expect("sig");
			std::fs::write(&path, bytes).expect("json");
		}
	}
	std::fs::write(
		bundle.join("keys").join(format!("{}.pem", other.id())),
		key::public_pem(&other.public_key()),
	)
	.expect("pem");
	resum(&bundle);
	let (code, report) = check(&server, &bundle, &[real]);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		failed(&report)
			.iter()
			.any(|name| name.ends_with("the signing key is the anchored key or took over from it")),
		"{:?}",
		failed(&report)
	);
	// Against its own key it vouches for itself on that point, which is why
	// the reader must bring the key.
	let (_, own) = check(&server, &bundle, &[other.id()]);
	assert!(
		!failed(&own)
			.iter()
			.any(|name| name.ends_with("the signing key is the anchored key or took over from it")),
		"{:?}",
		failed(&own)
	);
}

#[test]
fn check_tells_the_scope_and_refuses_a_bundle_about_something_else() {
	let server = Server::new();
	let key = key_of(&server);
	let (_dir, bundle) = export(&server, 1);
	let run_check = |message_id: Option<&str>, recipient: Option<&str>| {
		let action = EvidenceCli::Check {
			bundle: bundle.clone(),
			keys: vec![key.clone()],
			message_id: message_id.map(String::from),
			recipient: recipient.map(String::from),
			from: None,
			to: None,
			anchors: vec![to_hex(&server.tsa.anchor)],
			require_delivered: false,
			json: false,
		};
		let mut out = Vec::new();
		let code = run(Path::new("/nonexistent.toml"), action, now(), &mut out);
		(code, text(&out))
	};
	let (code, said) = run_check(Some("<1@example.org>"), Some("student1@example.net"));
	assert_eq!(code, ExitCode::SUCCESS, "{said}");
	assert!(
		said.contains("the records of all the recipients it names were looked at"),
		"{said}"
	);
	let (code, said) = run_check(Some("<2@example.org>"), None);
	assert_eq!(code, ExitCode::FAILURE, "{said}");
	assert!(
		said.contains(
			"the bundle was made for message <1@example.org>, not for message <2@example.org>"
		),
		"{said}"
	);
	let (code, said) = run_check(None, Some("nobody@example.net"));
	assert_eq!(code, ExitCode::FAILURE, "{said}");
	assert!(
		said.contains("was not sent to nobody@example.net"),
		"{said}"
	);
}

#[test]
fn an_export_that_leaves_records_out_for_want_of_a_seal_does_not_say_it_succeeded() {
	let server = Server::new();
	// A closed day nobody sealed.
	let day = server.first + 3;
	let chain = Chain::open(server.root()).expect("chain");
	chain.append_at(at(day, 1), accepted(8)).expect("accepted");
	chain
		.append_at(at(day, 2), crate::evidence::test_support::delivered(8))
		.expect("outcome");
	let export_with = |allow: bool| {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut out = Vec::new();
		let code = crate::cli::evidence::bundle::export(
			server.root(),
			&crate::storage::MessageCrypto::disabled(),
			&crate::evidence::bundle::Selector::MessageId("<8@example.org>".into()),
			&dir.path().join("bundle"),
			(false, allow),
			&mut out,
		);
		(code, text(&out))
	};
	let (code, said) = export_with(false);
	assert_eq!(code, ExitCode::FAILURE, "{said}");
	assert!(said.contains("not included, not sealed yet"), "{said}");
	assert!(said.contains("--allow-unsealed"), "{said}");
	let (code, said) = export_with(true);
	assert_eq!(code, ExitCode::SUCCESS, "{said}");
}
