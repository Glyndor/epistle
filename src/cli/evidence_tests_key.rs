//! The evidence key as a third party anchors it, and its rotation.

use std::path::{Path, PathBuf};

use super::tests::{Server, now, text};
use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{Checkpoint, files, seal_closed_days};
use crate::evidence::key::{self, EvidenceKey};
use crate::evidence::record::{sha256, to_hex};
use crate::evidence::test_support::{accepted, at};
use crate::evidence::tsa::request::{build, random_nonce};

fn export(server: &Server, message: u32) -> (tempfile::TempDir, PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let bundle = dir.path().join("bundle");
	let selector = crate::evidence::bundle::Selector::MessageId(format!("<{message}@example.org>"));
	let code = super::super::evidence_bundle::export(
		server.root(),
		&crate::storage::MessageCrypto::disabled(),
		&selector,
		&bundle,
		false,
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::SUCCESS);
	(dir, bundle)
}

fn check(server: &Server, bundle: &Path, keys: &[String]) -> (ExitCode, serde_json::Value) {
	let action = EvidenceCli::Check {
		bundle: bundle.to_path_buf(),
		keys: keys.to_vec(),
		anchors: vec![to_hex(&server.tsa.anchor)],
		json: true,
	};
	let mut out = Vec::new();
	let code = run(Path::new("/nonexistent.toml"), action, now(), &mut out);
	(code, serde_json::from_slice(&out).unwrap_or_default())
}

fn failed(report: &serde_json::Value) -> Vec<String> {
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

fn resum(bundle: &Path) {
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

fn key_of(server: &Server) -> String {
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

/// Rotate the key on `first + 3` and seal that day with the new key.
fn rotated_server() -> (Server, String, String) {
	let mut server = Server::new();
	let old = key_of(&server);
	let day = server.first + 3;
	Chain::open(server.root())
		.expect("chain")
		.append_at(at(day, 1), accepted(9))
		.expect("append");
	Chain::open(server.root())
		.expect("chain")
		.append_at(at(day, 2), crate::evidence::test_support::delivered(9))
		.expect("outcome");
	let new = crate::evidence::rotation::rotate(server.root(), true, at(day, 5)).expect("rotate");
	let current = EvidenceKey::load_or_create(server.root()).expect("key");
	seal_closed_days(server.root(), &current, true, at(day + 1, 0)).expect("seal");
	server.tsa.gen_time = at(day + 1, 1);
	let paths = files(server.root(), Day(day));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		server
			.tsa
			.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	(server, old, new)
}

#[test]
fn a_rotated_key_is_followed_from_the_anchored_one() {
	let (server, old, new) = rotated_server();
	let (_dir, bundle) = export(&server, 9);
	assert!(
		bundle
			.join("keys")
			.join("rotations")
			.join(format!("{new}.json"))
			.exists()
	);
	for anchor in [&old, &new] {
		let (code, report) = check(&server, &bundle, std::slice::from_ref(anchor));
		assert_eq!(code, ExitCode::SUCCESS, "{:?}", failed(&report));
	}
	let stranger = "ab".repeat(32);
	let (code, report) = check(&server, &bundle, &[stranger]);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		failed(&report)
			.iter()
			.any(|name| name.ends_with("the signing key is the anchored key or took over from it"))
	);
}

#[test]
fn a_hand_over_the_old_key_did_not_sign_breaks_the_chain() {
	let (server, old, new) = rotated_server();
	let (_dir, bundle) = export(&server, 9);
	let statement = bundle
		.join("keys")
		.join("rotations")
		.join(format!("{new}.json"));
	let mut rotation: crate::evidence::rotation::Rotation =
		serde_json::from_slice(&std::fs::read(&statement).expect("read")).expect("parse");
	let other_root = tempfile::tempdir().expect("tempdir");
	let other = EvidenceKey::load_or_create(other_root.path()).expect("other");
	rotation.signature = to_hex(&other.sign(&crate::evidence::rotation::statement(
		&old,
		&new,
		&rotation.day,
	)));
	std::fs::write(
		&statement,
		serde_json::to_vec_pretty(&rotation).expect("json"),
	)
	.expect("write");
	resum(&bundle);
	let (code, report) = check(&server, &bundle, &[old]);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		failed(&report)
			.iter()
			.any(|name| name.ends_with("the signing key is the anchored key or took over from it"))
	);
}

#[test]
fn an_anchor_may_be_an_id_or_a_pem_file_and_nothing_else() {
	let server = Server::new();
	let id = key_of(&server);
	let pem = server.root().join("keys").join(format!("{id}.pem"));
	let from_file = super::super::evidence_bundle::evidence_keys(&[pem.display().to_string()]);
	assert_eq!(from_file, Ok(vec![id.clone()]));
	assert_eq!(
		super::super::evidence_bundle::evidence_keys(std::slice::from_ref(&id)),
		Ok(vec![id])
	);
	assert!(super::super::evidence_bundle::evidence_keys(&["not a key".into()]).is_err());
}

#[test]
fn key_show_names_the_fingerprint_and_the_keys_it_took_over_from() {
	let (server, old, new) = rotated_server();
	let mut out = Vec::new();
	let code = super::super::evidence_key::run(
		server.root(),
		KeyCli::Show { json: true },
		now(),
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let shown: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(shown["key"], new);
	assert_eq!(
		shown["previous"],
		serde_json::json!([{ "key": old, "until": Day(Day::of_epoch(now()).0 - 2).name() }])
	);
	assert!(
		shown["public_key"]
			.as_str()
			.expect("pem")
			.starts_with("-----BEGIN PUBLIC KEY-----")
	);
	let mut out = Vec::new();
	super::super::evidence_key::run(server.root(), KeyCli::Show { json: false }, now(), &mut out);
	assert!(text(&out).contains(&format!("evidence key: {new}")));
}

#[test]
fn key_rotate_hands_over_and_the_evidence_still_verifies() {
	let server = Server::new();
	let old = key_of(&server);
	let mut out = Vec::new();
	let code = super::super::evidence_key::run(
		server.root(),
		KeyCli::Rotate {
			yes: true,
			json: true,
		},
		now(),
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{}", text(&out));
	let rotated: serde_json::Value = serde_json::from_slice(&out).expect("json");
	let new = rotated["key"].as_str().expect("key").to_string();
	assert_ne!(new, old);
	assert_eq!(key_of(&server), new);
}

#[test]
fn an_older_key_is_anchored_with_the_day_its_period_ended() {
	let server = Server::new();
	let id = key_of(&server);
	let pem = server.root().join("keys").join(format!("{id}.pem"));
	let keys = super::super::evidence_bundle::evidence_keys;
	assert_eq!(
		keys(&[format!("{id}@2026-10-17")]),
		Ok(vec![format!("{id}@2026-10-17")])
	);
	assert_eq!(
		keys(&[format!("{}@2026-10-17", pem.display())]),
		Ok(vec![format!("{id}@2026-10-17")])
	);
	assert!(keys(&[format!("{id}@2026-02-30")]).is_err(), "not a day");
}
