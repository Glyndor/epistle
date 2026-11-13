//! Rotation of the evidence key and the hand-overs a check follows.

use super::base::{Server, now, text};
use super::key::{check, export, failed, key_of, resum};
use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{sha256, to_hex};
use crate::evidence::test_support::{accepted, at};
use crate::evidence::tsa::request::{build, random_nonce};

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
	let new = crate::evidence::rotation::rotate_at(server.root(), at(day, 5)).expect("rotate");
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
	let from_file = crate::cli::evidence::bundle::evidence_keys(&[pem.display().to_string()]);
	assert_eq!(from_file, Ok(vec![id.clone()]));
	assert_eq!(
		crate::cli::evidence::bundle::evidence_keys(std::slice::from_ref(&id)),
		Ok(vec![id])
	);
	assert!(crate::cli::evidence::bundle::evidence_keys(&["not a key".into()]).is_err());
}

#[test]
fn key_show_names_the_fingerprint_and_the_keys_it_took_over_from() {
	let (server, old, new) = rotated_server();
	let mut out = Vec::new();
	let code =
		crate::cli::evidence::key::run(server.root(), KeyCli::Show { json: true }, now(), &mut out);
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
	let _ = crate::cli::evidence::key::run(
		server.root(),
		KeyCli::Show { json: false },
		now(),
		&mut out,
	);
	assert!(text(&out).contains(&format!("evidence key: {new}")));
}

#[test]
fn key_rotate_hands_over_and_the_evidence_still_verifies() {
	let server = Server::new();
	let old = key_of(&server);
	// Midday of the day, whatever the hour the test runs: a rotation waits
	// out the first half hour of a day.
	let midday = crate::evidence::day::Day::of_epoch(now()).start_epoch() + 12 * 3600;
	crate::evidence::test_support::running_server(server.root(), midday);
	let mut out = Vec::new();
	let code = crate::cli::evidence::key::run(
		server.root(),
		KeyCli::Rotate {
			yes: true,
			json: true,
		},
		midday,
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
	let keys = crate::cli::evidence::bundle::evidence_keys;
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
