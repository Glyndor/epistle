//! Checking a bundle that carries a bounce, which is not a delivery.

use std::path::{Path, PathBuf};

use super::base::{Server, now, text};
use super::key::{export, key_of};
use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{Entry, sha256, to_hex};
use crate::evidence::test_support::{accepted, at};
use crate::evidence::tsa::request::{build, random_nonce};

/// A message accepted and then bounced, on a day sealed and stamped after
/// the server's own, and the bundle of it.
fn bounced_bundle(server: &mut Server) -> (tempfile::TempDir, PathBuf) {
	let chain = Chain::open(server.root()).expect("chain");
	let day = server.first + 3;
	chain.append_at(at(day, 1), accepted(9)).expect("accepted");
	let Entry::Outcome(mut outcome) = crate::evidence::test_support::delivered(9) else {
		unreachable!()
	};
	outcome.result = crate::evidence::record::OutcomeKind::Bounced;
	outcome.reply = Some("550 5.1.1 no such user".into());
	chain
		.append_at(at(day, 2), Entry::Outcome(outcome))
		.expect("bounced");
	let key = EvidenceKey::load_or_create(server.root()).expect("key");
	seal_closed_days(server.root(), &key, true, at(day + 1, 0)).expect("seal");
	server.tsa.gen_time = at(day + 1, 1);
	let paths = files(server.root(), crate::evidence::day::Day(day));
	let json = std::fs::read(&paths.json).expect("json");
	std::fs::write(
		&paths.tsr,
		server
			.tsa
			.respond(&build(&sha256(&json), random_nonce()).der),
	)
	.expect("tsr");
	export(server, 9)
}

#[test]
fn check_says_a_bounce_is_not_a_delivery_and_can_be_made_to_fail_on_it() {
	let mut server = Server::new();
	let key = key_of(&server);
	let (_kept, bounced) = bounced_bundle(&mut server);
	let (_dir, delivered) = export(&server, 1);
	let run_check = |bundle: &Path, require_delivered: bool| {
		let action = EvidenceCli::Check {
			bundle: bundle.to_path_buf(),
			keys: vec![key.clone()],
			message_id: None,
			recipient: None,
			from: None,
			to: None,
			anchors: vec![to_hex(&server.tsa.anchor)],
			require_delivered,
			json: true,
		};
		let mut out = Vec::new();
		let code = run(Path::new("/nonexistent.toml"), action, now(), &mut out);
		(
			code,
			serde_json::from_slice::<serde_json::Value>(&out).expect("json"),
		)
	};
	let (code, report) = run_check(&delivered, true);
	assert_eq!(code, ExitCode::SUCCESS, "{report}");
	assert_eq!(report["all_delivered"], true);
	assert_eq!(report["delivery"]["delivered"], 1);
	let (code, report) = run_check(&bounced, false);
	assert_eq!(code, ExitCode::SUCCESS, "it verifies: {report}");
	assert_eq!(report["passed"], true);
	assert_eq!(report["all_delivered"], false);
	assert_eq!(report["delivery"]["bounced"], 1);
	assert_eq!(report["delivery"]["delivered"], 0);
	let (code, report) = run_check(&bounced, true);
	assert_eq!(code, ExitCode::FAILURE, "{report}");
	assert_eq!(report["passed"], true, "the bundle itself verifies");
}

#[test]
fn the_text_of_a_check_does_not_call_a_bounce_a_delivery() {
	let mut server = Server::new();
	let key = key_of(&server);
	let (_kept, bounced) = bounced_bundle(&mut server);
	let action = EvidenceCli::Check {
		bundle: bounced,
		keys: vec![key],
		message_id: None,
		recipient: None,
		from: None,
		to: None,
		anchors: vec![to_hex(&server.tsa.anchor)],
		require_delivered: false,
		json: false,
	};
	let mut out = Vec::new();
	let code = run(Path::new("/nonexistent.toml"), action, now(), &mut out);
	let said = text(&out);
	assert_eq!(code, ExitCode::SUCCESS, "{said}");
	assert!(said.contains("delivery: 0 delivered, 1 bounced"), "{said}");
	assert!(
		said.contains("does NOT show that every recipient it covers was delivered"),
		"{said}"
	);
	assert!(
		!said.contains("every recipient it covers was delivered\n"),
		"{said}"
	);
}

#[test]
fn a_bundle_that_fails_reports_nothing_of_delivery_in_json() {
	let mut server = Server::new();
	let key = key_of(&server);
	let (_dir, delivered) = export(&server, 1);
	let _ = &mut server;
	// A file nothing vouches for.
	std::fs::write(delivered.join("records/stray.txt"), b"x").expect("stray");
	let action = EvidenceCli::Check {
		bundle: delivered,
		keys: vec![key],
		message_id: None,
		recipient: None,
		from: None,
		to: None,
		anchors: vec![to_hex(&server.tsa.anchor)],
		require_delivered: false,
		json: true,
	};
	let mut out = Vec::new();
	let code = run(Path::new("/nonexistent.toml"), action, now(), &mut out);
	let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(code, ExitCode::FAILURE, "{report}");
	assert_eq!(report["passed"], false);
	assert_eq!(report["all_delivered"], false);
	assert!(report["delivery"].is_null(), "{report}");
}
