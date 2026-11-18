//! Acknowledgements, policy changes, clock acceptance and export.

use std::io::IsTerminal;

use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Entry, Record};

use super::base::*;

#[test]
fn acknowledge_records_a_signed_acknowledgement_of_the_first_break() {
	let server = Server::new();
	server.trust();
	let mut out = Vec::new();
	let code = crate::cli::evidence::verify::acknowledge(
		server.root(),
		"ok",
		true,
		now(),
		false,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(text(&out).contains("nothing to acknowledge"));
	tamper(&server);
	let blank = crate::cli::evidence::verify::acknowledge(
		server.root(),
		"  ",
		true,
		now(),
		false,
		&mut Vec::new(),
	);
	assert_eq!(blank, ExitCode::from(2), "a reason is required");
	if !std::io::stdin().is_terminal() {
		let unconfirmed = crate::cli::evidence::verify::acknowledge(
			server.root(),
			"restored",
			false,
			now(),
			false,
			&mut Vec::new(),
		);
		assert_eq!(unconfirmed, ExitCode::from(2), "no terminal and no --yes");
	}
	let mut out = Vec::new();
	let code = crate::cli::evidence::verify::acknowledge(
		server.root(),
		"disk restored from backup",
		true,
		now(),
		true,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{}", text(&out));
	let report = crate::evidence::audit::verify(
		server.root(),
		&crate::evidence::audit::Options {
			from: None,
			to: None,
			anchors: vec![server.tsa.anchor],
			now: now(),
		},
	)
	.expect("verify");
	assert_eq!(
		report.acknowledged.len(),
		1,
		"the break is acknowledged and stays visible"
	);
}

#[test]
fn policy_set_records_the_change_and_refuses_turning_transactional_off() {
	let server = Server::new();
	let set = |class: &str, mode, days| {
		crate::cli::evidence::policy::run(
			server.root(),
			PolicyCli::Set {
				class: class.into(),
				account: Some("Notices".into()),
				tenant: None,
				mode,
				days,
				json: false,
			},
			&mut Vec::new(),
		)
	};
	assert_eq!(set("transactional", Mode::Off, 0), ExitCode::from(2));
	assert_eq!(set("bulk", Mode::Full, 30), ExitCode::from(2));
	assert_eq!(set("transactional", Mode::Full, 400), ExitCode::SUCCESS);
	let policy = crate::evidence::policy::load(server.root()).expect("policy");
	assert_eq!(policy.rules.len(), 1);
	assert_eq!(
		policy.rules[0].scope,
		crate::evidence::policy::Scope::Account("notices".into())
	);
	assert!(last_setting(&server).contains("retention"));
	let mut out = Vec::new();
	let shown =
		crate::cli::evidence::policy::run(server.root(), PolicyCli::Show { json: true }, &mut out);
	assert_eq!(shown, ExitCode::SUCCESS);
	let shown: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(shown["rules"][0]["days"], 400);
}

pub(super) fn last_setting(server: &Server) -> String {
	let path = Chain::open(server.root())
		.expect("open")
		.day_file(Day::of_epoch(now()));
	let text = std::fs::read_to_string(path).expect("today's records");
	let line = text.lines().last().expect("a record");
	let record = Record::parse_canonical(line.as_bytes()).expect("record");
	match record.entry {
		Entry::Setting(setting) => format!("{} {}", setting.name, setting.value),
		other => panic!("last record is {other:?}"),
	}
}

#[test]
fn timestamps_disable_and_enable_are_recorded() {
	let server = Server::new();
	if !std::io::stdin().is_terminal() {
		let unconfirmed = crate::cli::evidence::timestamp::run(
			server.root(),
			TimestampCli::Disable {
				yes: false,
				json: false,
			},
			&mut Vec::new(),
		);
		assert_eq!(unconfirmed, ExitCode::from(2), "no terminal and no --yes");
		assert!(
			crate::evidence::tsa::settings::load(server.root())
				.expect("settings")
				.enabled
		);
	}
	let code = crate::cli::evidence::timestamp::run(
		server.root(),
		TimestampCli::Disable {
			yes: true,
			json: false,
		},
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		!crate::evidence::tsa::settings::load(server.root())
			.expect("settings")
			.enabled
	);
	assert!(last_setting(&server).starts_with("timestamp disabled by uid="));
	let refused = crate::cli::evidence::timestamp::run(
		server.root(),
		TimestampCli::Enable {
			urls: vec!["http://tsa.example.net".into()],
			anchors: vec!["ab".repeat(32)],
			policy: None,
			token_file: None,
			json: false,
		},
		&mut Vec::new(),
	);
	assert_eq!(refused, ExitCode::from(2), "plain HTTP is refused");
	let mut out = Vec::new();
	let code = crate::cli::evidence::timestamp::run(
		server.root(),
		TimestampCli::Enable {
			urls: Vec::new(),
			anchors: Vec::new(),
			policy: None,
			token_file: None,
			json: true,
		},
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let shown: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(shown["authorities"][0], "timestamp.sectigo.com");
	assert!(last_setting(&server).starts_with("timestamp enabled (timestamp.sectigo.com)"));
}

#[test]
fn clock_accept_leaves_a_request_the_server_can_take() {
	let server = Server::new();
	let mut out = Vec::new();
	// One reading of the clock for the whole test: two readings can fall in
	// different seconds and make the comparison below fail by one.
	let at = now();
	let code = crate::cli::evidence::clock::run(
		server.root(),
		super::ClockCli::Accept {
			yes: true,
			json: true,
		},
		at,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let reply: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(reply["accepted"], at);
	assert!(crate::evidence::clock_accept::take(server.root(), at + 5));
	if !std::io::stdin().is_terminal() {
		let unconfirmed = crate::cli::evidence::clock::run(
			server.root(),
			super::ClockCli::Accept {
				yes: false,
				json: false,
			},
			now(),
			&mut Vec::new(),
		);
		assert_eq!(unconfirmed, ExitCode::from(2), "no terminal and no --yes");
		assert!(!crate::evidence::clock_accept::take(server.root(), now()));
	}
}

#[test]
fn an_accepted_break_is_not_reported_as_verified() {
	let server = Server::new();
	server.trust();
	// A token lost: a break the seal alone accounts for.
	std::fs::remove_file(crate::evidence::checkpoint::files(server.root(), Day(server.first)).tsr)
		.expect("remove the token");
	let code = crate::cli::evidence::verify::acknowledge(
		server.root(),
		"token lost in a disk failure",
		true,
		now(),
		false,
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let mut out = Vec::new();
	let code =
		crate::cli::evidence::verify::verify(server.root(), None, None, now(), true, &mut out);
	assert_eq!(code, ExitCode::SUCCESS, "mail flows again");
	let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(report["no_open_break"], true);
	assert_eq!(
		report["verified"], false,
		"an accepted break was called verified"
	);
	let mut out = Vec::new();
	let _ = crate::cli::evidence::verify::verify(server.root(), None, None, now(), false, &mut out);
	assert!(
		text(&out).contains("verifies except for 1 acknowledged break"),
		"{}",
		text(&out)
	);
}

/// A run delegated to the service account writes into a staged copy of the
/// directory; the line it prints names the path the operator asked for.
#[test]
fn export_names_the_requested_path_not_the_staged_one() {
	let server = Server::new();
	let out_dir = tempfile::tempdir().expect("tempdir");
	let staged = out_dir.path().join("staged-bundle");
	let staged_text = staged.display().to_string();
	let selector = crate::evidence::bundle::Selector::MessageId("<1@example.org>".into());
	for as_json in [false, true] {
		let _ = std::fs::remove_dir_all(&staged);
		let mut out = Vec::new();
		let code =
			super::super::super::staging::with_shown_pair(&staged_text, "/home/op/bundle", || {
				crate::cli::evidence::bundle::export(
					server.root(),
					&crate::storage::MessageCrypto::disabled(),
					&selector,
					&staged,
					(as_json, false),
					&mut out,
				)
			});
		assert_eq!(code, ExitCode::SUCCESS, "{}", text(&out));
		let printed = text(&out);
		assert!(printed.contains("/home/op/bundle"), "{printed}");
		assert!(!printed.contains(&staged_text), "{printed}");
	}
}
