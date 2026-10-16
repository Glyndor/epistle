use std::io::IsTerminal;

use clap::Parser;

use super::*;
use crate::cli::{Cli, Command};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{Entry, Record, sha256};
use crate::evidence::test_support::{accepted, at, delivered};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
	let mut argv = vec!["epistle", "evidence"];
	argv.extend(args);
	Cli::try_parse_from(argv)
}

fn now() -> u64 {
	super::super::ban::now_epoch()
}

/// Three sealed and stamped days, ending two days before today.
struct Server {
	dir: tempfile::TempDir,
	tsa: FakeTsa,
	first: i64,
}

impl Server {
	fn new() -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let first = Day::of_epoch(now()).0 - 5;
		let tsa = FakeTsa::new(at(first + 3, 1));
		let key = EvidenceKey::load_or_create(dir.path()).expect("key");
		let chain = Chain::open(dir.path()).expect("open");
		for offset in 0..3 {
			chain
				.append_at(at(first + offset, 1), accepted(offset as u32))
				.expect("append");
			chain
				.append_at(at(first + offset, 2), delivered(offset as u32))
				.expect("append");
		}
		seal_closed_days(dir.path(), &key, true, at(first + 3, 0)).expect("seal");
		for offset in 0..3 {
			let paths = files(dir.path(), Day(first + offset));
			let json = std::fs::read(&paths.json).expect("json");
			std::fs::write(
				&paths.tsr,
				tsa.respond(&build(&sha256(&json), random_nonce()).der),
			)
			.expect("tsr");
		}
		Server { dir, tsa, first }
	}

	fn root(&self) -> &Path {
		self.dir.path()
	}

	/// Trust the fake authority, as an operator would with `--anchor`.
	fn trust(&self) {
		let settings = crate::evidence::tsa::settings::Settings {
			enabled: false,
			authorities: vec![crate::evidence::tsa::settings::Authority {
				url: "https://tsa.example.net".into(),
				anchors: vec![crate::evidence::record::to_hex(&self.tsa.anchor)],
				policy: None,
				local_test: false,
				token_file: None,
			}],
		};
		crate::evidence::tsa::settings::save(self.root(), &settings).expect("save");
	}
}

fn text(out: &[u8]) -> String {
	String::from_utf8_lossy(out).to_string()
}

#[test]
fn check_parses_without_a_configuration_and_export_needs_a_selector() {
	let cli = parse(&["check", "bundle", "--anchor", "ab"]).expect("check parses");
	match cli.command {
		Command::Evidence {
			action: EvidenceCli::Check { anchors, .. },
			..
		} => assert_eq!(anchors, ["ab"]),
		other => panic!("parsed as {other:?}"),
	}
	assert!(parse(&["export", "--out", "b"]).is_err(), "no selector");
	assert!(
		parse(&["export", "--out", "b", "--recipient", "a@example.net"]).is_err(),
		"no range"
	);
	assert!(parse(&["export", "--out", "b", "--message-id", "<1@example.org>"]).is_ok());
	assert!(
		parse(&[
			"export",
			"--out",
			"b",
			"--recipient",
			"a@example.net",
			"--from",
			"2026-10-01",
			"--to",
			"2026-10-02"
		])
		.is_ok()
	);
	assert!(
		parse(&["verify", "--from", "2026-02-30"]).is_err(),
		"not a day"
	);
	assert!(
		parse(&["timestamp", "enable", "--tsa", "https://tsa.example.net"]).is_err(),
		"a URL needs an anchor"
	);
	assert!(parse(&["acknowledge"]).is_err(), "a reason is required");
}

#[test]
fn check_runs_without_any_configuration_file() {
	let server = Server::new();
	let out_dir = tempfile::tempdir().expect("tempdir");
	let bundle = out_dir.path().join("bundle");
	let selector = crate::evidence::bundle::Selector::MessageId("<1@example.org>".into());
	let mut out = Vec::new();
	let code = super::super::evidence_bundle::export(
		server.root(),
		&crate::storage::MessageCrypto::disabled(),
		&selector,
		&bundle,
		false,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{}", text(&out));
	let anchor = crate::evidence::record::to_hex(&server.tsa.anchor);
	let missing = out_dir.path().join("no-such-config.toml");
	let action = EvidenceCli::Check {
		bundle: bundle.clone(),
		anchors: vec![anchor.clone()],
		json: true,
	};
	let mut out = Vec::new();
	assert_eq!(
		run(&missing, action, now(), &mut out),
		ExitCode::SUCCESS,
		"{}",
		text(&out)
	);
	let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(report["passed"], true);
	assert!(
		report["notes"][0]
			.as_str()
			.expect("note")
			.contains("not checked")
	);
	// Without the anchor, only the default authority is trusted: it fails.
	let action = EvidenceCli::Check {
		bundle: bundle.clone(),
		anchors: Vec::new(),
		json: false,
	};
	let mut out = Vec::new();
	assert_eq!(run(&missing, action, now(), &mut out), ExitCode::FAILURE);
	assert!(text(&out).contains("FAIL") && text(&out).contains("does NOT verify"));
	let action = EvidenceCli::Check {
		bundle,
		anchors: vec!["zz".into()],
		json: false,
	};
	assert_eq!(
		run(&missing, action, now(), &mut Vec::new()),
		ExitCode::from(2)
	);
}

#[test]
fn verify_reports_intact_evidence_and_a_break() {
	let server = Server::new();
	server.trust();
	let mut out = Vec::new();
	let code =
		super::super::evidence_verify::verify(server.root(), None, None, now(), true, &mut out);
	assert_eq!(code, ExitCode::SUCCESS, "{}", text(&out));
	let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(report["verified"], true);
	assert_eq!(report["records"], 6);
	tamper(&server);
	let mut out = Vec::new();
	let code =
		super::super::evidence_verify::verify(server.root(), None, None, now(), false, &mut out);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(text(&out).contains("BREAK") && text(&out).contains("acknowledge"));
}

/// Change the middle day's last record in place.
fn tamper(server: &Server) {
	let path = Chain::open(server.root())
		.expect("open")
		.day_file(Day(server.first + 1));
	let edited = std::fs::read_to_string(&path)
		.expect("read")
		.replace("student1", "student7");
	std::fs::write(&path, edited).expect("write");
}

#[test]
fn acknowledge_records_a_signed_acknowledgement_of_the_first_break() {
	let server = Server::new();
	server.trust();
	let mut out = Vec::new();
	let code = super::super::evidence_verify::acknowledge(
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
	let blank = super::super::evidence_verify::acknowledge(
		server.root(),
		"  ",
		true,
		now(),
		false,
		&mut Vec::new(),
	);
	assert_eq!(blank, ExitCode::from(2), "a reason is required");
	if !std::io::stdin().is_terminal() {
		let unconfirmed = super::super::evidence_verify::acknowledge(
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
	let code = super::super::evidence_verify::acknowledge(
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
		super::super::evidence_policy::run(
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
		super::super::evidence_policy::run(server.root(), PolicyCli::Show { json: true }, &mut out);
	assert_eq!(shown, ExitCode::SUCCESS);
	let shown: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(shown["rules"][0]["days"], 400);
}

fn last_setting(server: &Server) -> String {
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
		let unconfirmed = super::super::evidence_timestamp::run(
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
	let code = super::super::evidence_timestamp::run(
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
	let refused = super::super::evidence_timestamp::run(
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
	let code = super::super::evidence_timestamp::run(
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
