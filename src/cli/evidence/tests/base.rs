use clap::Parser;

use super::*;
use crate::cli::{Cli, Command};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::sha256;
use crate::evidence::test_support::{accepted, at, delivered};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

pub(super) fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
	let mut argv = vec!["epistle", "evidence"];
	argv.extend(args);
	Cli::try_parse_from(argv)
}

pub(super) fn now() -> u64 {
	super::super::super::ban::now_epoch()
}

/// Three sealed and stamped days, ending two days before today.
pub(super) struct Server {
	pub(super) dir: tempfile::TempDir,
	pub(super) tsa: FakeTsa,
	pub(super) first: i64,
}

impl Server {
	pub(super) fn new() -> Self {
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
		// A server is running, and believes the clock: commands may date by it.
		crate::evidence::test_support::running_server(dir.path(), now());
		Server { dir, tsa, first }
	}

	pub(super) fn root(&self) -> &Path {
		self.dir.path()
	}

	/// Trust the fake authority, as an operator would with `--anchor`.
	pub(super) fn trust(&self) {
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

pub(super) fn text(out: &[u8]) -> String {
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
	let code = crate::cli::evidence::bundle::export(
		server.root(),
		&crate::storage::MessageCrypto::disabled(),
		&selector,
		&bundle,
		(false, false),
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{}", text(&out));
	let anchor = crate::evidence::record::to_hex(&server.tsa.anchor);
	let key = EvidenceKey::load_or_create(server.root())
		.expect("key")
		.id();
	let missing = out_dir.path().join("no-such-config.toml");
	let action = EvidenceCli::Check {
		bundle: bundle.clone(),
		message_id: None,
		recipient: None,
		from: None,
		to: None,
		keys: vec![key.clone()],
		anchors: vec![anchor.clone()],
		require_delivered: false,
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
		report["notes"]
			.as_array()
			.expect("notes")
			.iter()
			.any(|note| note.as_str().is_some_and(|n| n.contains("not checked")))
	);
	// Without the anchor, only the default authority is trusted: it fails.
	let action = EvidenceCli::Check {
		bundle: bundle.clone(),
		message_id: None,
		recipient: None,
		from: None,
		to: None,
		keys: vec![key],
		anchors: Vec::new(),
		require_delivered: false,
		json: false,
	};
	let mut out = Vec::new();
	assert_eq!(run(&missing, action, now(), &mut out), ExitCode::FAILURE);
	assert!(text(&out).contains("FAIL") && text(&out).contains("does NOT verify"));
	let action = EvidenceCli::Check {
		bundle,
		message_id: None,
		recipient: None,
		from: None,
		to: None,
		keys: Vec::new(),
		anchors: vec!["zz".into()],
		require_delivered: false,
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
		crate::cli::evidence::verify::verify(server.root(), None, None, now(), true, &mut out);
	assert_eq!(code, ExitCode::SUCCESS, "{}", text(&out));
	let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(report["verified"], true);
	assert_eq!(report["records"], 6);
	tamper(&server);
	let mut out = Vec::new();
	let code =
		crate::cli::evidence::verify::verify(server.root(), None, None, now(), false, &mut out);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(text(&out).contains("BREAK") && text(&out).contains("acknowledge"));
}

/// Change the middle day's last record in place.
pub(super) fn tamper(server: &Server) {
	let path = Chain::open(server.root())
		.expect("open")
		.day_file(Day(server.first + 1));
	let edited = std::fs::read_to_string(&path)
		.expect("read")
		.replace("student1", "student7");
	std::fs::write(&path, edited).expect("write");
}
