//! `epistle queue destinations` and `release-destination` against the
//! holds file the worker reads.

use super::*;
use crate::cli::{Cli, Command};
use crate::storage::DestinationHold;
use clap::Parser;

const NOW: u64 = 1_800_000_000;

fn run_args(dir: &Path, args: &[&str]) -> (ExitCode, String) {
	let mut argv = vec!["epistle", "queue"];
	argv.extend(args);
	let cli = Cli::try_parse_from(argv).expect("parse");
	let Command::Queue { action, .. } = cli.command else {
		panic!("not a queue command");
	};
	let mut out = Vec::new();
	let code = run(dir, 0, action, NOW, None, &mut out);
	(code, String::from_utf8(out).expect("utf8"))
}

fn held(dir: &Path) -> FsSpool {
	let spool = FsSpool::open(dir).expect("spool");
	spool
		.update_holds(|holds| {
			holds.insert(
				"busy.example".into(),
				DestinationHold {
					until: NOW + 300,
					level: 1,
					reason: "421 4.7.0 slow down".into(),
					since: NOW - 120,
					sender: None,
				},
			);
			holds.insert(
				"over.example".into(),
				DestinationHold {
					until: NOW - 1,
					level: 0,
					reason: "421 busy".into(),
					since: NOW - 61,
					sender: None,
				},
			);
		})
		.expect("holds");
	spool
}

#[test]
fn destinations_lists_the_holds_in_force_and_why() {
	let dir = tempfile::tempdir().expect("tempdir");
	held(dir.path());

	let (code, out) = run_args(dir.path(), &["destinations"]);

	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		out,
		format!(
			"busy.example\tuntil={} (in 300s)\tdeferrals=2\treason=421 4.7.0 slow down\n\
			 1 destinations on hold\n",
			NOW + 300
		)
	);
}

#[test]
fn destinations_json_is_one_array() {
	let dir = tempfile::tempdir().expect("tempdir");
	held(dir.path());

	let (code, out) = run_args(dir.path(), &["destinations", "--json"]);

	assert_eq!(code, ExitCode::SUCCESS);
	let value: serde_json::Value = serde_json::from_str(&out).expect("json");
	assert_eq!(
		value,
		serde_json::json!([{
			"domain": "busy.example",
			"until": NOW + 300,
			"since": NOW - 120,
			"deferrals": 2,
			"reason": "421 4.7.0 slow down",
		}])
	);
}

#[test]
fn release_destination_lifts_one_hold_and_refuses_an_unknown_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = held(dir.path());

	let (code, out) = run_args(dir.path(), &["release-destination", "Busy.Example."]);
	assert_eq!(
		(code, out.as_str()),
		(ExitCode::SUCCESS, "released busy.example\n")
	);
	assert!(
		!spool
			.load_holds()
			.expect("holds")
			.contains_key("busy.example")
	);
	assert!(
		spool
			.load_holds()
			.expect("holds")
			.contains_key("over.example")
	);

	let (code, out) = run_args(dir.path(), &["release-destination", "busy.example"]);
	assert_eq!(code, crate::cli::exit::refused("test"));
	assert!(out.is_empty());

	let (code, out) = run_args(dir.path(), &["release-destination", "--all"]);
	assert_eq!(
		(code, out.as_str()),
		(ExitCode::SUCCESS, "released 1 destinations\n")
	);
	assert!(spool.load_holds().expect("holds").is_empty());
}

#[test]
fn release_destination_needs_a_domain_or_all() {
	for args in [
		vec!["epistle", "queue", "release-destination"],
		vec![
			"epistle",
			"queue",
			"release-destination",
			"a.example",
			"--all",
		],
	] {
		assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
	}
}

#[test]
fn the_queue_listing_names_the_destinations_on_hold() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.update_holds(|holds| {
			holds.insert(
				"busy.example".into(),
				DestinationHold {
					until: now_epoch() + 3600,
					level: 0,
					reason: "421 4.7.0 slow down".into(),
					since: now_epoch(),
					sender: None,
				},
			);
		})
		.expect("holds");
	let mut out = Vec::new();

	assert_eq!(list(dir.path(), &mut out), ExitCode::SUCCESS);

	let out = String::from_utf8(out).expect("utf8");
	assert!(
		out.ends_with("1 destinations on hold: busy.example (see `epistle queue destinations`)\n"),
		"{out}"
	);
}

#[test]
fn a_remote_reply_cannot_drive_the_terminal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let reply = "421 \u{1b}[2J\u{1b}[31mslow\r\nfake line\tand \u{9b}31m";
	spool
		.update_holds(|holds| {
			holds.insert(
				"mx:evil\u{1b}]0;title\u{7}.example".into(),
				DestinationHold {
					until: NOW + 60,
					level: 0,
					reason: reply.into(),
					since: NOW,
					sender: None,
				},
			);
		})
		.expect("holds");

	let (_, text) = run_args(dir.path(), &["destinations"]);
	assert!(
		!text
			.chars()
			.any(|c| c.is_control() && c != '\t' && c != '\n'),
		"{text:?}"
	);
	assert_eq!(text.lines().count(), 2, "{text:?}");
	assert!(
		text.contains("421 \\u{1b}[2J\\u{1b}[31mslow\\r\\nfake line\\tand \\u{9b}31m"),
		"{text:?}"
	);
	assert!(
		text.contains("mx:evil\\u{1b}]0;title\\u{7}.example"),
		"{text:?}"
	);

	let (_, json) = run_args(dir.path(), &["destinations", "--json"]);
	let value: serde_json::Value = serde_json::from_str(&json).expect("json");
	assert_eq!(value[0]["reason"], reply, "JSON keeps the reply exact");
}

#[test]
fn queue_show_escapes_the_last_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
				sender_verified: false,
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
	spool
		.update_envelope(id, |envelope| {
			envelope.last_error = Some("450 \u{1b}[2Jgone\r\nfake: line".into());
		})
		.expect("update");

	let (_, text) = run_args(dir.path(), &["show", &id.to_string()]);

	assert!(
		text.contains("last error: 450 \\u{1b}[2Jgone\\r\\nfake: line\n"),
		"{text:?}"
	);
	assert!(!text.contains('\u{1b}'), "{text:?}");
}

#[test]
fn a_held_sender_is_released_by_its_key_as_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.update_holds(|holds| {
			holds.insert(
				"sender:account:Bob".into(),
				DestinationHold {
					until: NOW + 60,
					level: 0,
					reason: "421 busy".into(),
					since: NOW,
					sender: Some("account:Bob".into()),
				},
			);
		})
		.expect("holds");

	let (code, out) = run_args(dir.path(), &["release-destination", "sender:account:Bob"]);

	assert_eq!(
		(code, out.as_str()),
		(ExitCode::SUCCESS, "released sender:account:Bob\n")
	);
	assert!(spool.load_holds().expect("holds").is_empty());
}
