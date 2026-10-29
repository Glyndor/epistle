//! `epistle queue destinations` and `release-destination` against the
//! holds the spool shows: recipients that wait after a slow-down reply.

use super::*;
use crate::cli::{Cli, Command};
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
	let code = run(dir, None, 0, action, false, NOW, None, &mut out);
	(code, String::from_utf8(out).expect("utf8"))
}

/// Queue a message to `recipient` that waits until `until` after
/// `deferrals` slow-down replies in a row from `remote`.
fn throttled(
	spool: &FsSpool,
	recipient: &str,
	(until, deferrals): (u64, u32),
	reason: &str,
	remote: &str,
) -> Uuid {
	let id = spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec![recipient.into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
	spool
		.update_envelope(id, |envelope| {
			let mut state = envelope.recipient_state(recipient);
			state.next_attempt = until;
			state.throttled = deferrals;
			state.attempts = deferrals;
			state.last_error = Some(reason.into());
			state.remote = Some(remote.into());
			envelope.set_recipient_state(recipient, state);
			envelope.settle();
		})
		.expect("throttle");
	id
}

fn held(dir: &Path) -> FsSpool {
	let spool = FsSpool::open(dir).expect("spool");
	throttled(
		&spool,
		"bob@busy.example",
		(NOW + 300, 2),
		"421 4.7.0 slow down",
		"mx.busy.example",
	);
	throttled(
		&spool,
		"carol@over.example",
		(NOW - 1, 1),
		"421 busy",
		"mx.over.example",
	);
	spool
}

fn state_of(spool: &FsSpool, recipient: &str) -> crate::storage::RecipientState {
	spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| spool.load_envelope(id).expect("envelope"))
		.find(|envelope| envelope.recipients.iter().any(|r| r == recipient))
		.expect("entry")
		.recipient_state(recipient)
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
			"domain busy.example\tuntil={until} (in 300s)\tdeferrals=2\treason=421 4.7.0 slow down\n\
			 exchanger mx.busy.example\tuntil={until} (in 300s)\tdeferrals=2\treason=421 4.7.0 slow down\n\
			 2 destinations on hold\n",
			until = "2027-01-15T08:05:00Z"
		)
	);
	assert!(
		!out.contains("1800000300"),
		"the epoch must not reach the text output: {out}"
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
		value[0],
		serde_json::json!({
			"kind": "domain",
			"name": "busy.example",
			"until": NOW + 300,
			"deferrals": 2,
			"reason": "421 4.7.0 slow down",
		})
	);
	assert_eq!(value.as_array().map(Vec::len), Some(2));
}

#[test]
fn release_destination_makes_the_waiting_recipients_due_and_refuses_an_unknown_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = held(dir.path());

	let (code, out) = run_args(dir.path(), &["release-destination", "Busy.Example."]);
	assert_eq!(
		(code, out.as_str()),
		(ExitCode::SUCCESS, "released busy.example\n")
	);
	let bob = state_of(&spool, "bob@busy.example");
	assert_eq!((bob.next_attempt, bob.throttled), (NOW, 0));
	assert_eq!(state_of(&spool, "carol@over.example").throttled, 1);

	let (code, out) = run_args(dir.path(), &["release-destination", "busy.example"]);
	assert_eq!(code, crate::cli::exit::refused("test"));
	assert!(out.is_empty());

	let (code, out) = run_args(dir.path(), &["release-destination", "--all"]);
	assert_eq!(
		(code, out.as_str()),
		(ExitCode::SUCCESS, "released 1 destinations\n")
	);
	assert_eq!(state_of(&spool, "carol@over.example").throttled, 0);
}

#[test]
fn release_destination_by_exchanger_frees_every_domain_waiting_for_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	for recipient in ["a@one.example", "b@two.example"] {
		throttled(
			&spool,
			recipient,
			(NOW + 60, 1),
			"421 slow down",
			"MX.Provider.Example",
		);
	}

	let (code, out) = run_args(dir.path(), &["release-destination", "mx.provider.example."]);

	assert_eq!(
		(code, out.as_str()),
		(ExitCode::SUCCESS, "released mx.provider.example\n")
	);
	for recipient in ["a@one.example", "b@two.example"] {
		assert_eq!(state_of(&spool, recipient).next_attempt, NOW, "{recipient}");
	}
}

#[test]
fn releasing_an_exchanger_frees_the_mail_of_other_domains_waiting_for_it() {
	// bob's domain never asked to slow down: his message only waits
	// because its exchanger is on hold for another domain.
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	throttled(
		&spool,
		"alice@one.example",
		(NOW + 300, 1),
		"421 slow down",
		"mx.provider.example",
	);
	throttled(
		&spool,
		"bob@two.example",
		(NOW + 300, 0),
		"mx.provider.example is on hold: 421 slow down",
		"mx.provider.example",
	);

	let (code, _) = run_args(dir.path(), &["release-destination", "mx.provider.example"]);

	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(state_of(&spool, "alice@one.example").next_attempt, NOW);
	assert_eq!(state_of(&spool, "bob@two.example").next_attempt, NOW);
}

#[test]
fn the_queue_listing_names_a_few_holds_however_many_there_are() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	for n in 0..30 {
		throttled(
			&spool,
			&format!("bob@d{n:02}.example"),
			(now_epoch() + 3600, 1),
			"421 slow down",
			"mx.provider.example",
		);
	}
	let mut out = Vec::new();

	assert_eq!(list(dir.path(), None, &mut out), ExitCode::SUCCESS);

	let out = String::from_utf8(out).expect("utf8");
	let line = out.lines().last().expect("summary");
	assert!(
		line.starts_with("31 destinations on hold: domain d00.example, "),
		"{line}"
	);
	assert!(
		line.ends_with("domain d09.example and 21 more (see `epistle queue destinations`)"),
		"{line}"
	);
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
	throttled(
		&spool,
		"bob@busy.example",
		(now_epoch() + 3600, 1),
		"421 4.7.0 slow down",
		"mx.busy.example",
	);
	let mut out = Vec::new();

	assert_eq!(list(dir.path(), None, &mut out), ExitCode::SUCCESS);

	let out = String::from_utf8(out).expect("utf8");
	assert!(
		out.ends_with(
			"2 destinations on hold: domain busy.example, exchanger mx.busy.example \
			 (see `epistle queue destinations`)\n"
		),
		"{out}"
	);
}

#[test]
fn a_remote_reply_cannot_drive_the_terminal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let reply = "421 \u{1b}[2J\u{1b}[31mslow\r\nfake line\tand \u{9b}31m";
	throttled(
		&spool,
		"bob@busy.example",
		(NOW + 60, 1),
		reply,
		"evil\u{1b}]0;title\u{7}.example",
	);

	let (_, text) = run_args(dir.path(), &["destinations"]);
	assert!(
		!text
			.chars()
			.any(|c| c.is_control() && c != '\t' && c != '\n'),
		"{text:?}"
	);
	assert_eq!(text.lines().count(), 3, "{text:?}");
	assert!(
		text.contains("421 \\u{1b}[2J\\u{1b}[31mslow\\r\\nfake line\\tand \\u{9b}31m"),
		"{text:?}"
	);
	assert!(
		text.contains("evil\\u{1b}]0;title\\u{7}.example"),
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
	let id = throttled(
		&spool,
		"bob@remote.example",
		(0, 0),
		"450 x",
		"mx.remote.example",
	);
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
