//! `epistle queue list` and `queue destinations` with recipients waiting
//! for the warm-up cap: shown as such, never as deferred or held.

use std::path::Path;
use std::process::ExitCode;

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
	let code = crate::cli::queue::run(dir, None, 0, action, false, NOW, None, &mut out);
	(code, String::from_utf8(out).expect("utf8"))
}

/// Queue a message to `recipients`, the first `capped` of them waiting
/// for the Gmail cap until `NOW + 600`.
fn queued(spool: &FsSpool, recipients: &[&str], capped: usize) -> uuid::Uuid {
	let id = spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "sena@example.org".into(),
				recipients: recipients.iter().map(|r| r.to_string()).collect(),
				data: b"Subject: notice\r\n\r\nbody\r\n".to_vec(),
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
			for recipient in &recipients[..capped] {
				let mut state = envelope.recipient_state(recipient);
				state.wait_for_cap("gmail", NOW + 600, NOW - 60);
				envelope.set_recipient_state(recipient, state);
			}
			envelope.settle();
		})
		.expect("wait");
	id
}

#[test]
fn the_list_marks_mail_waiting_for_the_cap_and_sums_it_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let waiting = queued(&spool, &["a@gmail.com", "b@gmail.com"], 2);
	let (code, out) = run_args(dir.path(), &["list"]);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		out,
		format!(
			"{waiting}\tattempts=0\tfrom=sena@example.org\tto=a@gmail.com,b@gmail.com\twarm-up cap\n\
			 1 queued\n\
			 2 recipients waiting for the warm-up cap: gmail 2 (see `epistle warmup status`)\n"
		)
	);
	let (_, json) = run_args(dir.path(), &["list", "--json"]);
	let rows: serde_json::Value = serde_json::from_str(&json).expect("json");
	assert_eq!(
		(
			&rows[0]["warmup_cap"],
			&rows[0]["held"],
			&rows[0]["attempts"]
		),
		(
			&serde_json::json!(true),
			&serde_json::json!(false),
			&serde_json::json!(0)
		)
	);
}

#[test]
fn destinations_name_each_group_at_its_cap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	queued(&spool, &["a@gmail.com", "b@gmail.com"], 2);
	queued(&spool, &["c@gmail.com", "d@other.example"], 1);
	let (code, out) = run_args(dir.path(), &["destinations"]);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		out,
		format!(
			"0 destinations on hold\n\
			 warm-up gmail\tuntil={} (in 600s)\twaiting=3\treason=warm-up cap\n\
			 1 groups at the warm-up cap\n",
			NOW + 600
		)
	);
	let (_, json) = run_args(dir.path(), &["destinations", "--json"]);
	assert_eq!(
		json,
		format!(
			"[{{\"kind\":\"warmup\",\"name\":\"gmail\",\"reason\":\"warm-up cap\",\"until\":{},\"waiting\":3}}]\n",
			NOW + 600
		)
	);
}

#[test]
fn a_message_with_mail_also_due_is_not_only_waiting() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = queued(&spool, &["c@gmail.com", "d@other.example"], 1);
	let envelope = spool.load_envelope(id).expect("envelope");
	assert_eq!((waits(&envelope), only_waits(&envelope)), (true, false));
}
