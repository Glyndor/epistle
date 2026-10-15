//! `epistle warmup status`: the report, from the files a server leaves.

use super::*;
use crate::queue::warmup::policy::Verdict;
use crate::queue::warmup::state::{self, Cause, DayRecord, State};
use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord, FsSpool};

/// A data directory as a server with the warm-up on would leave it at
/// 01:00 on 2025-10-14: Gmail grew to 75 yesterday, 40 went out today and
/// were all delivered, one more recipient waits, and an Outlook order is
/// not applied yet.
fn server_files() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut wanted = Settings {
		enabled: true,
		..Settings::default()
	};
	wanted.order(Group::Outlook, Action::Set { cap: 120 });
	settings::save(dir.path(), &wanted).expect("settings");
	let mut kept = State::new(20_375);
	let gmail = kept.group_mut(Group::Gmail);
	gmail.cap = Some(75);
	gmail.sent = 40;
	gmail.remember(DayRecord {
		day: 20_374,
		cap: Some(50),
		sent: 50,
		attempted: 50,
		deferred: 0,
		bounced: 2,
		spam_blocks: 0,
		verdict: Verdict::Bad,
		next_cap: Some(50),
		raise: None,
		paused: false,
		causes: vec![Cause {
			account: "bulk\u{1b}[31m@school.example".into(),
			bad: 2,
		}],
	});
	state::save(dir.path(), &kept).expect("state");
	let log = DeliveryLog::open(dir.path(), 30);
	for n in 0..40 {
		log.append(&DeliveryRecord {
			time: MIDNIGHT + 60,
			spool_id: uuid::Uuid::nil(),
			account: None,
			from: "sena@sender.example".into(),
			recipient: format!("student{n}@gmail.com"),
			outcome: DeliveryOutcome::Delivered,
			remote: Some("gmail-smtp-in.l.google.com".into()),
			reply: Some("250 OK".into()),
			attempt: 1,
			extra: Default::default(),
		})
		.expect("log");
	}
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "sena@sender.example".into(),
				recipients: vec!["late@gmail.com".into()],
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
			let mut state = envelope.recipient_state("late@gmail.com");
			state.wait_for_cap("gmail", MIDNIGHT + 5000, MIDNIGHT + 60);
			envelope.set_recipient_state("late@gmail.com", state);
		})
		.expect("wait");
	dir
}

#[test]
fn the_report_shows_each_group_the_waiting_mail_and_the_last_day() {
	let dir = server_files();
	let (code, out) = run_args(dir.path(), 30, &["status"]);
	assert_eq!(code, 0);
	let idle = |group: &str| {
		format!(
			"{group}\tcap=50\tsent=0\tdeferred=0.0%\tbounced=0.0%\tspam=0\tverdict=idle\tnext=50\twaiting=0\n"
		)
	};
	let want = [
		"warm-up: on (UTC day 2025-10-14)\n".to_string(),
		"gmail\tcap=75\tsent=40\tdeferred=0.0%\tbounced=0.0%\tspam=0\tverdict=good\tnext=113\twaiting=1\n".into(),
		idle("outlook"),
		idle("yahoo"),
		idle("icloud"),
		idle("other"),
		// An account name is shown with its control characters escaped.
		"last gmail 2025-10-13 bad: 50 -> 50 (most bad replies: bulk\\u{1b}[31m@school.example=2)\n".into(),
		"pending: outlook set 120 (the server has not applied it yet)\n".into(),
	]
	.concat();
	assert_eq!(out, want);
}

#[test]
fn the_report_in_json_carries_the_same_figures() {
	let dir = server_files();
	let (code, out) = run_args(dir.path(), 30, &["status", "--json"]);
	assert_eq!(code, 0);
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON object");
	assert_eq!(
		(
			&value["enabled"],
			&value["paused"],
			&value["day"],
			&value["pending"][0]["group"],
		),
		(
			&serde_json::json!(true),
			&serde_json::json!(false),
			&serde_json::json!("2025-10-14"),
			&serde_json::json!("outlook"),
		)
	);
	assert_eq!(
		value["groups"][0],
		serde_json::json!({
			"group": "gmail",
			"cap": 75,
			"sent": 40,
			"attempted": 40,
			"deferred_percent": 0.0,
			"bounced_percent": 0.0,
			"spam_blocks": 0,
			"verdict": "good",
			"next_cap": 113,
			"raise": null,
			"waiting": 1,
			"last": {
				"day": 20_374,
				"cap": 50,
				"sent": 50,
				"attempted": 50,
				"deferred": 0,
				"bounced": 2,
				"spam_blocks": 0,
				"verdict": "bad",
				"next_cap": 50,
				"causes": [{"account": "bulk\u{1b}[31m@school.example", "bad": 2}]
			}
		})
	);
}

#[test]
fn a_fresh_install_reports_the_warm_up_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (code, out) = run_args(dir.path(), 30, &["status"]);
	assert_eq!(code, 0);
	assert!(
		out.starts_with("warm-up: off (UTC day 2025-10-14)\ngmail\tcap=50\tsent=0\t"),
		"{out}"
	);
}
