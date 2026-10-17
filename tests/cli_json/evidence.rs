//! `epistle evidence abandon` against the real binary: an acceptance that
//! nothing settles is closed with a record, once, and only when it is
//! really orphaned.

use epistle::evidence::MailClass;
use epistle::evidence::chain::Chain;
use epistle::evidence::record::{Accepted, Entry, Retention, RetentionMode};

use crate::harness::{env, epistle, json};

const ID: &str = "01a142e5-edcf-7490-9152-8a1a76b72933";

/// Seconds since the epoch.
fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

/// An acceptance an hour old: old enough to be an orphan.
fn accept(root: &std::path::Path, id: &str) {
	accept_aged(root, id, &["student@example.net"], 3600);
}

fn accept_aged(root: &std::path::Path, id: &str, recipients: &[&str], age: u64) {
	Chain::open(root)
		.expect("chain")
		.append_at(
			now() - age,
			Entry::Accepted(Accepted {
				spool_id: id.parse().expect("uuid"),
				account: "notices".into(),
				tenant: None,
				class: MailClass::Transactional,
				from: "notices@example.org".into(),
				recipients: recipients.iter().map(|r| (*r).to_string()).collect(),
				message_id: Some("<n1@example.org>".into()),
				date: None,
				subject: None,
				sha256: "ab".repeat(32),
				size: 100,
				retention: Retention {
					mode: RetentionMode::Metadata,
					days: 365,
				},
			}),
		)
		.expect("record");
}

fn abandon(env: &crate::harness::Env, id: &str) -> (i32, Option<serde_json::Value>) {
	abandon_because(env, id, "the client retried")
}

fn abandon_because(
	env: &crate::harness::Env,
	id: &str,
	reason: &str,
) -> (i32, Option<serde_json::Value>) {
	let output = epistle(
		&[
			"evidence",
			"abandon",
			id,
			"--reason",
			reason,
			"--yes",
			"--json",
			"--config",
			&env.config,
		],
		b"",
	);
	let code = output.status.code().unwrap_or(-1);
	let stdout = String::from_utf8_lossy(&output.stdout);
	match stdout.trim().is_empty() {
		true => (code, None),
		false => (code, Some(json(&output).1)),
	}
}

#[test]
fn an_orphaned_acceptance_is_closed_once() {
	let env = env("");
	let root = env.data_dir().join("evidence");
	accept(&root, ID);
	let (code, closed) = abandon(&env, ID);
	assert_eq!(code, 0);
	assert_eq!(closed.expect("json")["closed"], ID);
	// It has an ending now: closing it again is refused.
	let (code, nothing) = abandon(&env, ID);
	assert_eq!((code, nothing), (2, None));
	// The record names the operator and the reason.
	let day = std::fs::read_dir(root.join("chain"))
		.expect("chain")
		.flatten()
		.map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
		.collect::<String>();
	assert!(
		day.contains("closed by uid=") && day.contains(": the client retried"),
		"the record does not say who closed it: {day}"
	);
}

#[test]
fn what_was_never_accepted_is_not_closed() {
	let env = env("");
	let (code, nothing) = abandon(&env, ID);
	assert_eq!((code, nothing), (2, None));
}

#[test]
fn a_message_the_queue_still_holds_is_left_to_the_worker() {
	let env = env("");
	let root = env.data_dir().join("evidence");
	accept(&root, ID);
	// An entry of the queue with that id.
	let spool = epistle::storage::FsSpool::open(&env.data_dir()).expect("spool");
	let message = epistle::smtp::session::AcceptedMessage {
		reverse_path: "notices@example.org".into(),
		recipients: vec!["student@example.net".into()],
		data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	spool
		.store(&message, None, &Default::default())
		.expect("queued");
	let queued = spool.list().expect("list")[0].to_string();
	accept(&root, &queued);
	let (code, nothing) = abandon(&env, &queued);
	assert_eq!((code, nothing), (2, None));
}

/// A queue entry with that id, and its envelope file.
fn queue(env: &crate::harness::Env, id: &str) -> std::path::PathBuf {
	let spool = epistle::storage::FsSpool::open(&env.data_dir()).expect("spool");
	let message = epistle::smtp::session::AcceptedMessage {
		reverse_path: "notices@example.org".into(),
		recipients: vec!["student@example.net".into()],
		data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	let queued = spool
		.store(&message, None, &Default::default())
		.expect("queued");
	let _ = id;
	env.data_dir()
		.join("spool/new")
		.join(format!("{queued}.json"))
}

#[test]
fn an_entry_the_queue_holds_but_cannot_be_read_still_counts_as_held() {
	let env = env("");
	let root = env.data_dir().join("evidence");
	let envelope = queue(&env, ID);
	let id = envelope
		.file_stem()
		.and_then(|stem| stem.to_str())
		.expect("id")
		.to_string();
	accept(&root, &id);
	// The envelope cannot be decoded: damaged, or sealed with a key this
	// process was not given. The entry is there all the same.
	std::fs::write(&envelope, b"\0not an envelope").expect("damage");
	let (code, nothing) = abandon(&env, &id);
	assert_eq!((code, nothing), (2, None));
	let chain = std::fs::read_dir(root.join("chain"))
		.expect("chain")
		.flatten()
		.map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
		.collect::<String>();
	assert!(!chain.contains("closed by"), "a live acceptance was closed");
}

#[test]
fn the_reason_is_kept_without_control_or_bidi_characters() {
	let env = env("");
	let root = env.data_dir().join("evidence");
	accept(&root, ID);
	let (code, _) = abandon_because(&env, ID, "retried\u{7}\u{202e} by the client");
	assert_eq!(code, 0);
	let chain = std::fs::read_dir(root.join("chain"))
		.expect("chain")
		.flatten()
		.map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
		.collect::<String>();
	assert!(chain.contains(": retried by the client"), "{chain}");
	assert!(
		!chain.contains('\u{202e}') && !chain.contains("\\u202e"),
		"{chain}"
	);
}

/// Everything the chain of the evidence holds, as text.
fn chain_text(root: &std::path::Path) -> String {
	std::fs::read_dir(root.join("chain"))
		.expect("chain")
		.flatten()
		.map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
		.collect()
}

fn delivered(root: &std::path::Path, id: &str, recipient: &str) {
	Chain::open(root)
		.expect("chain")
		.append_at(
			now() - 3000,
			Entry::Outcome(epistle::evidence::record::Outcome {
				spool_id: id.parse().expect("uuid"),
				class: MailClass::Transactional,
				recipient: recipient.into(),
				result: epistle::evidence::record::OutcomeKind::Delivered,
				attempt: 1,
				remote: None,
				reply: None,
				tls: None,
				dane: false,
				mta_sts: None,
				retain_days: 365,
			}),
		)
		.expect("outcome");
}

#[test]
fn an_acceptance_that_may_still_be_on_its_way_to_the_queue_is_not_closed() {
	let env = env("");
	let root = env.data_dir().join("evidence");
	accept_aged(&root, ID, &["student@example.net"], 30);
	let (code, nothing) = abandon(&env, ID);
	assert_eq!((code, nothing), (2, None));
	assert!(!chain_text(&root).contains("closed by"));
}

#[test]
fn what_is_left_of_a_message_with_some_recipients_settled_is_closed_for_those() {
	let env = env("");
	let root = env.data_dir().join("evidence");
	let two = ["first@example.net", "second@example.net"];
	accept_aged(&root, ID, &two, 3600);
	delivered(&root, ID, "first@example.net");
	let (code, closed) = abandon(&env, ID);
	assert_eq!(code, 0);
	assert_eq!(closed.expect("json")["closed"], ID);
	let text = chain_text(&root);
	assert!(
		text.contains("\"recipients\":[\"second@example.net\"]"),
		"the record does not name what it closes: {text}"
	);
	assert!(!text.contains("\"recipients\":[\"first@example.net\"]"));
	// Nothing is left pending now.
	let (code, nothing) = abandon(&env, ID);
	assert_eq!((code, nothing), (2, None));
}

#[test]
fn a_reason_that_is_nothing_once_cleaned_is_refused() {
	let env = env("");
	let root = env.data_dir().join("evidence");
	accept(&root, ID);
	let (code, nothing) = abandon_because(&env, ID, "\u{7}\u{202e} ");
	assert_eq!((code, nothing), (2, None));
	assert!(!chain_text(&root).contains("closed by"));
}

fn run(env: &crate::harness::Env, args: &[&str]) -> (i32, String) {
	let mut full: Vec<&str> = args.to_vec();
	full.push("--config");
	full.push(&env.config);
	let out = epistle(&full, b"");
	(
		out.status.code().unwrap_or(-1),
		String::from_utf8_lossy(&out.stderr).to_string(),
	)
}

#[test]
fn a_break_an_operator_acknowledged_does_not_stop_closing_an_orphan() {
	const A: &str = "01a142e5-edcf-7490-9152-8a1a76b72931";
	const B: &str = "01a142e5-edcf-7490-9152-8a1a76b72932";
	let env = env("");
	let root = env.data_dir().join("evidence");
	for id in [A, B, ID] {
		accept(&root, id);
	}
	// The second line is cut out of the day: a break at the third.
	let file = std::fs::read_dir(root.join("chain"))
		.expect("chain")
		.flatten()
		.map(|entry| entry.path())
		.find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
		.expect("day file");
	let text = std::fs::read_to_string(&file).expect("day");
	let lines: Vec<&str> = text.lines().collect();
	std::fs::write(&file, format!("{}\n{}\n", lines[0], lines[2])).expect("cut");
	// Nobody acknowledged it yet: nothing is closed on a chain that is broken.
	assert_eq!(abandon(&env, ID).0, 1);
	let (code, err) = run(
		&env,
		&["evidence", "acknowledge", "--reason", "test", "--yes"],
	);
	assert_eq!(code, 0, "{err}");
	// Acknowledged: the orphan after the break and the one before it close.
	assert_eq!(abandon(&env, ID).0, 0);
	assert_eq!(abandon(&env, A).0, 0);
}
