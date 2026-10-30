//! The auto-reply is outbound mail triggered by inbound mail, so these tests
//! drive the real delivery path (`deliver_routed`) and pin what keeps it from
//! turning into backscatter: who never gets a reply, that one reply per
//! sender per period holds under concurrent deliveries, that the tracking
//! store is bounded and fails closed, and which of the JMAP and Sieve
//! settings answers.

use std::fs;
use std::path::Path;

use crate::directory_store::DirectoryHandle;
use crate::smtp::session::AcceptedMessage;
use crate::storage::vacation_store::{VacationSetting, write as write_setting};

use super::super::super::LocalDelivery;

/// `alice` owns two addresses; `bob` is a second local account.
fn delivery(dir: &Path) -> LocalDelivery {
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("al@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	));
	LocalDelivery::new(dir, directory).expect("delivery")
}

fn enable(dir: &Path, text: &str) {
	let setting = VacationSetting {
		is_enabled: true,
		from_date: None,
		to_date: None,
		subject: Some("Away".to_string()),
		text_body: Some(text.to_string()),
		html_body: None,
	};
	write_setting(dir, "alice", &setting).expect("write setting");
}

fn sieve(dir: &Path, script: &str) {
	let account = dir.join("accounts").join("alice");
	fs::create_dir_all(&account).expect("account dir");
	fs::write(account.join("filter.sieve"), script).expect("filter");
}

/// A message from a verified sender, addressed `To: alice@example.org`.
fn inbound(sender: &str, recipients: &[&str], headers: &str) -> AcceptedMessage {
	raw(
		sender,
		recipients,
		&format!("To: alice@example.org\r\n{headers}"),
		true,
	)
}

fn raw(sender: &str, recipients: &[&str], headers: &str, verified: bool) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: sender.to_string(),
		recipients: recipients.iter().map(|r| (*r).to_string()).collect(),
		data: format!("{headers}\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: verified,
		no_dsn: Vec::new(),
	}
}

fn replies(d: &LocalDelivery, sender: &str) -> Vec<AcceptedMessage> {
	let message = inbound(sender, &["alice@example.org"], "Subject: hi");
	d.deliver_routed(&message, None).expect("deliver").replies
}

fn text(reply: &AcceptedMessage) -> String {
	String::from_utf8(reply.data.clone()).expect("utf-8 reply")
}

#[test]
fn jmap_vacation_replies_without_a_sieve_filter() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Back on Monday.");
	let sent = replies(&d, "carol@example.net");
	assert_eq!(sent.len(), 1, "an account with no filter still answers");
	assert_eq!(sent[0].recipients, vec!["carol@example.net".to_string()]);
	assert!(text(&sent[0]).contains("Back on Monday."));
}

#[test]
fn jmap_and_sieve_vacation_together_send_one_reply_from_jmap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "From the JMAP setting.");
	sieve(dir.path(), "vacation \"From the Sieve script.\";");
	let sent = replies(&d, "carol@example.net");
	assert_eq!(sent.len(), 1, "one inbound message, one reply");
	assert!(text(&sent[0]).contains("From the JMAP setting."));
	assert!(!text(&sent[0]).contains("From the Sieve script."));
}

#[test]
fn enabled_jmap_vacation_outside_its_window_silences_sieve_vacation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let setting = VacationSetting {
		is_enabled: true,
		from_date: Some("2099-01-01T00:00:00Z".to_string()),
		to_date: None,
		subject: None,
		text_body: Some("Later.".to_string()),
		html_body: None,
	};
	write_setting(dir.path(), "alice", &setting).expect("write setting");
	sieve(dir.path(), "vacation \"From the Sieve script.\";");
	assert!(
		replies(&d, "carol@example.net").is_empty(),
		"the enabled JMAP setting owns the vacation, even before its window"
	);
}

#[test]
fn disabled_jmap_vacation_leaves_sieve_vacation_in_charge() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	write_setting(dir.path(), "alice", &VacationSetting::disabled()).expect("write");
	sieve(dir.path(), "vacation \"From the Sieve script.\";");
	let sent = replies(&d, "carol@example.net");
	assert_eq!(sent.len(), 1);
	assert!(text(&sent[0]).contains("From the Sieve script."));
}

#[test]
fn no_reply_to_mailer_daemon_or_list_robots() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	for sender in [
		"MAILER-DAEMON@example.net",
		"mailer-daemon@example.net",
		"owner-staff@example.net",
		"staff-request@example.net",
		"LISTSERV@example.net",
		"majordomo@example.net",
	] {
		assert!(replies(&d, sender).is_empty(), "replied to {sender}");
	}
	assert_eq!(replies(&d, "daemon-fan@example.net").len(), 1, "control");
}

#[test]
fn no_reply_to_list_headers_beyond_list_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	for (index, header) in [
		"List-Unsubscribe: <mailto:leave@example.net>",
		"List-Post: <mailto:staff@example.net>",
		"auto-submitted: auto-replied",
	]
	.iter()
	.enumerate()
	{
		let sender = format!("sender{index}@example.net");
		let message = inbound(&sender, &["alice@example.org"], header);
		let sent = d.deliver_routed(&message, None).expect("deliver").replies;
		assert!(sent.is_empty(), "replied despite {header}");
	}
	let control = inbound("sender@example.net", &["alice@example.org"], "X-List: no");
	let sent = d.deliver_routed(&control, None).expect("deliver").replies;
	assert_eq!(sent.len(), 1, "control");
}

#[test]
fn no_reply_to_any_of_the_accounts_own_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	assert!(replies(&d, "al@example.org").is_empty(), "second address");
	assert!(replies(&d, "ALICE@example.org").is_empty(), "case folded");
	assert_eq!(replies(&d, "alison@example.org").len(), 1, "control");
}

#[test]
fn reply_comes_from_the_address_the_copy_was_delivered_to() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let message = inbound(
		"carol@example.net",
		&["bob@example.org", "alice@example.org"],
		"Subject: hi",
	);
	let sent = d.deliver_routed(&message, None).expect("deliver").replies;
	assert_eq!(sent.len(), 1, "only alice is away");
	let reply = text(&sent[0]);
	assert!(reply.contains("From: <alice@example.org>"), "{reply}");
	assert!(!reply.contains("bob@example.org"), "{reply}");
}

#[test]
fn reply_threads_with_in_reply_to_and_references() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let message = inbound(
		"carol@example.net",
		&["alice@example.org"],
		"Subject: hi\r\nMessage-ID: <two@example.net>\r\nReferences: <one@example.net>",
	);
	let sent = d.deliver_routed(&message, None).expect("deliver").replies;
	let reply = text(&sent[0]);
	assert!(
		reply.contains("In-Reply-To: <two@example.net>\r\n"),
		"{reply}"
	);
	assert!(
		reply.contains("References: <one@example.net> <two@example.net>\r\n"),
		"{reply}"
	);
	assert!(reply.contains("Auto-Submitted: auto-replied"), "{reply}");
}

#[test]
fn concurrent_deliveries_from_one_sender_send_one_reply() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let barrier = std::sync::Barrier::new(16);
	let sent: usize = std::thread::scope(|scope| {
		let handles: Vec<_> = (0..16)
			.map(|_| {
				scope.spawn(|| {
					barrier.wait();
					replies(&d, "carol@example.net").len()
				})
			})
			.collect();
		handles.into_iter().map(|h| h.join().expect("thread")).sum()
	});
	assert_eq!(sent, 1, "sixteen racing deliveries, one reply");
}

#[test]
fn a_reply_that_cannot_be_recorded_is_not_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	// A regular file where the tracking directory belongs: nothing can be
	// recorded, and an unrecorded reply would repeat on every message.
	fs::write(dir.path().join("accounts/alice/.vacation"), b"").expect("blocker");
	assert!(replies(&d, "carol@example.net").is_empty());
	assert!(replies(&d, "carol@example.net").is_empty());
	fs::remove_file(dir.path().join("accounts/alice/.vacation")).expect("unblock");
	assert_eq!(replies(&d, "carol@example.net").len(), 1, "control");
}

#[test]
fn sieve_days_zero_still_replies_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	sieve(dir.path(), "vacation :days 0 \"Away.\";");
	assert_eq!(replies(&d, "carol@example.net").len(), 1);
	assert!(
		replies(&d, "carol@example.net").is_empty(),
		":days 0 must not mean a reply to every message"
	);
}

#[test]
fn the_tracking_store_is_bounded() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let markers = dir.path().join("accounts/alice/.vacation");
	fs::create_dir_all(&markers).expect("markers dir");
	let cap = crate::storage::vacation_markers::MAX_MARKERS;
	for index in 0..cap {
		fs::write(markers.join(format!("{index:064x}")), b"").expect("marker");
	}
	assert!(
		replies(&d, "carol@example.net").is_empty(),
		"a full store of recent replies refuses a new sender"
	);
	assert_eq!(fs::read_dir(&markers).expect("list").count(), cap);
	// Markers past the period make room again.
	let old = std::time::SystemTime::now() - std::time::Duration::from_secs(8 * 86_400);
	for index in 0..10 {
		let file = fs::File::options()
			.write(true)
			.open(markers.join(format!("{index:064x}")))
			.expect("open marker");
		file.set_modified(old).expect("age marker");
	}
	assert_eq!(replies(&d, "carol@example.net").len(), 1);
	assert!(fs::read_dir(&markers).expect("list").count() <= cap);
}

#[test]
fn reply_body_lines_are_crlf_and_short_and_the_subject_is_encoded() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let setting = VacationSetting {
		is_enabled: true,
		from_date: None,
		to_date: None,
		subject: Some("Fuera de la oficina, vuelvo el lunes".replace("oficina", "oficiña")),
		text_body: Some(format!("line one\nline two\r.\r\n{}", "x".repeat(2_000))),
		html_body: Some("<p>away</p>\n--x\n.\n".to_string()),
	};
	write_setting(dir.path(), "alice", &setting).expect("write");
	let sent = replies(&d, "carol@example.net");
	let reply = &sent[0].data;
	let (head, _) = text(&sent[0])
		.split_once("\r\n\r\n")
		.map(|(h, b)| (h.to_string(), b.to_string()))
		.expect("header block");
	assert!(head.is_ascii(), "non-ASCII subject must be encoded: {head}");
	for line in reply.split(|&b| b == b'\n') {
		assert!(line.len() <= 999, "line longer than 998 octets");
	}
	for (index, &byte) in reply.iter().enumerate() {
		if byte == b'\n' {
			assert_eq!(reply[index - 1], b'\r', "bare LF at {index}");
		}
		if byte == b'\r' {
			assert_eq!(reply.get(index + 1), Some(&b'\n'), "bare CR at {index}");
		}
	}
}

#[test]
fn a_sieve_from_the_account_does_not_own_is_ignored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	sieve(
		dir.path(),
		"vacation :from \"ceo@elsewhere.example\" \"Away.\";",
	);
	let sent = replies(&d, "carol@example.net");
	let reply = text(&sent[0]);
	assert!(reply.contains("From: <alice@example.org>"), "{reply}");
	assert!(!reply.contains("ceo@elsewhere.example"), "{reply}");
	assert_eq!(replies(&d, "dave@example.net").len(), 1);
	sieve(dir.path(), "vacation :from \"al@example.org\" \"Away.\";");
	let sent = replies(&d, "erin@example.net");
	assert!(
		text(&sent[0]).contains("From: <al@example.org>"),
		"own address kept"
	);
}

#[test]
fn no_reply_to_a_sender_the_server_did_not_verify() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let headers = "To: alice@example.org\r\nSubject: hi";
	let forged = raw("carol@example.net", &["alice@example.org"], headers, false);
	let sent = d.deliver_routed(&forged, None).expect("deliver").replies;
	assert!(
		sent.is_empty(),
		"an unverified envelope sender gets nothing"
	);
	let verified = raw("carol@example.net", &["alice@example.org"], headers, true);
	let sent = d.deliver_routed(&verified, None).expect("deliver").replies;
	assert_eq!(sent.len(), 1, "control");
}

#[test]
fn sieve_vacation_also_needs_a_verified_and_addressed_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	sieve(dir.path(), "vacation \"Away.\";");
	let unverified = raw(
		"carol@example.net",
		&["alice@example.org"],
		"To: alice@example.org",
		false,
	);
	assert!(
		d.deliver_routed(&unverified, None)
			.expect("deliver")
			.replies
			.is_empty()
	);
	let blind = raw(
		"dave@example.net",
		&["alice@example.org"],
		"To: list@example.net",
		true,
	);
	assert!(
		d.deliver_routed(&blind, None)
			.expect("deliver")
			.replies
			.is_empty()
	);
	let addressed = raw(
		"erin@example.net",
		&["alice@example.org"],
		"Cc: alice@example.org",
		true,
	);
	assert_eq!(
		d.deliver_routed(&addressed, None)
			.expect("deliver")
			.replies
			.len(),
		1
	);
}

#[test]
fn reply_only_when_an_own_address_is_in_to_or_cc() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let cases = [
		("To: team@example.net", false),
		("Bcc: alice@example.org", false),
		("Reply-To: alice@example.org", false),
		("To: xalice@example.org", false),
		("To: alice@example.org.evil.example", false),
		("To: <alice@example.orgx>", false),
		("Subject: alice@example.org", false),
		("To: Alice <alice@example.org>", true),
		("To: someone@example.net,\r\n ALICE@Example.Org", true),
		("Cc: \"Al\" <al@example.org>", true),
		(
			"To: a@example.net\r\nCc: b@example.net, alice@example.org",
			true,
		),
	];
	for (index, (headers, expected)) in cases.iter().enumerate() {
		let sender = format!("sender{index}@example.net");
		let message = raw(&sender, &["alice@example.org"], headers, true);
		let sent = d.deliver_routed(&message, None).expect("deliver").replies;
		assert_eq!(sent.len(), usize::from(*expected), "{headers:?}");
	}
}

#[test]
fn a_huge_to_header_costs_linear_time() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let headers = format!("To: {}", "alice@example.or".repeat(1 << 16));
	let message = raw("carol@example.net", &["alice@example.org"], &headers, true);
	let started = std::time::Instant::now();
	let sent = d.deliver_routed(&message, None).expect("deliver").replies;
	assert!(sent.is_empty(), "no full own address in the header");
	assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
