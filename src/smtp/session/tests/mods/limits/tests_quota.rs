//! SMTP enforces the mailbox quota of local recipients: a full mailbox is
//! refused at RCPT TO for that recipient only, and a message that would
//! overfill one is refused whole only when no recipient can take it.

use std::collections::HashMap;
use std::sync::Mutex;

use super::tests_basic::reply_code;
use super::*;

/// bob and carol each have a 100-byte quota; `usage` says what they store.
fn session(usage: HashMap<&'static str, u64>) -> Session {
	let directory = Directory::new(
		["example.org".to_string()],
		[
			("bob@example.org".to_string(), "bob".to_string()),
			("carol@example.org".to_string(), "carol".to_string()),
		],
	)
	.with_account_quotas([("bob".to_string(), 100), ("carol".to_string(), 100)]);
	let usage = Mutex::new(usage);
	let quota = crate::smtp::quota::MailboxQuota::new(
		move |account| {
			usage
				.lock()
				.expect("usage")
				.get(account)
				.copied()
				.unwrap_or(0)
		},
		1 << 30,
	);
	let mut session = Session::new("mx.example.org")
		.with_directory(Arc::new(directory))
		.with_quota(Arc::new(quota));
	session.command_line("EHLO client.example.net");
	session
}

fn reply_line(action: &Action) -> String {
	match action {
		Action::Continue(reply) | Action::Deliver(reply, _) => reply.to_string(),
		_ => String::new(),
	}
}

/// Send `body` as DATA after MAIL FROM and the given RCPT TOs.
fn transaction(session: &mut Session, recipients: &[&str], body: &[u8]) -> Action {
	session.command_line("MAIL FROM:<alice@sender.example>");
	for recipient in recipients {
		assert_eq!(
			reply_code(&session.command_line(&format!("RCPT TO:<{recipient}>"))),
			250
		);
	}
	session.command_line("DATA");
	assert_eq!(session.data_line(body), None);
	session.data_line(b".").expect("final action")
}

#[test]
fn a_full_mailbox_is_refused_at_rcpt_for_that_recipient_only() {
	let mut session = session(HashMap::from([("bob", 100)]));
	session.command_line("MAIL FROM:<alice@sender.example>");

	let bob = session.command_line("RCPT TO:<bob@example.org>");
	let carol = session.command_line("RCPT TO:<carol@example.org>");

	assert_eq!(reply_line(&bob), "452 4.2.2 mailbox full\r\n");
	assert_eq!(reply_code(&carol), 250);
}

#[test]
fn a_message_that_overfills_one_mailbox_goes_to_the_others_with_a_dsn() {
	let mut session = session(HashMap::from([("bob", 90)]));

	let action = transaction(
		&mut session,
		&["bob@example.org", "carol@example.org"],
		&[b'x'; 40],
	);

	let Action::Deliver(reply, message) = action else {
		panic!("expected delivery, got {}", reply_line(&action));
	};
	assert_eq!(reply.code(), 250);
	assert_eq!(message.recipients, vec!["carol@example.org".to_string()]);
	let reports = session.take_quota_reports();
	assert_eq!(reports.len(), 1, "one DSN for bob");
	assert_eq!(
		reports[0].recipients,
		vec!["alice@sender.example".to_string()]
	);
	let body = String::from_utf8_lossy(&reports[0].data);
	assert!(
		body.contains(
			"Final-Recipient: rfc822; bob@example.org\r\nAction: failed\r\nStatus: 5.2.2"
		),
		"{body}"
	);
	assert!(session.take_quota_reports().is_empty(), "taken once");
}

#[test]
fn a_message_that_overfills_every_mailbox_is_refused() {
	let mut session = session(HashMap::from([("bob", 90), ("carol", 99)]));

	let action = transaction(
		&mut session,
		&["bob@example.org", "carol@example.org"],
		&[b'x'; 40],
	);

	assert_eq!(reply_line(&action), "552 5.2.2 mailbox full\r\n");
	assert!(session.take_quota_reports().is_empty());
}

#[test]
fn an_authenticated_submission_to_a_full_local_mailbox_is_refused_too() {
	let mut session = session(HashMap::from([("bob", 100)]));
	// An authenticated sender reaches the same RCPT check: quota does not
	// depend on who sends.
	session.authenticated = Some("carol".to_string());
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<carol@example.org>")),
		250
	);
	let bob = session.command_line("RCPT TO:<bob@example.org>");
	assert_eq!(reply_line(&bob), "452 4.2.2 mailbox full\r\n");
}

#[test]
fn rcpt_before_mail_is_a_bad_sequence_whatever_the_address() {
	// RFC 5321 §4.1.4: the order is checked first, so the reply says nothing
	// about whether the mailbox exists or is full.
	let mut session = session(HashMap::from([("bob", 100)]));
	for recipient in ["carol@example.org", "nobody@example.org", "bob@example.org"] {
		let reply = session.command_line(&format!("RCPT TO:<{recipient}>"));
		assert_eq!(
			reply_line(&reply),
			"503 5.5.1 bad sequence of commands\r\n",
			"{recipient}"
		);
	}
}

#[test]
fn a_zero_default_quota_is_unlimited() {
	// carol has no quota of her own; a server default of 0 means no limit.
	let directory = Directory::new(
		["example.org".to_string()],
		[("carol@example.org".to_string(), "carol".to_string())],
	);
	let quota = crate::smtp::quota::MailboxQuota::new(|_| 10, 0);
	let mut session = Session::new("mx.example.org")
		.with_directory(Arc::new(directory))
		.with_quota(Arc::new(quota));
	session.command_line("EHLO client.example.net");
	session.command_line("MAIL FROM:<alice@sender.example>");
	let carol = session.command_line("RCPT TO:<carol@example.org>");
	assert_eq!(reply_line(&carol), "250 2.0.0 ok\r\n");
}

#[test]
fn final_delivery_admission_includes_the_stored_trace_headers() {
	let message = AcceptedMessage {
		reverse_path: "alice@sender.example".to_string(),
		recipients: vec!["bob@example.org".to_string()],
		no_dsn: Vec::new(),
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
	};
	let bytes = crate::storage::local_delivery_copy(
		&message.reverse_path,
		&message.recipients[0],
		&message.data,
	)
	.len() as u64;
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let mut exact = Session::new("mx.example.org")
		.with_directory(directory.clone())
		.with_quota(Arc::new(crate::smtp::quota::MailboxQuota::new(
			|_| 0,
			bytes,
		)));
	assert!(exact.recheck_delivery_quota(message.clone()).is_some());
	let mut smaller = Session::new("mx.example.org")
		.with_directory(directory)
		.with_quota(Arc::new(crate::smtp::quota::MailboxQuota::new(
			|_| 0,
			bytes - 1,
		)));
	assert!(smaller.recheck_delivery_quota(message).is_none());
}
