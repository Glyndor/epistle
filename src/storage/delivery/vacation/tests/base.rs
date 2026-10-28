use super::*;
use crate::directory_store::DirectoryHandle;
use crate::sieve::interp::VacationRequest;

fn delivery(dir: &std::path::Path) -> LocalDelivery {
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	LocalDelivery::new(dir, directory).expect("delivery")
}

fn request() -> VacationRequest {
	VacationRequest {
		reason: "Away".to_string(),
		subject: None,
		from: None,
		days: 7,
	}
}

fn message(reverse_path: &str, headers: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: reverse_path.to_string(),
		recipients: vec!["alice@example.org".to_string()],
		data: format!("To: alice@example.org\r\n{headers}\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

#[test]
fn suppresses_replies_per_rfc5230() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	// Null sender: never autorespond.
	assert!(
		d.vacation_reply(
			"alice",
			"alice@example.org",
			&message("", "Subject: x"),
			&request()
		)
		.is_none()
	);
	// Automated mail.
	assert!(
		d.vacation_reply(
			"alice",
			"alice@example.org",
			&message("bob@example.net", "Auto-Submitted: auto-generated"),
			&request()
		)
		.is_none()
	);
	// Mailing-list mail.
	assert!(
		d.vacation_reply(
			"alice",
			"alice@example.org",
			&message("bob@example.net", "List-Id: <list.example.net>"),
			&request()
		)
		.is_none()
	);
	// Bulk precedence.
	assert!(
		d.vacation_reply(
			"alice",
			"alice@example.org",
			&message("bob@example.net", "Precedence: bulk"),
			&request()
		)
		.is_none()
	);
}

#[test]
fn replies_once_then_dedups() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let msg = message("bob@example.net", "Subject: hi");
	// First reply is sent; an immediate second is suppressed by dedup.
	assert!(
		d.vacation_reply("alice", "alice@example.org", &msg, &request())
			.is_some()
	);
	assert!(
		d.vacation_reply("alice", "alice@example.org", &msg, &request())
			.is_none()
	);
}

#[test]
fn a_traversing_account_gets_no_marker() {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let d = delivery(&data);
	assert!(!vacation_markers::claim(
		&d.data_dir,
		"../evil",
		"bob@example.net",
		7
	));
	let msg = message("bob@example.net", "Subject: hi");
	assert!(
		d.vacation_reply("../evil", "alice@example.org", &msg, &request())
			.is_none()
	);
	assert!(
		!data.join("evil").exists(),
		"nothing was written outside accounts/"
	);
	assert!(!data.join("accounts/../evil").exists());
}
