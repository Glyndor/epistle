//! Tests for the JMAP-side vacation reply path (`LocalDelivery::jmap_vacation_reply`).
//!
//! The test helpers here are shared with [`super::tests`], so each call builds a
//! fresh `tempfile::tempdir` and an isolated `LocalDelivery` rooted in it.

use crate::directory_store::DirectoryHandle;
use crate::smtp::session::AcceptedMessage;
use crate::storage::vacation_store::{VacationSetting, write as write_setting};

fn delivery(dir: &std::path::Path) -> super::LocalDelivery {
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	super::LocalDelivery::new(dir, directory).expect("delivery")
}

fn enabled_setting() -> VacationSetting {
	VacationSetting {
		is_enabled: true,
		from_date: None,
		to_date: None,
		subject: Some("OOO".to_string()),
		text_body: Some("Away until Monday.".to_string()),
		html_body: None,
	}
}

fn message(reverse_path: &str, headers: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: reverse_path.to_string(),
		recipients: vec!["alice@example.org".to_string()],
		data: format!("{headers}\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		no_dsn: Vec::new(),
	}
}

#[test]
fn disabled_setting_sends_no_reply() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	write_setting(dir.path(), "alice", &VacationSetting::disabled()).expect("write disabled");
	let reply = d.jmap_vacation_reply(
		"alice",
		"alice@example.org",
		&message("bob@example.net", "Subject: hi"),
		&VacationSetting::disabled(),
	);
	assert!(reply.is_none(), "disabled setting must not produce a reply");
}

#[test]
fn enabled_setting_sends_a_reply() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let reply = d.jmap_vacation_reply(
		"alice",
		"alice@example.org",
		&message(
			"bob@example.net",
			"Subject: hi\r\nMessage-ID: <orig@example.net>",
		),
		&enabled_setting(),
	);
	let reply = reply.expect("reply");
	assert_eq!(
		reply.reverse_path, "",
		"vacation replies use a null reverse-path"
	);
	assert_eq!(reply.recipients, vec!["bob@example.net".to_string()]);
	let body = String::from_utf8(reply.data).expect("ascii");
	assert!(body.contains("From: <alice@example.org>"), "{body}");
	assert!(body.contains("Subject: OOO"), "{body}");
	assert!(
		body.contains("Auto-Submitted: auto-replied (vacation)"),
		"{body}"
	);
	assert!(body.contains("In-Reply-To: <orig@example.net>"), "{body}");
	assert!(body.contains("Away until Monday."), "{body}");
}

#[test]
fn enabled_setting_includes_three_levels_in_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let setting = VacationSetting {
		from_date: Some("2000-01-01T00:00:00Z".to_string()),
		to_date: Some("2099-12-31T23:59:59Z".to_string()),
		..enabled_setting()
	};
	write_setting(dir.path(), "alice", &setting).expect("write");
	let read = d.jmap_vacation("alice");
	assert_eq!(read, Some(setting.clone()));
	let mid = crate::storage::vacation_store::utc_date_to_unix_secs(Some("2024-06-01T12:00:00Z"))
		.unwrap();
	assert!(setting.is_within_window(mid));
	// "before": outside the lower bound.
	let before =
		crate::storage::vacation_store::utc_date_to_unix_secs(Some("1999-12-31T23:59:59Z"))
			.unwrap();
	assert!(!setting.is_within_window(before));
	// "after": past the upper bound.
	let after = crate::storage::vacation_store::utc_date_to_unix_secs(Some("2100-01-01T00:00:00Z"))
		.unwrap();
	assert!(!setting.is_within_window(after));
}

#[test]
fn deliver_routed_skips_reply_outside_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let setting = VacationSetting {
		from_date: Some("2099-01-01T00:00:00Z".to_string()),
		to_date: Some("2099-12-31T23:59:59Z".to_string()),
		..enabled_setting()
	};
	write_setting(dir.path(), "alice", &setting).expect("write");
	assert!(
		d.jmap_vacation("alice").is_some(),
		"setting must be enabled and stored"
	);
	let msg = message("bob@example.net", "Subject: hi");
	let delivered = d.deliver_routed(&msg, None).expect("delivery");
	assert!(
		delivered.replies.is_empty(),
		"outside-window setting sends no reply"
	);
}

#[test]
fn reply_skips_automated_or_list_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	for headers in [
		"Auto-Submitted: auto-generated",
		"List-Id: <list.example.net>",
		"Precedence: bulk",
		"Precedence: list",
		"Precedence: junk",
	] {
		let reply = d.jmap_vacation_reply(
			"alice",
			"alice@example.org",
			&message("bob@example.net", headers),
			&enabled_setting(),
		);
		assert!(reply.is_none(), "should skip {headers}");
	}
}

#[test]
fn reply_skips_null_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let reply = d.jmap_vacation_reply(
		"alice",
		"alice@example.org",
		&message("", "Subject: x"),
		&enabled_setting(),
	);
	assert!(reply.is_none(), "null sender must not trigger a reply");
}

#[test]
fn reply_skips_own_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let reply = d.jmap_vacation_reply(
		"alice",
		"alice@example.org",
		&message("alice@example.org", "Subject: x"),
		&enabled_setting(),
	);
	assert!(
		reply.is_none(),
		"a sender equal to the recipient must not loop"
	);
}

#[test]
fn reply_dedups_per_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let msg = message("bob@example.net", "Subject: hi");
	let first = d.jmap_vacation_reply("alice", "alice@example.org", &msg, &enabled_setting());
	assert!(first.is_some(), "first reply goes out");
	let second = d.jmap_vacation_reply("alice", "alice@example.org", &msg, &enabled_setting());
	assert!(second.is_none(), "an immediate second reply is suppressed");
	// A different sender is a fresh slate.
	let other = d.jmap_vacation_reply(
		"alice",
		"alice@example.org",
		&message("carol@example.net", "Subject: hi"),
		&enabled_setting(),
	);
	assert!(other.is_some(), "another sender gets a reply");
}

#[test]
fn reply_dedup_survives_restart() {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().join("data");
	std::fs::create_dir_all(&data).expect("mkdir");
	{
		let d = delivery(&data);
		let msg = message("bob@example.net", "Subject: hi");
		assert!(
			d.jmap_vacation_reply("alice", "alice@example.org", &msg, &enabled_setting())
				.is_some()
		);
	}
	// Restart: a brand-new instance over the same directory sees the marker
	// file that the first run wrote and suppresses a follow-up reply.
	let d = delivery(&data);
	let msg = message("bob@example.net", "Subject: hi");
	let reply = d.jmap_vacation_reply("alice", "alice@example.org", &msg, &enabled_setting());
	assert!(
		reply.is_none(),
		"marker file from the previous run suppresses the next reply"
	);
}

#[test]
fn html_body_produces_multipart_alternative() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let setting = VacationSetting {
		html_body: Some("<p>Away.</p>".to_string()),
		..enabled_setting()
	};
	let reply = d.jmap_vacation_reply(
		"alice",
		"alice@example.org",
		&message("bob@example.net", "Subject: x"),
		&setting,
	);
	let reply = reply.expect("reply");
	let body = String::from_utf8(reply.data).expect("ascii");
	assert!(body.contains("multipart/alternative"), "{body}");
	assert!(body.contains("<p>Away.</p>"), "{body}");
}

#[test]
fn own_address_does_not_match_a_different_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	// `alice@example.org` is the recipient. A sender of `not-alice@example.org`
	// shares the domain but is a different person, so the reply still fires.
	let reply = d.jmap_vacation_reply(
		"alice",
		"alice@example.org",
		&message("not-alice@example.org", "Subject: x"),
		&enabled_setting(),
	);
	assert!(
		reply.is_some(),
		"a sender that only shares the domain still receives a reply"
	);
}

#[test]
fn reads_jmap_setting_from_data_dir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	write_setting(dir.path(), "alice", &enabled_setting()).expect("write");
	let read = d.jmap_vacation("alice");
	assert_eq!(read, Some(enabled_setting()));
}

#[test]
fn missing_setting_is_none() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	let read = d.jmap_vacation("alice");
	assert!(read.is_none(), "no file means no vacation");
}
