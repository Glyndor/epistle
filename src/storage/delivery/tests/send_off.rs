//! An account whose sending is off sends nothing on its own either: what its
//! forwards, its Sieve filter and its vacation reply would put on the outbound
//! side is dropped, and the message stays in its mailbox. So does mail that
//! reaches an address of a receive-only domain, whoever the account is.

use super::*;
use crate::storage::vacation_store::{VacationSetting, write as write_setting};

fn directory(send_off: bool, domain_off: bool, forward: Option<bool>) -> DirectoryHandle {
	let base = crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	);
	let base = match forward {
		Some(keep_local) => base.with_forwards([(
			"alice".to_string(),
			(vec!["ext@other.example".to_string()], keep_local),
		)]),
		None => base,
	};
	let off: Vec<String> = send_off.then(|| "alice".to_string()).into_iter().collect();
	let domains: Vec<String> = domain_off
		.then(|| "example.org".to_string())
		.into_iter()
		.collect();
	DirectoryHandle::new(
		base.with_switches(off, Vec::new())
			.with_send_off_domains(domains),
	)
}

fn deliver(
	send_off: bool,
	forward: Option<bool>,
	script: Option<&str>,
	vacation: bool,
) -> (Delivered, usize) {
	deliver_in(false, send_off, forward, script, vacation)
}

fn deliver_in(
	domain_off: bool,
	send_off: bool,
	forward: Option<bool>,
	script: Option<&str>,
	vacation: bool,
) -> (Delivered, usize) {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery =
		LocalDelivery::new(dir.path(), directory(send_off, domain_off, forward)).expect("delivery");
	let account = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account).expect("mkdir");
	if let Some(script) = script {
		fs::write(account.join("filter.sieve"), script).expect("filter");
	}
	if vacation {
		let setting = VacationSetting {
			is_enabled: true,
			from_date: None,
			to_date: None,
			subject: Some("Away".to_string()),
			text_body: Some("Back on Monday.".to_string()),
			html_body: None,
		};
		write_setting(dir.path(), "alice", &setting).expect("vacation");
	}
	let message = AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec!["alice@example.org".to_string()],
		data: b"To: alice@example.org\r\nSubject: hi\r\nMessage-ID: <m1@elsewhere.example>\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	let delivered = delivery.deliver_routed(&message, None).expect("deliver");
	let inbox = fs::read_dir(account.join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0);
	(delivered, inbox)
}

#[test]
fn a_configured_forward_is_not_sent_and_the_message_is_kept() {
	// A pure forward would store nothing at all: the copy must stay.
	let (delivered, inbox) = deliver(true, Some(false), None, false);
	assert!(delivered.redirects.is_empty(), "{:?}", delivered.redirects);
	assert_eq!(inbox, 1);
}

#[test]
fn a_sieve_redirect_is_not_sent_and_the_message_is_kept() {
	// `redirect` cancels the implicit keep, so the filter alone would lose it.
	let (delivered, inbox) = deliver(true, None, Some("redirect \"x@target.example\";"), false);
	assert!(delivered.redirects.is_empty(), "{:?}", delivered.redirects);
	assert_eq!(inbox, 1);
}

#[test]
fn a_sieve_reject_does_not_bounce_and_the_message_is_kept() {
	let (delivered, inbox) = deliver(
		true,
		None,
		Some("require \"reject\";\nreject \"no\";"),
		false,
	);
	assert!(delivered.reject.is_none());
	assert_eq!(inbox, 1);
}

#[test]
fn a_sieve_vacation_sends_no_reply() {
	let script = "require \"vacation\";\nvacation :days 1 \"away\";";
	let (delivered, inbox) = deliver(true, None, Some(script), false);
	assert!(delivered.replies.is_empty());
	assert_eq!(inbox, 1);
}

#[test]
fn the_jmap_vacation_response_sends_no_reply() {
	let (delivered, inbox) = deliver(true, None, None, true);
	assert!(delivered.replies.is_empty());
	assert_eq!(inbox, 1);
}

#[test]
fn the_jmap_vacation_response_sends_no_reply_beside_a_filter() {
	let (delivered, _) = deliver(true, None, Some("keep;"), true);
	assert!(delivered.replies.is_empty());
}

#[test]
fn the_same_account_with_sending_on_does_all_of_it() {
	let (forwarded, _) = deliver(false, Some(true), None, false);
	assert_eq!(forwarded.redirects.len(), 1);
	let (redirected, _) = deliver(false, None, Some("redirect \"x@target.example\";"), false);
	assert_eq!(redirected.redirects.len(), 1);
	let (rejected, _) = deliver(
		false,
		None,
		Some("require \"reject\";\nreject \"no\";"),
		false,
	);
	assert!(rejected.reject.is_some());
	let (replied, _) = deliver(false, None, None, true);
	assert_eq!(replied.replies.len(), 1);
	let script = "require \"vacation\";\nvacation :days 1 \"away\";";
	let (sieve_replied, _) = deliver(false, None, Some(script), false);
	assert_eq!(sieve_replied.replies.len(), 1);
}

#[test]
fn nothing_leaves_for_an_address_of_a_receive_only_domain() {
	let (forwarded, inbox) = deliver_in(true, false, Some(false), None, false);
	assert!(forwarded.redirects.is_empty(), "{:?}", forwarded.redirects);
	assert_eq!(inbox, 1, "the copy stays");
	let (redirected, _) = deliver_in(
		true,
		false,
		None,
		Some("redirect \"x@target.example\";"),
		false,
	);
	assert!(redirected.redirects.is_empty());
	let (rejected, inbox) = deliver_in(
		true,
		false,
		None,
		Some("require \"reject\";\nreject \"no\";"),
		false,
	);
	assert!(rejected.reject.is_none());
	assert_eq!(inbox, 1);
	let (replied, _) = deliver_in(true, false, None, None, true);
	assert!(replied.replies.is_empty());
}

#[test]
fn the_same_account_in_a_domain_that_sends_does_all_of_it() {
	let (forwarded, _) = deliver_in(false, false, Some(true), None, false);
	assert_eq!(forwarded.redirects.len(), 1);
	let (replied, _) = deliver_in(false, false, None, None, true);
	assert_eq!(replied.replies.len(), 1);
}
