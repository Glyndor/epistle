//! The sender lists at `RCPT TO` for a session that has authenticated: the
//! recipients an account may not write to.

use super::tests_basic::reply_code;
use super::*;

fn lists(extra: &str) -> Arc<crate::antispam::scopes::Scopes> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n{extra}"
	)
	.expect("write config");
	let config = crate::config::Config::load(file.path()).expect("config loads");
	Arc::new(crate::antispam::scopes::Scopes::from_config(&config))
}

fn alice(scopes: Arc<crate::antispam::scopes::Scopes>) -> Session {
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	));
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_scopes(scopes);
	session.mark_authenticated_for_test("alice");
	session.command_line("EHLO client.example.org");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
		250
	);
	session
}

fn rcpt(session: &mut Session, recipient: &str) -> String {
	match session.command_line(&format!("RCPT TO:<{recipient}>")) {
		Action::Continue(reply) => reply.to_string(),
		_ => panic!("RCPT is answered, not collected"),
	}
}

const SERVER_DENY: &str =
	"[antispam.senders]\ndeny_recipients = [\"*.example.net\", \"blocked@example.com\"]\n";

#[test]
fn an_account_cannot_write_to_a_denied_domain_or_its_subdomains() {
	let mut session = alice(lists(SERVER_DENY));
	for recipient in [
		"x@a.example.net",
		"x@deep.a.example.net",
		"blocked@example.com",
	] {
		assert_eq!(
			rcpt(&mut session, recipient),
			"550 5.7.1 sending to this recipient is not allowed\r\n",
			"{recipient}"
		);
	}
}

#[test]
fn near_misses_and_local_recipients_are_accepted() {
	let mut session = alice(lists(SERVER_DENY));
	for recipient in [
		"x@example.net",
		"x@badexample.net",
		"other@example.com",
		"bob@example.org",
	] {
		let reply = rcpt(&mut session, recipient);
		assert!(
			reply.starts_with("250 "),
			"a near miss or local recipient must be accepted"
		);
	}
}

#[test]
fn a_scope_denies_recipients_for_its_own_account_only() {
	let scope = "[[antispam_scope]]\naccount = \"alice\"\n[antispam_scope.senders]\ndeny_recipients = [\"bob@example.org\"]\n";
	let mut session = alice(lists(scope));
	assert_eq!(
		rcpt(&mut session, "bob@example.org"),
		"550 5.7.1 sending to this recipient is not allowed\r\n"
	);
	let other = "[[antispam_scope]]\naccount = \"carol\"\n[antispam_scope.senders]\ndeny_recipients = [\"bob@example.org\"]\n";
	let mut session = alice(lists(other));
	assert!(rcpt(&mut session, "bob@example.org").starts_with("250 "));
}

#[test]
fn a_domain_scope_denies_recipients_for_every_account_of_the_domain() {
	let scope = "[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\ndeny_recipients = [\"x@example.net\"]\n";
	let mut session = alice(lists(scope));
	assert_eq!(
		rcpt(&mut session, "x@example.net"),
		"550 5.7.1 sending to this recipient is not allowed\r\n"
	);
}

#[test]
fn a_session_with_no_lists_is_unchanged() {
	let mut session = alice(lists(""));
	assert!(rcpt(&mut session, "x@a.example.net").starts_with("250 "));
}

#[test]
fn a_deny_of_senders_does_not_apply_to_an_account_that_logged_in() {
	// `deny` names envelope senders of other servers; an account of this
	// server submitting mail is judged by `deny_recipients` only.
	let scope = "[antispam.senders]\ndeny = [\"example.org\"]\n";
	let mut session = alice(lists(scope));
	assert!(rcpt(&mut session, "bob@example.org").starts_with("250 "));
}

#[test]
fn the_envelope_domain_of_an_account_does_not_choose_its_scope() {
	// alice owns an address in two domains; the domain scope of the first
	// denies a recipient. Sending as the address of the other domain must
	// not get around it.
	let scope = "[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\ndeny_recipients = [\"x@example.net\"]\n";
	let directory = Arc::new(Directory::new(
		["example.org".to_string(), "example.com".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("alice@example.com".to_string(), "alice".to_string()),
		],
	));
	for sender in ["alice@example.org", "alice@example.com"] {
		let mut session = Session::new("mail.example.org")
			.with_directory(Arc::clone(&directory))
			.with_scopes(lists(scope));
		session.mark_authenticated_for_test("alice");
		session.command_line("EHLO client.example.org");
		assert_eq!(
			reply_code(&session.command_line(&format!("MAIL FROM:<{sender}>"))),
			250
		);
		assert_eq!(
			rcpt(&mut session, "x@example.net"),
			"550 5.7.1 sending to this recipient is not allowed\r\n",
			"sent as {sender}"
		);
	}
}

#[test]
fn a_recipient_deny_matches_every_spelling_of_the_address() {
	let mut session = alice(lists(SERVER_DENY));
	for recipient in ["BLOCKED@Example.COM", "x@A.Example.NET"] {
		assert_eq!(
			rcpt(&mut session, recipient),
			"550 5.7.1 sending to this recipient is not allowed\r\n",
			"{recipient}"
		);
	}
}
