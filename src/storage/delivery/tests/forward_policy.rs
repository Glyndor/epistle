//! The forwarding policy and limits (`[forwarding]` and the scopes): where
//! a forward, a Sieve redirect and a vacation reply may go, and how many an
//! account may send. What is held back is never lost: the message stays in
//! the mailbox.

use std::sync::Arc;

use super::*;
use crate::antispam::scopes::Scopes;
use crate::config::Config;
use crate::forwarding::Guard;

const REDIRECT: &str = "redirect \"x@target.example\";";
const REDIRECT_TWO: &str = "redirect \"x@target.example\";\nredirect \"y@target.example\";";
const REDIRECT_HOSTED: &str = "redirect \"bob@example.org\";";
const VACATION: &str = "require \"vacation\";\nvacation :days 1 \"away\";";

fn guard(extra: &str) -> Arc<Guard> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n{extra}"
	)
	.expect("write config");
	let config = Config::load(file.path()).expect("config loads");
	Arc::new(Guard::from_config(
		&config,
		Arc::new(Scopes::from_config(&config)),
	))
}

fn directory(forward: Option<bool>) -> DirectoryHandle {
	let base = crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	);
	DirectoryHandle::new(match forward {
		Some(keep_local) => base.with_forwards([(
			"alice".to_string(),
			(vec!["ext@other.example".to_string()], keep_local),
		)]),
		None => base,
	})
}

fn message(data: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec!["alice@example.org".to_string()],
		data: data.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

const PLAIN: &[u8] =
	b"To: alice@example.org\r\nSubject: hi\r\nMessage-ID: <m1@elsewhere.example>\r\n\r\nbody\r\n";

/// A delivery to alice, `times` times, under `guard`. Returns what each
/// delivery produced and how many copies alice's INBOX holds.
fn deliver(
	guard: Arc<Guard>,
	forward: Option<bool>,
	script: Option<&str>,
	data: &[u8],
	times: usize,
) -> (Vec<Delivered>, usize) {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory(forward))
		.expect("delivery")
		.with_forwarding(guard);
	let account = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account).expect("mkdir");
	if let Some(script) = script {
		fs::write(account.join("filter.sieve"), script).expect("filter");
	}
	let delivered: Vec<Delivered> = (0..times)
		.map(|_| {
			delivery
				.deliver_routed(&message(data), None)
				.expect("deliver")
		})
		.collect();
	let inbox = fs::read_dir(account.join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0);
	(delivered, inbox)
}

fn forwarded(delivered: &[Delivered]) -> usize {
	delivered.iter().map(|one| one.redirects.len()).sum()
}

#[test]
fn the_default_policy_forwards_anywhere() {
	let (out, _) = deliver(guard(""), Some(true), None, PLAIN, 1);
	assert_eq!(forwarded(&out), 1);
	let (out, _) = deliver(guard(""), None, Some(REDIRECT), PLAIN, 1);
	assert_eq!(forwarded(&out), 1);
}

#[test]
fn policy_none_stops_a_forward_a_redirect_and_a_reply() {
	let none = "[forwarding]\npolicy = \"none\"";
	// A pure forward would store nothing: the copy must stay.
	let (out, inbox) = deliver(guard(none), Some(false), None, PLAIN, 1);
	assert_eq!(forwarded(&out), 0);
	assert_eq!(inbox, 1);
	// `redirect` cancels the implicit keep, so the filter alone would lose it.
	let (out, inbox) = deliver(guard(none), None, Some(REDIRECT), PLAIN, 1);
	assert_eq!(forwarded(&out), 0);
	assert_eq!(inbox, 1);
	let (out, _) = deliver(guard(none), None, Some(VACATION), PLAIN, 1);
	assert!(out[0].replies.is_empty());
	// Control: the same vacation answers under the default policy.
	let (out, _) = deliver(guard(""), None, Some(VACATION), PLAIN, 1);
	assert_eq!(out[0].replies.len(), 1);
}

#[test]
fn hosted_only_lets_a_copy_reach_a_hosted_domain_and_no_other() {
	let hosted = "[forwarding]\npolicy = \"hosted-only\"";
	let (out, inbox) = deliver(guard(hosted), None, Some(REDIRECT), PLAIN, 1);
	assert_eq!(forwarded(&out), 0);
	assert_eq!(inbox, 1);
	let (out, _) = deliver(guard(hosted), None, Some(REDIRECT_HOSTED), PLAIN, 1);
	assert_eq!(forwarded(&out), 1);
	// The same script with two targets forwards the hosted one only.
	let mixed = "redirect \"bob@example.org\";\nredirect \"x@target.example\";";
	let (out, inbox) = deliver(guard(hosted), None, Some(mixed), PLAIN, 1);
	assert_eq!(out[0].redirects.len(), 1);
	assert_eq!(out[0].redirects[0].to, "bob@example.org");
	assert_eq!(inbox, 1, "a refused target keeps the message");
	// A configured forward to another server is refused as well.
	let (out, inbox) = deliver(guard(hosted), Some(false), None, PLAIN, 1);
	assert_eq!(forwarded(&out), 0);
	assert_eq!(inbox, 1);
	// The vacation reply goes to an unhosted sender: refused.
	let (out, _) = deliver(guard(hosted), None, Some(VACATION), PLAIN, 1);
	assert!(out[0].replies.is_empty());
}

#[test]
fn a_scope_overrides_the_server_policy_for_its_account() {
	let extra = "[forwarding]\npolicy = \"none\"\n\
		[[antispam_scope]]\naccount = \"alice\"\nforward_policy = \"any\"";
	let (out, _) = deliver(guard(extra), None, Some(REDIRECT), PLAIN, 1);
	assert_eq!(forwarded(&out), 1, "the account's scope relaxes the server");
	let extra = "[[antispam_scope]]\ndomain = \"example.org\"\nforward_policy = \"none\"";
	let (out, inbox) = deliver(guard(extra), None, Some(REDIRECT), PLAIN, 1);
	assert_eq!(
		forwarded(&out),
		0,
		"the domain's scope tightens the default"
	);
	assert_eq!(inbox, 1);
}

#[test]
fn a_batch_over_the_account_limit_is_refused_whole_and_kept() {
	let limit = "[forwarding]\naccount_per_min = 1";
	let (out, inbox) = deliver(guard(limit), None, Some(REDIRECT_TWO), PLAIN, 1);
	assert_eq!(forwarded(&out), 0, "two copies do not fit one");
	assert_eq!(inbox, 1);
	// One copy fits, the next message's does not.
	let (out, inbox) = deliver(guard(limit), None, Some(REDIRECT), PLAIN, 2);
	assert_eq!(out[0].redirects.len(), 1);
	assert_eq!(out[1].redirects.len(), 0);
	assert_eq!(inbox, 1, "only the limited message was kept");
}

#[test]
fn the_account_limit_follows_the_submission_limit_unless_set() {
	let submission = "submission_rate_limit_per_min = 1";
	let (out, _) = deliver(guard(submission), None, Some(REDIRECT), PLAIN, 2);
	assert_eq!((out[0].redirects.len(), out[1].redirects.len()), (1, 0));
	// A limit of its own for forwarding wins over the submission one.
	let both = "submission_rate_limit_per_min = 1\n[forwarding]\naccount_per_min = 5";
	let (out, _) = deliver(guard(both), None, Some(REDIRECT), PLAIN, 2);
	assert_eq!(forwarded(&out), 2);
	// So does the one of a scope.
	let scoped = "[forwarding]\naccount_per_min = 5\n\
		[[antispam_scope]]\naccount = \"alice\"\nforward_per_min = 1";
	let (out, _) = deliver(guard(scoped), None, Some(REDIRECT), PLAIN, 2);
	assert_eq!((out[0].redirects.len(), out[1].redirects.len()), (1, 0));
}

#[test]
fn the_server_limit_counts_every_account() {
	let server = "[forwarding]\nserver_per_min = 1";
	let shared = guard(server);
	let (first, _) = deliver(Arc::clone(&shared), None, Some(REDIRECT), PLAIN, 1);
	assert_eq!(forwarded(&first), 1);
	// Another delivery under the same guard shares the server's window.
	let (second, inbox) = deliver(shared, None, Some(REDIRECT), PLAIN, 1);
	assert_eq!(forwarded(&second), 0);
	assert_eq!(inbox, 1);
}

#[test]
fn a_vacation_reply_is_charged_like_a_forward() {
	let limit = "[forwarding]\naccount_per_min = 1";
	// One reply fits the limit of one.
	let (out, _) = deliver(guard(limit), None, Some(VACATION), PLAIN, 1);
	assert_eq!(out[0].replies.len(), 1);
	// A redirect spends it first, so the reply of the same message is held.
	let both = format!("{VACATION}\nredirect \"x@target.example\";");
	let (out, _) = deliver(guard(limit), None, Some(&both), PLAIN, 1);
	assert_eq!(out[0].redirects.len() + out[0].replies.len(), 1);
}

#[test]
fn a_sieve_redirect_stops_after_too_many_hops() {
	let mut data = Vec::new();
	for _ in 0..(MAX_FORWARD_HOPS + 1) {
		data.extend_from_slice(b"Received: from a by b\r\n");
	}
	data.extend_from_slice(PLAIN);
	let (out, inbox) = deliver(guard(""), None, Some(REDIRECT), &data, 1);
	assert_eq!(forwarded(&out), 0, "a chain of redirects ends");
	assert_eq!(inbox, 1);
}

#[test]
fn a_message_that_loops_back_is_still_refused_whatever_the_policy() {
	let mut data = b"Delivered-To: alice@example.org\r\n".to_vec();
	data.extend_from_slice(PLAIN);
	let (out, inbox) = deliver(guard(""), None, Some(REDIRECT), &data, 1);
	assert_eq!(out[0].looped, vec!["alice@example.org".to_string()]);
	assert_eq!(inbox, 0);
}
