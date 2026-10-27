//! What a user's `redirect` may become on the outbound side: an address this
//! server would accept as a recipient, and no more of them than the limit.

use super::*;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

fn deliver_with(script: &str) -> Delivered {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	let account = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account).expect("mkdir");
	fs::write(account.join("filter.sieve"), script).expect("filter");
	let message = AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec!["alice@example.org".to_string()],
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	};
	delivery.deliver_routed(&message, None).expect("deliver")
}

fn targets(delivered: &Delivered) -> Vec<&str> {
	delivered.redirects.iter().map(|r| r.to.as_str()).collect()
}

#[test]
fn a_redirect_that_is_not_an_address_is_never_queued() {
	// The target goes to the outbound queue as an envelope recipient and is
	// written into an `RCPT TO:<...>` line. A line break in it would be a
	// second SMTP command on a connection to a server of the script
	// author's choosing.
	for target in [
		"a@b.example>\r\nRCPT TO:<z@victim.example",
		"a@b.example\r\nDATA",
		"a b@c.example",
		"<a@c.example>",
		"a@c.example, d@e.example",
		"no-at-sign",
		"",
	] {
		let delivered = deliver_with(&format!("redirect text:\n{target}\n.\n;"));
		assert!(
			targets(&delivered).is_empty(),
			"queued {:?}",
			targets(&delivered)
		);
	}
}

#[test]
fn a_redirect_that_is_an_address_is_queued_in_its_canonical_form() {
	let delivered = deliver_with("redirect \"Who@Target.Example\";");
	assert_eq!(targets(&delivered), vec!["Who@target.example"]);
}

#[test]
fn a_script_of_many_redirects_queues_only_the_limit() {
	let script: String = (0..5_000)
		.map(|n| format!("redirect \"user{n}@target.example\";"))
		.collect();
	let delivered = deliver_with(&script);
	assert_eq!(
		delivered.redirects.len(),
		crate::sieve::interp::MAX_REDIRECTS
	);
}
