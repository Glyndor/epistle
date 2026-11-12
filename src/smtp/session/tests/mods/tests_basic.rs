use super::*;

pub(super) fn test_directory() -> Arc<Directory> {
	let mut entries: Vec<(String, String)> = vec![
		("b@example.org".to_string(), "bob".to_string()),
		("bob@example.org".to_string(), "bob".to_string()),
		("c@example.org".to_string(), "bob".to_string()),
		("overflow@example.org".to_string(), "bob".to_string()),
	];
	for i in 0..=DEFAULT_MAX_RECIPIENTS {
		entries.push((format!("r{i}@example.org"), "bob".to_string()));
	}
	Arc::new(Directory::new(["example.org".to_string()], entries))
}

pub(super) fn greeted() -> Session {
	let mut session = Session::new("mail.example.org").with_directory(test_directory());
	session.command_line("EHLO client.example.org");
	session
}

pub(super) fn reply_code(action: &Action) -> u16 {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r)
		| Action::DiscardChunk { reply: r, .. } => r.code(),
		Action::Deliver(r, _) => r.code(),
		// A BDAT chunk read carries no reply.
		Action::CollectChunk { .. } => 0,
	}
}

#[test]
fn greeting_announces_hostname() {
	let session = Session::new("mail.example.org");
	assert_eq!(
		session.greeting().to_string(),
		"220 mail.example.org ESMTP ready\r\n"
	);
}

#[test]
fn helo_greeting_has_no_esmtp_extensions() {
	let mut session = Session::new("mail.example.org")
		.with_directory(test_directory())
		.with_tls_available();
	let Action::Continue(reply) = session.command_line("HELO client.example.org") else {
		panic!("expected continue");
	};
	// Plain SMTP: a single-line greeting, no capability list.
	assert_eq!(reply.to_string(), "250 mail.example.org\r\n");
	assert!(!session.esmtp());
}

#[test]
fn ehlo_greeting_advertises_extensions() {
	let mut session = Session::new("mail.example.org")
		.with_directory(test_directory())
		.with_tls_available();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	let rendered = reply.to_string();
	assert!(
		rendered.contains("PIPELINING"),
		"EHLO must advertise PIPELINING"
	);
	assert!(
		rendered.contains("ENHANCEDSTATUSCODES"),
		"EHLO must advertise ENHANCEDSTATUSCODES"
	);
	assert!(
		rendered.contains("8BITMIME"),
		"EHLO must advertise 8BITMIME"
	);
	assert!(
		rendered.contains("SMTPUTF8"),
		"EHLO must advertise SMTPUTF8"
	);
	assert!(rendered.contains("SIZE "), "EHLO must advertise SIZE");
	assert!(
		rendered.contains("STARTTLS"),
		"EHLO must advertise STARTTLS"
	);
	assert!(
		rendered.contains(&format!("LIMITS RCPTMAX={DEFAULT_MAX_RECIPIENTS}")),
		"EHLO must advertise the recipient limit"
	);
	assert!(session.esmtp());
}

#[test]
fn full_transaction_delivers_message() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
		250
	);
	let action = session.command_line("DATA");
	assert!(matches!(action, Action::CollectData(_)));

	assert_eq!(session.data_line(b"Subject: hi"), None);
	assert_eq!(session.data_line(b""), None);
	assert_eq!(session.data_line(b"hello"), None);
	let Some(Action::Deliver(reply, message)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert_eq!(reply.code(), 250);
	assert_eq!(message.reverse_path, "alice@example.org");
	assert_eq!(message.recipients, vec!["bob@example.org".to_string()]);
	assert_eq!(message.data, b"Subject: hi\r\n\r\nhello\r\n");
	// Default NOTIFY: nobody opted out of failure DSNs.
	assert!(message.no_dsn.is_empty());
}
