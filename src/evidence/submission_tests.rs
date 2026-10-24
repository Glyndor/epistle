use super::*;

fn message(headers: &str, recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "news@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: format!("From: news@example.org\r\n{headers}Subject: s\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

const ONE_CLICK: &str = "List-Unsubscribe: <https://example.org/u>\r\n\
	List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n";

fn marketing() -> ClassSources {
	ClassSources {
		explicit: Some(MailClass::Marketing),
		..ClassSources::default()
	}
}

#[test]
fn the_class_comes_from_the_server_and_the_header_is_removed() {
	let mut submitted = message("Epistle-Class: transactional\r\n", &["a@example.net"]);
	let prepared = prepare(
		&mut submitted,
		ClassSources::default(),
		None,
		&Policy::default(),
		None,
	)
	.expect("prepared");
	assert_eq!(prepared.class, MailClass::Personal);
	let text = String::from_utf8(submitted.data).expect("utf8");
	assert!(
		!text.contains("Epistle-Class"),
		"the class header reached the queue"
	);
}

#[test]
fn marketing_without_one_click_is_refused() {
	let mut submitted = message("", &["a@example.net"]);
	assert_eq!(
		prepare(&mut submitted, marketing(), None, &Policy::default(), None),
		Err(MarketingRefusal::NoUnsubscribeUri)
	);
}

/// A list address sending marketing mail it already published a one-click
/// unsubscribe for: the list block must not replace that URL with a mailto
/// and refuse the message over it.
#[test]
fn marketing_from_a_list_keeps_the_one_click_the_client_chose() {
	let directory = crate::smtp::directory::Directory::default().with_aliases([(
		"news@example.org".to_string(),
		crate::smtp::directory::AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: false,
			list_id: Some("news.example.org".to_string()),
		},
	)]);
	let mut submitted = message(ONE_CLICK, &["a@example.net"]);
	prepare(
		&mut submitted,
		marketing(),
		None,
		&Policy::default(),
		Some(&directory),
	)
	.expect("a list that honours one-click is not refused");
	assert_eq!(
		crate::smtp::trace::header_values(&submitted.data, "list-unsubscribe"),
		vec!["<https://example.org/u>".to_string()]
	);
	assert_eq!(
		crate::smtp::trace::header_values(&submitted.data, "list-post"),
		vec!["<mailto:news@example.org>".to_string()],
		"the list block still says what the list is"
	);
}

#[test]
fn marketing_is_marked_bulk_and_suppressed_recipients_are_dropped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let list = crate::queue::SuppressionList::open(dir.path()).expect("list");
	list.suppress("gone@example.net");
	list.suppress_for_because(
		"news@example.org",
		"unsubscribed@example.net",
		"550 5.1.1",
		1,
	);
	let mut submitted = message(
		ONE_CLICK,
		&[
			"kept@example.net",
			"gone@example.net",
			"unsubscribed@example.net",
		],
	);
	let prepared = prepare(
		&mut submitted,
		marketing(),
		Some(dir.path()),
		&Policy::default(),
		None,
	)
	.expect("prepared");
	assert_eq!(prepared.class, MailClass::Marketing);
	assert_eq!(
		prepared.suppressed,
		vec!["gone@example.net", "unsubscribed@example.net"]
	);
	assert_eq!(submitted.recipients, vec!["kept@example.net"]);
	assert!(
		submitted.data.starts_with(b"Precedence: bulk\r\n"),
		"bulk was not marked"
	);
}

#[test]
fn other_classes_keep_suppressed_recipients_for_the_worker() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@example.net");
	let mut submitted = message("", &["gone@example.net"]);
	let sources = ClassSources {
		explicit: Some(MailClass::Transactional),
		..ClassSources::default()
	};
	let prepared = prepare(
		&mut submitted,
		sources,
		Some(dir.path()),
		&Policy::default(),
		None,
	)
	.expect("prepared");
	assert!(prepared.suppressed.is_empty());
	assert_eq!(submitted.recipients, vec!["gone@example.net"]);
}
