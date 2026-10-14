use super::render;

const DATE: &str = "Date: Thu, 15 Feb 2007 01:02:03 +0200\r\n";
const REAL: &str = "(\"Real Name\" NIL \"user\" \"domain\")";

fn envelope(headers: &str) -> String {
	let raw = format!("{DATE}{headers}\r\nbody\r\n");
	let parsed = super::super::parse(raw.as_bytes());
	String::from_utf8(render(&parsed, 0)).unwrap()
}

#[test]
fn empty_sender_and_reply_to_default_to_from() {
	// RFC 9051 §7.5.2: Sender and Reply-To that are present but empty take
	// the From value, exactly as when they are absent.
	let actual = envelope("From: user@domain (Real Name)\r\nSender: \r\nReply-To: \r\n");
	let expected = format!(
		"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ({REAL}) ({REAL}) ({REAL}) NIL NIL NIL NIL NIL)"
	);
	assert_eq!(actual, expected);
}

#[test]
fn comment_in_an_empty_group_is_not_an_address() {
	let actual = envelope(concat!(
		"From: user@domain (Real Name)\r\n",
		"To: group: g1@d1.org, g2@d2.org;, group2: g3@d3.org;\r\n",
		"Cc: group:;, group2: (foo) ;\r\n",
	));
	let to = concat!(
		"((NIL NIL \"group\" NIL)(NIL NIL \"g1\" \"d1.org\")(NIL NIL \"g2\" \"d2.org\")",
		"(NIL NIL NIL NIL)(NIL NIL \"group2\" NIL)(NIL NIL \"g3\" \"d3.org\")(NIL NIL NIL NIL))",
	);
	let cc = "((NIL NIL \"group\" NIL)(NIL NIL NIL NIL)(NIL NIL \"group2\" NIL)(NIL NIL NIL NIL))";
	let expected = format!(
		"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ({REAL}) ({REAL}) ({REAL}) {to} {cc} NIL NIL NIL)"
	);
	assert_eq!(actual, expected);
}

#[test]
fn source_route_is_kept_apart_from_the_mailbox() {
	let actual = envelope("From: <@route:user@domain>\r\n");
	let route = "(NIL \"@route\" \"user\" \"domain\")";
	let expected = format!(
		"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ({route}) ({route}) ({route}) NIL NIL NIL NIL NIL)"
	);
	assert_eq!(actual, expected);
}
