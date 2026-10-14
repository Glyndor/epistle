use super::super::wire::Segment;
use super::*;

fn line(text: &[u8]) -> Response {
	Response {
		segments: vec![Segment {
			text: text.to_vec(),
			literal: None,
		}],
	}
}

#[test]
fn kinds() {
	assert_eq!(kind(&line(b"+ go on")), Kind::Continuation);
	assert_eq!(
		kind(&line(b"M1 NO [AUTHENTICATIONFAILED] nope")),
		Kind::Tagged {
			tag: b"M1".to_vec(),
			status: Status::No,
			text: b"[AUTHENTICATIONFAILED] nope".to_vec()
		}
	);
	assert_eq!(
		kind(&line(b"* BYE shutting down")),
		Kind::UntaggedStatus {
			status: Status::Bye,
			text: b"shutting down".to_vec()
		}
	);
	assert_eq!(kind(&line(b"* 3 EXISTS")), Kind::Data);
}

#[test]
fn response_codes() {
	assert_eq!(
		response_code(b"[UIDVALIDITY 3857529045] UIDs valid"),
		vec!["UIDVALIDITY", "3857529045"]
	);
	assert!(response_code(b"no code").is_empty());
	assert!(response_code(b"[unterminated").is_empty());
}

#[test]
fn list_entries() {
	let entry = list_entry(&line(br#"* LIST (\HasNoChildren \Sent) "." "Sent Items""#))
		.expect("parse")
		.expect("entry");
	assert_eq!(entry.attributes, vec!["\\hasnochildren", "\\sent"]);
	assert_eq!(entry.delimiter, Some(b'.'));
	assert_eq!(entry.name, b"Sent Items");
	let flat = list_entry(&line(br#"* XLIST () NIL INBOX"#))
		.expect("parse")
		.expect("entry");
	assert_eq!(
		(flat.delimiter, flat.name.as_slice()),
		(None, &b"INBOX"[..])
	);
	assert_eq!(list_entry(&line(b"* 3 EXISTS")).expect("parse"), None);
	assert!(list_entry(&line(br#"* LIST (\Sent) "//" x"#)).is_err());
	assert!(list_entry(&line(br#"* LIST \Sent "/" x"#)).is_err());
}

#[test]
fn namespace_prefix() {
	assert_eq!(
		personal_namespace(&line(br#"* NAMESPACE (("INBOX." ".")) NIL NIL"#)),
		Some(b"INBOX.".to_vec())
	);
	assert_eq!(personal_namespace(&line(b"* NAMESPACE NIL NIL NIL")), None);
}

#[test]
fn a_fetch_with_a_body_literal() {
	let response = Response {
		segments: vec![
			Segment {
				text: br#"* 4 FETCH (UID 9 FLAGS (\Seen $Work) INTERNALDATE "17-Jul-1996 02:44:25 -0700" RFC822.SIZE 3 X-GM-LABELS (a (b)) BODY[] {3}"#.to_vec(),
				literal: Some(b"abc".to_vec()),
			},
			Segment {
				text: b")".to_vec(),
				literal: None,
			},
		],
	};
	let fetched = fetch(response).expect("parse").expect("fetch");
	assert_eq!(fetched.uid, 9);
	assert_eq!(fetched.flags, vec!["\\Seen", "$Work"]);
	assert_eq!(
		fetched.internal_date,
		crate::imap::command::parse_date_time("17-Jul-1996 02:44:25 -0700")
	);
	assert_eq!(fetched.size, Some(3));
	assert_eq!(fetched.body.as_deref(), Some(&b"abc"[..]));
}

#[test]
fn listing_answers_and_noise() {
	assert_eq!(
		listed(line(b"* 1 FETCH (UID 5 RFC822.SIZE 120)")).expect("parse"),
		Some(Listed { uid: 5, size: 120 })
	);
	assert_eq!(
		listed(line(b"* 1 FETCH (FLAGS (\\Seen))")).expect("parse"),
		None
	);
	assert_eq!(listed(line(b"* 2 EXPUNGE")).expect("parse"), None);
	assert!(listed(line(b"* 1 FETCH (UID five)")).is_err());
	assert!(listed(line(b"* 1 FETCH UID 5")).is_err());
}
