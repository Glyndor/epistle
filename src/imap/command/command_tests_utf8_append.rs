//! Parsing of the RFC 6855 §4 `UTF8 (~{n})` APPEND data item.

use super::*;

fn append(line: &str) -> (usize, bool, Vec<String>) {
	match parse(line).expect("parses").command {
		Command::Append {
			size, utf8, flags, ..
		} => (size, utf8, flags),
		other => panic!("not an APPEND: {other:?}"),
	}
}

#[test]
fn recognises_the_utf8_data_item() {
	assert_eq!(append("a APPEND INBOX UTF8 (~{12}"), (12, true, vec![]));
	assert_eq!(
		append("a APPEND INBOX (\\Seen) utf8 (~{7+}"),
		(7, true, vec!["\\Seen".to_string()])
	);
	assert_eq!(
		append("a APPEND INBOX (\\Seen)UTF8 (~{7}"),
		(7, true, vec!["\\Seen".to_string()])
	);
}

#[test]
fn plain_and_look_alike_literals_are_not_utf8() {
	assert_eq!(append("a APPEND INBOX {12}"), (12, false, vec![]));
	assert_eq!(append("a APPEND INBOX ~{12}"), (12, false, vec![]));
	assert_eq!(append("a APPEND INBOX XUTF8 (~{12}"), (12, false, vec![]));
	assert_eq!(append("a APPEND INBOX UTF8 ({12}"), (12, false, vec![]));
}
