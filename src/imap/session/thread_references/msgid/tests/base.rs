use super::*;

fn key(id: &str) -> Key {
	digest(id.as_bytes())
}

#[test]
fn quoting_and_folding_do_not_change_the_id() {
	let plain = first_id("<01KF8JCEOCBS0045PS@xxx.yyy.com>");
	assert_eq!(plain, Some(key("01KF8JCEOCBS0045PS@xxx.yyy.com")));
	assert_eq!(first_id("<\"01KF8JCEOCBS0045PS\"@xxx.yyy.com>"), plain);
	assert_eq!(first_id("< 01KF8JCEOCBS0045PS@\r\n xxx.yyy.com >"), plain);
	assert_eq!(first_id("<\"a\\\"b\"@x>"), Some(key("a\"b@x")));
	assert_ne!(
		first_id("<A@x>"),
		first_id("<a@x>"),
		"ids compare case-sensitively"
	);
}

#[test]
fn invalid_ids_are_skipped() {
	for value in ["", "a@b", "<>", "<ab>", "<@b>", "<a@>", "<a@b", "(c) <x"] {
		assert_eq!(first_id(value), None, "{value:?}");
	}
	// An unclosed `<` before a valid id does not hide it.
	assert_eq!(first_id("<x <a@b>"), Some(key("a@b")));
	// In-Reply-To with an address after the id, as RFC 5256 §3 warns.
	assert_eq!(
		first_id("<a@b> (Joe's message of 1 Jan) <joe@example.org>"),
		Some(key("a@b"))
	);
}

#[test]
fn an_id_longer_than_the_cap_is_invalid() {
	let at_cap = format!("<{}@b>", "x".repeat(MAX_MSGID_LEN - 2));
	assert!(first_id(&at_cap).is_some());
	let over = format!("<{}@b>", "x".repeat(MAX_MSGID_LEN - 1));
	assert_eq!(first_id(&over), None);
}

#[test]
fn references_win_over_in_reply_to() {
	assert_eq!(
		references(Some("<a@b> <c@d>"), Some("<e@f>")),
		vec![key("a@b"), key("c@d")]
	);
	// No valid id in References falls back to the first in In-Reply-To.
	assert_eq!(
		references(Some("<junk>"), Some("<e@f> <g@h>")),
		vec![key("e@f")]
	);
	assert_eq!(references(None, Some("<e@f>")), vec![key("e@f")]);
	assert!(references(None, None).is_empty());
}

#[test]
fn only_the_last_references_are_kept() {
	let count = MAX_REFERENCES * 3 + 7;
	let value: String = (0..count).map(|i| format!("<r{i}@x> ")).collect();
	let kept = references(Some(&value), None);
	let expected: Vec<Key> = (count - MAX_REFERENCES..count)
		.map(|i| key(&format!("r{i}@x")))
		.collect();
	assert_eq!(kept, expected);
}
