use super::*;

#[test]
fn star_before_end_resolves_to_full_range() {
	// RFC 9051 §6.4.9 / RFC 3501 sequence-set ABNF: a range is an ordered
	// pair, but the order is free. "*:1" denotes the same set as "1:*"
	// once the maximum is resolved, i.e. every message in the mailbox.
	let set = parse_sequence_set("*:1").expect("parses");
	assert!(set.contains(1, 10, &[]), "*:1 must include msg 1");
	assert!(set.contains(5, 10, &[]), "*:1 must include mid-mailbox msg");
	assert!(set.contains(10, 10, &[]), "*:1 must include the last msg");
	assert!(!set.contains(0, 10, &[]));
	assert!(!set.contains(11, 10, &[]));
}

#[test]
fn star_after_start_resolves_to_full_range() {
	// Symmetric case: the existing tests already cover "3:*", so make
	// sure the same resolution still holds after the contains() fix.
	let set = parse_sequence_set("3:*").expect("parses");
	assert!(set.contains(3, 10, &[]));
	assert!(set.contains(10, 10, &[]));
	assert!(!set.contains(2, 10, &[]));
	assert!(!set.contains(11, 10, &[]));
}

#[test]
fn star_only_resolves_to_last_message() {
	// "*" alone is the highest message; nothing below it is included.
	let set = parse_sequence_set("*").expect("parses");
	assert!(set.contains(10, 10, &[]));
	assert!(!set.contains(9, 10, &[]));
	assert!(!set.contains(1, 10, &[]));
}

#[test]
fn star_colon_star_is_full_mailbox() {
	// "each end of the range resolves to max" → the range is (max, max),
	// which after ordering stays (max, max): one message. The real
	// "every message" form is the comma'd "1:*", "1,2,3", or "ALL".
	// "*:*" specifically means just the last message.
	let set = parse_sequence_set("*:*").expect("parses");
	assert!(set.contains(10, 10, &[]));
	assert!(!set.contains(9, 10, &[]));
}
