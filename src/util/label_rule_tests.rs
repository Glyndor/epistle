use super::*;

#[test]
fn a_plain_label_is_accepted() {
	for label in [
		"iphone",
		"work phone",
		"tel\u{e9}fono",
		"a",
		&"a".repeat(MAX_LEN),
	] {
		assert_eq!(check(label), Ok(()), "{label:?}");
	}
}

#[test]
fn each_fault_is_found_in_the_order_of_the_rule() {
	let long = "a".repeat(MAX_LEN + 1);
	for (label, fault) in [
		("", Fault::Empty),
		("   ", Fault::Empty),
		("a\nb", Fault::Control('\n')),
		("a\u{202e}b", Fault::Invisible('\u{202e}')),
		("a\u{200b}b", Fault::Invisible('\u{200b}')),
		(" a", Fault::EdgeSpace),
		("a ", Fault::EdgeSpace),
		(long.as_str(), Fault::TooLong(MAX_LEN + 1)),
	] {
		assert_eq!(check(label), Err(fault), "{label:?}");
	}
}

#[test]
fn the_length_is_counted_in_characters_not_bytes() {
	assert_eq!(check(&"\u{e9}".repeat(MAX_LEN)), Ok(()));
}

#[test]
fn a_refusal_names_the_value_the_rule_and_a_label_to_type() {
	let line = problem("a\u{202e}b").expect("refused");
	assert!(line.contains("a\\u{202e}b"), "{line}");
	assert!(line.contains("invisible formatting"), "{line}");
	assert!(line.contains("for example \"work phone\""), "{line}");
	assert!(!line.contains('\u{202e}'), "the value is echoed escaped");
}

#[test]
fn a_long_value_is_cut_in_the_message() {
	let line = problem(&"a".repeat(500)).expect("refused");
	assert!(line.len() < 300, "{line}");
	assert!(line.contains("500 characters"), "{line}");
}
