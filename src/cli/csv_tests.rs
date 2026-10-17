//! The CSV field writer.

use super::field;

#[test]
fn a_field_is_quoted_only_when_it_has_to_be() {
	assert_eq!(field("plain text"), "plain text");
	assert_eq!(field("a,b"), "\"a,b\"");
	assert_eq!(field("say \"no\""), "\"say \"\"no\"\"\"");
	assert_eq!(field(" padded "), "\" padded \"");
	assert_eq!(field("tab\tinside\u{1b}"), "\"tab inside \"");
}

#[test]
fn an_apostrophe_is_added_even_in_front_of_an_apostrophe_and_a_formula_character() {
	assert_eq!(field("'-neg"), "''-neg");
	assert_eq!(field("'plain"), "'plain");
	assert_eq!(field("''=x"), "'''=x");
}
