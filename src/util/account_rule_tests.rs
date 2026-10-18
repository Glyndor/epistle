//! The account-name rule and the name an address gives.

use super::*;

#[test]
fn a_dot_becomes_a_hyphen_and_capitals_are_lowered() {
	assert_eq!(derive("torre.control"), Ok("torre-control".to_string()));
	assert_eq!(derive("Torre.Control"), Ok("torre-control".to_string()));
	assert_eq!(derive("a.b.c"), Ok("a-b-c".to_string()));
	assert_eq!(derive("alice"), Ok("alice".to_string()));
}

#[test]
fn a_dot_at_the_start_at_the_end_or_twice_in_a_row_is_refused() {
	assert_eq!(derive(".torre"), Err(Fault::DotAtStart));
	assert_eq!(derive("torre."), Err(Fault::DotAtEnd));
	assert_eq!(derive("torre..control"), Err(Fault::DoubleDot));
	assert_eq!(derive("."), Err(Fault::DotAtStart));
}

#[test]
fn a_character_outside_the_rule_is_named() {
	assert_eq!(derive("a_b"), Err(Fault::BadChar('_')));
	assert_eq!(derive("a+b"), Err(Fault::BadChar('+')));
	assert_eq!(derive("josé"), Err(Fault::BadChar('é')));
	assert_eq!(derive("ñandú"), Err(Fault::BadChar('ñ')));
	let message = derive("a_b").unwrap_err().to_string();
	assert!(message.contains("'_'") && message.contains("lowercase letters, digits and hyphens"));
}

#[test]
fn a_leading_hyphen_an_empty_name_and_a_long_name_are_refused() {
	assert_eq!(derive("-a"), Err(Fault::LeadingHyphen));
	assert_eq!(derive(""), Err(Fault::Empty));
	assert_eq!(derive(&"a".repeat(64)), Ok("a".repeat(64)));
	assert_eq!(derive(&"a".repeat(65)), Err(Fault::TooLong(65)));
	assert_eq!(
		derive(&format!("{}.b", "a".repeat(63))),
		Err(Fault::TooLong(65))
	);
}

#[test]
fn the_stored_form_is_checked_without_converting_anything() {
	assert_eq!(check("torre-control"), Ok(()));
	assert_eq!(check("Torre"), Err(Fault::BadChar('T')));
	assert_eq!(check("torre.control"), Err(Fault::BadChar('.')));
	assert_eq!(check("-torre"), Err(Fault::LeadingHyphen));
	assert_eq!(check(""), Err(Fault::Empty));
	assert!(
		check("Torre")
			.unwrap_err()
			.to_string()
			.contains("capital letter")
	);
}

#[test]
fn two_addresses_that_differ_only_by_dot_or_hyphen_give_the_same_name() {
	// The collision `init` must detect: the rule alone cannot tell them apart.
	assert_eq!(derive("torre.control"), derive("torre-control"));
}

#[test]
fn the_messages_never_promise_a_conversion() {
	// The same text reaches the API, SCIM, config-check and migrations,
	// where nothing converts a capital letter; only init does, and it says
	// so itself.
	for c in ['A', 'É', '_', '+', 'é', ' '] {
		let text = Fault::BadChar(c).to_string();
		assert!(!text.contains("convert"), "{c:?}: {text}");
		assert!(!text.contains("init"), "{c:?}: {text}");
	}
	let outside = Fault::BadChar('É').to_string();
	assert!(outside.contains("outside ASCII"), "{outside}");
}

#[test]
fn the_dot_message_does_not_claim_init_converts_it() {
	// The same text reaches the API, SCIM, config-check and migrations,
	// where nothing turns a dot into a hyphen.
	let dot = Fault::BadChar('.').to_string();
	assert!(dot.contains("'.'") && dot.contains("use a hyphen"), "{dot}");
	assert!(!dot.contains("init"), "{dot}");
}

#[test]
fn an_empty_name_is_one_plain_sentence() {
	assert_eq!(refusal("", &Fault::Empty), "account name must not be empty");
	assert_eq!(
		refusal("a.b", &Fault::BadChar('.')),
		format!("account name \"a.b\": {}", Fault::BadChar('.'))
	);
}
