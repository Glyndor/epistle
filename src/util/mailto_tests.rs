//! The two spellings of the address a `mailto` URI names. An alias local part
//! may legally carry `?`, `&`, `%` and `/` (RFC 5321 `sub-addresses`,
//! SMTPUTF8), and each of them means something else inside a URI: left alone
//! they turn `a?b&c%d@example.org` into a query the unsubscribe reader never
//! gets to, and `a/b@example.org` into a path.

use super::*;

#[test]
fn a_local_part_that_carries_uri_characters_is_percent_encoded() {
	// The same address the bulk unsubscribe encodes, so the list block and the
	// bulk block cannot disagree about how an address is spelled.
	assert_eq!(
		uri("a?b&c%d@example.org"),
		"<mailto:a%3Fb%26c%25d@example.org>"
	);
	assert_eq!(
		unsubscribe("a?b&c%d@example.org"),
		"<mailto:a%3Fb%26c%25d@example.org?subject=unsubscribe>"
	);
}

#[test]
fn a_slash_in_the_local_part_is_percent_encoded() {
	// `/` is atext, so the address is one a client may submit, and it is a
	// path delimiter in a URI: RFC 6068 spells that address `a%2Fb@`.
	assert_eq!(uri("a/b@example.org"), "<mailto:a%2Fb@example.org>");
	assert_eq!(
		unsubscribe("a/b@example.org"),
		"<mailto:a%2Fb@example.org?subject=unsubscribe>"
	);
}

#[test]
fn an_ordinary_address_is_written_as_it_is() {
	assert_eq!(uri("team@example.org"), "<mailto:team@example.org>");
	assert_eq!(
		unsubscribe("team@example.org"),
		"<mailto:team@example.org?subject=unsubscribe>"
	);
}
