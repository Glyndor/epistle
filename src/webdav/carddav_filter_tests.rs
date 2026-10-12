use super::{Test, matches, parse};

const CARD_ADA: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nEMAIL:ada@example.org\r\nitem1.EMAIL;TYPE=home:ada@personal.example.org\r\nEND:VCARD\r\n";

const CARD_BABBAGE: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Charles Babbage\r\nEMAIL:charles@example.org\r\nNOTE:R&D\r\nEND:VCARD\r\n";

const CARD_NO_EMAIL: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Anon Ymous\r\nEND:VCARD\r\n";

const CARDS: [&str; 3] = [CARD_ADA, CARD_BABBAGE, CARD_NO_EMAIL];

/// Parse `filter` (the `<CR:filter>` element) and report which of Ada,
/// Babbage and the card without EMAIL (`a`, `b`, `c`) it selects.
fn selected(filter: &str) -> Vec<char> {
	let body = format!(
		"<CR:addressbook-query xmlns:CR=\"urn:ietf:params:xml:ns:carddav\">{filter}</CR:addressbook-query>"
	);
	let parsed = parse(&body).expect("supported filter");
	CARDS
		.iter()
		.zip(['a', 'b', 'c'])
		.filter(|(card, _)| matches(&parsed, card))
		.map(|(_, name)| name)
		.collect()
}

fn email(text_match: &str) -> String {
	format!("<CR:filter><CR:prop-filter name=\"EMAIL\">{text_match}</CR:prop-filter></CR:filter>")
}

#[test]
fn no_filter_matches_every_card() {
	assert_eq!(selected(""), ['a', 'b', 'c']);
	assert_eq!(selected("<CR:filter/>"), ['a', 'b', 'c']);
}

#[test]
fn match_types_and_default_collation() {
	let tm = |kind: &str, text: &str| {
		email(&format!(
			"<CR:text-match match-type=\"{kind}\">{text}</CR:text-match>"
		))
	};
	assert_eq!(selected(&tm("equals", "ADA@EXAMPLE.ORG")), ['a']);
	assert_eq!(selected(&tm("starts-with", "charles@")), ['b']);
	assert_eq!(selected(&tm("ends-with", "personal.example.org")), ['a']);
	assert_eq!(selected(&tm("contains", "example")), ['a', 'b']);
}

#[test]
fn octet_collation_is_case_sensitive() {
	let tm = |text: &str| {
		email(&format!(
			"<CR:text-match collation=\"i;octet\" match-type=\"contains\">{text}</CR:text-match>"
		))
	};
	assert!(selected(&tm("ADA")).is_empty());
	assert_eq!(selected(&tm("ada")), ['a']);
}

#[test]
fn group_prefix_and_parameters_do_not_hide_the_property() {
	// Ada's personal address is on `item1.EMAIL;TYPE=home`.
	assert_eq!(
		selected(&email("<CR:text-match>personal</CR:text-match>")),
		['a']
	);
}

#[test]
fn negate_condition_applies_to_the_property_as_a_whole() {
	let negated = email("<CR:text-match negate-condition=\"yes\">personal</CR:text-match>");
	// Ada has one personal address among two: excluded. No EMAIL at all:
	// nothing to test, excluded.
	assert_eq!(selected(&negated), ['b']);
}

#[test]
fn filter_test_attribute_combines_prop_filters() {
	let pfs = "<CR:prop-filter name=\"EMAIL\"><CR:text-match>personal</CR:text-match></CR:prop-filter>\
		<CR:prop-filter name=\"FN\"><CR:text-match>anon</CR:text-match></CR:prop-filter>";
	assert_eq!(
		selected(&format!("<CR:filter>{pfs}</CR:filter>")),
		['a', 'c']
	);
	assert!(selected(&format!("<CR:filter test=\"allof\">{pfs}</CR:filter>")).is_empty());
}

#[test]
fn prop_filter_test_attribute_combines_its_text_matches() {
	let pf = |test: &str| {
		format!(
			"<CR:filter><CR:prop-filter name=\"FN\" test=\"{test}\">\
			<CR:text-match>ada</CR:text-match><CR:text-match>love</CR:text-match>\
			<CR:text-match>babbage</CR:text-match></CR:prop-filter></CR:filter>"
		)
	};
	assert_eq!(selected(&pf("anyof")), ['a', 'b']);
	assert!(selected(&pf("allof")).is_empty());
}

#[test]
fn prop_filter_test_does_not_leak_into_the_filter() {
	// The filter has no `test`, so it is anyof even though the first
	// prop-filter says allof.
	let body = "<CR:filter><CR:prop-filter name=\"FN\" test=\"allof\"><CR:text-match>ada</CR:text-match>\
		</CR:prop-filter><CR:prop-filter name=\"FN\"><CR:text-match>anon</CR:text-match></CR:prop-filter></CR:filter>";
	let parsed = parse(body).expect("supported filter");
	assert_eq!(parsed.test, Test::AnyOf);
	assert_eq!(parsed.prop_filters[0].test, Test::AllOf);
	assert_eq!(selected(body), ['a', 'c']);
}

#[test]
fn is_not_defined_and_bare_prop_filter() {
	let undefined = "<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:is-not-defined/></CR:prop-filter></CR:filter>";
	assert_eq!(selected(undefined), ['c']);
	let present = "<CR:filter><CR:prop-filter name=\"email\"/></CR:filter>";
	assert_eq!(selected(present), ['a', 'b']);
}

#[test]
fn text_match_entities_are_decoded() {
	let note = "<CR:filter><CR:prop-filter name=\"NOTE\">\
		<CR:text-match match-type=\"equals\">r&amp;d</CR:text-match></CR:prop-filter></CR:filter>";
	assert_eq!(selected(note), ['b']);
}

#[test]
fn unsupported_shapes_are_refused() {
	for filter in [
		"<CR:filter test=\"oneof\"/>",
		"<CR:filter><CR:prop-filter name=\"EMAIL\" test=\"none\"/></CR:filter>",
		"<CR:filter><CR:prop-filter/></CR:filter>",
		"<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:param-filter name=\"TYPE\"/></CR:prop-filter></CR:filter>",
		"<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:text-match collation=\"i;ascii-numeric\">1</CR:text-match></CR:prop-filter></CR:filter>",
		"<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:text-match match-type=\"regex\">a</CR:text-match></CR:prop-filter></CR:filter>",
		"<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:is-not-defined/><CR:text-match>a</CR:text-match></CR:prop-filter></CR:filter>",
		"<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:text-match>a</CR:prop-filter></CR:filter>",
		"<CR:filter><CR:comp-filter name=\"VCARD\"/></CR:filter>",
	] {
		let body = format!("<CR:addressbook-query xmlns:CR=\"x\">{filter}</CR:addressbook-query>");
		assert!(parse(&body).is_err(), "accepted: {filter}");
	}
}
