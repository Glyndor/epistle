//! Malformed lines, Apple groups, empty values and RFC 6350 folding.

use super::{isolated, measured};
use crate::webdav::carddav_filter;

pub(super) fn hostile_card() -> String {
	format!(
		"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Hostile\r\nX-FOO\r\nX-EMPTY:\r\n\
		item1.EMAIL;TYPE=work:ali\r\n ce@example.org\r\nNOTE:start\r\n{}\
		EMAIL:other@example.net\r\nEND:VCARD\r\n",
		" x\r\n".repeat(500_000)
	)
}

pub(super) fn query(property: &str, text: &str) -> String {
	format!(
		"<CR:addressbook-query xmlns:D=\"DAV:\" xmlns:CR=\"urn:ietf:params:xml:ns:carddav\">\
		<D:prop><D:getetag/></D:prop><CR:filter><CR:prop-filter name=\"{property}\">\
		<CR:text-match match-type=\"equals\">{text}</CR:text-match>\
		</CR:prop-filter></CR:filter></CR:addressbook-query>"
	)
}

#[test]
fn hostile_properties_match_exactly_with_bounded_memory() {
	isolated(
		"card::hostile_properties_match_exactly_with_bounded_memory",
		|| {
			let card = hostile_card();
			assert!(card.len() as u64 <= crate::webdav::report_bounds::MAX_RESOURCE_BYTES);
			for (property, value, expected) in [
				("EMAIL", "alice@example.org", true),
				("EMAIL", "other@example.net", true),
				("EMAIL", "ce@example.org", false),
				("X-EMPTY", "", true),
				("X-FOO", "", false),
				("FN", "Hostile", true),
			] {
				let f = carddav_filter::parse(&query(property, value)).expect("filter");
				assert_eq!(
					measured(|| carddav_filter::matches(&f, &card)),
					expected,
					"{property}={value}"
				);
			}
		},
	);
}
