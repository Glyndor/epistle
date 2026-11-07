//! A signed minimum in a selector is refused, not an overflow in a build that checks.

use super::{calendar, event, filter, isolated, measured};
use crate::webdav::caldav_filter;

#[test]
fn signed_minimum_in_a_selector_does_not_panic() {
	isolated(
		"selector_overflow::signed_minimum_in_a_selector_does_not_panic",
		|| {
			let ics = calendar(&event("FREQ=MONTHLY;BYMONTHDAY=-2147483648", ""));
			let f = filter("20260101T000000Z", "20260201T000000Z", "");
			// Malformed input may be refused or approximated; it must not panic.
			let _ = measured(|| caldav_filter::matches(&f, &ics));
		},
	);
}

#[test]
fn signed_minimum_in_a_weekday_ordinal_does_not_panic() {
	isolated(
		"selector_overflow::signed_minimum_in_a_weekday_ordinal_does_not_panic",
		|| {
			let ics = calendar(&event("FREQ=MONTHLY;BYDAY=-2147483648MO", ""));
			let f = filter("20260101T000000Z", "20260201T000000Z", "");
			let _ = measured(|| caldav_filter::matches(&f, &ics));
		},
	);
}
