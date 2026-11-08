//! The web adapters: the token, the CalDAV query and the request body.

use super::common::INPUT_CAP;
use super::common::floor_char_boundary;

/// A CalDAV or CardDAV query body, the iCalendar and vCard text it is matched
/// against, and the recurrence rule that expands an event: the XML filter
/// parser, the component walker and the bounded RRULE expansion.
pub fn webdav_filter_rrule(input: &str) {
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	if let Ok(filter) = crate::webdav::caldav_filter::parse(input) {
		let _ = std::hint::black_box(crate::webdav::caldav_filter::matches(&filter, input));
	}
	if let Ok(filter) = crate::webdav::carddav_filter::parse(input) {
		std::hint::black_box(crate::webdav::carddav_filter::matches(&filter, input));
	}
	std::hint::black_box(crate::webdav::rrule::parse_datetime(input));
	if let Some(rule) = crate::webdav::rrule::parse_rule(input) {
		std::hint::black_box(crate::webdav::rrule::expand_bounded(
			0,
			Some(&rule),
			0,
			4_000_000_000,
			1_000,
		));
	}
}

/// A JWT as an identity provider would present it: the three parts, the
/// header and the payload decoding and the claim checks. The key is fixed and
/// does not match, so a signature never verifies and every path before that
/// check is the one that runs.
pub fn jwt_decode(token: &str) {
	let token = &token[..floor_char_boundary(token, INPUT_CAP)];
	let validation = crate::jwt::Validation {
		now: 1_800_000_000,
		issuer: Some("https://issuer.example"),
		audience: Some("epistle"),
	};
	for algorithm in [crate::jwt::Algorithm::Rs256, crate::jwt::Algorithm::Es256] {
		let _ = crate::jwt::validate(token, algorithm, &[0u8; 32], &validation);
	}
}

/// A CalDAV or CardDAV request body outside the filters: the hrefs of a
/// multiget, the discovery and data checks, and a `sync-collection` request
/// with its level, its token and the change log the token is checked against.
pub fn webdav_report_body(input: &str) {
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	crate::webdav::fuzzing::report_body_for_fuzzing(input);
}
