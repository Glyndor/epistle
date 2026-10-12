use super::{
	CalendarQueryFilter, CompFilter, PropFilter, TextMatch, TimeRange, load_and_match, matches,
	none, parse, time_range_only,
};

const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTART:20260115T090000Z\r\nDTEND:20260115T100000Z\r\nSUMMARY:One\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const RECURRING: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:r1\r\nDTSTART:20260101T080000Z\r\nDTEND:20260101T090000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:Daily\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const TODO: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:t1\r\nSUMMARY:Buy milk\r\nDUE:20260115T100000Z\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";

#[test]
fn empty_filter_matches_everything() {
	let f = none();
	assert!(matches(&f, EVENT));
	assert!(matches(&f, TODO));
}

#[test]
fn time_range_filter_includes_overlapping_event() {
	let range = TimeRange {
		start: 1_766_620_800, // 2025-12-25T00:00:00Z
		end: 1_769_904_000,   // 2026-02-01T00:00:00Z
	};
	let f = time_range_only("VEVENT", range).expect("filter");
	assert!(matches(&f, EVENT));
}

#[test]
fn time_range_filter_excludes_event_outside_window() {
	let range = TimeRange {
		start: 1_700_006_400, // 2023-11-15T00:00:00Z
		end: 1_700_092_800,   // 2023-11-16T00:00:00Z
	};
	let f = time_range_only("VEVENT", range).expect("filter");
	assert!(!matches(&f, EVENT));
}

#[test]
fn time_range_filter_includes_a_recurring_occurrence_in_window() {
	// The first occurrence of RECURRING is 2026-01-01T08:00:00Z, the
	// third is 2026-01-03T08:00:00Z.
	let range = TimeRange {
		start: 1_767_312_000, // 2026-01-02T00:00:00Z
		end: 1_767_398_400,   // 2026-01-03T00:00:00Z
	};
	let f = time_range_only("VEVENT", range).expect("filter");
	// The window covers the 2nd occurrence (2026-01-02T08:00Z) and
	// the upper bound is exclusive of the 3rd, but the matcher
	// returns the next occurrence that lies in the window and an
	// occurrence that ends at 09:00 with start at 08:00 is well
	// inside. The test asserts at least one occurrence overlaps.
	assert!(matches(&f, RECURRING));
}

#[test]
fn time_range_filter_excludes_recurring_event_with_no_occurrence_in_window() {
	let range = TimeRange {
		start: 1_770_000_000, // 2026-02-01T00:00:00Z (after the last)
		end: 1_770_086_400,
	};
	let f = time_range_only("VEVENT", range).expect("filter");
	assert!(!matches(&f, RECURRING));
}

#[test]
fn vtodo_filter_excludes_events() {
	let f = CalendarQueryFilter {
		components: vec![CompFilter {
			name: "VTODO".to_string(),
			time_range: None,
			prop_filters: Vec::new(),
			is_not_defined: false,
		}],
	};
	assert!(!matches(&f, EVENT));
	assert!(matches(&f, TODO));
}

#[test]
fn vevent_filter_excludes_todos() {
	let f = CalendarQueryFilter {
		components: vec![CompFilter {
			name: "VEVENT".to_string(),
			time_range: None,
			prop_filters: Vec::new(),
			is_not_defined: false,
		}],
	};
	assert!(matches(&f, EVENT));
	assert!(!matches(&f, TODO));
}

#[test]
fn prop_filter_text_match_contains_filters_by_summary() {
	let f = CalendarQueryFilter {
		components: vec![CompFilter {
			name: "VEVENT".to_string(),
			time_range: None,
			prop_filters: vec![PropFilter {
				name: "SUMMARY".to_string(),
				text_match: Some(TextMatch {
					text: "One".to_string(),
					match_type: "contains".to_string(),
					collation: "i;unicode-casemap".to_string(),
					negate_condition: false,
				}),
				is_not_defined: false,
			}],
			is_not_defined: false,
		}],
	};
	assert!(matches(&f, EVENT));
	assert!(!matches(&f, RECURRING));
}

#[test]
fn prop_filter_text_match_equals_is_exact() {
	let f = CalendarQueryFilter {
		components: vec![CompFilter {
			name: "VEVENT".to_string(),
			time_range: None,
			prop_filters: vec![PropFilter {
				name: "SUMMARY".to_string(),
				text_match: Some(TextMatch {
					text: "One".to_string(),
					match_type: "equals".to_string(),
					collation: "i;unicode-casemap".to_string(),
					negate_condition: false,
				}),
				is_not_defined: false,
			}],
			is_not_defined: false,
		}],
	};
	assert!(matches(&f, EVENT));
	assert!(!matches(&f, RECURRING));
}

#[test]
fn prop_filter_text_match_negate_inverts() {
	let f = CalendarQueryFilter {
		components: vec![CompFilter {
			name: "VEVENT".to_string(),
			time_range: None,
			prop_filters: vec![PropFilter {
				name: "SUMMARY".to_string(),
				text_match: Some(TextMatch {
					text: "Daily".to_string(),
					match_type: "equals".to_string(),
					collation: "i;unicode-casemap".to_string(),
					negate_condition: true,
				}),
				is_not_defined: false,
			}],
			is_not_defined: false,
		}],
	};
	// EVENT's summary is "One", not "Daily", so the inverted test
	// matches.
	assert!(matches(&f, EVENT));
	// RECURRING's summary is "Daily", so the inverted test excludes
	// it.
	assert!(!matches(&f, RECURRING));
}

#[test]
fn prop_filter_is_not_defined_excludes_when_property_present() {
	let f = CalendarQueryFilter {
		components: vec![CompFilter {
			name: "VEVENT".to_string(),
			time_range: None,
			prop_filters: vec![PropFilter {
				name: "LOCATION".to_string(),
				text_match: None,
				is_not_defined: true,
			}],
			is_not_defined: false,
		}],
	};
	assert!(matches(&f, EVENT));
	// With a LOCATION property added, the same filter excludes.
	let with_location = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n\
		UID:e1\r\nDTSTART:20260115T090000Z\r\nDTEND:20260115T100000Z\r\n\
		SUMMARY:One\r\nLOCATION:Office\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
		.to_string();
	assert!(!matches(&f, &with_location));
}

#[test]
fn prop_filter_unicode_casemap_is_case_insensitive() {
	let f = CalendarQueryFilter {
		components: vec![CompFilter {
			name: "VEVENT".to_string(),
			time_range: None,
			prop_filters: vec![PropFilter {
				name: "SUMMARY".to_string(),
				text_match: Some(TextMatch {
					text: "one".to_string(), // lower-case
					match_type: "contains".to_string(),
					collation: "i;unicode-casemap".to_string(),
					negate_condition: false,
				}),
				is_not_defined: false,
			}],
			is_not_defined: false,
		}],
	};
	// EVENT has SUMMARY "One" which equals "one" under the case-map
	// collation.
	assert!(matches(&f, EVENT));
}

#[test]
fn parse_vcalendar_with_vevent_time_range() {
	let body = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:time-range start=\"20260101T000000Z\" end=\"20260201T000000Z\"/>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let filter = parse(body).expect("filter");
	assert_eq!(filter.components.len(), 1);
	assert_eq!(filter.components[0].name, "VEVENT");
	assert!(filter.components[0].time_range.is_some());
}

#[test]
fn parse_vcalendar_with_vtodo_filter() {
	let body = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VTODO\"/>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let filter = parse(body).expect("filter");
	assert_eq!(filter.components.len(), 1);
	assert_eq!(filter.components[0].name, "VTODO");
}

#[test]
fn parse_unsupported_element_returns_err() {
	let body = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:limit-recurrence-set>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	assert!(parse(body).is_err());
}

#[test]
fn parse_unknown_collation_returns_err() {
	let body = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:prop-filter name=\"SUMMARY\">\
		<C:text-match collation=\"i;bogus\" match-type=\"contains\">One</C:text-match>\
		</C:prop-filter>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	assert!(parse(body).is_err());
}

#[test]
fn parse_unknown_match_type_returns_err() {
	let body = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:prop-filter name=\"SUMMARY\">\
		<C:text-match match-type=\"fuzzy\" collation=\"i;unicode-casemap\">One</C:text-match>\
		</C:prop-filter>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	assert!(parse(body).is_err());
}

#[test]
fn text_passes_basics() {
	let tm_contains = TextMatch {
		text: "foo".to_string(),
		match_type: "contains".to_string(),
		collation: "i;unicode-casemap".to_string(),
		negate_condition: false,
	};
	assert!(super::text_passes("foobar", &tm_contains));
	assert!(!super::text_passes("baz", &tm_contains));
	let tm_starts = TextMatch {
		match_type: "starts-with".to_string(),
		..tm_contains.clone()
	};
	assert!(super::text_passes("foobar", &tm_starts));
	assert!(!super::text_passes("bazfoo", &tm_starts));
	let tm_ends = TextMatch {
		match_type: "ends-with".to_string(),
		..tm_contains.clone()
	};
	assert!(super::text_passes("barfoo", &tm_ends));
	assert!(!super::text_passes("foobar", &tm_ends));
	let tm_equals = TextMatch {
		match_type: "equals".to_string(),
		..tm_contains.clone()
	};
	assert!(super::text_passes("foo", &tm_equals));
	assert!(!super::text_passes("foobar", &tm_equals));
}

#[test]
fn text_passes_octet_is_case_sensitive() {
	let tm = TextMatch {
		text: "FOO".to_string(),
		match_type: "contains".to_string(),
		collation: "i;octet".to_string(),
		negate_condition: false,
	};
	assert!(super::text_passes("FOObar", &tm));
	assert!(!super::text_passes("foobar", &tm));
}

#[tokio::test]
async fn load_and_match_returns_none_for_non_matching() {
	let tmp = tempfile::tempdir().expect("dir");
	let path = tmp.path().join("e.ics");
	std::fs::write(&path, EVENT).expect("write");
	let f = time_range_only(
		"VEVENT",
		TimeRange {
			start: 1_700_006_400,
			end: 1_700_092_800,
		},
	)
	.expect("filter");
	let result = load_and_match(&f, &path).await;
	assert!(result.is_none());
}

#[tokio::test]
async fn load_and_match_returns_some_for_matching() {
	let tmp = tempfile::tempdir().expect("dir");
	let path = tmp.path().join("e.ics");
	std::fs::write(&path, EVENT).expect("write");
	let f = time_range_only(
		"VEVENT",
		TimeRange {
			start: 1_766_620_800,
			end: 1_769_904_000,
		},
	)
	.expect("filter");
	let result = load_and_match(&f, &path).await;
	assert!(result.is_some());
}

#[test]
fn text_match_default_is_contains_and_default_collation_is_unicode_casemap() {
	// A prop-filter whose text-match omits both match-type and
	// collation should still parse and be treated as contains +
	// i;unicode-casemap.
	let body = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:prop-filter name=\"SUMMARY\">\
		<C:text-match>One</C:text-match>\
		</C:prop-filter>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let filter = parse(body).expect("filter");
	let prop = &filter.components[0].prop_filters[0];
	let tm = prop.text_match.as_ref().expect("text-match");
	assert_eq!(tm.match_type, "contains");
	assert_eq!(tm.collation, "i;unicode-casemap");
}
