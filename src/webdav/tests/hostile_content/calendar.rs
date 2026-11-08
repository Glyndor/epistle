//! Bounded current behavior, including unsupported SECONDLY's single DTSTART.

use super::{calendar, event, filter, isolated, matches, measured};
use crate::webdav::caldav_filter_ical;

#[test]
fn nested_events_do_not_leak_properties_or_recurse() {
	isolated(
		"calendar::nested_events_do_not_leak_properties_or_recurse",
		|| {
			let depth = 20_000;
			let events = format!(
				"BEGIN:VEVENT\r\nDTSTART:20260101T000000Z\r\n{}SUMMARY:secret\r\n{}END:VEVENT\r\n",
				"BEGIN:VEVENT\r\n".repeat(depth),
				"END:VEVENT\r\n".repeat(depth)
			);
			let ics = calendar(&events);
			let components = measured(|| caldav_filter_ical::top_level(&ics));
			assert_eq!(components.len(), 1);
			assert_eq!(components[0].name, "VEVENT");
			assert_eq!(components[0].values("SUMMARY").count(), 0);
			let f = filter("20260101T000000Z", "20260102T000000Z", "");
			assert!(measured(|| matches(&f, &ics)));
		},
	);
}

#[test]
fn endless_folding_preserves_the_property_and_event_boundary() {
	isolated(
		"calendar::endless_folding_preserves_the_property_and_event_boundary",
		|| {
			let summary = format!("SUMMARY:start\r\n{}\tEND\r\n", " x\r\n".repeat(500_000));
			let ics = calendar(&event("FREQ=DAILY;COUNT=1", &summary));
			let f = filter(
				"20260101T000000Z",
				"20260102T000000Z",
				"<C:prop-filter name=\"SUMMARY\"><C:text-match match-type=\"ends-with\">xEND</C:text-match></C:prop-filter>",
			);
			assert!(measured(|| matches(&f, &ics)));
			let absent = filter("20260102T000000Z", "20260103T000000Z", "");
			assert!(!measured(|| matches(&absent, &ics)));
		},
	);
}

#[test]
fn secondly_without_end_uses_the_current_single_start_fallback() {
	isolated(
		"calendar::secondly_without_end_uses_the_current_single_start_fallback",
		|| {
			let ics = calendar(&event("FREQ=SECONDLY", ""));
			let at_start = filter("20260101T000000Z", "99990101T000000Z", "");
			let later = filter("20260101T000001Z", "99990101T000000Z", "");
			assert!(measured(|| matches(&at_start, &ics)));
			assert!(!measured(|| matches(&later, &ics)));
		},
	);
}

#[test]
fn enormous_interval_and_combined_selectors_finish_with_exact_matches() {
	isolated(
		"calendar::enormous_interval_and_combined_selectors_finish_with_exact_matches",
		|| {
			for rule in [
				"FREQ=DAILY;INTERVAL=4294967295",
				"FREQ=YEARLY;INTERVAL=4294967295;BYMONTH=1,2,12;BYMONTHDAY=1,-1;BYDAY=MO,TU,WE,TH,FR,SA,SU",
			] {
				let ics = calendar(&event(rule, ""));
				let hit = filter("20260101T000000Z", "20260102T000000Z", "");
				let miss = filter("20270101T000000Z", "99990101T000000Z", "");
				assert!(measured(|| matches(&hit, &ics)), "{rule}");
				assert!(!measured(|| matches(&miss, &ics)), "{rule}");
			}
		},
	);
}

#[test]
fn combined_selectors_clip_one_series_at_the_expansion_budget() {
	isolated(
		"calendar::combined_selectors_clip_one_series_at_the_expansion_budget",
		|| {
			use crate::webdav::rrule;
			let rule = "FREQ=YEARLY;BYMONTH=1,2,3,4,5,6,7,8,9,10,11,12;BYMONTHDAY=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31;BYDAY=MO,TU,WE,TH,FR,SA,SU";
			let parsed = rrule::parse_rule(rule).expect("supported selectors");
			assert!(!parsed.unsupported);
			let start = rrule::parse_datetime("20260101T000000Z").expect("start");
			let end = rrule::parse_datetime("99990101T000000Z").expect("end");
			let (occurrences, clipped) = measured(|| {
				rrule::expand_bounded(start, Some(&parsed), start, end, rrule::DEFAULT_BUDGET)
			});
			assert!(clipped);
			assert!(occurrences.len() > 1000 && occurrences.len() <= rrule::DEFAULT_BUDGET);
			assert_eq!(occurrences[0], start);
			let ics = calendar(&event(rule, ""));
			let f = filter("20260101T000000Z", "99990101T000000Z", "");
			assert!(measured(|| matches(&f, &ics)));
		},
	);
}

#[test]
fn counted_selectors_refuse_the_object_they_cannot_reach() {
	isolated(
		"calendar::counted_selectors_refuse_the_object_they_cannot_reach",
		|| {
			// 2026 to 2500 is >100,000 days. COUNT forces the selector to walk
			// from DTSTART, exhausting its budget before the requested window.
			let ics = calendar(&event(
				"FREQ=DAILY;COUNT=1000000;BYDAY=MO,TU,WE,TH,FR,SA,SU",
				"",
			));
			let f = filter("25000101T000000Z", "25000102T000000Z", "");
			// The search ran out of work before it reached the window, so it
			// cannot answer: the object is refused, not called a non-match.
			assert_eq!(
				measured(|| crate::webdav::caldav_filter::matches(&f, &ics)),
				Err(crate::webdav::caldav_filter::TooMuchWork)
			);
		},
	);
}
