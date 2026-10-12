//! `calendar-query` filter parsing and matching (RFC 4791 §9.7).
//!
//! The filter is one `comp-filter` named `VCALENDAR` whose children are
//! `comp-filter` elements for the top-level components (`VEVENT`, `VTODO`,
//! ...). Every child must match (RFC 4791 §9.7.1). A component filter holds
//! either `is-not-defined` or an optional `time-range` plus `prop-filter`
//! elements; a prop-filter holds either `is-not-defined` or one
//! `text-match`.
//!
//! `time-range` (§9.9) may be open at either end and is matched against
//! every occurrence of a recurring component, through the same
//! [`super::rrule`] expansion free-busy uses, with the component's length
//! taken from `DTEND`, `DUE` or `DURATION` (an all-day `DTSTART` lasts a
//! day). It is honoured on `VEVENT` and `VTODO` only.
//!
//! Anything else (a nested comp-filter such as `VALARM`, a `param-filter`,
//! a time-range on a property, a bound that does not parse) is refused with
//! `403` and `CALDAV:supported-filter`, never silently dropped: a client
//! that gets an unfiltered answer to a filtered query would show the wrong
//! calendar.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::caldav_filter_xml::{Element, children, elements, tag_attr, unescape};
use super::rrule;

/// `403 Forbidden` with the `CALDAV:supported-filter` precondition.
pub fn unsupported_filter_response() -> Response {
	(
		StatusCode::FORBIDDEN,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		concat!(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
			"<D:error xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\n",
			"  <C:supported-filter/>\n",
			"</D:error>\n",
		),
	)
		.into_response()
}

/// A parsed `calendar-query` filter: the component filters under
/// `VCALENDAR`, all of which must match. Empty matches every object.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CalendarQueryFilter {
	/// The comp-filters under `VCALENDAR`, in document order.
	pub components: Vec<CompFilter>,
}

/// One top-level `comp-filter`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CompFilter {
	/// The component name, uppercased (`VEVENT`, `VTODO`, ...).
	pub name: String,
	/// The `time-range`, when present.
	pub time_range: Option<TimeRange>,
	/// The `prop-filter` children; every one must match.
	pub prop_filters: Vec<PropFilter>,
	/// `is-not-defined`: the object matches only without this component.
	pub is_not_defined: bool,
}

/// A `time-range` in epoch seconds. A missing `start` is `i64::MIN` and a
/// missing `end` is `i64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
	/// Inclusive lower bound.
	pub start: i64,
	/// Exclusive upper bound.
	pub end: i64,
}

/// One `prop-filter` of a component filter.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PropFilter {
	/// The property name, uppercased (`SUMMARY`, `ATTENDEE`, ...).
	pub name: String,
	/// The `text-match`, when present.
	pub text_match: Option<TextMatch>,
	/// `is-not-defined`: matches only when the property is absent.
	pub is_not_defined: bool,
}

/// A `text-match` (RFC 4791 §9.7.5, RFC 6352 §10.5.4).
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TextMatch {
	/// The text compared against the property value.
	pub text: String,
	/// `contains` (default), `equals`, `starts-with` or `ends-with`.
	pub match_type: String,
	/// `i;unicode-casemap` (default) or `i;octet`.
	pub collation: String,
	/// Inverts the result.
	pub negate_condition: bool,
}

/// The filter uses an element or value outside the supported subset.
#[derive(Debug)]
pub struct Unsupported;

/// Parse the `<C:filter>` of a `calendar-query` body. A body without a
/// filter element matches every object.
pub fn parse(body: &str) -> Result<CalendarQueryFilter, Unsupported> {
	let filters = elements(body, "filter").ok_or(Unsupported)?;
	let filter = match filters.as_slice() {
		[] => return Ok(CalendarQueryFilter::default()),
		[only] => only,
		_ => return Err(Unsupported),
	};
	let root = match only_children(filter, &["comp-filter"])?.as_slice() {
		[(_, root)] => *root,
		_ => return Err(Unsupported),
	};
	if !tag_attr(root.tag, "name").is_some_and(|name| name.eq_ignore_ascii_case("VCALENDAR")) {
		return Err(Unsupported);
	}
	let components = only_children(&root, &["comp-filter"])?
		.iter()
		.map(|(_, element)| comp_filter(element))
		.collect::<Result<_, _>>()?;
	Ok(CalendarQueryFilter { components })
}

/// The direct children of `element`, refusing any whose local name is not
/// in `allowed`.
fn only_children<'a>(
	element: &Element<'a>,
	allowed: &[&str],
) -> Result<Vec<(String, Element<'a>)>, Unsupported> {
	let found = children(element.inner).ok_or(Unsupported)?;
	if found
		.iter()
		.any(|(name, _)| !allowed.contains(&name.as_str()))
	{
		return Err(Unsupported);
	}
	Ok(found)
}

fn name_of(element: &Element<'_>) -> Result<String, Unsupported> {
	tag_attr(element.tag, "name")
		.map(|name| name.trim().to_ascii_uppercase())
		.filter(|name| !name.is_empty())
		.ok_or(Unsupported)
}

fn comp_filter(element: &Element<'_>) -> Result<CompFilter, Unsupported> {
	let mut filter = CompFilter {
		name: name_of(element)?,
		..CompFilter::default()
	};
	for (child, inner) in only_children(element, &["is-not-defined", "time-range", "prop-filter"])?
	{
		match child.as_str() {
			"is-not-defined" => filter.is_not_defined = true,
			"time-range" if filter.time_range.is_none() => {
				if !matches!(filter.name.as_str(), "VEVENT" | "VTODO") {
					return Err(Unsupported);
				}
				filter.time_range = Some(time_range(&inner)?);
			}
			"prop-filter" => filter.prop_filters.push(prop_filter(&inner)?),
			_ => return Err(Unsupported),
		}
	}
	let refined = filter.time_range.is_some() || !filter.prop_filters.is_empty();
	if filter.is_not_defined && refined {
		return Err(Unsupported);
	}
	Ok(filter)
}

fn time_range(element: &Element<'_>) -> Result<TimeRange, Unsupported> {
	let bound = |name: &str, open: i64| match tag_attr(element.tag, name) {
		None => Ok(open),
		Some(value) => rrule::parse_datetime(&value).ok_or(Unsupported),
	};
	if tag_attr(element.tag, "start").is_none() && tag_attr(element.tag, "end").is_none() {
		return Err(Unsupported);
	}
	let range = TimeRange {
		start: bound("start", i64::MIN)?,
		end: bound("end", i64::MAX)?,
	};
	if range.end <= range.start {
		return Err(Unsupported);
	}
	Ok(range)
}

fn prop_filter(element: &Element<'_>) -> Result<PropFilter, Unsupported> {
	let mut filter = PropFilter {
		name: name_of(element)?,
		..PropFilter::default()
	};
	for (child, inner) in only_children(element, &["is-not-defined", "text-match"])? {
		if child == "is-not-defined" && !filter.is_not_defined {
			filter.is_not_defined = true;
		} else if child == "text-match" && filter.text_match.is_none() {
			filter.text_match = Some(text_match(inner.tag, inner.inner).ok_or(Unsupported)?);
		} else {
			return Err(Unsupported);
		}
	}
	if filter.is_not_defined && filter.text_match.is_some() {
		return Err(Unsupported);
	}
	Ok(filter)
}

/// Whether the iCalendar object `ics` matches `filter`.
pub fn matches(filter: &CalendarQueryFilter, ics: &str) -> bool {
	if filter.components.is_empty() {
		return true;
	}
	let components = super::caldav_filter_ical::top_level(ics);
	filter.components.iter().all(|comp_filter| {
		let mut named = components.iter().filter(|c| c.name == comp_filter.name);
		if comp_filter.is_not_defined {
			named.next().is_none()
		} else {
			named.any(|comp| component_matches(comp_filter, comp))
		}
	})
}

fn component_matches(filter: &CompFilter, comp: &super::caldav_filter_ical::Component) -> bool {
	if let Some(range) = filter.time_range
		&& !comp.overlaps(range)
	{
		return false;
	}
	filter.prop_filters.iter().all(|prop_filter| {
		let mut values = comp.values(&prop_filter.name).peekable();
		if prop_filter.is_not_defined {
			return values.peek().is_none();
		}
		match &prop_filter.text_match {
			Some(tm) => values.any(|value| text_passes(value, tm)),
			None => values.peek().is_some(),
		}
	})
}

/// Apply a `text-match` to a property value. The two collations
/// (`i;unicode-casemap` and `i;octet`) and the four match-types
/// (`contains`, `equals`, `starts-with`, `ends-with`) are honoured, and
/// `negate-condition` inverts the result.
pub fn text_passes(value: &str, tm: &TextMatch) -> bool {
	text_hits(value, tm) != tm.negate_condition
}

/// The positive half of a `text-match`: the collation and match-type
/// applied to `value`, ignoring `negate-condition`. CardDAV negates once
/// per property rather than once per value, so it needs this form.
pub fn text_hits(value: &str, tm: &TextMatch) -> bool {
	let (value, needle) = if tm.collation == "i;octet" {
		(value.to_string(), tm.text.clone())
	} else {
		(value.to_lowercase(), tm.text.to_lowercase())
	};
	match tm.match_type.as_str() {
		"equals" => value == needle,
		"starts-with" => value.starts_with(&needle),
		"ends-with" => value.ends_with(&needle),
		_ => value.contains(&needle),
	}
}

/// Build a [`TextMatch`] from a `text-match` element: `tag` is its opening
/// tag (attributes included) and `inner` its text. `None` for a collation,
/// match-type or `negate-condition` value outside what RFC 4791 and RFC 6352
/// define, which the caller answers with `supported-filter`.
pub fn text_match(tag: &str, inner: &str) -> Option<TextMatch> {
	let collation = tag_attr(tag, "collation").unwrap_or_else(|| "i;unicode-casemap".to_string());
	if collation != "i;unicode-casemap" && collation != "i;octet" {
		return None;
	}
	let match_type = tag_attr(tag, "match-type").unwrap_or_else(|| "contains".to_string());
	if !matches!(
		match_type.as_str(),
		"contains" | "equals" | "starts-with" | "ends-with"
	) {
		return None;
	}
	let negate_condition = match tag_attr(tag, "negate-condition").as_deref() {
		None | Some("no") | Some("false") => false,
		Some("yes") | Some("true") => true,
		Some(_) => return None,
	};
	Some(TextMatch {
		text: unescape(inner.trim()),
		match_type,
		collation,
		negate_condition,
	})
}

#[cfg(test)]
#[path = "caldav_filter_tests.rs"]
mod tests;
