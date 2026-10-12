//! `calendar-query` filter parsing and matching (RFC 4791 §9.7).
//!
//! The filter is a small tree of `comp-filter` and `prop-filter` elements
//! nested inside `<C:filter>`. The root is always `VCALENDAR`; each child
//! `comp-filter` names a calendar component (`VEVENT`, `VTODO`, ...) and
//! further refines the match with a `time-range` and `prop-filter`
//! elements. We support the subset a CardDAV / CalDAV client actually
//! sends: `comp-filter` for the top-level components, `time-range` with
//! `start`/`end` (using the existing recurrence expansion in
//! [`super::rrule`]), and `prop-filter` with `text-match` and
//! `is-not-defined`. Any element outside this set is answered with
//! `403 Forbidden` and the `CALDAV:supported-filter` precondition — we
//! do not silently ignore what we do not understand.

use std::path::Path;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::caldav_filter_xml::{
	attr, contains_local_element, first_open, is_supported_element, local_names, matching_close,
};
use super::rrule;

/// One iCalendar property the filter can look at, after `unfold` (so a
/// continuation line that lives inside one property stays in that
/// property). The `text` is the raw property value, with parameters
/// stripped.
struct VProperty {
	name: String,
	text: String,
}

/// One component the filter has to consider, flattened for matching:
/// the `name` (`VEVENT`, `VTODO`, ...) and the `properties` it carries.
struct VComponent {
	name: String,
	properties: Vec<VProperty>,
	dtstart: Option<i64>,
	dtend: Option<i64>,
	rrule: Option<String>,
}

/// Build a 403 Forbidden response carrying the `CALDAV:supported-filter`
/// precondition for a filter we do not support.
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

/// The parsed shape of a `calendar-query` filter, ready to be applied
/// to a single iCalendar object. `None` means "no filter" and matches
/// every object.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CalendarQueryFilter {
	/// The set of component filters the root `VCALENDAR` carries. An
	/// empty list is "match all top-level components", which is what
	/// the spec calls a no-op filter.
	pub components: Vec<CompFilter>,
}

/// One `comp-filter` element. `name` is the component it names
/// (`VEVENT`, `VTODO`, ...); the other fields are the additional
/// refinements the body attached.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CompFilter {
	/// The component name as it appears in the filter, uppercased
	/// (`VEVENT`, `VTODO`, ...).
	pub name: String,
	/// `time-range` inside this `comp-filter`, when present.
	pub time_range: Option<TimeRange>,
	/// `prop-filter` children of this `comp-filter`, in document order.
	pub prop_filters: Vec<PropFilter>,
	/// `is-not-defined` flag: when true, the filter matches only when
	/// the named component is NOT present in the calendar object.
	pub is_not_defined: bool,
}

/// A `<C:time-range start=... end=.../>` with the bounds already parsed
/// into epoch seconds. The component is treated as a time-anchored
/// event if its `DTSTART` (and any occurrence the `RRULE` produces
/// within the window) lies inside the range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
	/// Inclusive lower bound, in epoch seconds.
	pub start: i64,
	/// Exclusive upper bound, in epoch seconds.
	pub end: i64,
}

/// A `<C:prop-filter name="..."/>` element with whatever the body
/// attached.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PropFilter {
	/// The property name, uppercased (`SUMMARY`, `UID`, ...).
	pub name: String,
	/// `text-match` inside this `prop-filter`, when present.
	pub text_match: Option<TextMatch>,
	/// `is-not-defined` flag.
	pub is_not_defined: bool,
}

/// A `<C:text-match>` element with the comparison parameters and the
/// text to compare against.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TextMatch {
	/// The literal text the property value is compared against.
	pub text: String,
	/// `contains`, `equals`, `starts-with`, `ends-with`. Default per
	/// the spec is `contains`; we apply the same default when the body
	/// omits the attribute.
	pub match_type: String,
	/// `i;unicode-casemap` (the spec default) or `i;octet`. We honour
	/// the same default.
	pub collation: String,
	/// When true, the test result is inverted: the property value must
	/// NOT match.
	pub negate_condition: bool,
}

/// Sentinel returned when the filter uses an element we do not
/// support. `?` distinguishes it from a parse error and keeps the
/// `Result` shape small.
#[derive(Debug)]
pub struct Unsupported;

/// Local helper: extract the local name of a tag from the slice
/// after its opening `<` (or `</` for closing). Returns a `String`
/// directly (not `Option`) because the parser only invokes this
/// after a tag boundary has been confirmed, so a non-empty name is
/// always present.
fn tag_local_name(after: &str) -> String {
	let bytes = after.as_bytes();
	let mut name_end = 0;
	while name_end < bytes.len() {
		let c = bytes[name_end];
		if c == b'>' || c == b' ' || c == b'/' || c == b'<' || c == b'\t' || c == b'\n' {
			break;
		}
		name_end += 1;
	}
	let name = &after[..name_end];
	name.rsplit(':').next().unwrap_or(name).to_string()
}

/// Parse the `<C:filter>` element out of a `calendar-query` body. The
/// body is small (a few hundred bytes) and the search is linear, so a
/// hand-rolled scan is fine.
///
/// A body that names a `comp-filter` but no `<C:filter>` wrapper is
/// accepted; the spec allows the wrapper to be omitted, and a missing
/// filter is the same as an empty one. A body without any
/// `comp-filter` is also accepted: it is the same as "match every
/// resource" (the spec's no-op filter, RFC 4791 §7.8).
///
/// Returns `Err` for any element the spec lists that we do not honour
/// (e.g. `<C:comp-filter>` with a `name` outside the top-level set, a
/// `prop-filter` whose `text-match` has a collation or match-type we
/// do not support, a `time-range` that does not parse, anything else
/// outside the supported subset). The caller turns the error into a
/// 403.
pub fn parse(body: &str) -> Result<CalendarQueryFilter, Unsupported> {
	// A body that has no comp-filter at all is a no-op filter
	// (match everything). This is the spec's behaviour for a
	// missing `<C:filter>` wrapper, and a few clients (notably
	// Evolution) take advantage of it.
	let Some(root_open) = first_open(body, "comp-filter") else {
		return Ok(CalendarQueryFilter::default());
	};
	let after_root_open = body[root_open..]
		.find('>')
		.map(|p| root_open + p + 1)
		.unwrap_or(root_open);
	let Some((root_close, _)) = matching_close(body, after_root_open, "comp-filter") else {
		return Err(Unsupported);
	};
	let root_content = &body[after_root_open..root_close];
	// The root is required to be a single `comp-filter
	// name="VCALENDAR"`. The attribute parser has already been
	// used inside `first_open` to extract the name; we
	// re-extract here for the check.
	let root_name = attr(body, root_open, "name").unwrap_or_default();
	if root_name.to_ascii_uppercase() != "VCALENDAR" {
		return Err(Unsupported);
	}
	let mut components = Vec::new();
	let mut cursor = root_content;
	while let Some(child_open) = first_open(cursor, "comp-filter") {
		let absolute = after_root_open + child_open;
		let after_open = body[absolute..]
			.find('>')
			.map(|p| absolute + p + 1)
			.unwrap_or(absolute);
		let Some((close, _)) = matching_close(body, after_open, "comp-filter") else {
			return Err(Unsupported);
		};
		let content = &body[after_open..close];
		let name = attr(body, absolute, "name").unwrap_or_default();
		if name == "VCALENDAR" {
			// Nested VCALENDAR comp-filters are not in the
			// supported set; treat as unsupported so a buggy
			// client does not silently get a no-op.
			return Err(Unsupported);
		}
		components.push(CompFilter {
			name: name.to_ascii_uppercase(),
			time_range: extract_time_range(content),
			prop_filters: extract_prop_filters(content)?,
			is_not_defined: contains_local_element(content, "is-not-defined"),
		});
		// Advance the cursor past the closing tag.
		cursor = &body[close + "</comp-filter>".len()..];
	}
	// Reject any non-supported element that appears inside the
	// root, where a `comp-filter` would otherwise be expected.
	if has_unknown_top_level(root_content) {
		return Err(Unsupported);
	}
	Ok(CalendarQueryFilter { components })
}

fn has_unknown_top_level(body: &str) -> bool {
	for element in local_names(body) {
		if !is_supported_element(&element) {
			return true;
		}
	}
	false
}

/// Pull a `time-range` out of a `comp-filter`'s content. The element
/// is self-closing in CalDAV; if any of `start` / `end` is missing or
/// unparseable, the filter is treated as unsupported.
fn extract_time_range(content: &str) -> Option<TimeRange> {
	// Find the `<...:time-range .../>` element.
	let bytes = content.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let rest = &content[i..];
		let Some(close) = rest.find('>') else {
			return None;
		};
		let tag = &rest[1..close];
		if tag.starts_with('?') || tag.starts_with('!') {
			i += close + 1;
			continue;
		}
		let local = tag_local_name(tag);
		if local == "time-range" {
			let start = attr(content, i, "start")?;
			let end = attr(content, i, "end")?;
			let start = rrule::parse_datetime(&start)?;
			let end = rrule::parse_datetime(&end)?;
			if end <= start {
				return None;
			}
			return Some(TimeRange { start, end });
		}
		i += close + 1;
	}
	None
}

/// Pull every `prop-filter` element out of a comp-filter's content.
/// Each one is parsed into a [`PropFilter`] with its `text-match` and
/// `is-not-defined` flags. A prop-filter whose `text-match` carries an
/// unknown collation or match-type is reported as `Err`, so the caller
/// can refuse the whole filter with `403 CALDAV:supported-filter`.
/// A prop-filter without any `text-match` element is taken at face
/// value (the filter degenerates to "no refinement", the spec's
/// definition of a match).
fn extract_prop_filters(content: &str) -> Result<Vec<PropFilter>, Unsupported> {
	let mut out = Vec::new();
	let bytes = content.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let rest = &content[i..];
		let Some(close) = rest.find('>') else {
			break;
		};
		let tag = &rest[1..close];
		if tag.starts_with('?') || tag.starts_with('!') {
			i += close + 1;
			continue;
		}
		let local = tag_local_name(tag);
		if local == "prop-filter" {
			let name = attr(content, i, "name").unwrap_or_default();
			let Some((close_at, next)) = matching_close(content, i + close + 1, "prop-filter")
			else {
				break;
			};
			let inner = &content[i + close + 1..close_at];
			let has_text_match = contains_local_element(inner, "text-match");
			let text_match = if has_text_match {
				Some(extract_text_match(inner).ok_or(Unsupported)?)
			} else {
				None
			};
			let prop = PropFilter {
				name: name.to_ascii_uppercase(),
				text_match,
				is_not_defined: contains_local_element(inner, "is-not-defined"),
			};
			out.push(prop);
			i = next;
			continue;
		}
		i += close + 1;
	}
	Ok(out)
}

/// Pull a `text-match` out of a prop-filter's content. Returns
/// `Some(TextMatch)` for a parseable text-match, `None` for one that
/// is missing or malformed (caller treats as unsupported).
fn extract_text_match(content: &str) -> Option<TextMatch> {
	let bytes = content.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let rest = &content[i..];
		let Some(close) = rest.find('>') else {
			return None;
		};
		let tag = &rest[1..close];
		if tag.starts_with('?') || tag.starts_with('!') {
			i += close + 1;
			continue;
		}
		let local = tag_local_name(tag);
		if local == "text-match" {
			// `<C:text-match ...>TEXT</C:text-match>`.
			let after_open = i + close + 1;
			let Some((close_idx, _)) = matching_close(content, after_open, "text-match")
			else {
				return None;
			};
			let inner = &content[after_open..close_idx];
			let text = inner.trim().to_string();
			// The attributes are on the open tag (at `i`), so
			// search from there.
			let negate = attr(content, i, "negate-condition")
				.map(|value| matches!(value.trim(), "yes" | "true" | "1"))
				.unwrap_or(false);
			let collation = attr(content, i, "collation")
				.unwrap_or_else(|| "i;unicode-casemap".to_string());
			// Only two collations are defined; the rest are unsupported.
			if collation != "i;unicode-casemap" && collation != "i;octet" {
				return None;
			}
			let match_type = attr(content, i, "match-type")
				.unwrap_or_else(|| "contains".to_string());
			if !matches!(
				match_type.as_str(),
				"contains" | "equals" | "starts-with" | "ends-with"
			) {
				return None;
			}
			return Some(TextMatch {
				text,
				match_type,
				collation,
				negate_condition: negate,
			});
		}
		i += close + 1;
	}
	None
}

/// Apply a parsed filter to a single iCalendar object. Returns `true`
/// when the object should be included in the query result.
///
/// An empty filter (no components) matches every object, the spec's
/// definition of a no-op. A non-empty filter matches an object iff at
/// least one of the requested components matches.
pub fn matches(filter: &CalendarQueryFilter, ics: &str) -> bool {
	if filter.components.is_empty() {
		return true;
	}
	let components = extract_components(ics);
	for comp_filter in &filter.components {
		for comp in &components {
			if comp_filter.name == comp.name && component_matches(comp_filter, comp) {
				return true;
			}
		}
		// `is-not-defined` flips the match: the comp is required to
		// be absent from the object. The component list above
		// already reflects "present", so a missing one always
		// matches the is-not-defined case.
		if comp_filter.is_not_defined
			&& !components.iter().any(|c| c.name == comp_filter.name)
		{
			return true;
		}
	}
	false
}

fn component_matches(filter: &CompFilter, comp: &VComponent) -> bool {
	// `time-range`: a time-anchored comp (with DTSTART) matches when
	// any occurrence in the range overlaps. A comp without DTSTART
	// can only match if the filter has no time-range.
	if let Some(range) = filter.time_range {
		if comp.dtstart.is_none() {
			return false;
		}
		let dtstart = comp.dtstart.unwrap();
		let duration = match (comp.dtstart, comp.dtend) {
			(Some(s), Some(e)) => e - s,
			_ => 0,
		};
		let rule = comp.rrule.as_deref().and_then(rrule::parse_rule);
		let occurrences = rrule::expand(dtstart, rule.as_ref(), range.start, range.end);
		let any_overlap = occurrences
			.iter()
			.any(|occ| *occ + duration > range.start && *occ < range.end);
		if !any_overlap {
			return false;
		}
	}
	// `prop-filter`: every prop-filter must match. A prop-filter
	// with `is-not-defined` matches when the property is missing
	// from the comp. A prop-filter with `text-match` matches when
	// the property value passes the text test.
	for prop_filter in &filter.prop_filters {
		let prop_value = comp
			.properties
			.iter()
			.find(|p| p.name == prop_filter.name)
			.map(|p| p.text.as_str());
		match (prop_filter.is_not_defined, prop_value) {
			(true, None) => continue,
			(true, Some(_)) => return false,
			(false, None) => return false,
			(false, Some(value)) => {
				if let Some(text_match) = &prop_filter.text_match
					&& !text_passes(value, text_match)
				{
					return false;
				}
			}
		}
	}
	true
}

/// Apply a `text-match` to a property value. The two collations
/// (`i;unicode-casemap` and `i;octet`) and the four match-types
/// (`contains`, `equals`, `starts-with`, `ends-with`) are honoured.
pub fn text_passes(value: &str, tm: &TextMatch) -> bool {
	let (value, needle) = if tm.collation == "i;octet" {
		(value.to_string(), tm.text.clone())
	} else {
		(value.to_lowercase(), tm.text.to_lowercase())
	};
	let raw = match tm.match_type.as_str() {
		"equals" => value == needle,
		"starts-with" => value.starts_with(&needle),
		"ends-with" => value.ends_with(&needle),
		_ => value.contains(&needle),
	};
	if tm.negate_condition { !raw } else { raw }
}

/// Flatten an iCalendar object into the components the filter
/// considers. The parser is the same as the free-busy one in
/// [`super::caldav`], extended to surface every property of every
/// component: the filter's `prop-filter` text-match needs to look at
/// the property value verbatim. Top-level components (those whose
/// direct parent is `VCALENDAR`) are returned in `out`; nested
/// components (e.g. `VALARM` inside a `VEVENT`) are dropped on the
/// floor because the filter only considers the top level.
fn extract_components(ics: &str) -> Vec<VComponent> {
	let unfolded = super::caldav::unfold(ics);
	let mut out = Vec::new();
	let mut stack: Vec<VComponent> = Vec::new();
	for line in unfolded.lines() {
		let line = line.trim_end_matches('\r');
		if let Some(rest) = line.strip_prefix("BEGIN:") {
			stack.push(VComponent {
				name: rest.trim().to_ascii_uppercase(),
				properties: Vec::new(),
				dtstart: None,
				dtend: None,
				rrule: None,
			});
		} else if let Some(rest) = line.strip_prefix("END:") {
			let name = rest.trim().to_ascii_uppercase();
			if let Some(comp) = stack.pop() {
				// A top-level component is the one whose parent
				// stack frame is `VCALENDAR`. After popping the
				// component, the new top of stack tells us its
				// parent.
				if comp.name == name
					&& stack.last().is_some_and(|p| p.name == "VCALENDAR")
				{
					out.push(comp);
				}
				// Otherwise the component is nested (e.g. VALARM),
				// and we drop it: the filter only looks at
				// top-level comps.
			}
		} else if let Some(top) = stack.last_mut() {
			apply_line(top, line);
		}
	}
	out
}

fn apply_line(comp: &mut VComponent, line: &str) {
	let Some((name_and_params, value)) = line.split_once(':') else {
		return;
	};
	let name = name_and_params
		.split(';')
		.next()
		.unwrap_or("")
		.to_ascii_uppercase();
	match name.as_str() {
		"DTSTART" => comp.dtstart = rrule::parse_datetime(value),
		"DTEND" => comp.dtend = rrule::parse_datetime(value),
		"RRULE" => comp.rrule = Some(value.trim().to_string()),
		_ => {}
	}
	comp.properties.push(VProperty {
		name,
		text: value.to_string(),
	});
}

/// A handy constructor for the most common test filter: a single
/// `comp-filter` of `name` on a top-level VCALENDAR, with the
/// requested time-range. Returns `Err(())` for an empty range, which
/// is the only shape we use internally.
pub fn time_range_only(component: &str, range: TimeRange) -> Result<CalendarQueryFilter, ()> {
	if range.end <= range.start {
		return Err(());
	}
	Ok(CalendarQueryFilter {
		components: vec![CompFilter {
			name: component.to_ascii_uppercase(),
			time_range: Some(range),
			prop_filters: Vec::new(),
			is_not_defined: false,
		}],
	})
}

/// Build a no-op filter (matches every object) without going through
/// the XML parser. Useful for tests and for the report dispatcher
/// when the body has no `<C:filter>`.
pub fn none() -> CalendarQueryFilter {
	CalendarQueryFilter::default()
}

/// Check whether a `.ics` resource should be served under the given
/// `target` collection: the on-disk file has to be a regular file the
/// filter can read.
pub async fn load_and_match(filter: &CalendarQueryFilter, disk: &Path) -> Option<(String, Vec<u8>)> {
	let data = tokio::fs::read(disk).await.ok()?;
	let text = String::from_utf8_lossy(&data);
	if !matches(filter, &text) {
		return None;
	}
	let href = disk
		.file_name()
		.and_then(|name| name.to_str())
		.map(|name| format!("/{name}"))?;
	Some((href, data.to_vec()))
}

#[cfg(test)]
#[path = "caldav_filter_tests.rs"]
mod tests;
