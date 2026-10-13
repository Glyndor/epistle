//! The iCalendar side of the `calendar-query` filter: the top-level
//! components of an object with their properties, and the RFC 4791 §9.9
//! overlap test a `time-range` applies to them.

use super::caldav_filter::TimeRange;
use super::rrule;

const DAY: i64 = 86_400;

/// One property line: name (uppercased, no parameters), parameters, value.
struct Property {
	name: String,
	params: String,
	value: String,
}

/// A component directly under `VCALENDAR` (`VEVENT`, `VTODO`, ...). Lines of
/// a nested component such as `VALARM` belong to that component, not to
/// this one.
pub struct Component {
	/// The component name, uppercased.
	pub name: String,
	properties: Vec<Property>,
}

/// Every top-level component of the iCalendar object `ics`, after unfolding
/// continuation lines.
pub fn top_level(ics: &str) -> Vec<Component> {
	let mut out = Vec::new();
	let mut stack: Vec<Component> = Vec::new();
	for line in super::caldav::unfold(ics).lines() {
		let line = line.trim_end_matches('\r');
		let Some(property) = parse_line(line) else {
			continue;
		};
		match property.name.as_str() {
			"BEGIN" => stack.push(Component {
				name: property.value.trim().to_ascii_uppercase(),
				properties: Vec::new(),
			}),
			"END" => {
				let Some(component) = stack.pop() else {
					continue;
				};
				if stack
					.last()
					.is_some_and(|parent| parent.name == "VCALENDAR")
				{
					out.push(component);
				}
			}
			_ => {
				if let Some(top) = stack.last_mut() {
					top.properties.push(property);
				}
			}
		}
	}
	out
}

/// Split a content line at the first `:` outside a quoted parameter value.
fn parse_line(line: &str) -> Option<Property> {
	let mut quoted = false;
	let colon = line.char_indices().find_map(|(i, c)| {
		if c == '"' {
			quoted = !quoted;
		}
		(c == ':' && !quoted).then_some(i)
	})?;
	let (head, value) = (&line[..colon], &line[colon + 1..]);
	let (name, params) = head.split_once(';').unwrap_or((head, ""));
	Some(Property {
		name: name.trim().to_ascii_uppercase(),
		params: params.to_ascii_uppercase(),
		value: value.to_string(),
	})
}

impl Component {
	/// Every value of the property `name`, one per occurrence.
	pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
		self.properties
			.iter()
			.filter(move |p| p.name == name)
			.map(|p| p.value.as_str())
	}

	fn property(&self, name: &str) -> Option<&Property> {
		self.properties.iter().find(|p| p.name == name)
	}

	/// A date or date-time property as epoch seconds, and whether it is a
	/// whole-day `DATE` value.
	fn instant(&self, name: &str) -> Option<(i64, bool)> {
		let property = self.property(name)?;
		let value = property.value.trim();
		let all_day = value.len() == 8
			|| property.params.contains("VALUE=DATE;")
			|| property.params.ends_with("VALUE=DATE");
		Some((rrule::parse_datetime(value)?, all_day))
	}

	/// Whether any occurrence of this component overlaps `range`, following
	/// the table in RFC 4791 §9.9. The length of an occurrence comes from
	/// `DTEND` (`DUE` for a `VTODO`), else `DURATION`, else one day for an
	/// all-day start and zero otherwise. A `VTODO` without `DTSTART` is
	/// placed at its `DUE`, and one with neither matches every range.
	pub fn overlaps(&self, range: TimeRange) -> bool {
		let todo = self.name == "VTODO";
		let end_name = if todo { "DUE" } else { "DTEND" };
		let Some((start, all_day)) = self.instant("DTSTART") else {
			return match self.instant("DUE") {
				Some((due, _)) if todo => range.start < due && range.end >= due,
				_ => todo,
			};
		};
		let length = match self.instant(end_name) {
			Some((end, _)) => end - start,
			None => match self.property("DURATION").and_then(|p| duration(&p.value)) {
				Some(seconds) => seconds,
				None if all_day => DAY,
				None => 0,
			},
		}
		.max(0);
		let rule = self
			.property("RRULE")
			.and_then(|p| rrule::parse_rule(&p.value));
		let from = range.start.saturating_sub(length);
		rrule::expand(start, rule.as_ref(), from, range.end)
			.into_iter()
			.any(|occurrence| {
				occurrence < range.end
					&& if length > 0 {
						occurrence.saturating_add(length) > range.start
					} else {
						occurrence >= range.start
					}
			})
	}
}

/// Parse an RFC 5545 §3.3.6 duration (`P1D`, `PT1H30M`, `P2W`, `-PT15M`)
/// into seconds.
fn duration(value: &str) -> Option<i64> {
	let value = value.trim();
	let (sign, rest) = match value.as_bytes().first()? {
		b'-' => (-1, &value[1..]),
		b'+' => (1, &value[1..]),
		_ => (1, value),
	};
	let rest = rest.strip_prefix('P')?;
	let mut total = 0i64;
	let mut number = String::new();
	let mut in_time = false;
	for c in rest.chars() {
		match c {
			'0'..='9' => number.push(c),
			'T' if number.is_empty() => in_time = true,
			_ => {
				let n: i64 = number.parse().ok()?;
				number.clear();
				let unit = match (c, in_time) {
					('W', false) => 7 * DAY,
					('D', false) => DAY,
					('H', true) => 3600,
					('M', true) => 60,
					('S', true) => 1,
					_ => return None,
				};
				total = total.checked_add(n.checked_mul(unit)?)?;
			}
		}
	}
	number.is_empty().then_some(sign * total)
}
