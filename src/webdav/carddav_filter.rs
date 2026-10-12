//! `addressbook-query` filter parsing and matching (RFC 6352 §10.5).
//!
//! A `<CR:filter>` is a list of `<CR:prop-filter>` elements combined by the
//! filter's `test` attribute (`anyof`, the default, or `allof`). Each
//! prop-filter names a vCard property and holds either `is-not-defined` or
//! any number of `text-match` elements, combined by the prop-filter's own
//! `test`. A text-match supports the four match-types (`equals`, `contains`,
//! `starts-with`, `ends-with`), the `i;unicode-casemap` (default) and
//! `i;octet` collations, and `negate-condition`.
//!
//! A property can occur several times in one card (two `EMAIL` lines). A
//! text-match hits when any instance matches, and `negate-condition` inverts
//! that per-property answer: a negated "contains personal" excludes a card
//! that has a personal address among others, which is what a user filtering
//! out a domain expects.
//!
//! `param-filter` and every other element are refused with `403` and the
//! `CARDDAV:supported-filter` precondition instead of being ignored, so a
//! client never mistakes an unfiltered answer for a filtered one.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::caldav_filter::{TextMatch, text_hits, text_match};
use super::caldav_filter_xml::{Element, elements, local_names, tag_attr};

/// How a list of tests combines.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum Test {
	/// Any test passing is enough (the default for both elements).
	#[default]
	AnyOf,
	/// Every test has to pass.
	AllOf,
}

/// A parsed `addressbook-query` filter. No prop-filter matches every card.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AddressbookQueryFilter {
	/// How the prop-filters combine.
	pub test: Test,
	/// The `prop-filter` children, in document order.
	pub prop_filters: Vec<PropFilter>,
}

/// One `prop-filter`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PropFilter {
	/// The vCard property name, uppercased (`EMAIL`, `FN`, ...).
	pub name: String,
	/// How the text-matches of this prop-filter combine.
	pub test: Test,
	/// `is-not-defined`: the card matches only without this property.
	pub is_not_defined: bool,
	/// The `text-match` children; empty means "the property exists".
	pub text_matches: Vec<TextMatch>,
}

/// The filter uses an element or a value outside the supported subset.
#[derive(Debug)]
pub struct Unsupported;

/// `403 Forbidden` with the `CARDDAV:supported-filter` precondition.
pub fn unsupported_filter_response() -> Response {
	(
		StatusCode::FORBIDDEN,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		concat!(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
			"<D:error xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\n",
			"  <C:supported-filter/>\n",
			"</D:error>\n",
		),
	)
		.into_response()
}

/// Parse the `<CR:filter>` of an `addressbook-query` body. A body without
/// a filter element matches every card.
pub fn parse(body: &str) -> Result<AddressbookQueryFilter, Unsupported> {
	let filters = elements(body, "filter").ok_or(Unsupported)?;
	let filter = match filters.as_slice() {
		[] => return Ok(AddressbookQueryFilter::default()),
		[only] => only,
		_ => return Err(Unsupported),
	};
	let supported = ["prop-filter", "text-match", "is-not-defined"];
	if local_names(filter.inner)
		.iter()
		.any(|name| !supported.contains(&name.as_str()))
	{
		return Err(Unsupported);
	}
	let prop_filters = elements(filter.inner, "prop-filter")
		.ok_or(Unsupported)?
		.iter()
		.map(prop_filter)
		.collect::<Result<_, _>>()?;
	Ok(AddressbookQueryFilter {
		test: test_of(filter)?,
		prop_filters,
	})
}

/// The `test` attribute of a `filter` or `prop-filter` element.
fn test_of(element: &Element<'_>) -> Result<Test, Unsupported> {
	match tag_attr(element.tag, "test").as_deref() {
		None | Some("anyof") => Ok(Test::AnyOf),
		Some("allof") => Ok(Test::AllOf),
		Some(_) => Err(Unsupported),
	}
}

fn prop_filter(element: &Element<'_>) -> Result<PropFilter, Unsupported> {
	let name = tag_attr(element.tag, "name")
		.filter(|name| !name.trim().is_empty())
		.ok_or(Unsupported)?;
	let is_not_defined = !elements(element.inner, "is-not-defined")
		.ok_or(Unsupported)?
		.is_empty();
	let text_matches = elements(element.inner, "text-match")
		.ok_or(Unsupported)?
		.iter()
		.map(|tm| text_match(tm.tag, tm.inner).ok_or(Unsupported))
		.collect::<Result<Vec<_>, _>>()?;
	// RFC 6352 §10.5.1: `is-not-defined` excludes every other child.
	if is_not_defined && !text_matches.is_empty() {
		return Err(Unsupported);
	}
	Ok(PropFilter {
		name: name.trim().to_ascii_uppercase(),
		test: test_of(element)?,
		is_not_defined,
		text_matches,
	})
}

/// Whether the vCard `vcf` matches `filter`.
pub fn matches(filter: &AddressbookQueryFilter, vcf: &str) -> bool {
	if filter.prop_filters.is_empty() {
		return true;
	}
	let properties = properties(vcf);
	let mut results = filter
		.prop_filters
		.iter()
		.map(|pf| prop_filter_matches(pf, &properties));
	match filter.test {
		Test::AnyOf => results.any(|hit| hit),
		Test::AllOf => results.all(|hit| hit),
	}
}

fn prop_filter_matches(filter: &PropFilter, properties: &[(String, String)]) -> bool {
	let values: Vec<&str> = properties
		.iter()
		.filter(|(name, _)| *name == filter.name)
		.map(|(_, value)| value.as_str())
		.collect();
	if filter.is_not_defined {
		return values.is_empty();
	}
	if values.is_empty() {
		return false;
	}
	let mut results = filter.text_matches.iter().map(|tm| {
		let hit = values.iter().any(|value| text_hits(value, tm));
		hit != tm.negate_condition
	});
	match filter.test {
		Test::AnyOf => filter.text_matches.is_empty() || results.any(|hit| hit),
		Test::AllOf => results.all(|hit| hit),
	}
}

/// Every content line of a vCard as `(NAME, value)`, after unfolding. The
/// name loses its parameters and its group prefix (`item1.EMAIL` is
/// `EMAIL`), which Apple clients put on almost every line.
fn properties(vcf: &str) -> Vec<(String, String)> {
	super::caldav::unfold(vcf)
		.lines()
		.filter_map(|line| {
			let (name_and_params, value) = line.trim_end_matches('\r').split_once(':')?;
			let name = name_and_params.split(';').next()?;
			let name = name.rsplit('.').next()?.to_ascii_uppercase();
			if name == "BEGIN" || name == "END" {
				return None;
			}
			Some((name, value.to_string()))
		})
		.collect()
}

#[cfg(test)]
#[path = "carddav_filter_tests.rs"]
mod tests;
