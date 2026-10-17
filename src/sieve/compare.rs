//! Sieve match types and comparators: `:is`/`:contains`/`:matches` (RFC 5228
//! §2.7.1), the relational `:value`/`:count` extension (RFC 5231) and the
//! `i;ascii-casemap`/`i;octet`/`i;ascii-numeric` collations (RFC 4790).
//!
//! Also the positional-argument helpers: the string arguments consumed by the
//! `:comparator`/`:value`/`:count` tags must not be mistaken for a test's
//! header names or keys.

use std::cmp::Ordering;

use super::ast::Argument;
use super::env::Env;
use super::interp::has_tag;

/// The relational operator of `:value`/`:count` (RFC 5231).
#[derive(Clone, Copy)]
pub(super) enum Rel {
	Gt,
	Ge,
	Lt,
	Le,
	Eq,
	Ne,
}

impl Rel {
	fn parse(name: &str) -> Option<Rel> {
		Some(match name.to_ascii_lowercase().as_str() {
			"gt" => Rel::Gt,
			"ge" => Rel::Ge,
			"lt" => Rel::Lt,
			"le" => Rel::Le,
			"eq" => Rel::Eq,
			"ne" => Rel::Ne,
			_ => return None,
		})
	}

	fn test(self, ordering: Ordering) -> bool {
		match self {
			Rel::Gt => ordering == Ordering::Greater,
			Rel::Ge => ordering != Ordering::Less,
			Rel::Lt => ordering == Ordering::Less,
			Rel::Le => ordering != Ordering::Greater,
			Rel::Eq => ordering == Ordering::Equal,
			Rel::Ne => ordering != Ordering::Equal,
		}
	}
}

/// The collation a comparison uses (the `:comparator` argument).
#[derive(Clone, Copy)]
enum Collation {
	/// `i;ascii-casemap`: case-insensitive ASCII (the default).
	AsciiCasemap,
	/// `i;octet`: exact byte comparison.
	Octet,
	/// `i;ascii-numeric`: compare leading ASCII digits as numbers.
	AsciiNumeric,
}

impl Collation {
	fn from_name(name: &str) -> Collation {
		match name {
			"i;octet" => Collation::Octet,
			"i;ascii-numeric" => Collation::AsciiNumeric,
			_ => Collation::AsciiCasemap,
		}
	}

	fn order(self, a: &str, b: &str) -> Ordering {
		match self {
			Collation::Octet => a.cmp(b),
			Collation::AsciiCasemap => a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()),
			Collation::AsciiNumeric => numeric_key(a).cmp(&numeric_key(b)),
		}
	}

	fn contains(self, value: &str, key: &str) -> bool {
		match self {
			Collation::AsciiCasemap => value
				.to_ascii_lowercase()
				.contains(&key.to_ascii_lowercase()),
			_ => value.contains(key),
		}
	}
}

/// The `i;ascii-numeric` sort key: the leading run of ASCII digits as a number.
/// A value not starting with a digit is positive infinity (RFC 4790 §9.1.1), so
/// it sorts after every number; all such values are equal to each other.
fn numeric_key(value: &str) -> (u8, u64) {
	let digits: String = value.chars().take_while(char::is_ascii_digit).collect();
	match digits.parse::<u64>() {
		Ok(number) => (0, number),
		Err(_) => (1, 0),
	}
}

/// A parsed match type plus collation.
pub(super) struct MatchSpec {
	match_type: MatchType,
	collation: Collation,
}

#[derive(Clone, Copy)]
enum MatchType {
	Is,
	Contains,
	Matches,
	Value(Rel),
	Count(Rel),
}

/// Parse the match-type and comparator tags from a test's arguments.
pub(super) fn match_spec(args: &[Argument]) -> MatchSpec {
	let collation = tag_arg(args, "comparator")
		.map(|name| Collation::from_name(&name))
		.unwrap_or(Collation::AsciiCasemap);
	let match_type = if let Some(rel) = tag_arg(args, "count").and_then(|r| Rel::parse(&r)) {
		MatchType::Count(rel)
	} else if let Some(rel) = tag_arg(args, "value").and_then(|r| Rel::parse(&r)) {
		MatchType::Value(rel)
	} else if has_tag(args, "contains") {
		MatchType::Contains
	} else if has_tag(args, "matches") {
		MatchType::Matches
	} else {
		MatchType::Is
	};
	MatchSpec {
		match_type,
		collation,
	}
}

impl MatchSpec {
	/// For `:count`, the relational operator (the caller supplies the count).
	pub(super) fn count_rel(&self) -> Option<Rel> {
		match self.match_type {
			MatchType::Count(rel) => Some(rel),
			_ => None,
		}
	}

	/// Relational comparison of a value count against `key`.
	pub(super) fn count_matches(&self, rel: Rel, count: usize, key: &str) -> bool {
		rel.test(self.collation.order(&count.to_string(), key))
	}

	/// Compare `value` against `key`. On a successful `:matches`, the wildcard
	/// captures are stored as `${0..}` (RFC 5229 §6).
	pub(super) fn test(&self, value: &str, key: &str, env: &mut Env) -> bool {
		match self.match_type {
			MatchType::Matches => {
				let (key, value_lower) = (key.to_ascii_lowercase(), value.to_ascii_lowercase());
				let mut steps = 0;
				let outcome = glob(&key, &value_lower, &mut steps, env.remaining_work());
				if !env.charge(steps.max(value.len() as u64)) {
					return false;
				}
				match outcome {
					Glob::Match(spans) => {
						let chars: Vec<char> = value_lower.chars().collect();
						env.set("0", value);
						for (index, (from, to)) in spans.into_iter().enumerate() {
							let capture: String = chars[from..to].iter().collect();
							env.set(&(index + 1).to_string(), &capture);
						}
						true
					}
					Glob::NoMatch => false,
					Glob::Refused => {
						env.abandon();
						false
					}
				}
			}
			_ => self.test_simple(value, key),
		}
	}

	/// Compare without capturing (for tests that carry no variable scope).
	pub(super) fn test_simple(&self, value: &str, key: &str) -> bool {
		match self.match_type {
			MatchType::Is => self.collation.order(value, key) == Ordering::Equal,
			MatchType::Contains => self.collation.contains(value, key),
			MatchType::Value(rel) => rel.test(self.collation.order(value, key)),
			MatchType::Matches => {
				glob_match(&key.to_ascii_lowercase(), &value.to_ascii_lowercase())
			}
			MatchType::Count(_) => false,
		}
	}
}

/// The string argument following tag `name` (e.g. `:comparator "i;octet"`).
fn tag_arg(args: &[Argument], name: &str) -> Option<String> {
	let mut iter = args.iter();
	while let Some(arg) = iter.next() {
		if let Argument::Tag(tag) = arg
			&& tag.eq_ignore_ascii_case(name)
			&& let Some(Argument::Str(value)) = iter.next()
		{
			return Some(value.clone());
		}
	}
	None
}

/// Whether a tag consumes the following string as its argument.
fn consumes_string(tag: &str) -> bool {
	matches!(
		tag.to_ascii_lowercase().as_str(),
		"comparator" | "value" | "count"
	)
}

/// Positional string-argument groups (a bare string is a one-element group, a
/// string list its own group), skipping the strings consumed by tags.
pub(super) fn positional_groups(args: &[Argument]) -> Vec<Vec<String>> {
	let mut groups = Vec::new();
	let mut skip = false;
	for arg in args {
		match arg {
			Argument::Tag(tag) if consumes_string(tag) => skip = true,
			Argument::Str(value) => {
				if skip {
					skip = false;
				} else {
					groups.push(vec![value.clone()]);
				}
			}
			Argument::StrList(list) => {
				skip = false;
				groups.push(list.clone());
			}
			_ => skip = false,
		}
	}
	groups
}

/// Flat positional strings, skipping tag-consumed strings.
pub(super) fn positional_strings(args: &[Argument]) -> Vec<String> {
	positional_groups(args).into_iter().flatten().collect()
}

/// The longest `:matches` key, in characters. A longer one is refused.
pub(crate) const MAX_PATTERN_CHARS: usize = 256;
/// The most wildcards (`*` and `?`) a `:matches` key may hold.
pub(crate) const MAX_WILDCARDS: usize = 32;

/// What matching a text against a pattern came to.
enum Glob {
	/// The pattern matches; each wildcard's captured range of the text, in
	/// the order the wildcards appear.
	Match(Vec<(usize, usize)>),
	NoMatch,
	/// The pattern is over the limits, or the work ran past `budget`: the
	/// answer is not "no match" and the caller has to say so.
	Refused,
}

/// Match `text` against `pattern` (`*` any run, `?` one character), counting
/// the character comparisons made into `steps` and giving up past `budget`.
///
/// The pattern is cut at its `*` into segments. The first is anchored to the
/// start of the text, the last to its end, and each one between goes at the
/// leftmost place after the one before. That finds a match whenever there is
/// one, and each `*` ends up as short as the rest allows: the assignment RFC
/// 5229 asks for, and the one a search over all splits would give. There is no
/// recursion and no table: the text is only walked, and a match costs at most
/// the pattern's length times the text's, usually the text's.
fn glob(pattern: &str, text: &str, steps: &mut u64, budget: u64) -> Glob {
	let p: Vec<char> = pattern.chars().take(MAX_PATTERN_CHARS + 1).collect();
	let wildcards = p.iter().filter(|c| matches!(c, '*' | '?')).count();
	if p.len() > MAX_PATTERN_CHARS || wildcards > MAX_WILDCARDS {
		return Glob::Refused;
	}
	let t: Vec<char> = text.chars().collect();
	let segments: Vec<&[char]> = p.split(|c| *c == '*').collect();
	let (first, last) = (segments[0], segments[segments.len() - 1]);
	let mut spans = Vec::new();
	// A segment at `at`: its `?`s capture one character each.
	let place =
		|segment: &[char], at: usize, steps: &mut u64, spans: &mut Vec<(usize, usize)>| -> bool {
			for (offset, &c) in segment.iter().enumerate() {
				*steps += 1;
				if c != '?' && t[at + offset] != c {
					return false;
				}
			}
			spans.extend(
				segment
					.iter()
					.enumerate()
					.filter(|(_, c)| **c == '?')
					.map(|(offset, _)| (at + offset, at + offset + 1)),
			);
			true
		};
	if segments.len() == 1 {
		if t.len() != first.len() || !place(first, 0, steps, &mut spans) {
			return Glob::NoMatch;
		}
		return Glob::Match(spans);
	}
	if t.len() < first.len() + last.len() {
		return Glob::NoMatch;
	}
	let tail = t.len() - last.len();
	if !place(first, 0, steps, &mut spans) {
		return Glob::NoMatch;
	}
	let mut pos = first.len();
	for segment in &segments[1..segments.len() - 1] {
		let mut found = None;
		let mut at = pos;
		while at + segment.len() <= tail {
			let mut trial = Vec::new();
			if place(segment, at, steps, &mut trial) {
				found = Some((at, trial));
				break;
			}
			if *steps > budget {
				return Glob::Refused;
			}
			at += 1;
		}
		let Some((at, trial)) = found else {
			return Glob::NoMatch;
		};
		spans.push((pos, at));
		spans.extend(trial);
		pos = at + segment.len();
	}
	if pos > tail {
		return Glob::NoMatch;
	}
	spans.push((pos, tail));
	if !place(last, tail, steps, &mut spans) {
		return Glob::NoMatch;
	}
	if *steps > budget {
		return Glob::Refused;
	}
	Glob::Match(spans)
}

/// Whether `pattern` matches `text`, for a test that has no run to charge.
fn glob_match(pattern: &str, text: &str) -> bool {
	let mut steps = 0;
	matches!(
		glob(pattern, text, &mut steps, super::env::MAX_WORK),
		Glob::Match(_)
	)
}

#[cfg(test)]
#[path = "compare_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compare_tests_bounds.rs"]
mod bounds_tests;
