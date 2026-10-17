//! Sieve match types and comparators: `:is`/`:contains`/`:matches` (RFC 5228
//! §2.7.1), the relational `:value`/`:count` extension (RFC 5231) and the
//! `i;ascii-casemap`/`i;octet`/`i;ascii-numeric` collations (RFC 4790).
//!
//! Also the positional-argument helpers: the string arguments consumed by the
//! `:comparator`/`:value`/`:count` tags must not be mistaken for a test's
//! header names or keys.

use std::cmp::Ordering;
use std::collections::HashMap;

use super::ast::Argument;
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
	pub(super) fn test(&self, value: &str, key: &str, vars: &mut HashMap<String, String>) -> bool {
		match self.match_type {
			MatchType::Matches => {
				match glob_captures(&key.to_ascii_lowercase(), &value.to_ascii_lowercase()) {
					Some(captures) => {
						vars.insert("0".to_string(), value.to_string());
						for (index, capture) in captures.into_iter().enumerate() {
							vars.insert((index + 1).to_string(), capture);
						}
						true
					}
					None => false,
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

/// The longest `:matches` key, in characters. A longer one matches nothing.
pub(crate) const MAX_PATTERN_CHARS: usize = 256;
/// The most wildcards (`*` and `?`) a `:matches` key may hold.
pub(crate) const MAX_WILDCARDS: usize = 32;
/// The longest text `:matches` looks at, in characters. The table the
/// captures are read from has one cell per pattern character and text
/// character, so this and the pattern limit bound its size (about 2 MiB).
pub(crate) const MAX_TEXT_CHARS: usize = 8192;

/// A key and a text `:matches` is willing to compare, as characters.
fn bounded(pattern: &str, text: &str) -> Option<(Vec<char>, Vec<char>)> {
	let p: Vec<char> = pattern.chars().take(MAX_PATTERN_CHARS + 1).collect();
	let wildcards = p.iter().filter(|c| matches!(c, '*' | '?')).count();
	if p.len() > MAX_PATTERN_CHARS || wildcards > MAX_WILDCARDS {
		return None;
	}
	let t: Vec<char> = text.chars().take(MAX_TEXT_CHARS + 1).collect();
	(t.len() <= MAX_TEXT_CHARS).then_some((p, t))
}

/// Glob match supporting `*` (any run) and `?` (one char), per Sieve `:matches`.
fn glob_match(pattern: &str, text: &str) -> bool {
	let Some((p, t)) = bounded(pattern, text) else {
		return false;
	};
	let mut dp = vec![false; t.len() + 1];
	dp[0] = true;
	for &pc in &p {
		let mut prev = dp[0];
		dp[0] = dp[0] && pc == '*';
		for j in 0..t.len() {
			let here = dp[j + 1];
			dp[j + 1] = if pc == '*' {
				dp[j] || dp[j + 1]
			} else if pc == '?' || pc == t[j] {
				prev
			} else {
				false
			};
			prev = here;
		}
	}
	dp[t.len()]
}

/// Glob match returning each `*`/`?` capture in order, or `None` if no match.
/// `*` is non-greedy (shortest run), giving RFC 5229 leftmost assignment.
///
/// Whether a suffix of the pattern matches a suffix of the text is worked out
/// once for every pair, so the cost is the product of the two lengths and
/// nothing recurses. The captures are then read off that table, taking at
/// each `*` the shortest run that still lets the rest match.
fn glob_captures(pattern: &str, text: &str) -> Option<Vec<String>> {
	let (p, t) = bounded(pattern, text)?;
	let width = t.len() + 1;
	// fits[j * width + i]: p[j..] matches t[i..].
	let mut fits = vec![false; (p.len() + 1) * width];
	fits[p.len() * width + t.len()] = true;
	for j in (0..p.len()).rev() {
		for i in (0..=t.len()).rev() {
			fits[j * width + i] = match p[j] {
				'*' => fits[(j + 1) * width + i] || (i < t.len() && fits[j * width + i + 1]),
				'?' => i < t.len() && fits[(j + 1) * width + i + 1],
				c => i < t.len() && t[i] == c && fits[(j + 1) * width + i + 1],
			};
		}
	}
	if !fits[0] {
		return None;
	}
	let mut captures = Vec::new();
	let mut i = 0;
	for (j, &c) in p.iter().enumerate() {
		match c {
			'*' => {
				let run = (0..=t.len() - i).find(|run| fits[(j + 1) * width + i + run])?;
				captures.push(t[i..i + run].iter().collect());
				i += run;
			}
			'?' => {
				captures.push(t[i].to_string());
				i += 1;
			}
			_ => i += 1,
		}
	}
	Some(captures)
}

#[cfg(test)]
#[path = "compare_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compare_tests_bounds.rs"]
mod bounds_tests;
