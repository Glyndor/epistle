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

/// The comparators `:comparator` accepts (RFC 4790). `i;ascii-casemap` is the
/// default, and any other name falls back to it. Each is a Sieve extension,
/// `comparator-<name>` (RFC 5228 section 2.7.3), which [`super::EXTENSIONS`]
/// lists.
pub(crate) const COMPARATORS: [&str; 3] = ["i;octet", "i;ascii-casemap", "i;ascii-numeric"];

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
			Collation::AsciiCasemap => a
				.bytes()
				.map(|c| c.to_ascii_lowercase())
				.cmp(b.bytes().map(|c| c.to_ascii_lowercase())),
			Collation::AsciiNumeric => numeric_key(a).cmp(&numeric_key(b)),
		}
	}

	fn contains(self, value: &str, key: &str) -> bool {
		match self {
			Collation::AsciiCasemap => contains_ignoring_case(value, key),
			_ => value.contains(key),
		}
	}
}

/// Whether `value` holds `key`, ignoring ASCII case, in time linear in the two
/// and without copying `value` (it can be a whole message body). Knuth,
/// Morris and Pratt: the table is as long as the key, which the script wrote.
fn contains_ignoring_case(value: &str, key: &str) -> bool {
	let key: Vec<u8> = key.bytes().map(|c| c.to_ascii_lowercase()).collect();
	if key.is_empty() {
		return true;
	}
	let mut fail = vec![0usize; key.len()];
	let mut k = 0;
	for i in 1..key.len() {
		while k > 0 && key[i] != key[k] {
			k = fail[k - 1];
		}
		if key[i] == key[k] {
			k += 1;
		}
		fail[i] = k;
	}
	let mut matched = 0;
	for byte in value.bytes().map(|c| c.to_ascii_lowercase()) {
		while matched > 0 && byte != key[matched] {
			matched = fail[matched - 1];
		}
		if byte == key[matched] {
			matched += 1;
			if matched == key.len() {
				return true;
			}
		}
	}
	false
}

/// The `i;ascii-numeric` sort key: the leading run of ASCII digits as a number.
/// A value not starting with a digit, or whose digits do not fit a number, is
/// positive infinity (RFC 4790 §9.1.1), so it sorts after every number; all
/// such values are equal to each other.
fn numeric_key(value: &str) -> (u8, u64) {
	let mut number: u64 = 0;
	let mut digits = 0;
	for digit in value.bytes().take_while(u8::is_ascii_digit) {
		digits += 1;
		match number
			.checked_mul(10)
			.and_then(|n| n.checked_add(u64::from(digit - b'0')))
		{
			Some(next) => number = next,
			None => return (1, 0),
		}
	}
	if digits == 0 { (1, 0) } else { (0, number) }
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
		// Every comparison costs the octets it reads, and a minimum, before
		// anything is allocated or compared: a run past its budget compares
		// nothing more.
		if !env.charge(value.len() as u64 + key.len() as u64 + COMPARISON_COST) {
			return false;
		}
		match self.match_type {
			MatchType::Matches => {
				let mut steps = 0;
				let outcome = glob(key, value, &mut steps, env.remaining_work());
				if !env.charge(steps) {
					return false;
				}
				match outcome {
					Glob::Match(spans) => {
						env.set("0", value);
						for (index, (from, to)) in spans.into_iter().enumerate() {
							// Captures are lower case, as they always were, and
							// at most as long as a variable can be.
							let capture =
								lowercase_prefix(&value[from..to], super::env::MAX_VAR_BYTES);
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
			MatchType::Matches => glob_match(key, value),
			MatchType::Count(_) => false,
		}
	}
}

/// What one comparison costs a run at least, whatever the lengths.
const COMPARISON_COST: u64 = 64;

/// The first `limit` octets of `text` (cut at a character boundary), in
/// ASCII lower case: the copy is never longer than that.
fn lowercase_prefix(text: &str, limit: usize) -> String {
	let mut end = text.len().min(limit);
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	text[..end].to_ascii_lowercase()
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
	/// The pattern matches; each wildcard's captured range of the text, as
	/// byte offsets, in the order the wildcards appear.
	Match(Vec<(usize, usize)>),
	NoMatch,
	/// The pattern is over the limits, or the work ran past `budget`: the
	/// answer is not "no match" and the caller has to say so.
	Refused,
}

/// The character at byte offset `at` of `text`, which is a boundary.
fn char_at(text: &str, at: usize) -> Option<char> {
	text[at..].chars().next()
}

/// Match `text` against `pattern` (`*` any run, `?` one character, ASCII case
/// ignored), counting the character comparisons made into `steps` and giving
/// up past `budget`.
///
/// The pattern is cut at its `*` into segments. The first is anchored to the
/// start of the text, the last to its end, and each one between goes at the
/// leftmost place after the one before. That finds a match whenever there is
/// one, and each `*` ends up as short as the rest allows: the assignment RFC
/// 5229 asks for, and the one a search over all splits would give. There is no
/// recursion and no table, and the text is read in place by byte offset: it is
/// never copied, whatever its length.
fn glob(pattern: &str, text: &str, steps: &mut u64, budget: u64) -> Glob {
	let p: Vec<char> = pattern
		.chars()
		.take(MAX_PATTERN_CHARS + 1)
		.map(|c| c.to_ascii_lowercase())
		.collect();
	let wildcards = p.iter().filter(|c| matches!(c, '*' | '?')).count();
	if p.len() > MAX_PATTERN_CHARS || wildcards > MAX_WILDCARDS {
		return Glob::Refused;
	}
	let segments: Vec<&[char]> = p.split(|c| *c == '*').collect();
	let (first, last) = (segments[0], segments[segments.len() - 1]);
	// The segment at byte offset `at`: where it ends, or `None`. Its `?`s
	// capture one character each.
	let place = |segment: &[char],
	             at: usize,
	             steps: &mut u64,
	             spans: &mut Vec<(usize, usize)>|
	 -> Option<usize> {
		let mut pos = at;
		for &c in segment {
			*steps += 1;
			let found = char_at(text, pos)?;
			if c == '?' {
				spans.push((pos, pos + found.len_utf8()));
			} else if c != found.to_ascii_lowercase() {
				return None;
			}
			pos += found.len_utf8();
		}
		Some(pos)
	};
	let mut spans = Vec::new();
	if segments.len() == 1 {
		return match place(first, 0, steps, &mut spans) {
			Some(end) if end == text.len() => Glob::Match(spans),
			_ => Glob::NoMatch,
		};
	}
	// Where the last segment starts: as many characters from the end as it has.
	let mut tail = text.len();
	for _ in 0..last.len() {
		let Some((start, _)) = text[..tail].char_indices().next_back() else {
			return Glob::NoMatch;
		};
		tail = start;
	}
	let Some(mut pos) = place(first, 0, steps, &mut spans) else {
		return Glob::NoMatch;
	};
	if pos > tail {
		return Glob::NoMatch;
	}
	for segment in &segments[1..segments.len() - 1] {
		let mut at = pos;
		let (start, end, trial) = loop {
			let mut trial = Vec::new();
			if let Some(end) = place(segment, at, steps, &mut trial)
				&& end <= tail
			{
				break (at, end, trial);
			}
			if *steps > budget {
				return Glob::Refused;
			}
			match char_at(text, at) {
				Some(c) if at < tail => at += c.len_utf8(),
				_ => return Glob::NoMatch,
			}
		};
		spans.push((pos, start));
		spans.extend(trial);
		pos = end;
	}
	spans.push((pos, tail));
	if place(last, tail, steps, &mut spans).is_none() {
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
