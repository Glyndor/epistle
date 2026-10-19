use super::parse::parse_astring;
use super::search_key::parse_search_key;
use super::{Command, ParseError, ReturnOpt, SearchScope, SortKey, ThreadAlgorithm};

/// Parse `SORT (<keys>) <charset> <search-criteria>` (RFC 5256).
pub(super) fn parse_sort(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let rest = args.trim().strip_prefix('(').ok_or_else(bad)?;
	let (key_list, after) = rest.split_once(')').ok_or_else(bad)?;
	let keys = parse_sort_keys(key_list).ok_or_else(bad)?;

	// A charset token precedes the search criteria; we only support UTF-8/US-ASCII
	// semantics but accept any token and ignore it.
	let (_charset, criteria_text) = after.trim_start().split_once(' ').ok_or_else(bad)?;
	let mut criteria = Vec::new();
	let mut remaining = criteria_text.trim();
	while !remaining.is_empty() {
		let (key, next) = parse_search_key(remaining).ok_or_else(bad)?;
		criteria.push(key);
		remaining = next.trim_start();
	}
	if keys.is_empty() || criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Sort {
		keys,
		criteria,
		uid,
	})
}

/// Parse `THREAD <algorithm> <charset> <search-criteria>` (RFC 5256).
/// ORDEREDSUBJECT and REFERENCES are both supported; the parser only
/// accepts what the capability list advertises, so the dispatch step
/// can rely on the discriminant.
pub(super) fn parse_thread(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (algorithm, after) = args.trim().split_once(' ').ok_or_else(bad)?;
	let algorithm = if algorithm.eq_ignore_ascii_case("ORDEREDSUBJECT") {
		ThreadAlgorithm::OrderedSubject
	} else if algorithm.eq_ignore_ascii_case("REFERENCES") {
		ThreadAlgorithm::References
	} else {
		return Err(bad());
	};
	// A charset token precedes the search criteria; accept and ignore it.
	let (_charset, criteria_text) = after.trim_start().split_once(' ').ok_or_else(bad)?;
	let mut criteria = Vec::new();
	let mut remaining = criteria_text.trim();
	while !remaining.is_empty() {
		let (key, next) = parse_search_key(remaining).ok_or_else(bad)?;
		criteria.push(key);
		remaining = next.trim_start();
	}
	if criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Thread {
		algorithm,
		criteria,
		uid,
	})
}

fn parse_sort_keys(text: &str) -> Option<Vec<(bool, SortKey)>> {
	let mut keys = Vec::new();
	let mut reverse = false;
	for token in text.split_whitespace() {
		let key = match token.to_ascii_uppercase().as_str() {
			"REVERSE" => {
				reverse = true;
				continue;
			}
			"ARRIVAL" => SortKey::Arrival,
			"CC" => SortKey::Cc,
			"DATE" => SortKey::Date,
			"FROM" => SortKey::From,
			"SIZE" => SortKey::Size,
			"SUBJECT" => SortKey::Subject,
			"TO" => SortKey::To,
			_ => return None,
		};
		keys.push((reverse, key));
		reverse = false;
	}
	// A trailing REVERSE with no key is malformed.
	if reverse { None } else { Some(keys) }
}

pub(super) fn parse_search(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let mut rest = args.trim();

	// Optional leading `RETURN (...)` (RFC 4731 §3.2): RETURN first, then
	// the criteria.
	let mut return_opts = None;
	if let Some(after_return) = strip_keyword(rest, "RETURN") {
		let inner = after_return.trim_start();
		let close = find_close_paren(inner).ok_or_else(bad)?;
		if !inner.starts_with('(') {
			return Err(bad());
		}
		return_opts = Some(parse_return_opts(&inner[1..close]).ok_or_else(bad)?);
		rest = inner[close + 1..].trim_start();
	}

	// Parse criteria until either the input is consumed or we hit a trailing
	// `RETURN (...)` block (RFC 5182 §2.1 lets RETURN appear after the
	// criteria, and says servers MUST accept either form).
	let mut criteria = Vec::new();
	while !rest.is_empty() {
		if let Some(after_return) = strip_keyword(rest, "RETURN") {
			let inner = after_return.trim_start();
			let close = find_close_paren(inner).ok_or_else(bad)?;
			if !inner.starts_with('(') {
				return Err(bad());
			}
			// A trailing RETURN replaces any leading one to keep the most
			// recently-parsed intent; for SEARCHRES the SAVE option is the
			// important one and either form is acceptable.
			return_opts = Some(parse_return_opts(&inner[1..close]).ok_or_else(bad)?);
			rest = inner[close + 1..].trim_start();
			if !rest.is_empty() {
				return Err(bad());
			}
			break;
		}
		let (key, after) = parse_search_key(rest).ok_or_else(bad)?;
		criteria.push(key);
		rest = after.trim_start();
	}
	if criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Search {
		criteria,
		uid,
		return_opts,
	})
}

/// Parse the contents of `RETURN (...)`. An empty list defaults to ALL.
fn parse_return_opts(text: &str) -> Option<Vec<ReturnOpt>> {
	let mut opts = Vec::new();
	for token in text.split_whitespace() {
		opts.push(match token.to_ascii_uppercase().as_str() {
			"MIN" => ReturnOpt::Min,
			"MAX" => ReturnOpt::Max,
			"COUNT" => ReturnOpt::Count,
			"ALL" => ReturnOpt::All,
			"SAVE" => ReturnOpt::Save,
			_ => return None,
		});
	}
	if opts.is_empty() {
		opts.push(ReturnOpt::All);
	}
	Some(opts)
}

/// If `s` begins with `keyword` (case-insensitive) followed by whitespace,
/// return the remainder.
fn strip_keyword<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
	let rest = s.get(..keyword.len())?;
	if rest.eq_ignore_ascii_case(keyword) {
		let tail = &s[keyword.len()..];
		if tail.starts_with(char::is_whitespace) {
			return Some(tail);
		}
	}
	None
}

/// Find the index of the `)` that closes the `(` at position 0 of `s`.
pub(super) fn find_close_paren(s: &str) -> Option<usize> {
	let mut depth = 0usize;
	for (i, c) in s.char_indices() {
		match c {
			'(' => depth += 1,
			')' => {
				// A closing paren with no matching open is unbalanced input,
				// not a panic: guard the unsigned subtraction (`?` yields None).
				depth = depth.checked_sub(1)?;
				if depth == 0 {
					return Some(i);
				}
			}
			_ => {}
		}
	}
	None
}

/// Parse `ESEARCH [IN (sources)] [RETURN (...)] criteria` (RFC 7377).
pub(super) fn parse_esearch(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let mut rest = args.trim();

	// Optional source scope: `IN (...)`. Absent means the selected mailbox.
	let mut sources = Vec::new();
	if let Some(after_in) = strip_keyword(rest, "IN") {
		let inner = after_in.trim_start();
		if !inner.starts_with('(') {
			return Err(bad());
		}
		let close = find_close_paren(inner).ok_or_else(bad)?;
		sources = parse_scopes(&inner[1..close]).ok_or_else(bad)?;
		rest = inner[close + 1..].trim_start();
	}
	if sources.is_empty() {
		sources.push(SearchScope::Selected);
	}

	// Optional `RETURN (...)`; defaults to ALL when omitted.
	let mut return_opts = vec![ReturnOpt::All];
	if let Some(after_return) = strip_keyword(rest, "RETURN") {
		let inner = after_return.trim_start();
		if !inner.starts_with('(') {
			return Err(bad());
		}
		let close = find_close_paren(inner).ok_or_else(bad)?;
		return_opts = parse_return_opts(&inner[1..close]).ok_or_else(bad)?;
		rest = inner[close + 1..].trim_start();
	}

	let mut criteria = Vec::new();
	while !rest.is_empty() {
		let (key, after) = parse_search_key(rest).ok_or_else(bad)?;
		criteria.push(key);
		rest = after.trim_start();
	}
	if criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Esearch {
		sources,
		criteria,
		return_opts,
	})
}

/// Parse the `IN (...)` scope-option list (RFC 7377 §2.2).
fn parse_scopes(text: &str) -> Option<Vec<SearchScope>> {
	let mut scopes = Vec::new();
	let mut rest = text.trim();
	while !rest.is_empty() {
		let (token, after) = match rest.split_once(char::is_whitespace) {
			Some((token, after)) => (token, after.trim_start()),
			None => (rest, ""),
		};
		let (scope, next) = match token.to_ascii_uppercase().as_str() {
			"SELECTED" => (SearchScope::Selected, after),
			"INBOXES" => (SearchScope::Inboxes, after),
			"PERSONAL" => (SearchScope::Personal, after),
			"SUBSCRIBED" => (SearchScope::Subscribed, after),
			"SUBTREE" => {
				let (list, next) = parse_scope_mailboxes(after)?;
				(SearchScope::Subtree(list), next)
			}
			"SUBTREE-ONE" => {
				let (list, next) = parse_scope_mailboxes(after)?;
				(SearchScope::SubtreeOne(list), next)
			}
			"MAILBOXES" => {
				let (list, next) = parse_scope_mailboxes(after)?;
				(SearchScope::Mailboxes(list), next)
			}
			_ => return None,
		};
		scopes.push(scope);
		rest = next.trim_start();
	}
	if scopes.is_empty() {
		None
	} else {
		Some(scopes)
	}
}

/// Parse a parenthesized mailbox list, e.g. `("Sent" "Drafts")`, returning the
/// names and the remaining input.
fn parse_scope_mailboxes(s: &str) -> Option<(Vec<String>, &str)> {
	let s = s.trim_start();
	let inner_end = find_close_paren(s)?;
	if !s.starts_with('(') {
		return None;
	}
	let mut inner = s[1..inner_end].trim();
	let mut names = Vec::new();
	while !inner.is_empty() {
		let (name, after) = parse_astring(inner)?;
		if name.is_empty() {
			return None;
		}
		names.push(name);
		inner = after.trim_start();
	}
	if names.is_empty() {
		return None;
	}
	Some((names, s[inner_end + 1..].trim_start()))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn find_close_paren_handles_unbalanced_close() {
		// A `)` with no matching `(` must not overflow the unsigned depth
		// counter — it is unbalanced input, so there is no closing index.
		assert_eq!(find_close_paren(")"), None);
		assert_eq!(find_close_paren("))"), None);
		assert_eq!(find_close_paren("a) b"), None);
	}

	#[test]
	fn find_close_paren_matches_the_opener() {
		assert_eq!(find_close_paren("()"), Some(1));
		assert_eq!(find_close_paren("(a (b) c) d"), Some(8));
	}

	#[test]
	fn search_parse_never_panics_on_the_fuzz_crash() {
		// Regression for the fuzzer-found subtract-with-overflow: a malformed
		// SEARCH/ESEARCH line with a stray `)` before any `(` must return an
		// error, not panic.
		let crash = "E-- SEARCH       return   m E-) ESEARCH  HEADER EFFFFn   TMETFYm Y";
		let _ = super::super::parse(crash, super::super::DEFAULT_APPEND_LIMIT);
	}
}
