//! LIST and LSUB mailbox patterns (RFC 9051 §6.3.9).
//!
//! The reference is prepended to the pattern. `*` matches any run of
//! characters and `%` any run without the hierarchy delimiter `/`; every
//! other character matches itself. `INBOX` matches in any case, every other
//! name exactly. Both sides are in the stored spelling (modified UTF-7): the
//! session encodes a UTF-8 pattern before it gets here.

/// Whether `name` (as stored) is selected by `reference` + `pattern`.
pub(crate) fn matches(reference: &str, pattern: &str, name: &str) -> bool {
	let full = inbox_upper(&format!("{reference}{pattern}"));
	glob(full.as_bytes(), inbox_upper(name).as_bytes())
}

/// Spell a leading `INBOX` component in upper case, so the inbox matches in
/// any case while other names stay case-sensitive.
fn inbox_upper(text: &str) -> String {
	let head = text
		.get(..5)
		.filter(|head| head.eq_ignore_ascii_case("INBOX"));
	match head {
		Some(_) if text.len() == 5 || text[5..].starts_with(['/', '*', '%']) => {
			format!("INBOX{}", &text[5..])
		}
		_ => text.to_string(),
	}
}

/// Wildcard match in O(pattern × name) time, so a pattern made of many `*`
/// cannot make a LIST expensive. A run of wildcards is one `*` if it holds
/// one and one `%` otherwise, and a pattern with more literal bytes than the
/// name cannot match, so the table never outgrows (2 × name + 1) × name
/// however long the command line was.
fn glob(pattern: &[u8], name: &[u8]) -> bool {
	let pattern = collapse_wildcards(pattern);
	let literals = pattern.iter().filter(|p| !matches!(p, b'*' | b'%')).count();
	if literals > name.len() {
		return false;
	}
	// `row[j]`: the pattern read so far matches the first `j` bytes of name.
	let mut row = vec![false; name.len() + 1];
	row[0] = true;
	for &p in &pattern {
		let mut next = vec![false; name.len() + 1];
		next[0] = row[0] && matches!(p, b'*' | b'%');
		for j in 1..=name.len() {
			let c = name[j - 1];
			next[j] = match p {
				b'*' => row[j] || next[j - 1],
				b'%' => row[j] || (c != b'/' && next[j - 1]),
				_ => row[j - 1] && p == c,
			};
		}
		row = next;
	}
	row[name.len()]
}

/// `pattern` with each run of `*` and `%` replaced by the one wildcard that
/// matches the same names.
fn collapse_wildcards(pattern: &[u8]) -> Vec<u8> {
	let mut out: Vec<u8> = Vec::with_capacity(pattern.len());
	for &p in pattern {
		match (p, out.last_mut()) {
			(b'*' | b'%', Some(last @ (b'*' | b'%'))) => {
				if p == b'*' {
					*last = b'*';
				}
			}
			_ => out.push(p),
		}
	}
	out
}

#[cfg(test)]
#[path = "list_pattern_tests.rs"]
mod tests;
