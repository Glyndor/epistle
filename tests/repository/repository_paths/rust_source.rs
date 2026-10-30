//! The comments and string literals of a Rust source.

/// The comments of a Rust source, and its string literals when `strings` is
/// set, each with the line it starts on. Char literals and lifetimes are
/// skipped so that `'"'` does not open a string.
pub fn segments(source: &str, strings: bool) -> Vec<(usize, String)> {
	let chars: Vec<char> = source.chars().collect();
	let mut out = Vec::new();
	let (mut i, mut line) = (0, 1);
	while i < chars.len() {
		let (start, start_line) = (i, line);
		let mut keep = None;
		if chars[i] == '/' && chars.get(i + 1) == Some(&'/') {
			i = chars[i..]
				.iter()
				.position(|&c| c == '\n')
				.map_or(chars.len(), |p| i + p);
			keep = Some((start, i));
		} else if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
			i = block_comment_end(&chars, i);
			keep = Some((start, i));
		} else if let Some((body, hashes)) = string_start(&chars, i) {
			let (body_end, end) = string_end(&chars, body, hashes);
			i = end;
			keep = strings.then_some((body, body_end));
		} else if chars[i] == '\'' {
			i = char_literal_end(&chars, i);
		} else {
			i += 1;
		}
		line += chars[start..i].iter().filter(|&&c| c == '\n').count();
		if let Some((from, to)) = keep {
			out.push((start_line, chars[from..to].iter().collect()));
		}
	}
	out
}

/// The index after the `*/` that closes the block comment opened at `from`.
fn block_comment_end(chars: &[char], from: usize) -> usize {
	let (mut depth, mut i) = (0usize, from);
	while i < chars.len() {
		if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
			depth += 1;
			i += 2;
		} else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
			depth -= 1;
			i += 2;
			if depth == 0 {
				return i;
			}
		} else {
			i += 1;
		}
	}
	chars.len()
}

/// When a string literal opens at `i` (`"`, `b"`, `c"`, `r#"`), the index of
/// its first character and, for a raw string, its number of `#`.
fn string_start(chars: &[char], i: usize) -> Option<(usize, Option<usize>)> {
	if chars[i] != '"' && i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
		return None;
	}
	let mut j = i;
	if matches!(chars[j], 'b' | 'c') {
		j += 1;
	}
	let raw = chars.get(j) == Some(&'r');
	if raw {
		j += 1;
	}
	let hashes = chars
		.get(j..)
		.unwrap_or_default()
		.iter()
		.take_while(|&&c| c == '#')
		.count();
	if !raw && hashes > 0 {
		return None;
	}
	j += hashes;
	(chars.get(j) == Some(&'"')).then_some((j + 1, raw.then_some(hashes)))
}

/// The end of a string's content and the index after its closing quote.
fn string_end(chars: &[char], from: usize, hashes: Option<usize>) -> (usize, usize) {
	let mut i = from;
	while i < chars.len() {
		match (chars[i], hashes) {
			('\\', None) => i += 2,
			('"', None) => return (i, i + 1),
			('"', Some(n)) if chars[i + 1..].iter().take(n).filter(|&&c| c == '#').count() == n => {
				return (i, i + 1 + n);
			}
			_ => i += 1,
		}
	}
	(chars.len(), chars.len())
}

/// The index after a char literal (`'"'`, `'\''`) or a lifetime (`'a`)
/// that starts at `i`.
fn char_literal_end(chars: &[char], i: usize) -> usize {
	match chars.get(i + 1) {
		Some('\\') => chars[i + 2..]
			.iter()
			.skip(1)
			.position(|&c| c == '\'')
			.map_or(chars.len(), |p| i + 4 + p),
		Some(_) if chars.get(i + 2) == Some(&'\'') => i + 3,
		_ => i + 1,
	}
}
