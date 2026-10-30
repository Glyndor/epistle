//! Finding the paths a text cites, and deciding whether each one resolves.
//! What counts as a citation, and what is skipped, is written at the top of
//! `tests/repository/repository_paths_exist.rs`.

pub mod markdown;
pub mod rust_source;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

use std::path::Path;

/// The directories a citation can point into.
const CITED_ROOTS: &[&str] = &["src/", "tests/", "docs/"];

/// The paths cited in `segments`, each with its line in the file.
pub fn cited_paths(segments: &[(usize, String)]) -> Vec<(usize, String)> {
	segments
		.iter()
		.flat_map(|(start, text)| {
			citations(text)
				.into_iter()
				.map(move |(offset, path)| (start + offset, path))
		})
		.collect()
}

/// The paths cited in `text`, each with the number of newlines before it.
pub fn citations(text: &str) -> Vec<(usize, String)> {
	let mut out = Vec::new();
	for (at, _) in text.char_indices() {
		if !CITED_ROOTS
			.iter()
			.any(|cited_root| text[at..].starts_with(cited_root))
		{
			continue;
		}
		let mut start = at;
		while text[..start].ends_with("../") {
			start -= 3;
		}
		if text[..start]
			.chars()
			.next_back()
			.is_some_and(continues_a_path)
		{
			continue;
		}
		let (path, next) = take_path(&text[start..]);
		if is_placeholder(path, next) {
			continue;
		}
		out.push((text[..start].matches('\n').count(), path.to_string()));
	}
	out
}

/// Characters a cited path is made of. Anything else ends it, which is how
/// `::symbol`, `:12`, a closing backtick and a closing parenthesis stop it.
fn is_path_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '*')
}

/// A character that, right before `src/`, makes it part of something longer:
/// a path in another tree (`crates/common/src/`) or a word (`contests/`).
fn continues_a_path(c: char) -> bool {
	is_path_char(c) || matches!(c, '~' | '$')
}

/// The path at the start of `s`, without a trailing full stop, and the
/// character that ended it. A `{...}` group is part of the path.
fn take_path(s: &str) -> (&str, Option<char>) {
	let mut end = 0;
	while let Some(c) = s[end..].chars().next() {
		if is_path_char(c) {
			end += 1;
			continue;
		}
		if c == '{'
			&& let Some(close) = s[end..].find('}')
			&& s[end + 1..end + close]
				.chars()
				.all(|c| is_path_char(c) || c == ',')
		{
			end += close + 1;
			continue;
		}
		break;
	}
	(s[..end].trim_end_matches('.'), s[end..].chars().next())
}

/// A path that runs into `<...>`, or holds a `{...}` that is not a list of
/// alternatives, is a shape (`src/<domain>/`, `format!("src/{name}.rs")`).
fn is_placeholder(path: &str, next: Option<char>) -> bool {
	matches!(next, Some('<' | '{'))
		|| path
			.split('{')
			.skip(1)
			.any(|group| !group.split('}').next().unwrap_or_default().contains(','))
}

/// Why `cited`, found in the file `citing`, does not resolve, or `None`.
pub fn problem(citing: &str, cited: &str, tree: &[String], root: &Path) -> Option<&'static str> {
	let Some(rel) = resolve(citing, cited) else {
		return Some("points outside the repository");
	};
	if rel.contains(['*', '{']) {
		// `tree` holds files only, so a pattern that names a directory
		// (`src/{imap,pop3}/`) matches through what is under it.
		let patterns: Vec<String> = expand(&rel)
			.into_iter()
			.map(|p| if p.ends_with('/') { p + "**" } else { p })
			.collect();
		let matched = tree.iter().any(|file| {
			patterns
				.iter()
				.any(|p| glob_match(p.as_bytes(), file.as_bytes()))
		});
		return (!matched).then_some("matches no file");
	}
	(!root.join(&rel).exists()).then_some("does not exist")
}

/// `cited` as a path from the repository root. A `../` path resolves from
/// the directory of `citing`; `None` when it climbs out of the repository.
fn resolve(citing: &str, cited: &str) -> Option<String> {
	if !cited.starts_with("../") {
		return Some(cited.to_string());
	}
	let mut parts: Vec<&str> = citing.split('/').collect();
	parts.pop();
	for part in cited.split('/') {
		if part == ".." {
			parts.pop()?;
		} else {
			parts.push(part);
		}
	}
	Some(parts.join("/"))
}

/// One pattern per alternative of every `{a,b}` group in `pattern`.
fn expand(pattern: &str) -> Vec<String> {
	let (Some(open), Some(close)) = (pattern.find('{'), pattern.find('}')) else {
		return vec![pattern.to_string()];
	};
	if close < open {
		return vec![pattern.to_string()];
	}
	let (head, body, tail) = (
		&pattern[..open],
		&pattern[open + 1..close],
		&pattern[close + 1..],
	);
	body.split(',')
		.flat_map(|alt| expand(&format!("{head}{alt}{tail}")))
		.collect()
}

/// Shell-style match: `*` stays inside one path component, `**` crosses
/// them, and `**/` also matches no directory at all.
pub fn glob_match(pattern: &[u8], path: &[u8]) -> bool {
	match pattern {
		[] => path.is_empty(),
		[b'*', b'*', rest @ ..] => {
			(rest.first() == Some(&b'/') && glob_match(&rest[1..], path))
				|| (0..=path.len()).any(|i| glob_match(rest, &path[i..]))
		}
		[b'*', rest @ ..] => (0..=path.len())
			.take_while(|&i| i == 0 || path[i - 1] != b'/')
			.any(|i| glob_match(rest, &path[i..])),
		[c, rest @ ..] => path.first() == Some(c) && glob_match(rest, &path[1..]),
	}
}
