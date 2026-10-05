//! Migrations above 0003 follow the expand/contract discipline: a release
//! adds and dual-writes, the next reads the new shape, the one after drops.
//! `podman auto-update` rolls a container back when the new one fails to
//! start, but it cannot roll a migration back; a destructive statement
//! above 0003 leaves the old image looking for a column or table that is
//! already gone.
//!
//! `0001_reputation.sql`, `0002_bayes.sql` and `0003_bayes_scope.sql` are
//! exempt by number. The owner decided on 2026-08-30 to leave 0003 as it
//! is because nobody runs epistle yet and the four destructive statements
//! it carries are baked into every deployed instance that ever existed.
//! The exemption is not a pattern to extend: every new migration applies
//! the rule from this file.

use std::fs;
use std::path::Path;

const EXEMPT_PREFIX: u32 = 3;

#[test]
fn migrations_above_0003_have_no_destructive_statement() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let dir = root.join("migrations");

	let entries =
		fs::read_dir(&dir).unwrap_or_else(|e| panic!("read migrations/ at {}: {e}", dir.display()));

	let mut migrations: Vec<(u32, std::path::PathBuf)> = entries
		.filter_map(Result::ok)
		.map(|e| e.path())
		.filter(|p| p.extension().and_then(|e| e.to_str()) == Some("sql"))
		.filter_map(|p| Some((migration_prefix(&p)?, p)))
		.collect();

	if migrations.is_empty() {
		panic!(
			"migrations/ at {} is empty or contains no *.sql; the expand/contract test \
			 refuses to pass on an empty walk, because the rule is silence-fail until \
			 somebody adds a migration that drops a column",
			dir.display(),
		);
	}

	migrations.sort_by_key(|(prefix, _)| *prefix);

	let mut all_hits: Vec<(String, usize, String)> = Vec::new();
	for (prefix, path) in &migrations {
		if *prefix <= EXEMPT_PREFIX {
			continue;
		}
		let content =
			fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
		for (line_no, line) in find_hits(&content) {
			all_hits.push((
				path.file_name()
					.and_then(|n| n.to_str())
					.unwrap_or("?")
					.to_string(),
				line_no,
				line,
			));
		}
	}

	if !all_hits.is_empty() {
		let mut msg = String::from(
			"a migration above 0003 must not drop, rename or retype because podman \
			 auto-update cannot roll a migration back; the discipline is to add and \
			 dual-write in one release, read the new shape in the next, and drop the \
			 old shape in the one after that. Offending lines:\n",
		);
		for (file, line_no, line) in &all_hits {
			msg.push_str(&format!("  {file}:{line_no}: {line}\n"));
		}
		panic!("{msg}");
	}
}

#[test]
fn the_guard_sees_a_planted_drop() {
	let fixture = "-- a leading comment that says DROP TABLE must not count\n\
	               ALTER TABLE x DROP COLUMN y;\n";
	let hits = find_hits(fixture);
	assert_eq!(
		hits.len(),
		1,
		"the planted DROP COLUMN must produce exactly one hit; got: {hits:?}",
	);
	assert_eq!(
		hits[0].0, 2,
		"the hit must be on line 2 (the ALTER TABLE), not line 1 (the comment); got: {:?}",
		hits[0],
	);
	assert!(
		hits[0].1.contains("DROP COLUMN"),
		"the hit line must still carry the DROP COLUMN token; got: {:?}",
		hits[0].1,
	);
}

// --- checker shared by both tests ---

/// Numeric prefix of a migration file: `0004_directory.sql` → 4.
fn migration_prefix(path: &Path) -> Option<u32> {
	let name = path.file_name()?.to_str()?;
	let head = name.get(..4)?;
	head.parse().ok()
}

/// Walk `source`, strip SQL comments first, then return one entry per line
/// that carries any destructive pattern: `(line_number, original_line_text)`.
fn find_hits(source: &str) -> Vec<(usize, String)> {
	let stripped = strip_comments(source);
	let mut hits = Vec::new();
	for (idx, line) in stripped.lines().enumerate() {
		if line.trim().is_empty() {
			continue;
		}
		if line_has_destructive(line) {
			hits.push((idx + 1, line.to_string()));
		}
	}
	hits
}

/// Replace `/* ... */` block comments with whitespace (newlines stay
/// newlines, every other byte becomes a space) and `-- ...` line comments
/// with whitespace from the `--` to the end of the line. Identifiers and
/// tokens before a comment stay in place, so line numbers are preserved
/// and a block comment that spans three lines still leaves three lines for
/// the per-line scan to count.
fn strip_comments(source: &str) -> String {
	let bytes = source.as_bytes();
	let mut out = String::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
			out.push(' ');
			out.push(' ');
			i += 2;
			while i < bytes.len() {
				if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
					out.push(' ');
					out.push(' ');
					i += 2;
					break;
				}
				if bytes[i] == b'\n' {
					out.push('\n');
				} else {
					out.push(' ');
				}
				i += 1;
			}
		} else if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
			while i < bytes.len() && bytes[i] != b'\n' {
				out.push(' ');
				i += 1;
			}
		} else {
			out.push(bytes[i] as char);
			i += 1;
		}
	}
	out
}

fn is_ident_byte(b: u8) -> bool {
	b.is_ascii_alphanumeric() || b == b'_'
}

/// Does `upper` contain the keyword `w` starting at byte index `i`, with a
/// non-identifier byte (or the start of the line) on the left and another
/// on the right? `upper` is the already-uppercased scan buffer.
fn is_word_at(upper: &[u8], i: usize, w: &[u8]) -> bool {
	if i + w.len() > upper.len() {
		return false;
	}
	if &upper[i..i + w.len()] != w {
		return false;
	}
	let left_ok = i == 0 || !is_ident_byte(upper[i - 1]);
	let right_ok = i + w.len() == upper.len() || !is_ident_byte(upper[i + w.len()]);
	left_ok && right_ok
}

/// Does the line (comments already stripped) carry any of the destructive
/// patterns we refuse above migration 0003? Patterns are matched as whole
/// SQL words, so identifiers like `drop_count` do not trigger; case is
/// folded to ASCII upper before the scan.
fn line_has_destructive(line: &str) -> bool {
	let upper: Vec<u8> = line.bytes().map(|b| b.to_ascii_uppercase()).collect();
	let n = upper.len();
	let mut i = 0;
	while i < n {
		if !is_ident_byte(upper[i]) {
			i += 1;
			continue;
		}
		if is_word_at(&upper, i, b"DROP") {
			let mut j = i + 4;
			while j < n && upper[j].is_ascii_whitespace() {
				j += 1;
			}
			if is_word_at(&upper, j, b"TABLE")
				|| is_word_at(&upper, j, b"COLUMN")
				|| is_word_at(&upper, j, b"CONSTRAINT")
				|| is_word_at(&upper, j, b"INDEX")
			{
				return true;
			}
		}
		if is_word_at(&upper, i, b"TRUNCATE") {
			return true;
		}
		if is_word_at(&upper, i, b"DELETE") {
			let mut j = i + 6;
			while j < n && upper[j].is_ascii_whitespace() {
				j += 1;
			}
			if is_word_at(&upper, j, b"FROM") {
				return true;
			}
		}
		if is_word_at(&upper, i, b"ALTER") {
			let mut j = i + 5;
			while j < n && upper[j].is_ascii_whitespace() {
				j += 1;
			}
			if is_word_at(&upper, j, b"TABLE") {
				let mut k = j + 5;
				while k < n && upper[k].is_ascii_whitespace() {
					k += 1;
				}
				if k < n && is_ident_byte(upper[k]) {
					while k < n && is_ident_byte(upper[k]) {
						k += 1;
					}
					while k < n && upper[k].is_ascii_whitespace() {
						k += 1;
					}
					if is_word_at(&upper, k, b"RENAME") {
						return true;
					}
				}
			}
			if is_word_at(&upper, j, b"COLUMN") {
				let mut k = j + 6;
				while k < n && upper[k].is_ascii_whitespace() {
					k += 1;
				}
				if k < n && is_ident_byte(upper[k]) {
					while k < n && is_ident_byte(upper[k]) {
						k += 1;
					}
					while k < n && upper[k].is_ascii_whitespace() {
						k += 1;
					}
					if is_word_at(&upper, k, b"TYPE") {
						return true;
					}
				}
			}
		}
		i += 1;
	}
	false
}
