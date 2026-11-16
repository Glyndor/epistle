//! Reading back the unit `podup autostart install` writes.
//!
//! Only the compose-file list is read: it is recorded as literal `-f`
//! arguments on the `ExecStart=` line when the unit is installed, and nothing
//! updates it afterwards.

use std::path::{Path, PathBuf};

/// The compose files the unit's `ExecStart=` line starts the stack from, in
/// the order it names them. `None` when the unit has no such line.
pub(in crate::cli) fn compose_files(unit: &str) -> Option<Vec<PathBuf>> {
	let line = unit
		.lines()
		.find_map(|line| line.strip_prefix("ExecStart="))?;
	let words = split(line);
	let mut files = Vec::new();
	let mut words = words.iter();
	while let Some(word) = words.next() {
		if word == "-f" {
			files.push(PathBuf::from(words.next()?));
		}
	}
	Some(files)
}

#[cfg(test)]
/// Whether the unit's `ExecStart=` line passes `flag` as a word of its own.
pub(in crate::cli) fn has_flag(unit: &str, flag: &str) -> bool {
	unit.lines()
		.find_map(|line| line.strip_prefix("ExecStart="))
		.is_some_and(|line| split(line).iter().any(|word| word == flag))
}

/// Whether the unit orders itself after `name` with an `After=` line.
pub(in crate::cli) fn orders_after(unit: &str, name: &str) -> bool {
	unit.lines()
		.filter_map(|line| line.strip_prefix("After="))
		.any(|value| value.split_whitespace().any(|word| word == name))
}

/// Whether two file lists name the same files in the same order. A path is
/// compared by what it resolves to when it exists, so a link or a `..` in one
/// of them does not read as another file.
pub(in crate::cli) fn same_files(unit: &[PathBuf], current: &[PathBuf]) -> bool {
	let resolve = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
	unit.len() == current.len()
		&& unit
			.iter()
			.zip(current)
			.all(|(left, right)| resolve(left) == resolve(right))
}

/// Split an exec line into its words the way systemd does for the forms
/// podup writes: double quotes group, a backslash escapes inside them, and
/// `%%` and `$$` stand for a literal `%` and `$`.
fn split(line: &str) -> Vec<String> {
	let mut words = Vec::new();
	let mut word = String::new();
	let mut started = false;
	let mut quoted = false;
	let mut chars = line.chars().peekable();
	while let Some(c) = chars.next() {
		match c {
			'"' => {
				quoted = !quoted;
				started = true;
			}
			'\\' if quoted => match chars.next() {
				Some('n') => word.push('\n'),
				Some('t') => word.push('\t'),
				Some('r') => word.push('\r'),
				Some(other) => word.push(other),
				None => word.push('\\'),
			},
			'%' | '$' if chars.peek() == Some(&c) => {
				chars.next();
				word.push(c);
				started = true;
			}
			c if c.is_whitespace() && !quoted => {
				if started {
					words.push(std::mem::take(&mut word));
					started = false;
				}
			}
			c => {
				word.push(c);
				started = true;
			}
		}
	}
	if started {
		words.push(word);
	}
	words
}

#[cfg(test)]
mod tests;
