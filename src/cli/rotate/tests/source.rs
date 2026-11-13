//! Finds the configuration fields that look like a secret, from the source.
//!
//! The configuration is plain `serde` structs with no schema to ask, so the
//! structs are read as text: every `pub` field of every struct under
//! `src/config` whose name has a secret word in it and whose type is not a
//! flag or a number.

use std::path::{Path, PathBuf};

/// Substrings that make a configuration field look like a secret.
const SECRET_WORDS: &[&str] = &["secret", "password", "token", "key", "credential", "bearer"];

/// Types that hold a switch or a count, never a secret.
const PLAIN_TYPES: &[&str] = &[
	"bool", "u8", "u16", "u32", "u64", "usize", "i32", "i64", "f64",
];

/// The `Struct.field` of every secret-looking field in `source`.
pub(super) fn secret_fields(source: &str) -> Vec<String> {
	let mut found = Vec::new();
	let mut current: Option<String> = None;
	for line in source.lines() {
		let trimmed = line.trim_start();
		if let Some(name) = struct_name(line) {
			current = Some(name);
			continue;
		}
		if line == "}" {
			current = None;
			continue;
		}
		let (Some(owner), Some((field, kind))) = (&current, field_of(trimmed)) else {
			continue;
		};
		if SECRET_WORDS.iter().any(|word| field.contains(word))
			&& !PLAIN_TYPES.contains(&kind.as_str())
		{
			found.push(format!("{owner}.{field}"));
		}
	}
	found
}

/// The name of the struct a line opens, for a struct with named fields.
fn struct_name(line: &str) -> Option<String> {
	let rest = line
		.strip_prefix("pub struct ")
		.or_else(|| line.strip_prefix("pub(crate) struct "))
		.or_else(|| line.strip_prefix("struct "))?;
	if !line.trim_end().ends_with('{') {
		return None;
	}
	let end = rest.find(|c: char| !c.is_alphanumeric() && c != '_')?;
	Some(rest[..end].to_string())
}

/// A `pub name: Type,` line, as its name and the innermost type name.
fn field_of(trimmed: &str) -> Option<(String, String)> {
	let rest = trimmed
		.strip_prefix("pub(crate) ")
		.or_else(|| trimmed.strip_prefix("pub "))?;
	let (name, kind) = rest.split_once(':')?;
	let kind = kind
		.trim()
		.trim_start_matches("Option<")
		.trim_start_matches("Vec<");
	let kind: String = kind
		.chars()
		.take_while(|c| c.is_alphanumeric() || *c == '_')
		.collect();
	Some((name.trim().to_string(), kind))
}

/// Every non-test source file under `src/config`, with its text.
pub(super) fn config_sources() -> Vec<(PathBuf, String)> {
	fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
		for entry in std::fs::read_dir(dir).unwrap() {
			let path = entry.unwrap().path();
			if path.is_dir() {
				if path.file_name().is_some_and(|name| name != "tests") {
					walk(&path, out);
				}
			} else if path.extension().is_some_and(|ext| ext == "rs") {
				out.push(path);
			}
		}
	}
	let mut files = Vec::new();
	walk(
		&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config"),
		&mut files,
	);
	files
		.into_iter()
		.map(|path| {
			let text = std::fs::read_to_string(&path).unwrap();
			(path, text)
		})
		.collect()
}

/// Every secret-looking field of the configuration, sorted.
pub(super) fn config_secret_fields() -> Vec<String> {
	let mut fields: Vec<String> = config_sources()
		.iter()
		.flat_map(|(_, text)| secret_fields(text))
		.collect();
	fields.sort();
	fields.dedup();
	fields
}
