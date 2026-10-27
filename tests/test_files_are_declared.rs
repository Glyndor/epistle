//! A sibling test file that no `mod` or `#[path]` names is never compiled, so its
//! tests never run and nothing says so. `src/cli/limits/mod_tests_cli.rs` sat
//! that way after a move, and three more files like it were found when this
//! guard was written.
//!
//! Every `src` file named like a test file (`*_tests.rs`, `*_tests_*.rs`,
//! `tests.rs`, `mod_tests*.rs`) must be reached by a `#[path = "<file>"]`
//! attribute or by a `mod <name>;` declaration somewhere in `src`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
	for entry in fs::read_dir(dir).unwrap() {
		let path = entry.unwrap().path();
		if path.is_dir() {
			rust_files(&path, out);
		} else if path.extension().is_some_and(|ext| ext == "rs") {
			out.push(path);
		}
	}
}

fn is_test_file_name(name: &str) -> bool {
	name == "tests.rs" || name.starts_with("mod_tests") || name.contains("_tests")
}

/// File names a `#[path = "..."]` attribute points at, and `<name>.rs` for every
/// `mod <name>;`.
fn declared_names(sources: &[String]) -> HashSet<String> {
	let mut names = HashSet::new();
	for text in sources {
		for line in text.lines() {
			let line = line.trim();
			if let Some(rest) = line.strip_prefix("#[path")
				&& let Some(start) = rest.find('"')
				&& let Some(end) = rest[start + 1..].find('"')
			{
				let target = &rest[start + 1..start + 1 + end];
				names.insert(target.rsplit('/').next().unwrap().to_string());
			}
			let line = line
				.strip_prefix("pub(crate) ")
				.or_else(|| line.strip_prefix("pub(super) "))
				.or_else(|| line.strip_prefix("pub "))
				.unwrap_or(line);
			if let Some(name) = line.strip_prefix("mod ").and_then(|r| r.strip_suffix(';')) {
				names.insert(format!("{}.rs", name.trim()));
			}
		}
	}
	names
}

#[test]
fn every_test_file_in_src_is_declared_by_a_module() {
	let mut files = Vec::new();
	rust_files(
		&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
		&mut files,
	);
	let sources: Vec<String> = files
		.iter()
		.map(|p| fs::read_to_string(p).unwrap())
		.collect();
	let declared = declared_names(&sources);
	let mut orphans: Vec<String> = files
		.iter()
		.filter_map(|path| {
			let name = path.file_name()?.to_str()?;
			(is_test_file_name(name) && !declared.contains(name))
				.then(|| path.display().to_string())
		})
		.collect();
	orphans.sort();
	assert!(
		orphans.is_empty(),
		"these test files are not declared by any `mod` or `#[path]`, so their tests never run:\n{}",
		orphans.join("\n")
	);
}
