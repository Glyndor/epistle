//! A sibling test file that no `mod` or `#[path]` names is never compiled, so its
//! tests never run and nothing says so. `src/cli/limits/mod_tests_cli.rs` sat
//! that way after a move, and three more files like it were found when this
//! guard was written.
//!
//! Every `src` file named like a test file (`*_tests.rs`, `*_tests_*.rs`,
//! `tests.rs`, `mod_tests*.rs`) must be reached by a `#[path = "<file>"]`
//! attribute or by a `mod <name>;` declaration, resolved against the folder of
//! the file that declares it. The leaves of a `tests/` folder count as test
//! files too, whatever their name is, since the convention of 2026-10-27
//! names them after the topic and not after the word "tests".

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

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

/// The unit tests of a module live in its own `tests/` folder, one leaf per
/// topic, and the name of the leaf says nothing about what it holds. A leaf
/// may hold helpers of its own, which live in a folder named after it, so
/// every folder above the file counts, not only the one right next to it.
fn in_tests_folder(path: &Path) -> bool {
	path.ancestors()
		.skip(1)
		.filter_map(|dir| dir.file_name())
		.any(|name| name == "tests")
}

/// Full paths of the files the sources declare: a `#[path = "x.rs"]` attribute
/// names `x.rs` next to the declaring file, and `mod name;` names `name.rs` or
/// `name/mod.rs` next to it, or `name.rs` inside the folder of the declaring
/// file's own name. Matching whole paths matters: two modules may each have a
/// test file with the same name, and one declaration must not hide the other.
/// `a/b/../c` as `a/c`, without touching the file system.
fn normalised(path: PathBuf) -> PathBuf {
	let mut out = PathBuf::new();
	for part in path.components() {
		match part {
			Component::ParentDir => {
				out.pop();
			}
			other => out.push(other),
		}
	}
	out
}

fn declared_paths(files: &[PathBuf], sources: &[String]) -> HashSet<PathBuf> {
	let mut paths = HashSet::new();
	for (file, text) in files.iter().zip(sources) {
		let dir = file.parent().unwrap();
		let own_folder = dir.join(file.file_stem().unwrap());
		for line in text.lines() {
			let line = line.trim();
			if let Some(rest) = line.strip_prefix("#[path")
				&& let Some(start) = rest.find('"')
				&& let Some(end) = rest[start + 1..].find('"')
			{
				paths.insert(normalised(dir.join(&rest[start + 1..start + 1 + end])));
			}
			let line = line
				.strip_prefix("pub(crate) ")
				.or_else(|| line.strip_prefix("pub(super) "))
				.or_else(|| line.strip_prefix("pub "))
				.unwrap_or(line);
			if let Some(name) = line.strip_prefix("mod ").and_then(|r| r.strip_suffix(';')) {
				let name = name.trim();
				// A topic that is a Rust keyword is declared as a raw
				// identifier (`mod r#macro;`) and its leaf is `macro.rs`.
				let name = name.strip_prefix("r#").unwrap_or(name);
				paths.insert(dir.join(format!("{name}.rs")));
				paths.insert(dir.join(name).join("mod.rs"));
				paths.insert(own_folder.join(format!("{name}.rs")));
			}
		}
	}
	paths
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
	let declared = declared_paths(&files, &sources);
	let mut orphans: Vec<String> = files
		.iter()
		.filter_map(|path| {
			let name = path.file_name()?.to_str()?;
			((is_test_file_name(name) || in_tests_folder(path)) && !declared.contains(path))
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
