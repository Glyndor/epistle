//! A cache key must not hash with a `**` pattern.
//!
//! `hashFiles('**/Cargo.lock')` walks the whole workspace, `target/` included.
//! At the start of a job that is harmless; after a build it fails with `Fail to
//! hash files under directory`, so a step that saves a cache at the end of the
//! job turns a green build red. The key has to name the files it hashes.
//!
//! The test reads every workflow and composite action and refuses a
//! `hashFiles(` whose first argument starts with `**`.

use std::fs;
use std::path::{Path, PathBuf};

/// Fewer files than this means the walk stopped seeing the workflows, and an
/// empty pass proves nothing.
const MIN_FILES: usize = 10;

fn root() -> &'static Path {
	Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
	let Ok(entries) = fs::read_dir(dir) else {
		return;
	};
	for entry in entries.flatten() {
		let path = entry.path();
		if path.is_dir() {
			yaml_files(&path, out);
		} else if matches!(
			path.extension().and_then(|extension| extension.to_str()),
			Some("yml" | "yaml")
		) {
			out.push(path);
		}
	}
}

#[test]
fn no_hash_files_pattern_starts_with_a_double_star() {
	let mut files = Vec::new();
	yaml_files(&root().join(".github"), &mut files);
	assert!(
		files.len() >= MIN_FILES,
		"only {} workflow files were read",
		files.len()
	);
	let mut offenders = Vec::new();
	for path in &files {
		let text = fs::read_to_string(path).expect("read a workflow");
		for (number, line) in text.lines().enumerate() {
			let mut rest = line;
			while let Some(at) = rest.find("hashFiles(") {
				rest = &rest[at + "hashFiles(".len()..];
				let argument = rest.trim_start_matches(['\'', '"', ' ']);
				if argument.starts_with("**") {
					offenders.push(format!("{}:{}", path.display(), number + 1));
				}
			}
		}
	}
	assert!(
		offenders.is_empty(),
		"hashFiles walks target/ with a ** pattern at: {offenders:?}"
	);
}
