//! The directory handle is swapped in one place and nowhere else.
//!
//! Every change to the store rebuilds the directory and swaps it into the
//! hot handle. The swap is only safe when the build and the swap happen
//! under the same lock, so the swap lives in the one function that holds
//! it. A second `handle.replace(...)` anywhere else would put a directory
//! into the handle without that lock, and the race the store fixed — an
//! account the server just suspended is active again — would be back.
//!
//! The test reads the sources of the store and fails when the swap
//! appears outside `rebuild_directory` or inside a test.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
	for entry in std::fs::read_dir(dir).expect("read_dir").flatten() {
		let path = entry.path();
		if path.is_dir() {
			rust_files(&path, out);
		} else if path.extension().is_some_and(|extension| extension == "rs") {
			out.push(path);
		}
	}
}

/// The text range of `rebuild_directory` in the store's sources: from the
/// function's name to the brace that closes it.
fn rebuild_directory(text: &str) -> Option<(usize, usize)> {
	let start = text.find("fn rebuild_directory")?;
	let end = text[start..].find("\n\t}\n")? + start + "\n\t}\n".len();
	Some((start, end))
}

/// The swap happens under the store's directory lock, and only there.
#[test]
fn the_directory_handle_is_only_swapped_inside_rebuild_directory() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/directory_store");
	let mut files = Vec::new();
	rust_files(&root, &mut files);
	let mut offenders = Vec::new();
	for file in files {
		let text = std::fs::read_to_string(&file).expect("read source");
		// A test may swap the handle to set a directory up.
		let is_test = file.components().any(|part| part.as_os_str() == "tests");
		let allowed = if is_test {
			Some((0, text.len()))
		} else if file.ends_with("rebuild/mod.rs") {
			rebuild_directory(&text)
		} else {
			None
		};
		for (offset, _) in text.match_indices("handle.replace(") {
			let inside = allowed.is_some_and(|(start, end)| offset >= start && offset < end);
			if !inside {
				offenders.push(format!("{}:{}", file.display(), offset));
			}
		}
	}
	assert!(
		offenders.is_empty(),
		"the directory handle is swapped outside `rebuild_directory`: {offenders:?}"
	);
}
