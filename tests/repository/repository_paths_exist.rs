//! Every path this repository cites must exist in the tree.
//!
//! The documentation, the comments and the tests point at files by path, and
//! nothing ties that text to the file: move the file and the citation keeps
//! pointing at nothing, with every other check green. When this test was
//! written, nineteen citations in the tree were already broken that way.
//!
//! It reads every citation of a path under `src/`, `tests/` or `docs/` and
//! fails naming the file, the line and the path of each one that does not
//! resolve. The sources it reads:
//!
//! - `README.md`, `CONTRIBUTING.md` and every `.md` under `docs/`, by line;
//! - the comments of every `.rs` under `src/`;
//! - the comments and the string literals of every `.rs` under `tests/`.
//!
//! String literals under `src/` are left out on purpose. The ones that name a
//! path are `include_str!` arguments, which the compiler already resolves, or
//! inputs a unit test feeds to the code under test, which are not citations.
//!
//! What it accepts:
//!
//! - `src/imap/snapshot.rs::store_flags` and `src/cli/dispatch/mod.rs:132`: only
//!   the path before the colon is checked, not the symbol or the line.
//! - Globs (`src/imap/**`, `tests/database*.rs`, `src/{imap,pop3}/`): each
//!   must match at least one file, so a glob whose files all moved fails the
//!   same way a plain path does.
//! - A path that starts with `../` resolves from the citing file, the way a
//!   Markdown link does. Every other path is read from the repository root.
//!
//! What it skips, and why:
//!
//! - A path glued to a longer one (`crates/common/src/...`,
//!   `apt/tests/...`, a URL). It belongs to another repository or crate, and
//!   that prefix is how a comment cites a file outside this tree.
//! - A path that runs into a placeholder (`src/<domain>/`, `src/{name}.rs`).
//!   It describes a shape, not a file.
//! - A Markdown block fenced with an info string that holds the word
//!   `example` (```` ```text example ````). It shows a layout the tree has
//!   not reached yet, and the prose around it has to say so.
//! - `tests/repository/repository_paths/mod_tests.rs`, whose fixtures cite missing
//!   paths on purpose to prove the scanner reports them.

mod repository_paths;

use std::fs;
use std::path::Path;

use repository_paths::{cited_paths, markdown, problem, rust_source};

/// The scanner's own fixtures, the one file under `tests/` this test skips.
const FIXTURES: &str = "tests/repository/repository_paths/mod_tests.rs";

#[test]
fn every_cited_path_exists() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	assert!(
		root.join(FIXTURES).is_file(),
		"{FIXTURES} is skipped by name and is no longer there; drop or fix the skip"
	);
	let tree: Vec<String> = ["src", "tests", "docs"]
		.iter()
		.flat_map(|dir| files_under(root, dir))
		.collect();

	let mut broken = Vec::new();
	let mut read_from = [("docs", 0usize), ("src", 0), ("tests", 0)];
	for (rel, strings) in sources(root) {
		let text =
			fs::read_to_string(root.join(&rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
		let segments = match strings {
			None => markdown::lines(&text),
			Some(strings) => rust_source::segments(&text, strings),
		};
		for (line, cited) in cited_paths(&segments) {
			if let Some(count) = read_from
				.iter_mut()
				.find(|(dir, _)| rel.starts_with(&format!("{dir}/")))
			{
				count.1 += 1;
			}
			if let Some(problem) = problem(&rel, &cited, &tree, root) {
				broken.push(format!("{rel}:{line}: {cited} {problem}"));
			}
		}
	}

	for (dir, count) in read_from {
		assert!(
			count > 0,
			"read no citation at all under {dir}/. Either the walk is broken or nothing \
			 there cites a path any more; in both cases this test has stopped checking it"
		);
	}
	assert!(
		broken.is_empty(),
		"{} cited path(s) do not resolve in this tree:\n  {}\n\n\
		 Point each one at the file that holds the code today. When the path is an \
		 illustration and not a citation, write it with a placeholder (`src/<module>.rs`) \
		 or move it into a Markdown block fenced with ```text example. A path in another \
		 repository or crate carries that project's name in front (`apt/tests/...`).",
		broken.len(),
		broken.join("\n  ")
	);
}

/// Every file this test reads, with how to read it: `None` for Markdown,
/// `Some(strings)` for Rust, where `strings` says whether string literals
/// count as citations as well as comments.
fn sources(root: &Path) -> Vec<(String, Option<bool>)> {
	let mut out = vec![
		("README.md".to_string(), None),
		("CONTRIBUTING.md".to_string(), None),
	];
	out.extend(
		files_under(root, "docs")
			.into_iter()
			.filter(|f| f.ends_with(".md"))
			.map(|f| (f, None)),
	);
	out.extend(
		files_under(root, "src")
			.into_iter()
			.filter(|f| f.ends_with(".rs"))
			.map(|f| (f, Some(false))),
	);
	out.extend(
		files_under(root, "tests")
			.into_iter()
			.filter(|f| f.ends_with(".rs") && f != FIXTURES)
			.map(|f| (f, Some(true))),
	);
	out
}

/// Every file under `dir`, as a path relative to `root` with `/` separators.
/// A directory that cannot be read is a failure, never a skip: a walk that
/// quietly reads less would report success over a smaller tree.
fn files_under(root: &Path, dir: &str) -> Vec<String> {
	let mut out = Vec::new();
	let entries = fs::read_dir(root.join(dir)).unwrap_or_else(|e| panic!("read {dir}/: {e}"));
	for entry in entries {
		let entry = entry.unwrap_or_else(|e| panic!("read {dir}/: {e}"));
		let rel = format!("{dir}/{}", entry.file_name().to_string_lossy());
		if entry.path().is_dir() {
			out.extend(files_under(root, &rel));
		} else {
			out.push(rel);
		}
	}
	out.sort();
	out
}
