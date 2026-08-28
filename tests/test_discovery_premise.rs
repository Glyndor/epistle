//! Guard the premise that lets this repository skip a "does CI run every test?"
//! check, rather than the conclusion drawn from it.
//!
//! `apt`, `homebrew-tap` and `scoop-bucket` each carry
//! `tests/ci-runs-every-test.test.sh`, which fails when a test file exists and
//! no workflow invokes it. It exists because a test once lived in `apt/tests/`,
//! passed by hand, and nothing in CI called it. epistle does not carry that
//! guard, and the reason is narrow: every test here is a Rust test, cargo
//! discovers `tests/*.rs` and `#[cfg(test)]` modules on its own, and
//! `cargo test --locked` runs all of them. Nothing can be added to a Rust test
//! target and stay unrun.
//!
//! That reasoning is sound and it is also **conditional**, which is the part
//! worth writing down. podup reached the identical conclusion from the identical
//! premise, and three commits later added `tests/shell/locale-pinned.test.sh` —
//! a test file that runs only if a workflow names it. The premise had an
//! unwritten second half, "and there are no shell tests", and nobody re-read a
//! conclusion to notice it had expired.
//!
//! So this test asserts the premise itself: no file in this repository is a test
//! that runs only when something names it. The day that stops being true, this
//! fails and says what to do about it, instead of a shell test sitting green-by-
//! absence until someone happens to look.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories that never hold source this repository owns. `cargo-home` is
/// where `dpkg-buildpackage` drops the vendored crate registry: `sqlx`, `bytes`
/// and `vcpkg` all ship their own `tests/*.sh`, and a dependency's test scripts
/// say nothing about whether *our* tests are wired into CI. Scanning them made
/// this test fail the Debian build on its first run.
const SKIP_DIRS: &[&str] = &["target", ".git", "vendor", "node_modules", "cargo-home"];

/// Directories that contain test files invoked by a workflow committed to
/// this repository. The absence of a runner does not mean the absence of
/// coverage here: a workflow names each entry's tests by path. Every entry
/// MUST carry the name of the workflow that runs it in the comment, so that
/// deleting the workflow without deleting the exemption surfaces the lie
/// rather than hiding it.
const WORKFLOW_INVOKED_DIRS: &[&str] = &[
	// `.github/workflows/scripts.yml` runs
	// `python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v`
	// on every PR that touches this directory or that workflow. If the
	// workflow is renamed or deleted, delete this line in the same change:
	// the exemption no longer corresponds to anything.
	".github/scripts",
];

/// Extensions whose test files are not discovered by any runner — something has
/// to invoke them by name, which is the condition this test watches for.
const UNDISCOVERED_EXTS: &[&str] = &["sh", "bash", "bats", "py", "ps1", "rb", "pl"];

#[test]
fn no_test_file_here_needs_a_workflow_to_name_it() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let mut found: Vec<String> = Vec::new();
	collect(root, root, &mut found);
	found.sort();

	assert!(
		found.is_empty(),
		"the premise that lets epistle skip a `ci-runs-every-test` guard no longer holds.\n\n\
		 These files look like tests that only run when something names them:\n  {}\n\n\
		 Rust tests are discovered by cargo, so `cargo test --locked` cannot miss one.\n\
		 A shell or Python test has no such runner: it passes by hand and is invisible\n\
		 in CI until a workflow invokes it by path, which is how apt lost one.\n\n\
		 Pick one:\n  \
		 - delete the file, if the check belongs in a Rust test;\n  \
		 - or wire it into a workflow AND port `tests/ci-runs-every-test.test.sh`\n    \
		 from apt, so the next one cannot go unwired either.\n\n\
		 Do not simply delete this test to make the failure go away: it is the only\n\
		 thing standing between this repository and the defect apt already had.",
		found.join("\n  ")
	);
}

/// Walk `dir`, pushing every path that looks like an externally-invoked test.
fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
	let entries = match fs::read_dir(dir) {
		Ok(entries) => entries,
		Err(_) => return,
	};
	for entry in entries.filter_map(Result::ok) {
		let path = entry.path();
		let name = entry.file_name().to_string_lossy().into_owned();
		if path.is_dir() {
			if SKIP_DIRS.contains(&name.as_str())
				|| is_dependency_checkout(&path)
				|| is_workflow_invoked(root, &path)
			{
				continue;
			}
			collect(root, &path, out);
		} else if looks_like_an_invoked_test(&path, &name) {
			let rel: PathBuf = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
			out.push(rel.display().to_string());
		}
	}
}

/// True for a cargo registry checkout wherever it lands. `CARGO_HOME` is not
/// always named `cargo-home`, so the name list alone is not enough; every
/// registry checkout sits under a `registry/src` pair.
fn is_dependency_checkout(path: &Path) -> bool {
	let mut components = path.components().peekable();
	while let Some(component) = components.next() {
		if component.as_os_str() == "registry"
			&& components.peek().is_some_and(|n| n.as_os_str() == "src")
		{
			return true;
		}
	}
	false
}

/// True when `path` is one of `WORKFLOW_INVOKED_DIRS`, matched against the
/// repo-relative path. The list is short on purpose; each entry is a
/// promise that a workflow exists, and the matching is exact so the
/// promise cannot quietly extend to a sibling directory.
fn is_workflow_invoked(root: &Path, path: &Path) -> bool {
	let rel = path.strip_prefix(root).unwrap_or(path);
	WORKFLOW_INVOKED_DIRS
		.iter()
		.any(|exempt| Path::new(exempt) == rel)
}

/// A file counts when its extension has no runner *and* either its name marks it
/// as a test (`*.test.sh`, `test_*.py`, `*_test.sh`) or it sits under a `tests`
/// directory. `.github/scripts/sign.py` is a script, not a test, and does not
/// match — its missing coverage is a separate question.
fn looks_like_an_invoked_test(path: &Path, name: &str) -> bool {
	let ext_matches = path
		.extension()
		.and_then(|e| e.to_str())
		.is_some_and(|e| UNDISCOVERED_EXTS.contains(&e));
	if !ext_matches {
		return false;
	}
	let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
	let named_as_test = stem.ends_with(".test")
		|| stem.ends_with("_test")
		|| stem.ends_with("-test")
		|| stem.starts_with("test_")
		|| stem.starts_with("test-");
	let under_tests_dir = path
		.components()
		.any(|c| c.as_os_str() == "tests" || c.as_os_str() == "test");
	named_as_test || under_tests_dir
}
