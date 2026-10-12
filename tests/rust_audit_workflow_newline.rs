//! Pin that every file the rust-audit workflow tree produces for the
//! workflow is terminated with a newline.
//!
//! A workflow or script without a trailing newline parses as the last
//! line being unterminated. POSIX text files end in a newline; tools
//! that read them (git diff, actionlint, the Python interpreter) all
//! agree on that and produce slightly different output for a file
//! without one. The reusable-rust-audit.yml in this branch was the
//! first to lose its trailing newline; the others are pinned here so
//! none of them lose it again.
//!
//! The set of files is fixed: the two workflows and the four Python
//! scripts the workflows invoke. A new script that does not appear
//! here cannot satisfy the assertion, which is the point.

use std::fs;
use std::path::Path;

/// Files the rust-audit workflow tree touches directly. A workflow
/// without a trailing newline parses as an unterminated last line, so
/// git diff, actionlint and the Python interpreter all print
/// differently than they would for the same content with a final
/// newline.
const TRAILING_NEWLINE_FILES: &[&str] = &[
	".github/workflows/rust-audit.yml",
	".github/workflows/reusable-rust-audit.yml",
	".github/scripts/rust_audit_report.py",
	".github/scripts/rust_audit_combine.py",
	".github/scripts/test_rust_audit_report.py",
	".github/scripts/test_rust_audit_combine.py",
	".github/scripts/test_rust_audit_lookup.py",
];

#[test]
fn rust_audit_workflow_files_end_with_a_newline() {
	let mut missing: Vec<&str> = Vec::new();
	for rel in TRAILING_NEWLINE_FILES {
		let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
		let text = fs::read(&path).unwrap_or_else(|e| panic!("read {} | {e}", path.display()));
		match text.last() {
			Some(b'\n') => {}
			Some(_) => missing.push(rel),
			None => missing.push(rel),
		}
	}
	assert!(
		missing.is_empty(),
		"the following files do not end with a newline: {:?}.\n\
         POSIX text files end in a newline; tools that read them \
         (git diff, actionlint, the Python interpreter) all agree on \
         that. A workflow or script without a final newline parses as \
         an unterminated last line and produces different output than \
         the same content with one. The reusable-rust-audit.yml in \
         this branch was the first to lose its trailing newline; the \
         others are pinned here so none of them lose it again.",
		missing
	);
}