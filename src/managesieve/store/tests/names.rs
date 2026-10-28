//! Names that look like another name, the active marker, and what the store
//! says when it leaves something out.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::cli::trace::capture::run_with_capture;

fn store(dir: &std::path::Path) -> ScriptStore {
	ScriptStore::new(dir, "alice")
}

#[test]
fn a_name_that_looks_like_another_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	for name in [
		" x",
		"x ",
		"x\u{a0}",
		"\u{2003}x",
		"x\u{202e}y",
		"x\u{2066}y",
		"x\u{200f}y",
		"x\u{61c}y",
		// "e" and a combining acute accent: the same name as "\u{e9}", not
		// in the normal form (NFC) a client is to send (RFC 5198).
		"caf\u{65}\u{301}",
	] {
		assert_eq!(
			s.put(name, "keep;\r\n"),
			Err(StoreError::InvalidName),
			"{name:?}"
		);
	}
	s.put("caf\u{e9}", "keep;\r\n")
		.expect("the normal form is accepted");
	s.put("a b", "keep;\r\n")
		.expect("a space inside a name is fine");
	s.put("\u{65e5}\u{672c}", "keep;\r\n")
		.expect("so are other scripts");
}

#[test]
fn the_active_marker_is_read_exactly() {
	// A marker naming "x " is not the script "x". It used to be trimmed, so
	// activating a script whose name ended in a space marked its neighbour.
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("x", "keep;\r\n").expect("put");
	std::fs::write(dir.path().join("alice/sieve/.active"), "x ").expect("marker");
	assert_eq!(s.active_name().as_deref(), Some("x "));
	assert!(
		!s.list().expect("list")[0].active,
		"the script x is not the active one"
	);
	assert_eq!(s.delete("x"), Ok(()), "so it may be deleted");
}

#[test]
fn the_lock_file_is_private() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("a", "keep;\r\n").expect("put");
	for file in [".lock", ".index.json", ".active"] {
		let path = dir.path().join("alice/sieve").join(file);
		if path.exists() {
			let mode = std::fs::metadata(&path)
				.expect("metadata")
				.permissions()
				.mode();
			assert_eq!(mode & 0o077, 0, "{file} is {mode:o}");
		}
	}
	s.set_active(Some("a")).expect("activate");
	let mode = std::fs::metadata(dir.path().join("alice/sieve/.active"))
		.expect("metadata")
		.permissions()
		.mode();
	assert_eq!(mode & 0o077, 0, ".active is {mode:o}");
}

#[test]
fn scripts_left_out_of_the_listing_are_logged_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("ok", "keep;\r\n").expect("put");
	std::fs::write(
		dir.path().join("alice/sieve/bad\u{2028}name.sieve"),
		"keep;\r\n",
	)
	.expect("write");
	let events = run_with_capture(|| {
		s.list().expect("list");
		s.list().expect("list");
	});
	let said: Vec<_> = events
		.iter()
		.filter(|e| {
			e.fields
				.get("message")
				.is_some_and(|m| m.contains("not listed"))
		})
		.collect();
	assert_eq!(said.len(), 1, "{events:?}");
	assert_eq!(
		said[0].fields.get("account").map(String::as_str),
		Some("alice")
	);
}

#[test]
fn an_account_over_the_script_limit_is_told_why_it_cannot_add() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let sieve = dir.path().join("alice/sieve");
	std::fs::create_dir_all(&sieve).expect("mkdir");
	for n in 0..MAX_SCRIPTS + 3 {
		std::fs::write(sieve.join(format!("s{n}.sieve")), "keep;\r\n").expect("write");
	}
	let events = run_with_capture(|| {
		s.list().expect("list");
	});
	assert!(
		events.iter().any(|e| e
			.fields
			.get("message")
			.is_some_and(|m| m.contains("more scripts than the limit"))),
		"{events:?}"
	);
	assert_eq!(s.put("new", "keep;\r\n"), Err(StoreError::TooManyScripts));
}
