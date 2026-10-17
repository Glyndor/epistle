//! What the shared check accepts, refuses, and says about it.

use super::*;

fn reason(script: &str) -> String {
	match ScriptStore::validate(script) {
		Err(StoreError::InvalidScript(reason)) => reason,
		other => panic!("expected InvalidScript, got {other:?}"),
	}
}

#[test]
fn a_reason_names_the_line_of_a_grammar_error() {
	assert_eq!(
		reason("keep;\r\nkeep;\r\nif if\r\n"),
		"line 3: expected '{'"
	);
	assert_eq!(reason("keep;\n\n@"), "line 3: unexpected character");
	assert_eq!(
		reason("keep;\nkeep \"oops"),
		"line 2: unterminated string, text block or comment"
	);
	assert_eq!(reason("keep"), "line 1: expected ';' after action");
}

#[test]
fn a_reason_never_repeats_the_scripts_own_text() {
	// A string of a few thousand characters where a command should be: the
	// parser stops on it, and the reason must not carry it back.
	let filler = "ATTACKER-TEXT".repeat(400);
	for script in [
		format!("\"{filler}\";"),
		format!("keep; {filler}"),
		format!("if true {{ \"{filler}\" }}"),
	] {
		let reason = reason(&script);
		assert!(
			reason.len() < 120 && !reason.contains("ATTACKER"),
			"the reason echoed the script: {} octets",
			reason.len()
		);
	}
}

#[test]
fn nesting_deeper_than_the_parser_allows_is_a_reason_not_a_crash() {
	let script = format!("if {}true {{ keep; }}", "not ".repeat(10_000));
	assert_eq!(reason(&script), "line 1: nested more than 64 levels deep");
}

#[test]
fn requiring_an_extension_the_interpreter_does_not_run_is_refused() {
	for (script, name) in [
		("require \"regex\";\r\nkeep;", "regex"),
		("require [\"fileinto\", \"enotify\"];\r\nkeep;", "enotify"),
		("require \"imapflags\";\r\nkeep;", "imapflags"),
		("if true { require \"include\"; keep; }", "include"),
	] {
		assert_eq!(
			reason(script),
			format!("extension \"{name}\" is not supported"),
			"{script:?}"
		);
	}
}

#[test]
fn every_advertised_extension_can_be_required() {
	let all = crate::sieve::extensions()
		.map(|name| format!("\"{name}\""))
		.collect::<Vec<_>>()
		.join(", ");
	ScriptStore::validate(&format!("require [{all}];\r\nkeep;\r\n"))
		.expect("a script requiring what we advertise is valid");
}

#[test]
fn an_unsupported_extension_name_is_shown_short_and_printable() {
	let long = format!("x{}", "y".repeat(300));
	let shown = reason(&format!("require \"{long}\";"));
	assert!(shown.len() < 100, "{} octets", shown.len());
	let shown = reason("require \"a\u{1b}[31mb\";");
	assert_eq!(shown, "extension \"a?[31mb\" is not supported");
}
