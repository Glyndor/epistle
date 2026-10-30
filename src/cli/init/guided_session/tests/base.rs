//! Password retry uses injected secret events, never a terminal or a draft.

use super::*;
use crate::cli::prompt::Secret;

#[test]
fn password_retries_policy_and_mismatch_without_echoing_values() {
	let secret = "Zq8!vT3#mL0@pW6$";
	let mut reads = [
		Secret::Read("short".into()),
		Secret::Mismatch,
		Secret::Blank,
		Secret::Read(secret.into()),
	]
	.into_iter();
	let mut out = Vec::new();
	let password = password_with(|| reads.next().unwrap(), &mut out).unwrap();
	assert!(password.expose() == secret);
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("Try again"));
	assert!(text.contains("do not match"));
	assert!(!text.contains("short"));
	assert!(!text.contains(secret));
}

#[test]
fn password_eof_does_not_loop() {
	let result = password_with(|| Secret::Eof, &mut Vec::new());
	assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn final_confirmation_uses_the_injected_policy() {
	let yes = Policy {
		interactive: true,
		colour: false,
		input_tty: false,
	};
	let no = Policy {
		interactive: false,
		colour: false,
		input_tty: false,
	};
	assert!(confirm(&mut &b"yes\n"[..], &mut Vec::new(), yes));
	assert!(!confirm(&mut &b"\n"[..], &mut Vec::new(), yes));
	let mut out = Vec::new();
	assert!(!confirm(&mut &b"yes\n"[..], &mut out, no));
	assert!(out.is_empty());
}
