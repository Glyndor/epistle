//! The prompt logic driven through a [`Console`] built by the test: the
//! answers come from a `Cursor` and stderr is captured. Reads that turn echo
//! off on a real terminal are in `prompt_tests_tty.rs`.

use std::io::Cursor;
use std::process::ExitCode;

use super::{
	Answer, Console, MISMATCH, Secret, cancelled_message, confirm, confirm_with, parse_yes_no,
	read_secret, refused_message,
};

/// Run `body` with a console over `typed`, returning its result, the
/// captured stderr and how many typed bytes were left unread.
fn with<R>(
	interactive: bool,
	typed: &str,
	body: impl FnOnce(&mut Console<'_>) -> R,
) -> (R, String, usize) {
	let mut input = Cursor::new(typed.as_bytes().to_vec());
	let mut err = Vec::new();
	let result = body(&mut Console {
		interactive,
		tty: None,
		input: &mut input,
		err: &mut err,
	});
	let unread = typed.len() - input.position() as usize;
	(result, String::from_utf8(err).expect("utf-8"), unread)
}

/// `error: <message>\n` as `style::error_to` renders it into a raw buffer.
fn error_line(message: &str) -> String {
	let mut out = Vec::new();
	crate::cli::style::error_to(&mut out, message);
	String::from_utf8(out).expect("utf-8")
}

#[test]
fn parse_yes_no_accepts_only_y_and_yes_and_honours_the_default() {
	for reply in ["y", "Y", "yes", "YES", " yes \n"] {
		assert_eq!(parse_yes_no(reply, true), Answer::Yes, "{reply:?}");
	}
	for reply in ["n", "no", "q", "yess", "ye"] {
		assert_eq!(parse_yes_no(reply, false), Answer::No, "{reply:?}");
	}
	assert_eq!(parse_yes_no(" \n", true), Answer::No);
	assert_eq!(parse_yes_no("\n", false), Answer::Yes);
}

#[test]
fn confirm_asks_on_stderr_and_reads_one_answer() {
	let (answer, err, unread) = with(true, "y\nleft\n", |c| confirm(c, "Drop it? [y/N]", true));
	assert_eq!(answer, Answer::Yes);
	assert_eq!(err, "Drop it? [y/N] ");
	assert_eq!(unread, "left\n".len(), "exactly one line is read");
}

#[test]
fn confirm_treats_end_of_input_as_no_and_ends_the_line() {
	let (answer, err, _) = with(true, "", |c| confirm(c, "Drop it? [y/N]", false));
	assert_eq!(answer, Answer::No, "EOF never counts as consent");
	assert_eq!(err, "Drop it? [y/N] \n");
}

#[test]
fn confirm_without_a_terminal_asks_nothing_and_reads_nothing() {
	let (answer, err, unread) = with(false, "y\n", |c| confirm(c, "Drop it? [y/N]", true));
	assert_eq!(answer, Answer::No);
	assert_eq!(err, "");
	assert_eq!(unread, 2);
}

#[test]
fn confirm_with_refuses_a_piped_run_naming_yes() {
	let (result, err, unread) = with(false, "y\n", |c| {
		confirm_with(c, "queue remove", "Remove? [y/N]", false)
	});
	assert_eq!(result, Err(ExitCode::from(2)));
	assert_eq!(err, error_line(&refused_message("queue remove")));
	assert!(err.contains("--yes"), "the refusal names the flag: {err}");
	assert_eq!(unread, 2, "a piped run never reads an answer");
}

#[test]
fn confirm_with_yes_skips_the_question() {
	let (result, err, unread) = with(false, "n\n", |c| {
		confirm_with(c, "queue remove", "Remove? [y/N]", true)
	});
	assert_eq!(result, Ok(()));
	assert_eq!(err, "");
	assert_eq!(unread, 2);
}

#[test]
fn confirm_with_on_a_terminal_cancels_on_no_and_proceeds_on_yes() {
	let (result, err, _) = with(true, "n\n", |c| {
		confirm_with(c, "queue remove", "Remove? [y/N]", false)
	});
	assert_eq!(result, Err(ExitCode::from(2)));
	assert_eq!(
		err,
		format!(
			"Remove? [y/N] {}",
			error_line(&cancelled_message("queue remove"))
		)
	);
	let (result, err, _) = with(true, "y\n", |c| {
		confirm_with(c, "queue remove", "Remove? [y/N]", false)
	});
	assert_eq!(result, Ok(()));
	assert_eq!(err, "Remove? [y/N] ");
}

#[test]
fn read_secret_piped_reads_one_line_without_a_question() {
	let (secret, err, unread) = with(false, "first value\nsecond\n", |c| {
		read_secret(c, "Password", true)
	});
	assert_eq!(secret, Secret::Read("first value".to_string()));
	assert_eq!(err, "", "nothing is asked without a terminal");
	assert_eq!(unread, "second\n".len(), "a piped run is never asked twice");
}

#[test]
fn read_secret_piped_tells_end_of_input_from_a_blank_line() {
	assert_eq!(
		with(false, "", |c| read_secret(c, "P", false)).0,
		Secret::Eof
	);
	assert_eq!(
		with(false, "\r\n", |c| read_secret(c, "P", false)).0,
		Secret::Blank
	);
}

#[test]
fn read_secret_on_a_terminal_without_echo_control_refuses_to_read() {
	// Interactive but no terminal to silence: reading would echo the secret,
	// so nothing is read at all.
	let (secret, err, unread) = with(true, "visible\n", |c| read_secret(c, "Password", true));
	assert!(matches!(secret, Secret::Failed(_)), "{secret:?}");
	assert_eq!(err, "");
	assert_eq!(unread, "visible\n".len());
}

#[test]
fn mismatch_message_is_the_documented_one() {
	assert_eq!(MISMATCH, "passwords do not match");
}
