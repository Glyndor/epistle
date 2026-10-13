//! Picking one value from a numbered list on the prompt console.

use super::*;

fn options() -> Vec<String> {
	vec!["alice".to_string(), "bob".to_string()]
}

/// Ask with `typed` as the operator's answers; the pick and what stderr saw.
fn ask(interactive: bool, typed: &str) -> (Option<String>, String, usize) {
	let mut input = std::io::Cursor::new(typed.as_bytes().to_vec());
	let mut err = Vec::new();
	let picked = choose(
		&mut Console {
			interactive,
			tty: None,
			input: &mut input,
			err: &mut err,
		},
		"account",
		&options(),
	);
	let unread = typed.len() - input.position() as usize;
	(picked, String::from_utf8(err).expect("utf-8"), unread)
}

#[test]
fn a_number_picks_its_line() {
	let (picked, err, _) = ask(true, "2\n");
	assert_eq!(picked.as_deref(), Some("bob"));
	assert_eq!(
		err,
		"Pick an account:\n  1) alice\n  2) bob\nNumber (1-2, empty to cancel): "
	);
}

#[test]
fn the_value_itself_is_accepted_too() {
	let (picked, _, _) = ask(true, "alice\n");
	assert_eq!(picked.as_deref(), Some("alice"));
}

#[test]
fn a_wrong_answer_is_asked_again_and_three_give_up() {
	let (picked, err, _) = ask(true, "7\nbob\n");
	assert_eq!(picked.as_deref(), Some("bob"));
	assert!(err.contains("  type a number from 1 to 2\n"), "{err}");
	let (picked, err, unread) = ask(true, "x\ny\nz\n1\n");
	assert_eq!(picked, None);
	assert_eq!(err.matches("type a number").count(), 3, "{err}");
	assert_eq!(unread, 2, "the fourth line is not read");
}

#[test]
fn an_empty_line_or_end_of_input_cancels() {
	assert_eq!(ask(true, "\n").0, None);
	assert_eq!(ask(true, "").0, None);
}

#[test]
fn without_a_terminal_nothing_is_asked_or_read() {
	let (picked, err, unread) = ask(false, "1\n");
	assert_eq!(picked, None);
	assert_eq!(err, "");
	assert_eq!(unread, 2);
}

#[test]
fn nothing_to_pick_from_says_so_and_asks_nothing() {
	let mut input = std::io::Cursor::new(b"1\n".to_vec());
	let mut err = Vec::new();
	let picked = choose(
		&mut Console {
			interactive: true,
			tty: None,
			input: &mut input,
			err: &mut err,
		},
		"alias",
		&[],
	);
	assert_eq!(picked, None);
	assert_eq!(
		String::from_utf8(err).expect("utf-8"),
		"there is no alias to pick from\n"
	);
}
