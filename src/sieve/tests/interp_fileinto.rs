//! How many copies of one message a script can file.

use super::super::interp::{MAX_FILEINTO, Message, Outcome, evaluate};
use super::super::parser::parse;
use super::lexer::tokenize;

fn run(script: &str) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(&commands, &Message::parse(b"Subject: hi\r\n\r\nx\r\n"))
}

#[test]
fn a_folder_named_over_and_over_is_filed_into_once() {
	// 3000 lines of `fileinto "A";` stored 3001 copies of every message.
	let outcome = run(&"fileinto \"A\";\n".repeat(3000));
	assert_eq!(outcome.fileinto, vec!["A".to_string()]);
	assert!(
		!outcome.keep,
		"filing into a folder still cancels the implicit keep"
	);
}

#[test]
fn a_folder_is_one_folder_however_it_was_spelled_in_the_script() {
	let outcome = run(
		"require [\"variables\", \"copy\"];\nset \"f\" \"A\";\nfileinto \"A\";\nfileinto \"${f}\";\nfileinto :copy \"A\";\n",
	);
	assert_eq!(outcome.fileinto, vec!["A".to_string()]);
}

#[test]
fn a_script_files_into_at_most_the_limit_of_different_folders() {
	let script: String = (0..40).map(|n| format!("fileinto \"f{n}\";\n")).collect();
	let outcome = run(&script);
	let first: Vec<String> = (0..MAX_FILEINTO).map(|n| format!("f{n}")).collect();
	assert_eq!(outcome.fileinto, first);
	assert!(!outcome.aborted);
}

#[test]
fn the_create_flag_of_any_of_the_repeats_is_kept() {
	let outcome =
		run("require [\"fileinto\", \"mailbox\"];\nfileinto \"A\";\nfileinto :create \"A\";\n");
	assert_eq!(outcome.fileinto, vec!["A".to_string()]);
	assert!(outcome.fileinto_creates.contains("A"));
}

#[test]
fn a_copy_of_a_repeated_folder_keeps_the_implicit_keep() {
	let outcome = run("require [\"copy\"];\nfileinto :copy \"A\";\nfileinto :copy \"A\";\n");
	assert_eq!(outcome.fileinto, vec!["A".to_string()]);
	assert!(outcome.keep);
}

#[test]
fn files_beyond_the_limit_are_counted() {
	let mut script = String::from("require \"fileinto\";\n");
	for n in 0..12 {
		script.push_str(&format!("fileinto :copy \"F{n}\";\n"));
	}
	let outcome = run(&script);
	assert_eq!(outcome.fileinto.len(), 8);
	assert_eq!(outcome.fileinto_over_limit, 4);
}
