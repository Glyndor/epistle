//! The pieces of the container replay that decide whether a load counts: the
//! transaction the SQL travels in and the reading of what `psql` printed.

use super::{confirmed_commit, transaction};

#[test]
fn the_transaction_wraps_the_dump_and_does_not_rely_on_psql_dash_one() {
	assert_eq!(
		transaction(b"select 1;"),
		b"BEGIN;\nselect 1;\nCOMMIT;\n".to_vec()
	);
}

#[test]
fn a_dump_without_a_final_newline_still_gets_its_commit_on_a_line_of_its_own() {
	let wrapped = transaction(b"select 1; -- no newline");
	assert!(
		wrapped.ends_with(b"-- no newline\nCOMMIT;\n"),
		"{wrapped:?}"
	);
}

#[test]
fn a_commit_tag_as_the_last_line_is_a_confirmed_commit() {
	assert!(confirmed_commit(b"BEGIN\nINSERT 0 1\nCOMMIT\n"));
	assert!(confirmed_commit(b"COMMIT\r\n\n"));
}

#[test]
fn anything_else_at_the_end_is_not_a_confirmed_commit() {
	assert!(!confirmed_commit(b""));
	assert!(!confirmed_commit(b"BEGIN\nINSERT 0 1\n"));
	assert!(!confirmed_commit(b"COMMIT\nROLLBACK\n"));
	assert!(!confirmed_commit(b"COMMIT ROLLED BACK\n"));
}
