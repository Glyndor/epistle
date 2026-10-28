//! The credentials of a configuration diff are hidden over the tree of the
//! document, not over its lines: a value written as a multiline string
//! continues on the next lines, and those lines are part of the credential.
//!
//! The redaction is what keeps a dry run from printing a token the
//! operator just typed, so the cases here are the shapes a TOML value can
//! take: a basic string, a multiline basic or literal string, a quoted
//! key, and a `#` that is part of the string and not a comment.

use super::diff::unified;
use std::path::Path;

/// The diff of a configuration change, with the credentials hidden.
fn diff(old: &str, new: &str) -> String {
	unified(Path::new("mail.toml"), old, new)
}

/// A credential on one line is hidden, and the line still shows the change.
#[test]
fn a_secret_on_one_line_is_hidden() {
	let output = diff(
		"password = \"synthetic-old\"\n",
		"password = \"synthetic-new\"\n",
	);
	assert!(output.contains("-password = <redacted>"), "{output}");
	assert!(output.contains("+password = <redacted>"), "{output}");
	assert!(!output.contains("synthetic-old"), "{output}");
	assert!(!output.contains("synthetic-new"), "{output}");
}

/// A value that continues on the next lines is a credential on all of them:
/// hiding the first line and printing the rest prints the secret.
#[test]
fn a_multiline_basic_string_secret_is_hidden_whole() {
	let output = diff(
		"token = \"\"\"\nsynthetic-old-token\"\"\"\n",
		"token = \"\"\"\nsynthetic-new-token\"\"\"\n",
	);
	assert!(output.contains("token = <redacted>"), "{output}");
	assert!(!output.contains("synthetic-old-token"), "{output}");
	assert!(!output.contains("synthetic-new-token"), "{output}");
}

/// The literal string has the same shape as the basic one.
#[test]
fn a_multiline_literal_string_secret_is_hidden_whole() {
	let output = diff(
		"token = '''\nsynthetic-old-token'''\n",
		"token = '''\nsynthetic-new-token'''\n",
	);
	assert!(!output.contains("synthetic-old-token"), "{output}");
	assert!(!output.contains("synthetic-new-token"), "{output}");
}

/// A key between quotes is the same key: the value behind it is a
/// credential.
#[test]
fn a_quoted_key_secret_is_hidden() {
	let output = diff(
		"\"token\" = \"synthetic-old\"\n",
		"\"token\" = \"synthetic-new\"\n",
	);
	assert!(!output.contains("synthetic-old"), "{output}");
	assert!(!output.contains("synthetic-new"), "{output}");
}

/// A `#` inside a string is part of the value, not the start of a comment:
/// the whole value goes, and what follows the `#` with it.
#[test]
fn a_comment_inside_a_string_is_hidden_with_the_value() {
	let output = diff(
		"token = \"synthetic-old # not-a-comment\"\n",
		"token = \"synthetic-new # not-a-comment\"\n",
	);
	assert!(!output.contains("synthetic-old"), "{output}");
	assert!(!output.contains("not-a-comment"), "{output}");
	assert!(!output.contains("synthetic-new"), "{output}");
}

/// A credential inside an inline table is a credential: the key is nested,
/// but the value is the same one the server reads.
#[test]
fn a_secret_inside_an_inline_table_is_hidden() {
	let output = diff(
		"auth = { password = \"synthetic-old\" }\n",
		"auth = { password = \"synthetic-new\" }\n",
	);
	assert!(!output.contains("synthetic-old"), "{output}");
	assert!(!output.contains("synthetic-new"), "{output}");
}

/// The same for a credential inside an array of tables.
#[test]
fn a_secret_inside_an_array_of_tables_is_hidden() {
	let output = diff(
		"[[servers]]\nhost = \"a\"\npassword = \"synthetic-old\"\n",
		"[[servers]]\nhost = \"a\"\npassword = \"synthetic-new\"\n",
	);
	assert!(!output.contains("synthetic-old"), "{output}");
	assert!(!output.contains("synthetic-new"), "{output}");
}

/// A url is not a credential by itself: only its password is, and the user
/// and the host stay visible.
#[test]
fn a_url_keeps_its_user_and_its_host() {
	let output = diff(
		"url = \"postgres://epistle:synthetic-old@localhost/epistle\"\n",
		"url = \"postgres://epistle:synthetic-new@localhost/epistle\"\n",
	);
	assert!(!output.contains("synthetic-old"), "{output}");
	assert!(!output.contains("synthetic-new"), "{output}");
	assert!(output.contains("epistle:"), "{output}");
	assert!(output.contains("@localhost/epistle"), "{output}");
}

/// A url is only a url when it is a string. A key called `url` that holds
/// a table is walked like any other key, so the credential inside it goes.
#[test]
fn a_credential_under_a_url_key_is_hidden() {
	let output = diff(
		"url = { password = \"synthetic-old\" }\n",
		"url = { password = \"synthetic-new\" }\n",
	);
	assert!(!output.contains("synthetic-old"), "{output}");
	assert!(!output.contains("synthetic-new"), "{output}");
}

/// A url without credentials is not hidden: it is not a secret.
#[test]
fn a_url_without_credentials_is_printed() {
	let output = diff(
		"url = \"postgres://epistle@localhost/epistle\"\n",
		"url = \"postgres://epistle@localhost/epistle?sslmode=require\"\n",
	);
	assert!(
		output.contains("postgres://epistle@localhost/epistle"),
		"{output}"
	);
}

/// A value that is not a credential is printed as it is: the diff has to
/// say what changes.
#[test]
fn a_value_that_is_not_a_secret_is_printed() {
	let output = diff(
		"hostname = \"mail.example.org\"\n",
		"hostname = \"mail.example.net\"\n",
	);
	assert!(
		output.contains("-hostname = \"mail.example.org\""),
		"{output}"
	);
	assert!(
		output.contains("+hostname = \"mail.example.net\""),
		"{output}"
	);
}

/// A document that does not parse cannot be walked, and a line that cannot
/// be read may be a credential: every line goes.
#[test]
fn a_document_that_does_not_parse_hides_every_line() {
	let output = diff("this is not toml\n", "this is not toml either\n");
	assert!(!output.contains("this is not toml"), "{output}");
}
