//! What a ManageSieve client is told when a limit is reached.

use super::super::store::{MAX_SCRIPT_BYTES, MAX_SCRIPTS, ScriptStore};
use super::{Backend, Response, Session};
use crate::managesieve::command::Command;

struct Fixed(std::path::PathBuf);

impl Backend for Fixed {
	fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		None
	}
	fn store(&self, account: &str) -> ScriptStore {
		ScriptStore::new(&self.0, account)
	}
}

fn session(dir: &std::path::Path) -> Session<Fixed> {
	let mut session = Session::new(Fixed(dir.to_path_buf()), true);
	session.adopt_account_for_test("alice");
	session
}

fn put(session: &mut Session<Fixed>, name: &str, content: String) -> Response {
	session.handle(Command::PutScript {
		name: name.to_string(),
		content,
	})
}

fn wire(response: &Response) -> String {
	String::from_utf8(response.encode()).expect("utf8")
}

#[test]
fn putscript_over_the_size_limit_answers_quota_maxsize() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut s = session(dir.path());
	let big = format!("keep;\r\n#{}\r\n", "x".repeat(MAX_SCRIPT_BYTES));
	let response = put(&mut s, "big", big);
	assert_eq!(
		wire(&response),
		"NO (QUOTA/MAXSIZE) \"Script is too large.\"\r\n"
	);
}

#[test]
fn putscript_past_the_count_limit_answers_quota_maxscripts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut s = session(dir.path());
	for index in 0..MAX_SCRIPTS {
		assert_eq!(
			put(&mut s, &format!("s{index}"), "keep;\r\n".into()),
			Response::Ok(None)
		);
	}
	let response = put(&mut s, "extra", "keep;\r\n".into());
	assert_eq!(
		wire(&response),
		"NO (QUOTA/MAXSCRIPTS) \"Too many scripts.\"\r\n"
	);
}

#[test]
fn havespace_answers_before_the_script_is_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut s = session(dir.path());
	let ask = |s: &mut Session<Fixed>, name: &str, size: u64| {
		wire(&s.handle(Command::HaveSpace {
			name: name.to_string(),
			size,
		}))
	};
	assert_eq!(ask(&mut s, "a", MAX_SCRIPT_BYTES as u64), "OK\r\n");
	assert_eq!(
		ask(&mut s, "a", MAX_SCRIPT_BYTES as u64 + 1),
		"NO (QUOTA/MAXSIZE) \"Script is too large.\"\r\n"
	);
}

/// A refused name says what a name may be and offers one that works, so the
/// client is not left to guess at the rule, and the numbers it states are the
/// ones the store enforces.
#[test]
fn an_invalid_script_name_is_refused_with_the_rule_and_an_example() {
	use crate::managesieve::store::{MAX_NAME_BYTES, MAX_NAME_CHARS};
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path());
	let too_long = "a".repeat(MAX_NAME_CHARS + 1);
	assert!(
		too_long.len() <= MAX_NAME_BYTES,
		"the bytes cap alone would accept it"
	);
	for name in ["a/b", "..", ".", too_long.as_str()] {
		let Response::No(Some(text)) = put(&mut session, name, "keep;\r\n".to_string()) else {
			panic!("{name:?} must be refused");
		};
		assert!(
			text.contains(&format!("1 to {MAX_NAME_CHARS} characters")),
			"{text}"
		);
		assert!(
			text.contains(&format!("at most {MAX_NAME_BYTES} bytes")),
			"{text}"
		);
		assert!(text.contains("normal form C"), "{text}");
		assert!(text.contains("not . or .."), "{text}");
		assert!(text.contains("no slash"), "{text}");
		assert!(text.contains("for example keep-spam"), "{text}");
	}
}
