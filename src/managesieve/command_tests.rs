//! Tests for ManageSieve command parsing.

use super::*;

#[test]
fn parses_simple_commands() {
	assert_eq!(parse("CAPABILITY", None), Ok(Command::Capability));
	assert_eq!(parse("starttls", None), Ok(Command::StartTls));
	assert_eq!(parse("LOGOUT", None), Ok(Command::Logout));
	assert_eq!(parse("LISTSCRIPTS", None), Ok(Command::ListScripts));
	assert_eq!(parse("UNAUTHENTICATE", None), Ok(Command::Unauthenticate));
	assert_eq!(parse("NOOP", None), Ok(Command::Noop(None)));
	assert_eq!(
		parse("NOOP \"tag1\"", None),
		Ok(Command::Noop(Some("tag1".to_string())))
	);
}

#[test]
fn parses_authenticate_with_and_without_initial() {
	assert_eq!(
		parse("AUTHENTICATE \"PLAIN\"", None),
		Ok(Command::Authenticate {
			mechanism: "PLAIN".to_string(),
			initial: None,
		})
	);
	assert_eq!(
		parse("AUTHENTICATE \"PLAIN\" \"dGVzdA==\"", None),
		Ok(Command::Authenticate {
			mechanism: "PLAIN".to_string(),
			initial: Some("dGVzdA==".to_string()),
		})
	);
}

#[test]
fn parses_script_management_commands() {
	assert_eq!(
		parse("SETACTIVE \"work\"", None),
		Ok(Command::SetActive("work".to_string()))
	);
	assert_eq!(
		parse("SETACTIVE \"\"", None),
		Ok(Command::SetActive(String::new()))
	);
	assert_eq!(
		parse("GETSCRIPT \"work\"", None),
		Ok(Command::GetScript("work".to_string()))
	);
	assert_eq!(
		parse("DELETESCRIPT \"old\"", None),
		Ok(Command::DeleteScript("old".to_string()))
	);
	assert_eq!(
		parse("RENAMESCRIPT \"a\" \"b\"", None),
		Ok(Command::RenameScript {
			from: "a".to_string(),
			to: "b".to_string(),
		})
	);
	assert_eq!(
		parse("HAVESPACE \"x\" 1024", None),
		Ok(Command::HaveSpace {
			name: "x".to_string(),
			size: 1024,
		})
	);
}

#[test]
fn putscript_needs_literal_content() {
	assert_eq!(
		parse("PUTSCRIPT \"work\" {7+}", Some(b"keep;\r\n".to_vec())),
		Ok(Command::PutScript {
			name: "work".to_string(),
			content: "keep;\r\n".to_string(),
		})
	);
	assert_eq!(
		parse("PUTSCRIPT \"work\" {7+}", None),
		Err(ParseError::MissingLiteral)
	);
}

#[test]
fn checkscript_carries_literal() {
	assert_eq!(
		parse("CHECKSCRIPT {5+}", Some(b"keep;".to_vec())),
		Ok(Command::CheckScript {
			content: "keep;".to_string(),
		})
	);
}

#[test]
fn unknown_and_bad_arguments() {
	assert_eq!(parse("", None), Err(ParseError::Unknown));
	assert_eq!(parse("FROBNICATE", None), Err(ParseError::Unknown));
	assert_eq!(parse("GETSCRIPT", None), Err(ParseError::BadArguments));
	assert_eq!(
		parse("RENAMESCRIPT \"a\"", None),
		Err(ParseError::BadArguments)
	);
	assert_eq!(
		parse("HAVESPACE \"x\" notanumber", None),
		Err(ParseError::BadArguments)
	);
}

#[test]
fn detects_trailing_literal() {
	assert_eq!(
		trailing_literal("PUTSCRIPT \"x\" {12+}"),
		Some(Literal {
			len: 12,
			synchronizing: false,
		})
	);
	assert_eq!(
		trailing_literal("CHECKSCRIPT {30}"),
		Some(Literal {
			len: 30,
			synchronizing: true,
		})
	);
	assert_eq!(trailing_literal("CAPABILITY"), None);
}

#[test]
fn quoted_strings_handle_escapes() {
	assert_eq!(
		parse("GETSCRIPT \"a\\\"b\"", None),
		Ok(Command::GetScript("a\"b".to_string()))
	);
}
