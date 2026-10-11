use super::*;
use crate::test_fixtures as fixtures;

fn login(line: &str) -> LoginRequest {
	match parse_line(line) {
		Ok(Line::Login(request)) => request,
		_ => panic!("line must parse as a LOGIN request"),
	}
}

#[test]
fn login_with_quoted_strings_yields_credentials() {
	let request = login(r#"a1 LOGIN "alice" "p@ss w\"ord""#);
	assert_eq!(request.tag, "a1");
	assert!(request.username() == "alice", "username field must match");
	assert!(
		request.password() == "p@ss w\"ord",
		"password field must match"
	);
}

#[test]
fn login_with_atoms_yields_credentials() {
	let request = login(&format!(
		"a1 LOGIN alice@example.org {}",
		fixtures::password()
	));
	assert!(
		request.username() == "alice@example.org",
		"username field must match"
	);
	assert!(
		request.password() == fixtures::password(),
		"password field must match"
	);
}

#[test]
fn login_with_missing_or_extra_arguments_is_bad_arguments() {
	for line in [
		"a1 LOGIN onlyuser",
		"a1 LOGIN",
		r#"a1 LOGIN "" pw"#,
		r#"a1 LOGIN user """#,
		"a1 LOGIN user pw extra",
	] {
		assert_eq!(
			parse_line(line).err(),
			Some(ParseError::BadArguments("a1".to_string())),
			"LOGIN with unusable arguments must be BAD"
		);
	}
}

#[test]
fn debug_of_login_request_shows_neither_user_nor_password() {
	let line = format!("a1 LOGIN carol-login {}", fixtures::password());
	let shown = format!("{:?}", parse_line(&line).expect("parses"));
	assert!(
		!shown.contains(fixtures::password()),
		"Debug must not contain the password"
	);
	assert!(
		!shown.contains("carol-login"),
		"Debug must not contain the user name"
	);
	assert!(
		shown.contains("<redacted>"),
		"Debug must mark the redaction"
	);
}

#[test]
fn debug_of_authenticate_initial_response_hides_it() {
	let shown = format!(
		"{:?}",
		parse_line("a1 authenticate plain AGNhcm9sAGh1bnRlcjI=").expect("parses")
	);
	assert!(
		!shown.contains("AGNhcm9sAGh1bnRlcjI="),
		"Debug must not contain the initial response"
	);
	assert!(shown.contains("PLAIN"), "the mechanism stays visible");
}

#[test]
fn authenticate_parses_mechanism_and_optional_initial_response() {
	let Ok(Line::Authenticate(with)) = parse_line("a1 AUTHENTICATE plain QUJD") else {
		panic!("must parse as AUTHENTICATE");
	};
	assert_eq!(with.mechanism, "PLAIN");
	assert_eq!(with.initial.as_ref().map(Secret::expose), Some("QUJD"));
	let Ok(Line::Authenticate(without)) = parse_line("a2 AUTHENTICATE LOGIN") else {
		panic!("must parse as AUTHENTICATE");
	};
	assert!(without.initial.is_none(), "no initial response given");
	assert_eq!(
		parse_line("a3 AUTHENTICATE").err(),
		Some(ParseError::BadArguments("a3".to_string()))
	);
}

#[test]
fn the_general_command_parser_does_not_know_credential_verbs() {
	for line in ["a1 LOGIN alice pw", "a2 AUTHENTICATE PLAIN QUJD"] {
		assert!(
			matches!(parse(line), Err(ParseError::Unknown(_))),
			"a Command must never be able to carry credentials"
		);
	}
}

#[test]
fn other_lines_still_become_commands() {
	let Ok(Line::Command(tagged)) = parse_line("a1 NOOP") else {
		panic!("NOOP must parse as a command");
	};
	assert_eq!(tagged.command, super::super::Command::Noop);
	assert_eq!(
		parse_line("nospace").err(),
		Some(ParseError::Malformed),
		"malformed lines keep their error"
	);
}
