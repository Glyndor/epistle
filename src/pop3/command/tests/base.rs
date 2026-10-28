use super::*;

#[test]
fn parses_auth_commands_preserving_password_spaces() {
	assert_eq!(parse("USER alice"), Ok(Command::User("alice".into())));
	assert_eq!(parse("user Alice"), Ok(Command::User("Alice".into())));
	assert_eq!(
		parse("PASS hunter two"),
		Ok(Command::Pass("hunter two".into()))
	);
	assert_eq!(parse("USER"), Err(ParseError::InvalidArguments));
}

#[test]
fn parses_message_commands() {
	assert_eq!(parse("STAT"), Ok(Command::Stat));
	assert_eq!(parse("LIST"), Ok(Command::List(None)));
	assert_eq!(parse("LIST 2"), Ok(Command::List(Some(2))));
	assert_eq!(parse("RETR 3"), Ok(Command::Retr(3)));
	assert_eq!(parse("DELE 1"), Ok(Command::Dele(1)));
	assert_eq!(parse("UIDL"), Ok(Command::Uidl(None)));
	assert_eq!(parse("TOP 4 10"), Ok(Command::Top(4, 10)));
	assert_eq!(parse("QUIT"), Ok(Command::Quit));
	assert_eq!(parse("CAPA"), Ok(Command::Capa));
}

#[test]
fn rejects_bad_arguments_and_unknown() {
	assert_eq!(parse("RETR"), Err(ParseError::InvalidArguments));
	assert_eq!(parse("RETR x"), Err(ParseError::InvalidArguments));
	assert_eq!(parse("STAT now"), Err(ParseError::InvalidArguments));
	assert_eq!(parse("TOP 1"), Err(ParseError::InvalidArguments));
	assert_eq!(parse("FROB"), Err(ParseError::UnknownCommand));
}

#[test]
fn rejects_non_ascii_and_overlong() {
	assert_eq!(parse("USER café"), Err(ParseError::InvalidCharacters));
	let long = "X".repeat(MAX_COMMAND_LINE + 1);
	assert_eq!(parse(&long), Err(ParseError::LineTooLong));
}
