//! POP3 command parsing (RFC 1939).
//!
//! Strict and ASCII-only, like the SMTP parser: commands are case-insensitive
//! verbs with at most the arguments each defines. Anything malformed is a
//! parse error the session answers with `-ERR`, never a guess.

/// Maximum command line length including CRLF (RFC 1939 §3, generous bound).
pub const MAX_COMMAND_LINE: usize = 512;

/// A parsed POP3 client command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	/// `USER <name>`
	User(String),
	/// `PASS <string>`
	Pass(String),
	/// `STAT`
	Stat,
	/// `LIST [msg]`
	List(Option<u32>),
	/// `RETR <msg>`
	Retr(u32),
	/// `DELE <msg>`
	Dele(u32),
	/// `NOOP`
	Noop,
	/// `RSET`
	Rset,
	/// `QUIT`
	Quit,
	/// `UIDL [msg]`
	Uidl(Option<u32>),
	/// `TOP <msg> <n>`
	Top(u32, u32),
	/// `CAPA`
	Capa,
}

/// Why a command line failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
	/// The line exceeds `MAX_COMMAND_LINE`.
	LineTooLong,
	/// Non-ASCII or control characters in the line.
	InvalidCharacters,
	/// The verb is not recognized.
	UnknownCommand,
	/// The verb is known but its arguments are malformed or missing.
	InvalidArguments,
}

/// Parse one command line (without the trailing CRLF).
pub fn parse(line: &str) -> Result<Command, ParseError> {
	if line.len() > MAX_COMMAND_LINE {
		return Err(ParseError::LineTooLong);
	}
	if line.chars().any(|c| !c.is_ascii() || c.is_ascii_control()) {
		return Err(ParseError::InvalidCharacters);
	}
	let mut parts = line.split(' ').filter(|p| !p.is_empty());
	let verb = parts.next().ok_or(ParseError::UnknownCommand)?;
	let args: Vec<&str> = parts.collect();

	match verb.to_ascii_uppercase().as_str() {
		// USER/PASS take the rest verbatim (passwords may contain spaces).
		"USER" => one_arg(line, "USER").map(Command::User),
		"PASS" => one_arg(line, "PASS").map(Command::Pass),
		"STAT" => no_args(&args, Command::Stat),
		"LIST" => optional_msg(&args).map(Command::List),
		"RETR" => msg(&args).map(Command::Retr),
		"DELE" => msg(&args).map(Command::Dele),
		"NOOP" => no_args(&args, Command::Noop),
		"RSET" => no_args(&args, Command::Rset),
		"QUIT" => no_args(&args, Command::Quit),
		"UIDL" => optional_msg(&args).map(Command::Uidl),
		"TOP" => {
			if args.len() != 2 {
				return Err(ParseError::InvalidArguments);
			}
			let n = args[0].parse().map_err(|_| ParseError::InvalidArguments)?;
			let lines = args[1].parse().map_err(|_| ParseError::InvalidArguments)?;
			Ok(Command::Top(n, lines))
		}
		"CAPA" => no_args(&args, Command::Capa),
		_ => Err(ParseError::UnknownCommand),
	}
}

/// The single argument after `verb ` (preserving spaces), non-empty.
fn one_arg(line: &str, verb: &str) -> Result<String, ParseError> {
	let rest = line[verb.len()..].strip_prefix(' ').unwrap_or("");
	if rest.is_empty() {
		return Err(ParseError::InvalidArguments);
	}
	Ok(rest.to_string())
}

fn no_args(args: &[&str], command: Command) -> Result<Command, ParseError> {
	if args.is_empty() {
		Ok(command)
	} else {
		Err(ParseError::InvalidArguments)
	}
}

fn msg(args: &[&str]) -> Result<u32, ParseError> {
	if args.len() != 1 {
		return Err(ParseError::InvalidArguments);
	}
	args[0].parse().map_err(|_| ParseError::InvalidArguments)
}

fn optional_msg(args: &[&str]) -> Result<Option<u32>, ParseError> {
	match args.len() {
		0 => Ok(None),
		1 => args[0]
			.parse()
			.map(Some)
			.map_err(|_| ParseError::InvalidArguments),
		_ => Err(ParseError::InvalidArguments),
	}
}

#[cfg(test)]
mod tests {
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
}
