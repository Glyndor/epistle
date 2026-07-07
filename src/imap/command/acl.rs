//! Parsing for the RFC 4314 ACL commands (SETACL, DELETEACL, GETACL,
//! LISTRIGHTS, MYRIGHTS). Each argument is an astring.

use super::parse::parse_astring;
use super::{Command, ParseError};

/// Parse one of the ACL commands from its verb and argument tail.
pub(super) fn parse(verb: &str, tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	match verb {
		"GETACL" => Ok(Command::GetAcl {
			mailbox: one(args, &bad)?,
		}),
		"MYRIGHTS" => Ok(Command::MyRights {
			mailbox: one(args, &bad)?,
		}),
		"DELETEACL" => {
			let (mailbox, identifier) = two(args, &bad)?;
			Ok(Command::DeleteAcl {
				mailbox,
				identifier,
			})
		}
		"LISTRIGHTS" => {
			let (mailbox, identifier) = two(args, &bad)?;
			Ok(Command::ListRights {
				mailbox,
				identifier,
			})
		}
		"SETACL" => {
			let (mailbox, rest) = astr(args, &bad)?;
			let (identifier, rest) = astr(&rest, &bad)?;
			let (rights, rest) = astr(&rest, &bad)?;
			if !rest.trim().is_empty() {
				return Err(bad());
			}
			Ok(Command::SetAcl {
				mailbox,
				identifier,
				rights,
			})
		}
		_ => Err(ParseError::Unknown(tag.to_string())),
	}
}

/// Parse exactly one astring argument, rejecting trailing input.
fn one(args: &str, bad: &impl Fn() -> ParseError) -> Result<String, ParseError> {
	let (value, rest) = astr(args, bad)?;
	if !rest.trim().is_empty() {
		return Err(bad());
	}
	Ok(value)
}

/// Parse exactly two astring arguments, rejecting trailing input.
fn two(args: &str, bad: &impl Fn() -> ParseError) -> Result<(String, String), ParseError> {
	let (first, rest) = astr(args, bad)?;
	let (second, rest) = astr(&rest, bad)?;
	if !rest.trim().is_empty() {
		return Err(bad());
	}
	Ok((first, second))
}

/// Parse one non-empty astring, returning it and the remainder.
fn astr(input: &str, bad: &impl Fn() -> ParseError) -> Result<(String, String), ParseError> {
	let (value, rest) = parse_astring(input.trim_start()).ok_or_else(bad)?;
	if value.is_empty() {
		return Err(bad());
	}
	Ok((value, rest.to_string()))
}
