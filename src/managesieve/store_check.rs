//! The checks a Sieve script passes before it is stored or reported valid,
//! the same for ManageSieve and JMAP.
//!
//! A reason handed back to a client says where the script went wrong and
//! what kind of mistake it is, in words of ours. It never repeats the
//! script's own text: a token can be a string a megabyte long, and what the
//! client sent is already on the client's side.

use super::store::{MAX_SCRIPT_BYTES, StoreError};
use crate::sieve::ast::{Argument, Command};
use crate::sieve::lexer::{self, LexError};
use crate::sieve::parser::{self, ParseError};

/// Check `script`: size, grammar, the extensions it requires, and the
/// `mailbox` extension's own rule.
pub(super) fn check(script: &str) -> Result<(), StoreError> {
	if script.len() > MAX_SCRIPT_BYTES {
		return Err(StoreError::TooLarge);
	}
	let located = lexer::tokenize_located(script)
		.map_err(|(error, at)| invalid(script, at, lex_reason(&error)))?;
	let commands = parser::parse_located(&located.tokens).map_err(|(error, index)| {
		let at = located.starts.get(index).copied().unwrap_or(0);
		invalid(script, at, parse_reason(&error))
	})?;
	if let Some(problem) = crate::sieve::analysis::pattern_problem(&commands) {
		return Err(StoreError::InvalidScript(problem));
	}
	enforce_known_extensions(&commands)?;
	enforce_mailbox_require(&commands)
}

fn invalid(script: &str, at: usize, reason: String) -> StoreError {
	let line = lexer::line_of(script, at);
	StoreError::InvalidScript(format!("line {line}: {reason}"))
}

fn lex_reason(error: &LexError) -> String {
	match error {
		LexError::Unterminated => "unterminated string, text block or comment",
		LexError::BadNumber => "invalid number",
		LexError::Unexpected(_) => "unexpected character",
	}
	.to_string()
}

fn parse_reason(error: &ParseError) -> String {
	match error {
		ParseError::UnexpectedEof => "unexpected end of script".to_string(),
		ParseError::Unexpected(_) => "unexpected token".to_string(),
		ParseError::Expected(what) => format!("expected {what}"),
		ParseError::NestingDepth { max, .. } => {
			format!("nested more than {max} levels deep")
		}
	}
}

/// Reject a `require` of an extension the interpreter does not run
/// (RFC 5804 section 2.6: PUTSCRIPT and CHECKSCRIPT refuse such a script;
/// RFC 9661 section 2.2 says the same for JMAP). Looks at every `require`,
/// at any depth, with a stack of its own.
fn enforce_known_extensions(commands: &[Command]) -> Result<(), StoreError> {
	let mut pending: Vec<&[Command]> = vec![commands];
	while let Some(level) = pending.pop() {
		for command in level {
			match command {
				Command::Action { name, args } if name == "require" => {
					for extension in args.iter().flat_map(argument_strings) {
						if !crate::sieve::extensions().any(|known| known == extension) {
							return Err(StoreError::InvalidScript(format!(
								"extension \"{}\" is not supported",
								shown(extension)
							)));
						}
					}
				}
				Command::Action { .. } => {}
				Command::If(conditional) => {
					pending.extend(conditional.branches.iter().map(|b| b.body.as_slice()));
					pending.extend(conditional.otherwise.as_deref());
				}
			}
		}
	}
	Ok(())
}

fn argument_strings(argument: &Argument) -> Vec<&str> {
	match argument {
		Argument::Str(name) => vec![name.as_str()],
		Argument::StrList(list) => list.iter().map(String::as_str).collect(),
		_ => Vec::new(),
	}
}

/// An extension name as it may appear in a reason: at most 40 characters,
/// each one printable.
fn shown(name: &str) -> String {
	const MAX_SHOWN: usize = 40;
	let mut text: String = name
		.chars()
		.take(MAX_SHOWN)
		.map(|c| if c.is_control() { '?' } else { c })
		.collect();
	if name.chars().count() > MAX_SHOWN {
		text.push_str("...");
	}
	text
}

/// Walk a parsed script and reject it if it uses a feature of the
/// `mailbox` extension (RFC 5490) without first declaring it. The
/// `mailboxexists` test and the `:create` tag of `fileinto` only exist
/// when the extension is required, so a script that names them without
/// `require "mailbox"` cannot run anywhere it is uploaded; refusing it
/// here keeps the on-disk filter honest.
pub(super) fn enforce_mailbox_require(
	commands: &[crate::sieve::ast::Command],
) -> Result<(), StoreError> {
	if !uses_mailbox_feature(commands) {
		return Ok(());
	}
	if declares_mailbox_require(commands) {
		return Ok(());
	}
	Err(StoreError::InvalidScript(
		"mailboxexists or fileinto :create requires `require \"mailbox\"`".into(),
	))
}

/// Whether the script uses any of the `mailbox` extension's features.
fn uses_mailbox_feature(commands: &[crate::sieve::ast::Command]) -> bool {
	fn in_command(command: &crate::sieve::ast::Command) -> bool {
		match command {
			crate::sieve::ast::Command::Action { name, args } => {
				if name == "fileinto" {
					// `fileinto :create` only exists with the extension.
					if args.iter().any(
						|arg| matches!(arg, crate::sieve::ast::Argument::Tag(t) if t == "create"),
					) {
						return true;
					}
				}
				false
			}
			crate::sieve::ast::Command::If(conditional) => {
				in_test(&conditional.branches[0].test)
					|| conditional.branches.iter().any(|b| in_test(&b.test))
					|| conditional
						.branches
						.iter()
						.any(|b| b.body.iter().any(in_command))
					|| conditional
						.otherwise
						.as_ref()
						.is_some_and(|body| body.iter().any(in_command))
			}
		}
	}
	fn in_test(test: &crate::sieve::ast::Test) -> bool {
		if test.name == "mailboxexists" {
			return true;
		}
		test.children.iter().any(in_test)
	}
	commands.iter().any(in_command)
}

/// Whether the script has a `require "mailbox"` (or a list including
/// `"mailbox"`) anywhere in its top-level commands. Per RFC 5228 §3.3
/// the `require` must precede the first use, but for the validator's
/// purpose the presence anywhere in the script is enough; a client
/// that splits `require` from the action is malformed Sieve anyway.
fn declares_mailbox_require(commands: &[crate::sieve::ast::Command]) -> bool {
	use crate::sieve::ast::{Argument, Command};
	fn arg_names(arg: &Argument) -> Vec<&str> {
		match arg {
			Argument::Str(name) => vec![name.as_str()],
			Argument::StrList(list) => list.iter().map(String::as_str).collect(),
			_ => Vec::new(),
		}
	}
	commands.iter().any(|command| match command {
		Command::Action { name, args } => {
			name == "require" && args.iter().flat_map(arg_names).any(|s| s == "mailbox")
		}
		Command::If(_) => false,
	})
}
