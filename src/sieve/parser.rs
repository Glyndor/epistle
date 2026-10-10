//! Sieve parser (RFC 5228 §8.2): tokens into an AST.

use super::ast::{Argument, Branch, Command, Conditional, Test};
use super::lexer::Token;

/// Maximum nesting depth of blocks / test lists the parser will accept.
/// RFC 5228 does not set a limit but a malicious or buggy script can
/// otherwise recurse until the Rust stack overflows. 64 is far above
/// any reasonable script and well within the safety budget.
pub const MAX_NESTING_DEPTH: usize = 64;

/// Why a token stream is not a valid script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
	/// Input ended while a construct was still open.
	UnexpectedEof,
	/// A token appeared where the grammar did not allow it.
	Unexpected(Token),
	/// A required token (e.g. `;` or `}`) was missing.
	Expected(&'static str),
	/// A nested construct exceeded `MAX_NESTING_DEPTH`. The script is
	/// not unsafe to load, only to parse; the interpreter is not run.
	NestingDepth {
		/// Depth reached when the parser gave up.
		depth: usize,
		/// Maximum depth the parser allows.
		max: usize,
	},
}

/// Parse a whole script into a command list.
pub fn parse(tokens: &[Token]) -> Result<Vec<Command>, ParseError> {
	let mut parser = Parser {
		tokens,
		pos: 0,
		depth: 0,
	};
	let commands = parser.commands(false)?;
	if parser.pos != tokens.len() {
		return Err(ParseError::Unexpected(parser.tokens[parser.pos].clone()));
	}
	Ok(commands)
}

struct Parser<'a> {
	tokens: &'a [Token],
	pos: usize,
	/// Current nesting depth: incremented when entering a block
	/// (`commands(in_block=true)`) or a test list, decremented when
	/// leaving it.
	depth: usize,
}

impl Parser<'_> {
	fn peek(&self) -> Option<&Token> {
		self.tokens.get(self.pos)
	}

	fn next(&mut self) -> Result<&Token, ParseError> {
		let token = self.tokens.get(self.pos).ok_or(ParseError::UnexpectedEof)?;
		self.pos += 1;
		Ok(token)
	}

	fn eat(&mut self, expected: &Token, what: &'static str) -> Result<(), ParseError> {
		match self.peek() {
			Some(token) if token == expected => {
				self.pos += 1;
				Ok(())
			}
			_ => Err(ParseError::Expected(what)),
		}
	}

	/// Enter a new nesting level (block body or test list). Returns the
/// current depth after the bump so the caller can pass it to the
/// matching `leave`.
fn enter(&mut self) -> Result<usize, ParseError> {
	self.depth += 1;
	if self.depth > MAX_NESTING_DEPTH {
		return Err(ParseError::NestingDepth {
			depth: self.depth,
			max: MAX_NESTING_DEPTH,
		});
	}
	Ok(self.depth)
}

	/// Leave a nesting level. Called from `commands` and `test_list` on
	/// every exit; safe to call even if `enter` failed because the depth
	/// is bumped before the check.
	fn leave(&mut self) {
		self.depth = self.depth.saturating_sub(1);
	}

	/// Commands until end of input, or until `}` when `in_block`.
	fn commands(&mut self, in_block: bool) -> Result<Vec<Command>, ParseError> {
		self.enter()?;
		let mut commands = Vec::new();
		while let Some(token) = self.peek() {
			if in_block && *token == Token::BraceClose {
				break;
			}
			commands.push(self.command()?);
		}
		self.leave();
		Ok(commands)
	}

	fn command(&mut self) -> Result<Command, ParseError> {
		let name = self.identifier()?;
		if name == "if" {
			return Ok(Command::If(self.conditional()?));
		}
		// An action: arguments terminated by a semicolon.
		let args = self.arguments()?;
		self.eat(&Token::Semicolon, "';' after action")?;
		Ok(Command::Action { name, args })
	}

	/// Parse from just after the `if` keyword.
	fn conditional(&mut self) -> Result<Conditional, ParseError> {
		let mut branches = vec![self.branch()?];
		while self.peek() == Some(&Token::Identifier("elsif".into())) {
			self.pos += 1;
			branches.push(self.branch()?);
		}
		let otherwise = if self.peek() == Some(&Token::Identifier("else".into())) {
			self.pos += 1;
			Some(self.block()?)
		} else {
			None
		};
		Ok(Conditional {
			branches,
			otherwise,
		})
	}

	fn branch(&mut self) -> Result<Branch, ParseError> {
		let test = self.test()?;
		let body = self.block()?;
		Ok(Branch { test, body })
	}

	fn block(&mut self) -> Result<Vec<Command>, ParseError> {
		self.eat(&Token::BraceOpen, "'{'")?;
		let body = self.commands(true)?;
		self.eat(&Token::BraceClose, "'}'")?;
		Ok(body)
	}

	fn test(&mut self) -> Result<Test, ParseError> {
		let name = self.identifier()?;
		match name.as_str() {
			"allof" | "anyof" => {
				self.eat(&Token::ParenOpen, "'(' after test list")?;
				let children = self.test_list()?;
				self.eat(&Token::ParenClose, "')' after test list")?;
				Ok(Test {
					name,
					args: Vec::new(),
					children,
				})
			}
			"not" => {
				let inner = self.test()?;
				Ok(Test {
					name,
					args: Vec::new(),
					children: vec![inner],
				})
			}
			_ => {
				let args = self.arguments()?;
				Ok(Test {
					name,
					args,
					children: Vec::new(),
				})
			}
		}
	}

	fn test_list(&mut self) -> Result<Vec<Test>, ParseError> {
		self.enter()?;
		let mut tests = vec![self.test()?];
		while self.peek() == Some(&Token::Comma) {
			self.pos += 1;
			tests.push(self.test()?);
		}
		self.leave();
		Ok(tests)
	}

	/// Collect arguments while the next token can begin one.
	fn arguments(&mut self) -> Result<Vec<Argument>, ParseError> {
		let mut args = Vec::new();
		loop {
			match self.peek() {
				Some(Token::Tag(name)) => {
					args.push(Argument::Tag(name.clone()));
					self.pos += 1;
				}
				Some(Token::Number(value)) => {
					args.push(Argument::Number(*value));
					self.pos += 1;
				}
				Some(Token::QuotedString(value) | Token::MultiLine(value)) => {
					args.push(Argument::Str(value.clone()));
					self.pos += 1;
				}
				Some(Token::BracketOpen) => args.push(self.string_list()?),
				_ => break,
			}
		}
		Ok(args)
	}

	fn string_list(&mut self) -> Result<Argument, ParseError> {
		self.eat(&Token::BracketOpen, "'['")?;
		let mut items = Vec::new();
		loop {
			match self.next()? {
				Token::QuotedString(value) | Token::MultiLine(value) => items.push(value.clone()),
				other => return Err(ParseError::Unexpected(other.clone())),
			}
			match self.next()? {
				Token::Comma => continue,
				Token::BracketClose => break,
				other => return Err(ParseError::Unexpected(other.clone())),
			}
		}
		Ok(Argument::StrList(items))
	}

	fn identifier(&mut self) -> Result<String, ParseError> {
		match self.next()? {
			Token::Identifier(name) => Ok(name.clone()),
			other => Err(ParseError::Unexpected(other.clone())),
		}
	}
}
