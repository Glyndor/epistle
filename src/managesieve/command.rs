//! ManageSieve command parsing (RFC 5804 §2).
//!
//! Commands are single lines of space-separated arguments: a command word
//! followed by quoted strings and numbers. `PUTSCRIPT` and `CHECKSCRIPT` carry
//! the script as a trailing literal (`{n+}`/`{n}`); the network layer reads the
//! literal octets separately and passes them to [`parse`] as `literal`.

/// A parsed ManageSieve command.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
	/// `CAPABILITY`
	Capability,
	/// `STARTTLS`
	StartTls,
	/// `LOGOUT`
	Logout,
	/// `NOOP [tag]`
	Noop(Option<String>),
	/// `AUTHENTICATE "mech" ["initial"]`
	Authenticate {
		mechanism: String,
		initial: Option<String>,
	},
	/// `UNAUTHENTICATE`
	Unauthenticate,
	/// `LISTSCRIPTS`
	ListScripts,
	/// `SETACTIVE "name"` (empty name deactivates all).
	SetActive(String),
	/// `GETSCRIPT "name"`
	GetScript(String),
	/// `DELETESCRIPT "name"`
	DeleteScript(String),
	/// `RENAMESCRIPT "old" "new"`
	RenameScript { from: String, to: String },
	/// `HAVESPACE "name" size`
	HaveSpace { name: String, size: u64 },
	/// `PUTSCRIPT "name" {n+}` plus the literal content.
	PutScript { name: String, content: String },
	/// `CHECKSCRIPT {n+}` plus the literal content.
	CheckScript { content: String },
}

/// A trailing literal an input line announces.
#[derive(Debug, PartialEq, Eq)]
pub struct Literal {
	/// Octet count to read.
	pub len: usize,
	/// `true` for `{n}` (the client waits for a continuation), `false` for the
	/// non-synchronizing `{n+}` form.
	pub synchronizing: bool,
}

/// Why a command line could not be parsed.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
	/// Empty line or unknown command word.
	Unknown,
	/// Argument count or type is wrong for the command.
	BadArguments,
	/// A literal was expected (PUTSCRIPT/CHECKSCRIPT) but none was supplied.
	MissingLiteral,
}

/// If `line` ends with a literal announcement (`{n}` or `{n+}`), return it.
pub fn trailing_literal(line: &str) -> Option<Literal> {
	let line = line.trim_end();
	let inner = line.strip_suffix('}')?;
	let open = inner.rfind('{')?;
	let digits = &inner[open + 1..];
	let (digits, synchronizing) = match digits.strip_suffix('+') {
		Some(rest) => (rest, false),
		None => (digits, true),
	};
	let len = digits.parse::<usize>().ok()?;
	Some(Literal { len, synchronizing })
}

/// Parse a command line. `literal` carries the octets of a trailing literal the
/// caller already read (for `PUTSCRIPT`/`CHECKSCRIPT`).
pub fn parse(line: &str, literal: Option<Vec<u8>>) -> Result<Command, ParseError> {
	let line = strip_literal(line.trim());
	let mut args = tokenize(line).into_iter();
	let word = args.next().ok_or(ParseError::Unknown)?.to_ascii_uppercase();
	let rest: Vec<String> = args.collect();
	let literal_text = || {
		literal
			.as_ref()
			.map(|bytes| String::from_utf8_lossy(bytes).into_owned())
			.ok_or(ParseError::MissingLiteral)
	};
	match word.as_str() {
		"CAPABILITY" => Ok(Command::Capability),
		"STARTTLS" => Ok(Command::StartTls),
		"LOGOUT" => Ok(Command::Logout),
		"UNAUTHENTICATE" => Ok(Command::Unauthenticate),
		"LISTSCRIPTS" => Ok(Command::ListScripts),
		"NOOP" => Ok(Command::Noop(rest.into_iter().next())),
		"AUTHENTICATE" => {
			let mut it = rest.into_iter();
			let mechanism = it.next().ok_or(ParseError::BadArguments)?;
			Ok(Command::Authenticate {
				mechanism,
				initial: it.next(),
			})
		}
		"SETACTIVE" => Ok(Command::SetActive(one(rest)?)),
		"GETSCRIPT" => Ok(Command::GetScript(one(rest)?)),
		"DELETESCRIPT" => Ok(Command::DeleteScript(one(rest)?)),
		"RENAMESCRIPT" => {
			let [from, to] = two(rest)?;
			Ok(Command::RenameScript { from, to })
		}
		"HAVESPACE" => {
			let [name, size] = two(rest)?;
			let size = size.parse::<u64>().map_err(|_| ParseError::BadArguments)?;
			Ok(Command::HaveSpace { name, size })
		}
		"PUTSCRIPT" => Ok(Command::PutScript {
			name: one(rest)?,
			content: literal_text()?,
		}),
		"CHECKSCRIPT" => Ok(Command::CheckScript {
			content: literal_text()?,
		}),
		_ => Err(ParseError::Unknown),
	}
}

/// Remove a trailing `{...}` literal announcement from a line.
fn strip_literal(line: &str) -> &str {
	match line.rfind('{') {
		Some(pos) if line.trim_end().ends_with('}') => line[..pos].trim_end(),
		_ => line,
	}
}

/// Exactly one argument, else `BadArguments`.
fn one(args: Vec<String>) -> Result<String, ParseError> {
	let [arg] = <[String; 1]>::try_from(args).map_err(|_| ParseError::BadArguments)?;
	Ok(arg)
}

/// Exactly two arguments, else `BadArguments`.
fn two(args: Vec<String>) -> Result<[String; 2], ParseError> {
	<[String; 2]>::try_from(args).map_err(|_| ParseError::BadArguments)
}

/// Split a line into atoms and quoted strings. Quoted strings honor `\"` and
/// `\\` escapes; everything else splits on whitespace.
fn tokenize(line: &str) -> Vec<String> {
	let mut tokens = Vec::new();
	let mut chars = line.chars().peekable();
	while let Some(&c) = chars.peek() {
		if c.is_whitespace() {
			chars.next();
		} else if c == '"' {
			chars.next();
			let mut value = String::new();
			while let Some(c) = chars.next() {
				match c {
					'\\' => {
						if let Some(escaped) = chars.next() {
							value.push(escaped);
						}
					}
					'"' => break,
					_ => value.push(c),
				}
			}
			tokens.push(value);
		} else {
			let mut value = String::new();
			while let Some(&c) = chars.peek() {
				if c.is_whitespace() {
					break;
				}
				value.push(c);
				chars.next();
			}
			tokens.push(value);
		}
	}
	tokens
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;
