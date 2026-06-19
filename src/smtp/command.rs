//! SMTP command parsing (RFC 5321 section 4.1).
//!
//! Parsing is strict by design: commands must be ASCII, terminated by CRLF
//! (enforced by the line reader before reaching this parser), and within
//! length limits. Anything questionable is rejected — never guessed at.

/// Maximum command line length, including CRLF (RFC 5321 section 4.5.3.1.4).
pub const MAX_COMMAND_LINE: usize = 512;

/// A parsed SMTP client command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	/// `HELO <domain>`
	Helo { domain: String },
	/// `EHLO <domain>`
	Ehlo { domain: String },
	/// `MAIL FROM:<reverse-path> [parameters]`
	MailFrom {
		reverse_path: String,
		/// `SIZE=` parameter (RFC 1870), declared message size in bytes.
		size: Option<u64>,
		/// `BODY=` parameter (RFC 6152).
		body: Option<Body>,
		/// `REQUIRETLS` parameter (RFC 8689): the sender mandates TLS.
		require_tls: bool,
		/// `RET=` parameter (RFC 3461): how much of the message a DSN returns.
		ret: Option<Ret>,
		/// `ENVID=` parameter (RFC 3461): envelope identifier echoed in DSNs.
		envid: Option<String>,
	},
	/// `RCPT TO:<forward-path> [parameters]`
	RcptTo {
		forward_path: String,
		/// `NOTIFY=` parameter (RFC 3461): when to send a DSN for this recipient.
		notify: Option<Notify>,
		/// `ORCPT=` parameter (RFC 3461): the original recipient address.
		orcpt: Option<String>,
	},
	/// `DATA`
	Data,
	/// `BDAT <size> [LAST]` (RFC 3030 CHUNKING): a length-prefixed chunk of the
	/// message; `LAST` marks the final chunk.
	Bdat { size: usize, last: bool },
	/// `RSET`
	Rset,
	/// `NOOP`
	Noop,
	/// `QUIT`
	Quit,
	/// `VRFY <string>` — always answered with a non-disclosure reply.
	Vrfy,
	/// `STARTTLS`
	StartTls,
	/// `AUTH <mechanism> [initial-response]` (RFC 4954)
	Auth {
		mechanism: String,
		initial: Option<String>,
	},
}

/// `BODY=` parameter values (RFC 6152).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
	SevenBit,
	EightBitMime,
}

/// `RET=` parameter values (RFC 3461): whether a DSN returns the full message
/// or only its headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ret {
	Full,
	Headers,
}

/// `NOTIFY=` parameter (RFC 3461): the events that warrant a DSN. `Never` is
/// mutually exclusive with the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notify {
	/// `NOTIFY=NEVER`: suppress all DSNs for this recipient.
	Never,
	/// A selection of `SUCCESS`/`FAILURE`/`DELAY`.
	On {
		success: bool,
		failure: bool,
		delay: bool,
	},
}

/// Why a command line failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
	/// The line exceeds `MAX_COMMAND_LINE`.
	LineTooLong,
	/// The line contains non-ASCII or control characters.
	InvalidCharacters,
	/// The verb is not recognized.
	UnknownCommand,
	/// The verb is known but its arguments are malformed or missing.
	InvalidArguments,
	/// A syntactically valid ESMTP parameter this server does not implement.
	UnsupportedParameter,
}

/// Parse one command line (without the trailing CRLF).
pub fn parse(line: &str) -> Result<Command, ParseError> {
	if line.len() > MAX_COMMAND_LINE {
		return Err(ParseError::LineTooLong);
	}
	// Control characters are always forbidden (CR/LF/NUL injection); non-ASCII
	// UTF-8 is allowed so SMTPUTF8 (RFC 6531) addresses can be parsed.
	if line.chars().any(char::is_control) {
		return Err(ParseError::InvalidCharacters);
	}

	let (verb, args) = match line.split_once(' ') {
		Some((verb, args)) => (verb, args.trim()),
		None => (line, ""),
	};

	match verb.to_ascii_uppercase().as_str() {
		"HELO" => parse_domain_arg(args).map(|domain| Command::Helo { domain }),
		"EHLO" => parse_domain_arg(args).map(|domain| Command::Ehlo { domain }),
		"MAIL" => {
			let (path, params) = parse_path_arg(args, "FROM:")?;
			let mail = parse_mail_parameters(&params)?;
			Ok(Command::MailFrom {
				reverse_path: path,
				size: mail.size,
				body: mail.body,
				require_tls: mail.require_tls,
				ret: mail.ret,
				envid: mail.envid,
			})
		}
		"RCPT" => {
			let (path, params) = parse_path_arg(args, "TO:")?;
			let (notify, orcpt) = parse_rcpt_parameters(&params)?;
			Ok(Command::RcptTo {
				forward_path: path,
				notify,
				orcpt,
			})
		}
		"DATA" => parse_no_args(args, Command::Data),
		"BDAT" => parse_bdat(args),
		"RSET" => parse_no_args(args, Command::Rset),
		"NOOP" => Ok(Command::Noop),
		"QUIT" => parse_no_args(args, Command::Quit),
		"VRFY" => Ok(Command::Vrfy),
		"STARTTLS" => parse_no_args(args, Command::StartTls),
		"AUTH" => parse_auth(args),
		_ => Err(ParseError::UnknownCommand),
	}
}

/// Parse `BDAT <size> [LAST]` (RFC 3030): a decimal chunk size and an optional
/// case-insensitive `LAST` marker.
fn parse_bdat(args: &str) -> Result<Command, ParseError> {
	let mut parts = args.split_ascii_whitespace();
	let size: usize = parts
		.next()
		.ok_or(ParseError::InvalidArguments)?
		.parse()
		.map_err(|_| ParseError::InvalidArguments)?;
	let last = match parts.next() {
		None => false,
		Some(token) if token.eq_ignore_ascii_case("LAST") => true,
		Some(_) => return Err(ParseError::InvalidArguments),
	};
	if parts.next().is_some() {
		return Err(ParseError::InvalidArguments);
	}
	Ok(Command::Bdat { size, last })
}

/// Parse `AUTH <mechanism> [initial-response]`. An initial response of `=`
/// means an empty response (RFC 4954 section 4).
fn parse_auth(args: &str) -> Result<Command, ParseError> {
	let mut parts = args.split_ascii_whitespace();
	let mechanism = parts.next().ok_or(ParseError::InvalidArguments)?;
	let initial = parts.next();
	if parts.next().is_some() {
		return Err(ParseError::InvalidArguments);
	}
	let valid_mech = mechanism
		.chars()
		.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
	if !valid_mech {
		return Err(ParseError::InvalidArguments);
	}
	Ok(Command::Auth {
		mechanism: mechanism.to_ascii_uppercase(),
		initial: initial.map(|i| {
			if i == "=" {
				String::new()
			} else {
				i.to_string()
			}
		}),
	})
}

fn parse_no_args(args: &str, command: Command) -> Result<Command, ParseError> {
	if args.is_empty() {
		Ok(command)
	} else {
		Err(ParseError::InvalidArguments)
	}
}

fn parse_domain_arg(args: &str) -> Result<String, ParseError> {
	if args.is_empty() || args.contains(' ') {
		return Err(ParseError::InvalidArguments);
	}
	Ok(args.to_string())
}

/// Parse `FROM:<path>` / `TO:<path>` arguments, returning the path and any
/// trailing ESMTP parameter string (RFC 5321 section 4.1.2).
fn parse_path_arg(args: &str, prefix: &str) -> Result<(String, String), ParseError> {
	let rest = args
		.get(..prefix.len())
		.filter(|head| head.eq_ignore_ascii_case(prefix))
		.map(|_| args[prefix.len()..].trim_start())
		.ok_or(ParseError::InvalidArguments)?;

	let after_open = rest.strip_prefix('<').ok_or(ParseError::InvalidArguments)?;
	let (path, after_close) = after_open
		.split_once('>')
		.ok_or(ParseError::InvalidArguments)?;

	if path.contains('<') || path.contains('>') || path.contains(' ') {
		return Err(ParseError::InvalidArguments);
	}
	if !after_close.is_empty() && !after_close.starts_with(' ') {
		return Err(ParseError::InvalidArguments);
	}
	Ok((path.to_string(), after_close.trim().to_string()))
}

/// Parsed MAIL FROM parameters.
#[derive(Default)]
struct MailParams {
	size: Option<u64>,
	body: Option<Body>,
	require_tls: bool,
	ret: Option<Ret>,
	envid: Option<String>,
}

/// Parse MAIL parameters: `SIZE`, `BODY`, `REQUIRETLS`, and the DSN `RET`/
/// `ENVID` (RFC 3461) are implemented; anything else is rejected (555).
fn parse_mail_parameters(params: &str) -> Result<MailParams, ParseError> {
	let mut out = MailParams::default();
	for (keyword, value) in split_parameters(params)? {
		match keyword.to_ascii_uppercase().as_str() {
			"SIZE" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				let parsed: u64 = value.parse().map_err(|_| ParseError::InvalidArguments)?;
				if out.size.replace(parsed).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			"BODY" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				let parsed = match value.to_ascii_uppercase().as_str() {
					"7BIT" => Body::SevenBit,
					"8BITMIME" => Body::EightBitMime,
					_ => return Err(ParseError::InvalidArguments),
				};
				if out.body.replace(parsed).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			"REQUIRETLS" => {
				// RFC 8689: a valueless parameter; a value is a syntax error.
				if value.is_some() || out.require_tls {
					return Err(ParseError::InvalidArguments);
				}
				out.require_tls = true;
			}
			"SMTPUTF8" => {
				// RFC 6531: a valueless parameter declaring an internationalized
				// transaction. UTF-8 addresses are accepted regardless; this just
				// must not be rejected as unknown.
				if value.is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			"RET" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				let parsed = match value.to_ascii_uppercase().as_str() {
					"FULL" => Ret::Full,
					"HDRS" => Ret::Headers,
					_ => return Err(ParseError::InvalidArguments),
				};
				if out.ret.replace(parsed).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			"ENVID" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				if out.envid.replace(value.to_string()).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			_ => return Err(ParseError::UnsupportedParameter),
		}
	}
	Ok(out)
}

/// Parse RCPT parameters: the DSN `NOTIFY`/`ORCPT` (RFC 3461).
fn parse_rcpt_parameters(params: &str) -> Result<(Option<Notify>, Option<String>), ParseError> {
	let mut notify = None;
	let mut orcpt = None;
	for (keyword, value) in split_parameters(params)? {
		match keyword.to_ascii_uppercase().as_str() {
			"NOTIFY" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				if notify.replace(parse_notify(value)?).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			"ORCPT" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				if orcpt.replace(value.to_string()).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			_ => return Err(ParseError::UnsupportedParameter),
		}
	}
	Ok((notify, orcpt))
}

/// `NOTIFY=NEVER` or a comma list of `SUCCESS`/`FAILURE`/`DELAY` (RFC 3461).
fn parse_notify(value: &str) -> Result<Notify, ParseError> {
	let mut success = false;
	let mut failure = false;
	let mut delay = false;
	let mut never = false;
	for token in value.split(',') {
		match token.to_ascii_uppercase().as_str() {
			"NEVER" => never = true,
			"SUCCESS" => success = true,
			"FAILURE" => failure = true,
			"DELAY" => delay = true,
			_ => return Err(ParseError::InvalidArguments),
		}
	}
	// NEVER is mutually exclusive with the others.
	if never {
		if success || failure || delay {
			return Err(ParseError::InvalidArguments);
		}
		return Ok(Notify::Never);
	}
	Ok(Notify::On {
		success,
		failure,
		delay,
	})
}

/// Split ESMTP parameters into `(keyword, optional value)` pairs, validating
/// the keyword charset.
fn split_parameters(params: &str) -> Result<Vec<(&str, Option<&str>)>, ParseError> {
	let mut out = Vec::new();
	for parameter in params.split_ascii_whitespace() {
		let (keyword, value) = match parameter.split_once('=') {
			Some((keyword, value)) => (keyword, Some(value)),
			None => (parameter, None),
		};
		if keyword.is_empty()
			|| !keyword
				.chars()
				.all(|c| c.is_ascii_alphanumeric() || c == '-')
		{
			return Err(ParseError::InvalidArguments);
		}
		out.push((keyword, value));
	}
	Ok(out)
}
