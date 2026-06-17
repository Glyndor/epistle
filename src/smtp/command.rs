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
	if line.chars().any(|c| !c.is_ascii() || c.is_ascii_control()) {
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
		"RSET" => parse_no_args(args, Command::Rset),
		"NOOP" => Ok(Command::Noop),
		"QUIT" => parse_no_args(args, Command::Quit),
		"VRFY" => Ok(Command::Vrfy),
		"STARTTLS" => parse_no_args(args, Command::StartTls),
		"AUTH" => parse_auth(args),
		_ => Err(ParseError::UnknownCommand),
	}
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_helo_and_ehlo() {
		assert_eq!(
			parse("HELO client.example.org"),
			Ok(Command::Helo {
				domain: "client.example.org".into()
			})
		);
		assert_eq!(
			parse("ehlo client.example.org"),
			Ok(Command::Ehlo {
				domain: "client.example.org".into()
			})
		);
	}

	#[test]
	fn rejects_helo_without_domain() {
		assert_eq!(parse("HELO"), Err(ParseError::InvalidArguments));
		assert_eq!(parse("HELO "), Err(ParseError::InvalidArguments));
	}

	#[test]
	fn parses_mail_from() {
		assert_eq!(
			parse("MAIL FROM:<alice@example.org>"),
			Ok(Command::MailFrom {
				reverse_path: "alice@example.org".into(),
				size: None,
				body: None,
				require_tls: false,
				ret: None,
				envid: None,
			})
		);
	}

	#[test]
	fn parses_null_reverse_path() {
		assert_eq!(
			parse("MAIL FROM:<>"),
			Ok(Command::MailFrom {
				reverse_path: String::new(),
				size: None,
				body: None,
				require_tls: false,
				ret: None,
				envid: None,
			})
		);
	}

	#[test]
	fn parses_size_and_body_parameters() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE=1000 BODY=8BITMIME"),
			Ok(Command::MailFrom {
				reverse_path: "a@example.org".into(),
				size: Some(1000),
				body: Some(Body::EightBitMime),
				require_tls: false,
				ret: None,
				envid: None,
			})
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> body=7bit"),
			Ok(Command::MailFrom {
				reverse_path: "a@example.org".into(),
				size: None,
				body: Some(Body::SevenBit),
				require_tls: false,
				ret: None,
				envid: None,
			})
		);
	}

	#[test]
	fn parses_requiretls_parameter() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> REQUIRETLS"),
			Ok(Command::MailFrom {
				reverse_path: "a@example.org".into(),
				size: None,
				body: None,
				require_tls: true,
				ret: None,
				envid: None,
			})
		);
		// A value on the valueless parameter is a syntax error.
		assert_eq!(
			parse("MAIL FROM:<a@example.org> REQUIRETLS=1"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_malformed_parameters() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE=abc"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> BODY=BINARYMIME"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE=1 SIZE=2"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> =5"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_unsupported_parameters() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> AUTH=<>"),
			Err(ParseError::UnsupportedParameter)
		);
		assert_eq!(
			parse("RCPT TO:<b@example.org> FUTURE=1"),
			Err(ParseError::UnsupportedParameter)
		);
	}

	#[test]
	fn parses_rcpt_to_case_insensitively() {
		assert_eq!(
			parse("rcpt to:<bob@example.org>"),
			Ok(Command::RcptTo {
				forward_path: "bob@example.org".into(),
				notify: None,
				orcpt: None,
			})
		);
	}

	#[test]
	fn parses_dsn_mail_parameters() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> RET=HDRS ENVID=abc123"),
			Ok(Command::MailFrom {
				reverse_path: "a@example.org".into(),
				size: None,
				body: None,
				require_tls: false,
				ret: Some(Ret::Headers),
				envid: Some("abc123".into()),
			})
		);
	}

	#[test]
	fn parses_dsn_rcpt_parameters() {
		assert_eq!(
			parse("RCPT TO:<b@example.org> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;b@example.org"),
			Ok(Command::RcptTo {
				forward_path: "b@example.org".into(),
				notify: Some(Notify::On {
					success: true,
					failure: true,
					delay: false,
				}),
				orcpt: Some("rfc822;b@example.org".into()),
			})
		);
	}

	#[test]
	fn parses_notify_never() {
		let Ok(Command::RcptTo { notify, .. }) = parse("RCPT TO:<b@example.org> NOTIFY=NEVER")
		else {
			panic!("expected RcptTo");
		};
		assert_eq!(notify, Some(Notify::Never));
	}

	#[test]
	fn rejects_invalid_dsn_parameters() {
		// NEVER is mutually exclusive with other events.
		assert_eq!(
			parse("RCPT TO:<b@example.org> NOTIFY=NEVER,SUCCESS"),
			Err(ParseError::InvalidArguments)
		);
		// Unknown NOTIFY event.
		assert_eq!(
			parse("RCPT TO:<b@example.org> NOTIFY=MAYBE"),
			Err(ParseError::InvalidArguments)
		);
		// Unknown RET value.
		assert_eq!(
			parse("MAIL FROM:<a@example.org> RET=SOME"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_paths_without_angle_brackets() {
		assert_eq!(
			parse("MAIL FROM:alice@example.org"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_nested_angle_brackets() {
		assert_eq!(
			parse("MAIL FROM:<<alice@example.org>>"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_garbage_after_path() {
		assert_eq!(
			parse("MAIL FROM:<alice@example.org>junk"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn parses_bare_commands() {
		assert_eq!(parse("DATA"), Ok(Command::Data));
		assert_eq!(parse("RSET"), Ok(Command::Rset));
		assert_eq!(parse("QUIT"), Ok(Command::Quit));
		assert_eq!(parse("NOOP"), Ok(Command::Noop));
		assert_eq!(parse("STARTTLS"), Ok(Command::StartTls));
	}

	#[test]
	fn rejects_arguments_on_bare_commands() {
		assert_eq!(parse("DATA now"), Err(ParseError::InvalidArguments));
		assert_eq!(parse("QUIT bye"), Err(ParseError::InvalidArguments));
		assert_eq!(parse("STARTTLS x"), Err(ParseError::InvalidArguments));
	}

	#[test]
	fn vrfy_parses_regardless_of_argument() {
		assert_eq!(parse("VRFY alice"), Ok(Command::Vrfy));
		assert_eq!(parse("VRFY"), Ok(Command::Vrfy));
	}

	#[test]
	fn parses_auth_with_and_without_initial_response() {
		assert_eq!(
			parse("AUTH PLAIN dGVzdA=="),
			Ok(Command::Auth {
				mechanism: "PLAIN".into(),
				initial: Some("dGVzdA==".into())
			})
		);
		assert_eq!(
			parse("auth plain"),
			Ok(Command::Auth {
				mechanism: "PLAIN".into(),
				initial: None
			})
		);
		assert_eq!(
			parse("AUTH PLAIN ="),
			Ok(Command::Auth {
				mechanism: "PLAIN".into(),
				initial: Some(String::new())
			})
		);
	}

	#[test]
	fn rejects_malformed_auth() {
		assert_eq!(parse("AUTH"), Err(ParseError::InvalidArguments));
		assert_eq!(parse("AUTH PLAIN a b"), Err(ParseError::InvalidArguments));
		assert_eq!(
			parse("AUTH PL@IN dGVzdA=="),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_unknown_verbs() {
		assert_eq!(parse("EXPN list"), Err(ParseError::UnknownCommand));
		assert_eq!(parse(""), Err(ParseError::UnknownCommand));
	}

	#[test]
	fn rejects_control_characters() {
		assert_eq!(parse("NOOP\r"), Err(ParseError::InvalidCharacters));
		assert_eq!(parse("NO\0OP"), Err(ParseError::InvalidCharacters));
	}

	#[test]
	fn rejects_non_ascii() {
		assert_eq!(
			parse("HELO münchen.example"),
			Err(ParseError::InvalidCharacters)
		);
	}

	#[test]
	fn rejects_overlong_lines() {
		let line = format!("HELO {}", "a".repeat(MAX_COMMAND_LINE));
		assert_eq!(parse(&line), Err(ParseError::LineTooLong));
	}
}
