//! Tests for the SMTP command parser.

use super::command::*;

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
	let Ok(Command::RcptTo { notify, .. }) = parse("RCPT TO:<b@example.org> NOTIFY=NEVER") else {
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
