//! SMTP server replies (RFC 5321 section 4.2).

use std::fmt;

/// A server reply: three-digit code plus one or more text lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
	code: u16,
	lines: Vec<String>,
}

impl Reply {
	/// Build a reply. Panics if `code` is not a valid SMTP reply code or no
	/// lines are given — both are programming errors, not runtime input.
	pub fn new(code: u16, lines: Vec<String>) -> Self {
		assert!(
			(200..=599).contains(&code),
			"invalid SMTP reply code {code}"
		);
		assert!(!lines.is_empty(), "a reply needs at least one line");
		Reply { code, lines }
	}

	/// Single-line convenience constructor.
	pub fn single(code: u16, text: &str) -> Self {
		Reply::new(code, vec![text.to_string()])
	}

	/// The reply code.
	pub fn code(&self) -> u16 {
		self.code
	}

	/// Whether this reply indicates success (2xx) or an intermediate
	/// positive state (3xx).
	pub fn is_positive(&self) -> bool {
		(200..400).contains(&self.code)
	}
}

impl fmt::Display for Reply {
	/// Render with CRLF terminators, hyphen-continuation on all lines but
	/// the last (RFC 5321 section 4.2.1).
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let last = self.lines.len() - 1;
		for (i, line) in self.lines.iter().enumerate() {
			let separator = if i == last { ' ' } else { '-' };
			write!(f, "{}{}{}\r\n", self.code, separator, line)?;
		}
		Ok(())
	}
}

/// Frequently used replies.
impl Reply {
	/// Generic 250 OK after a positive command (`2.0.0 ok`).
	pub fn ok() -> Self {
		Reply::single(250, "2.0.0 ok")
	}

	/// 221 closing connection in response to `QUIT`.
	pub fn closing() -> Self {
		Reply::single(221, "2.0.0 closing connection")
	}

	/// 500 syntax error: the line could not be parsed.
	pub fn syntax_error() -> Self {
		Reply::single(500, "5.5.2 syntax error")
	}

	/// 501 invalid arguments: a known command with bad or missing
	/// arguments.
	pub fn invalid_arguments() -> Self {
		Reply::single(501, "5.5.4 invalid arguments")
	}

	/// 503 bad sequence: a command issued before its prerequisites
	/// (`STARTTLS`, `AUTH`, `MAIL FROM`).
	pub fn bad_sequence() -> Self {
		Reply::single(503, "5.5.1 bad sequence of commands")
	}

	/// 252 cannot VRFY: the server does not disclose whether the address
	/// is valid (always returned for `VRFY`).
	pub fn vrfy_not_disclosed() -> Self {
		Reply::single(252, "2.1.5 cannot verify, send some mail and find out")
	}

	/// 354 start mail input: the intermediate positive reply to `DATA`,
	/// after which the client streams the message until the terminating
	/// `<CRLF>.<CRLF>`.
	pub fn start_mail_input() -> Self {
		Reply::single(354, "start mail input, end with <CRLF>.<CRLF>")
	}
}

#[cfg(test)]
mod tests;
