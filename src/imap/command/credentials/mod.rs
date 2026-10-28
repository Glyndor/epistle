//! Credential-bearing IMAP lines: LOGIN and AUTHENTICATE.
//!
//! These never become a [`Command`]. A `Command` is matched, cloned and
//! `Debug`-printed by general code, so a password inside it could end up in a
//! log or an assertion message. Here the secret lives in a type that wipes
//! itself on drop and whose `Debug` shows nothing, and the session receives it
//! straight from the parser.

use std::fmt;

use zeroize::Zeroizing;

use super::parse::{parse, parse_astring, split_line};
use super::{ParseError, Tagged};

/// A secret string: wiped from memory on drop, never printed.
pub struct Secret(Zeroizing<String>);

impl Secret {
	fn new(value: String) -> Self {
		Self(Zeroizing::new(value))
	}

	/// The secret text, for the single call that verifies it.
	pub fn expose(&self) -> &str {
		&self.0
	}
}

impl fmt::Debug for Secret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("Secret(<redacted>)")
	}
}

/// A parsed `LOGIN <user> <pass>`.
pub struct LoginRequest {
	/// Client-supplied tag.
	pub tag: String,
	username: Secret,
	password: Secret,
}

impl LoginRequest {
	/// The user name (authcid), without any surrounding domain handling.
	pub fn username(&self) -> &str {
		self.username.expose()
	}

	/// The password.
	pub fn password(&self) -> &str {
		self.password.expose()
	}
}

impl fmt::Debug for LoginRequest {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("LoginRequest")
			.field("tag", &self.tag)
			.field("username", &self.username)
			.field("password", &self.password)
			.finish()
	}
}

/// A parsed `AUTHENTICATE <mechanism> [initial-response]` (RFC 9051). The
/// initial response can carry a whole PLAIN credential, so it is a [`Secret`].
#[derive(Debug)]
pub struct AuthenticateRequest {
	/// Client-supplied tag.
	pub tag: String,
	/// SASL mechanism name, uppercased.
	pub mechanism: String,
	/// Optional base64 initial response (RFC 4959).
	pub initial: Option<Secret>,
}

/// One parsed client line: a general command, or one of the two lines that
/// carry credentials.
#[derive(Debug)]
pub enum Line {
	/// Any command that holds no secret.
	Command(Tagged),
	/// `LOGIN`.
	Login(LoginRequest),
	/// `AUTHENTICATE`.
	Authenticate(AuthenticateRequest),
}

/// Parse one client line, routing credential-bearing verbs to their own
/// types. `append_limit` is the per-listener APPENDLIMIT, used by
/// APPEND and REPLACE to refuse over-size literals with
/// `NO [TOOBIG]` (RFC 7889 §3) before any payload is collected.
pub fn parse_line(line: &str, append_limit: usize) -> Result<Line, ParseError> {
	let (tag, verb, args) = split_line(line)?;
	match verb.to_ascii_uppercase().as_str() {
		"LOGIN" => parse_login(tag, args).map(Line::Login),
		"AUTHENTICATE" => parse_authenticate(tag, args).map(Line::Authenticate),
		_ => parse(line, append_limit).map(Line::Command),
	}
}

fn parse_login(tag: String, args: &str) -> Result<LoginRequest, ParseError> {
	let bad = || ParseError::BadArguments(tag.clone());
	let (username, rest) = parse_astring(args).ok_or_else(bad)?;
	let (password, rest) = parse_astring(rest).ok_or_else(bad)?;
	if !rest.trim().is_empty() || username.is_empty() || password.is_empty() {
		return Err(bad());
	}
	Ok(LoginRequest {
		tag,
		username: Secret::new(username),
		password: Secret::new(password),
	})
}

fn parse_authenticate(tag: String, args: &str) -> Result<AuthenticateRequest, ParseError> {
	let mut parts = args.split_whitespace();
	let mechanism = parts
		.next()
		.ok_or_else(|| ParseError::BadArguments(tag.clone()))?
		.to_ascii_uppercase();
	Ok(AuthenticateRequest {
		tag,
		mechanism,
		initial: parts.next().map(|text| Secret::new(text.to_string())),
	})
}

#[cfg(test)]
mod tests;
