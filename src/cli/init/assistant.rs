//! Interactive assistant: reads from an injectable `BufRead` and writes
//! prompts to an injectable `Write`, so tests drive it with strings.
//!
//! Each question validates the line on entry with the SAME rule the
//! `--answers` file path uses; a bad answer is echoed back with the
//! reason text from the validator and the question is asked again. EOF
//! or an interrupted read before the confirmation exits 2 having written
//! nothing.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use super::answers::{Answers, DnsAnswers, Invalid, Mode, Services};

/// The outcome of running the assistant: the answers they typed in.
/// Warnings are surfaced by the caller through `Answers::validate` so
/// the assistant path and the file path share the same rule.
#[derive(Debug)]
pub struct Filled {
	/// The values the operator typed in.
	pub answers: Answers,
}

/// Read one line, including empty ones (a `b"\n"` is a valid empty answer).
/// Returns `Err(())` only on EOF or an interrupted read before any line.
fn ask_line<R: BufRead>(reader: &mut R, prompt: &str, out: &mut impl Write) -> Result<String, ()> {
	let _ = write!(out, "{prompt}");
	let _ = out.flush();
	let mut line = String::new();
	let read = match reader.read_line(&mut line) {
		Ok(read) => read,
		Err(error) => {
			let _ = writeln!(out, "reading input: {error}");
			return Err(());
		}
	};
	if read == 0 {
		return Err(());
	}
	Ok(line.trim_end_matches('\r').trim().to_string())
}

/// Read a line and accept `y`/`yes` (case-insensitive) as confirmation.
fn ask_continue<R: BufRead>(reader: &mut R, out: &mut impl Write) -> Result<bool, ()> {
	let answer = ask_line(reader, "Continue? [y/N] ", out)?;
	Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// Read an FQDN and reject the empty string. Validation runs through
/// `crate::domain::normalize` and the rejection text is the same string
/// the file path reports.
fn ask_domain<R: BufRead>(
	reader: &mut R,
	prompt: &str,
	out: &mut impl Write,
) -> Result<String, ()> {
	loop {
		let raw = ask_line(reader, prompt, out)?;
		match crate::domain::normalize(&raw) {
			Ok(_) => return Ok(raw),
			Err(why) => {
				let reason = match why {
					crate::domain::DomainError::Invalid => "is not a valid FQDN",
					crate::domain::DomainError::Confusable => "is confusable with another name",
				};
				let _ = writeln!(out, "  {reason}; try again");
			}
		}
	}
}

/// Read a list of domains, one per line, until a blank line. Each
/// domain is validated the same way `ask_domain` validates a single one.
/// An empty line ends the list; an invalid domain is skipped (with a
/// message) and the question is asked again.
fn ask_domain_list<R: BufRead>(reader: &mut R, out: &mut impl Write) -> Result<Vec<String>, ()> {
	let _ = writeln!(out, "  one per line, empty line to finish");
	let mut out_list = Vec::new();
	loop {
		let raw = ask_line(reader, "  domain> ", out)?;
		if raw.is_empty() {
			if out_list.is_empty() {
				let _ = writeln!(out, "  at least one domain required; try again");
				continue;
			}
			return Ok(out_list);
		}
		match crate::domain::normalize(&raw) {
			Ok(_) => out_list.push(raw),
			Err(why) => {
				let reason = match why {
					crate::domain::DomainError::Invalid => "is not a valid FQDN",
					crate::domain::DomainError::Confusable => "is confusable with another name",
				};
				let _ = writeln!(out, "  {reason}; skipped");
			}
		}
	}
}

fn parse_bool(raw: &str) -> Option<bool> {
	match raw.to_ascii_lowercase().as_str() {
		"y" | "yes" | "true" | "1" | "on" => Some(true),
		"n" | "no" | "false" | "0" | "off" => Some(false),
		_ => None,
	}
}

fn ask_bool<R: BufRead>(
	reader: &mut R,
	prompt: &str,
	default: bool,
	out: &mut impl Write,
) -> Result<bool, ()> {
	let hint = if default { "Y/n" } else { "y/N" };
	loop {
		let raw = ask_line(reader, &format!("{prompt} [{hint}] "), out)?;
		if raw.is_empty() {
			return Ok(default);
		}
		if let Some(value) = parse_bool(&raw) {
			return Ok(value);
		}
		let _ = writeln!(out, "  answer y or n");
	}
}

fn parse_mode(raw: &str) -> Option<Mode> {
	match raw.to_ascii_lowercase().as_str() {
		"manual" | "m" => Some(Mode::Manual),
		"automatic" | "auto" | "a" => Some(Mode::Automatic),
		_ => None,
	}
}

fn ask_mode<R: BufRead>(reader: &mut R, out: &mut impl Write) -> Result<Mode, ()> {
	loop {
		let raw = ask_line(reader, "mode [manual/automatic] ", out)?;
		if let Some(mode) = parse_mode(&raw) {
			return Ok(mode);
		}
		let _ = writeln!(out, "  answer \"manual\" or \"automatic\"");
	}
}

fn parse_ip<R: BufRead>(
	reader: &mut R,
	prompt: &str,
	family: IpFamily,
	out: &mut impl Write,
) -> Result<Option<std::net::IpAddr>, ()> {
	loop {
		let raw = ask_line(reader, prompt, out)?;
		if raw.is_empty() {
			return Ok(None);
		}
		match raw.parse::<std::net::IpAddr>() {
			Ok(addr) => {
				if !family.matches(addr) {
					let _ = writeln!(out, "  expected an {family} address");
					continue;
				}
				if let Some(reason) = family.non_global_reason(addr) {
					let _ = writeln!(out, "  {reason}; public address required");
					continue;
				}
				return Ok(Some(addr));
			}
			Err(_) => {
				let _ = writeln!(out, "  not a valid IP address");
			}
		}
	}
}

/// What family an IP address slot accepts. `public_*` slots reject
/// any non-global address (loopback, link-local, private, CGNAT)
/// with the same rule `Answers::validate` applies, so the operator
/// sees the same diagnostic whether they typed the wrong family or
/// a private-range address.
#[derive(Clone, Copy)]
enum IpFamily {
	V4Public,
	V6Public,
}

impl IpFamily {
	fn matches(self, addr: std::net::IpAddr) -> bool {
		matches!(
			(self, addr),
			(IpFamily::V4Public, std::net::IpAddr::V4(_))
				| (IpFamily::V6Public, std::net::IpAddr::V6(_))
		)
	}
	fn non_global_reason(self, addr: std::net::IpAddr) -> Option<&'static str> {
		match (self, addr) {
			(IpFamily::V4Public, std::net::IpAddr::V4(v4)) => {
				crate::config::non_global_ipv4_reason(v4)
			}
			(IpFamily::V6Public, std::net::IpAddr::V6(v6)) => {
				crate::config::non_global_ipv6_reason(v6)
			}
			_ => None,
		}
	}
}

impl std::fmt::Display for IpFamily {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			IpFamily::V4Public => f.write_str("IPv4"),
			IpFamily::V6Public => f.write_str("IPv6"),
		}
	}
}

/// Drive the operator through every question, validating as we go.
/// Returns the filled answers and the warnings collected by the final
/// validator pass. Errors and warnings from the file path and the
/// assistant path share the same text, so an operator who switches
/// modes sees the same feedback.
pub fn run<R: BufRead>(reader: &mut R, out: &mut impl Write) -> Result<Filled, ()> {
	let mode = ask_mode(reader, out)?;
	let hostname = ask_domain(reader, "hostname> ", out)?;
	let _ = writeln!(out, "domains:");
	let domains = ask_domain_list(reader, out)?;
	let public_ipv4 = parse_ip(
		reader,
		"public IPv4 (empty to skip)> ",
		IpFamily::V4Public,
		out,
	)?
	.and_then(|addr| match addr {
		std::net::IpAddr::V4(v4) => Some(v4),
		std::net::IpAddr::V6(_) => None,
	});
	let public_ipv6 = parse_ip(
		reader,
		"public IPv6 (empty to skip)> ",
		IpFamily::V6Public,
		out,
	)?
	.and_then(|addr| match addr {
		std::net::IpAddr::V6(v6) => Some(v6),
		std::net::IpAddr::V4(_) => None,
	});
	let data_dir = ask_line(reader, "data_dir> ", out)?;
	let config_path = ask_line(reader, "config_path> ", out)?;
	let dns = if mode == Mode::Automatic {
		let provider = ask_line(reader, "dns provider> ", out)?;
		let zone = ask_domain(reader, "dns zone> ", out)?;
		let token = ask_line(reader, "dns token (empty to use a file or env var)> ", out)?;
		let token_file = ask_line(reader, "dns token_file (empty to skip)> ", out)?;
		let token_env = ask_line(reader, "dns token_env (empty to skip)> ", out)?;
		Some(DnsAnswers {
			provider,
			zone,
			token: (!token.is_empty()).then_some(token),
			token_file: (!token_file.is_empty()).then_some(PathBuf::from(token_file)),
			token_env: (!token_env.is_empty()).then_some(token_env),
		})
	} else {
		None
	};
	let services = Services {
		imap: ask_bool(reader, "enable IMAP", true, out)?,
		submission: ask_bool(reader, "enable submission", true, out)?,
		pop3: ask_bool(reader, "enable POP3", false, out)?,
		managesieve: ask_bool(reader, "enable ManageSieve", false, out)?,
		webdav: ask_bool(reader, "enable WebDAV", false, out)?,
		api: ask_bool(reader, "enable management API", false, out)?,
	};
	let answers = Answers {
		mode,
		hostname,
		domains,
		public_ipv4,
		public_ipv6,
		data_dir: PathBuf::from(data_dir),
		config_path: PathBuf::from(config_path),
		dns,
		services,
	};
	match answers.validate() {
		Ok(_) => Ok(Filled { answers }),
		Err(errors) => {
			for error in errors {
				print_invalid(out, &error);
			}
			Err(())
		}
	}
}

fn print_invalid(out: &mut impl Write, error: &Invalid) {
	let _ = writeln!(out, "  {error}");
}

/// Run the confirmation prompt: returns `Ok(true)` when the operator
/// confirms, `Ok(false)` when they decline, and `Err(())` when the read
/// fails before any input.
pub fn confirm<R: BufRead>(reader: &mut R, out: &mut impl Write) -> Result<bool, ()> {
	ask_continue(reader, out)
}

#[cfg(test)]
#[path = "assistant_tests.rs"]
mod tests;
