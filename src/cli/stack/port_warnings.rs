//! The warning podup prints for a port published on every interface, and
//! the ports the stack publishes on purpose.
//!
//! `podup` warns about every published port that names no host address:
//!
//! ```text
//! podup: warning: service 'mail': port 25 is published on every interface; use "127.0.0.1:25:25" to keep it on the host
//! ```
//!
//! The stack publishes several of them on purpose: inbound SMTP on port
//! 25 has to answer the whole internet, and every listener `init` writes
//! binds the wildcard, so the host reaches it on every address it owns.
//! The warning is right, and it is there on every single `stack up`, and
//! a warning that is always there is one nobody reads: the warning that
//! mattered (#1588) went unnoticed behind it.
//!
//! So the warnings about the ports the stack publishes on purpose are
//! replaced by one note, and the warning about a port the stack does NOT
//! publish on purpose stays exactly as podup printed it: that one is
//! about a port nobody asked to reach the public internet.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::path::Path;
use std::process::ExitCode;

use crate::config::Config;

/// The start of the warning podup prints for a published port.
const WARNING_PREFIX: &str = "podup: warning: service '";
/// What follows the service name in that warning.
const WARNING_SERVICE: &str = "': port ";
/// What follows the port in that warning.
const WARNING_PORT: &str = " is published on every interface; use \"127.0.0.1:";
/// What ends that warning.
const WARNING_END: &str = "\" to keep it on the host";

/// The port inbound SMTP answers on. The stack publishes it on every
/// interface on purpose: a server that does not receive mail from the
/// internet is not a mail server.
const SMTP_PORT: u16 = 25;

/// The ports the stack publishes on every interface on purpose, and the
/// warnings podup printed about them.
pub(in crate::cli) struct Published {
	/// The bind address the listener of each port has, keyed by the port.
	binds: BTreeMap<u16, IpAddr>,
	/// The ports podup warned about that the stack publishes on purpose.
	warned: BTreeSet<u16>,
}

impl Published {
	/// The ports the configuration publishes on every interface on
	/// purpose: every listener that binds the wildcard, and the inbound
	/// SMTP port, which has to answer the whole internet.
	pub(in crate::cli) fn new(config: &Config) -> Self {
		let mut binds = BTreeMap::new();
		for listener in &config.listeners {
			let port = listener
				.port
				.unwrap_or_else(|| listener.kind.default_port());
			binds.entry(port).or_insert(listener.addr);
		}
		Self {
			binds,
			warned: BTreeSet::new(),
		}
	}

	/// Whether the stack publishes the port on every interface on
	/// purpose: the listener behind it binds the wildcard, or it is the
	/// inbound SMTP port.
	fn on_purpose(&self, port: u16) -> bool {
		if port == SMTP_PORT {
			return true;
		}
		self.binds
			.get(&port)
			.is_some_and(|address| address.to_canonical().is_unspecified())
	}

	/// The port a line warns about, when the line has the shape podup
	/// prints for a port published on every interface. A line of any
	/// other shape names no port, and stays as it is.
	fn warned_port(line: &str) -> Option<u16> {
		let rest = line.strip_prefix(WARNING_PREFIX)?;
		let (_service, rest) = rest.split_once(WARNING_SERVICE)?;
		let (port, rest) = rest.split_once(WARNING_PORT)?;
		let port: u16 = port.parse().ok()?;
		// The advice names the port twice: the container port and the
		// host port of the mapping.
		let advice = rest.strip_suffix(WARNING_END)?;
		if advice != format!("{port}:{port}").as_str() {
			return None;
		}
		Some(port)
	}

	/// Take one line podup printed. The warnings about the ports the
	/// stack publishes on purpose are collected for the note, and every
	/// other line goes to stderr with the bytes podup wrote.
	pub(in crate::cli) fn line(&mut self, bytes: &[u8], out: &mut impl Write) {
		let text = String::from_utf8_lossy(bytes);
		let trimmed = text.trim_end_matches(['\n', '\r']);
		match Self::warned_port(trimmed) {
			Some(port) if self.on_purpose(port) => {
				self.warned.insert(port);
			}
			_ => {
				let _ = out.write_all(bytes);
			}
		}
	}

	/// The note that replaces the warnings, printed once per run. It
	/// names the ports and the bind that makes them public, so the
	/// operator reads why the warning was there and does not have to
	/// look it up.
	pub(in crate::cli) fn note(&self, out: &mut impl Write) {
		if self.warned.is_empty() {
			return;
		}
		let one = self.warned.len() == 1;
		let ports: Vec<String> = self.warned.iter().map(u16::to_string).collect();
		let binds: BTreeSet<IpAddr> = self
			.warned
			.iter()
			.filter_map(|port| self.binds.get(port).copied())
			.filter(|address| address.to_canonical().is_unspecified())
			.collect();
		let binds: Vec<String> = binds.iter().map(IpAddr::to_string).collect();
		let subject = if one { "port" } else { "ports" };
		let verb = if one { "is" } else { "are" };
		let them = if one { "it" } else { "them" };
		if binds.is_empty() {
			let _ = writeln!(
				out,
				"note: {subject} {} {verb} public on purpose; podup warns about {them} and it is expected",
				ports.join(", ")
			);
		} else {
			let _ = writeln!(
				out,
				"note: {subject} {} {verb} public on purpose (bind {}); podup warns about {them} and it is expected",
				ports.join(", "),
				binds.join(" or ")
			);
		}
	}
}

/// Run the steps with podup's stderr captured, so the warnings about the
/// ports the stack publishes on purpose can be replaced by the note. The
/// exit code of the first step that fails is the exit code of the run.
pub(in crate::cli) fn run_steps(
	podup: &str,
	compose: &Path,
	steps: &[&[&str]],
	published: &mut Published,
) -> ExitCode {
	for step in steps {
		let code = run_captured(podup, compose, step, published);
		if code != ExitCode::SUCCESS {
			return code;
		}
	}
	ExitCode::SUCCESS
}

/// Run podup with its stderr captured: the lines about the ports the
/// stack publishes on purpose are collected for the note, and the rest
/// goes to stderr as podup wrote it. The exit code of podup is the exit
/// code of the run.
fn run_captured(
	podup: &str,
	compose: &Path,
	extra: &[&str],
	published: &mut Published,
) -> ExitCode {
	let mut child = match super::build_command(podup, compose, extra)
		.stdin(std::process::Stdio::inherit())
		.stdout(super::super::json_out::child_stdout())
		.stderr(std::process::Stdio::piped())
		.spawn()
	{
		Ok(child) => child,
		Err(error) => return super::not_started(error),
	};
	let Some(stderr) = child.stderr.take() else {
		return ExitCode::FAILURE;
	};
	let mut reader = std::io::BufReader::new(stderr);
	let mut out = std::io::stderr().lock();
	let mut line = Vec::new();
	loop {
		line.clear();
		match reader.read_until(b'\n', &mut line) {
			Ok(0) => break,
			Ok(_) => published.line(&line, &mut out),
			Err(_) => break,
		}
	}
	drop(out);
	match child.wait() {
		Ok(status) => super::finished(&status, compose, extra),
		Err(_) => ExitCode::FAILURE,
	}
}
