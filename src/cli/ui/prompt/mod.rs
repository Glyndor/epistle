//! Inline questions with injected streams and validation, without terminal control.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

use crate::cli::term::{self, Env, Tone};

/// Interaction and colour are separate: NO_COLOR never prevents answering.
#[derive(Clone, Copy)]
pub(crate) struct Policy {
	pub interactive: bool,
	pub colour: bool,
	/// Whether stdin is the terminal the answers are read from. A hidden
	/// read needs it to turn echo off, so it is kept apart from
	/// `interactive`: a test reader is never a terminal.
	pub input_tty: bool,
}

impl Policy {
	pub fn new(input_tty: bool, output_tty: bool, json: bool, env: &Env<'_>) -> Self {
		Self {
			interactive: input_tty && output_tty && !json,
			colour: term::decorates(output_tty, env, json),
			input_tty,
		}
	}
}

/// Only ordinary answers belong here. Secret reads bypass this structure.
pub(crate) type Answers = BTreeMap<String, String>;
pub(crate) type Checkpoint<'a> = dyn FnMut(&Answers) -> io::Result<()> + 'a;

pub(crate) struct Prompt<'a, R, W> {
	pub reader: &'a mut R,
	pub out: &'a mut W,
	pub policy: Policy,
	pub answers: Answers,
	pub checkpoint: &'a mut Checkpoint<'a>,
}

impl<R: BufRead, W: Write> Prompt<'_, R, W> {
	fn require_interactive(&self) -> io::Result<()> {
		if self.policy.interactive {
			Ok(())
		} else {
			Err(io::Error::other(
				"interactive input requires a terminal; use --answers FILE",
			))
		}
	}

	pub fn step(&mut self, number: usize, total: usize, title: &str) -> io::Result<()> {
		self.require_interactive()?;
		writeln!(
			self.out,
			"\n{}",
			term::paint(
				Tone::Good.style(),
				&format!("◆ Step {number} of {total}: {title}"),
				self.policy.colour
			)
		)
	}

	pub fn line(&mut self, question: &str) -> io::Result<String> {
		if !self.policy.interactive {
			return Err(io::Error::other(
				"interactive input requires a terminal; use --answers FILE",
			));
		}
		write!(
			self.out,
			"{} ",
			term::paint(Tone::Good.style(), question, self.policy.colour)
		)?;
		self.out.flush()?;
		let mut line = String::new();
		if self.reader.read_line(&mut line)? == 0 {
			return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input ended"));
		}
		if line.contains('\u{3}') {
			return Err(io::Error::new(
				io::ErrorKind::Interrupted,
				"input interrupted",
			));
		}
		Ok(line.trim().to_string())
	}

	/// Read a line with the terminal's echo turned off, for a field that
	/// must never reach the screen: a value the operator pastes by mistake
	/// would otherwise stay in the scrollback. The question itself is
	/// printed, and a reader that is not a terminal is read in the ordinary
	/// way.
	pub fn hidden(&mut self, question: &str) -> io::Result<String> {
		self.require_interactive()?;
		let tty = self.policy.input_tty.then_some(libc::STDIN_FILENO);
		let mut console = crate::cli::prompt::Console {
			interactive: tty.is_some(),
			tty,
			input: self.reader,
			err: self.out,
		};
		let value = match crate::cli::prompt::read_secret(&mut console, question, false) {
			crate::cli::prompt::Secret::Read(value) => value,
			crate::cli::prompt::Secret::Eof => {
				return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input ended"));
			}
			crate::cli::prompt::Secret::Failed(why) => return Err(io::Error::other(why)),
			crate::cli::prompt::Secret::Blank => String::new(),
			// One read was asked for, so the prompt module cannot report a repeat.
			crate::cli::prompt::Secret::Mismatch => return Err(io::Error::other("unreadable")),
		};
		if value.contains('\u{3}') {
			return Err(io::Error::new(
				io::ErrorKind::Interrupted,
				"input interrupted",
			));
		}
		Ok(value)
	}

	pub fn validated<T>(
		&mut self,
		key: &str,
		purpose: &str,
		default: &str,
		example: &str,
		mut check: impl FnMut(&str) -> Result<T, String>,
	) -> io::Result<T> {
		self.require_interactive()?;
		writeln!(self.out, "{purpose}")?;
		let question = format!("{key} [{default}]>");
		let mut resumed = self.answers.get(key).cloned();
		loop {
			let raw = match resumed.take() {
				Some(value) => value,
				None => self.line(&question)?,
			};
			let value = if raw.is_empty() { default } else { &raw };
			match check(value) {
				Ok(parsed) => {
					self.answers.insert(key.to_string(), value.to_string());
					(self.checkpoint)(&self.answers)?;
					return Ok(parsed);
				}
				Err(rule) => writeln!(
					self.out,
					"✘ {}: {}; valid example: {}. Try again.",
					term::sanitize(value),
					term::sanitize(&rule),
					term::sanitize(example)
				)?,
			}
		}
	}

	pub fn choice(
		&mut self,
		key: &str,
		purpose: &str,
		options: &[&str],
		default: usize,
	) -> io::Result<usize> {
		self.require_interactive()?;
		for (index, option) in options.iter().enumerate() {
			writeln!(self.out, "  {}. {option}", index + 1)?;
		}
		self.validated(key, purpose, options[default], options[default], |raw| {
			options
				.iter()
				.position(|option| raw.eq_ignore_ascii_case(option))
				.or_else(|| {
					raw.parse::<usize>()
						.ok()
						.filter(|n| *n > 0 && *n <= options.len())
						.map(|n| n - 1)
				})
				.ok_or_else(|| {
					format!(
						"choose a number from 1 to {} or an option name",
						options.len()
					)
				})
		})
	}

	pub fn boolean(&mut self, key: &str, purpose: &str, default: bool) -> io::Result<bool> {
		self.choice(key, purpose, &["yes", "no"], usize::from(!default))
			.map(|n| n == 0)
	}

	/// Confirmation is deliberately never cached or resumed.
	pub fn confirm(&mut self, question: &str) -> io::Result<bool> {
		let value = self.line(&format!("{question} [y/N]"))?;
		Ok(value.eq_ignore_ascii_case("y") || value.eq_ignore_ascii_case("yes"))
	}
}

#[cfg(test)]
mod tests;
