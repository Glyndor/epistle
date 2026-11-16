//! `epistle stack logs`: the last lines of each service, in time order.
//!
//! podup prints one service after the other and, with no limit, from the
//! beginning of its log. This runs one `podup logs` per service, asks for
//! the time of each line and interleaves them as they arrive, so memory
//! stays bounded by one line per service. A message longer than
//! 500 characters is cut, unless `--raw` is given.

use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ExitCode, Stdio};

mod args;
mod line;
mod merge;
mod stamp;
#[cfg(test)]
mod tests;

pub use args::LogsArgs;

use super::{build_command, capture_podup, finished, not_started};

/// Run `epistle stack logs` against the compose file.
pub(super) fn run(podup: &str, compose: &Path, args: &LogsArgs) -> ExitCode {
	if args.follow {
		return follow(podup, compose, args);
	}
	let services = match &args.service {
		Some(name) => vec![name.clone()],
		None => match all_services(podup, compose) {
			Ok(services) => services,
			Err(code) => return code,
		},
	};
	let merged = args.merges(services.len());
	let mut sources = Vec::with_capacity(services.len());
	for service in &services {
		let mut argv = vec!["logs".to_string()];
		if merged {
			argv.push("-t".to_string());
		}
		argv.extend(args.range_argv());
		argv.push(service.clone());
		sources.push(Source { argv, child: None });
	}
	let mut out = io::stdout().lock();
	let result = if merged {
		merge::interleave(podup, compose, &mut sources, !args.raw, &mut out)
	} else {
		merge::one_after_the_other(podup, compose, &mut sources, !args.raw, &mut out)
	};
	finish(result)
}

/// One `podup logs` call whose lines are read through a pipe.
pub(super) struct Source {
	/// The words after `-f <compose>`.
	pub(super) argv: Vec<String>,
	/// The running call, once it was started.
	pub(super) child: Option<Child>,
}

impl Source {
	/// Start the call with its stdout piped, or say why it could not start.
	pub(super) fn start(&mut self, podup: &str, compose: &Path) -> Result<(), ExitCode> {
		let words: Vec<&str> = self.argv.iter().map(String::as_str).collect();
		let child = build_command(podup, compose, &words)
			.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()
			.map_err(not_started)?;
		self.child = Some(child);
		Ok(())
	}

	/// The reader of the call's stdout.
	pub(super) fn reader(&mut self) -> Option<BufReader<std::process::ChildStdout>> {
		let stdout = self.child.as_mut()?.stdout.take()?;
		Some(BufReader::new(stdout))
	}

	/// Wait for the call and turn a failure into the one-line error.
	pub(super) fn wait(&mut self, compose: &Path) -> ExitCode {
		let Some(mut child) = self.child.take() else {
			return ExitCode::SUCCESS;
		};
		match child.wait() {
			Ok(status) => {
				let words: Vec<&str> = self.argv.iter().map(String::as_str).collect();
				finished(&status, compose, &words)
			}
			Err(error) => not_started(error),
		}
	}

	/// Stop the call: the reader went away.
	pub(super) fn kill(&mut self) {
		if let Some(mut child) = self.child.take() {
			let _ = child.kill();
			let _ = child.wait();
		}
	}
}

/// The exit code of a pass over the services: a closed pipe on our side
/// (`| head`) is not a failure.
fn finish(result: io::Result<ExitCode>) -> ExitCode {
	match result {
		Ok(code) => code,
		Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
		Err(error) => {
			crate::cli::style::error(format_args!("cannot write the logs: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// The service names the compose file declares, in file order.
fn all_services(podup: &str, compose: &Path) -> Result<Vec<String>, ExitCode> {
	let listing = capture_podup(podup, compose, &["ps", "--all-services"])?;
	let services: Vec<String> = listing
		.lines()
		.map(str::trim)
		.filter(|name| !name.is_empty())
		.map(str::to_owned)
		.collect();
	if services.is_empty() {
		crate::cli::style::error(format_args!(
			"{} declares no services; there are no logs to show",
			compose.display()
		));
		return Err(ExitCode::FAILURE);
	}
	Ok(services)
}

/// `--follow`: one podup call streams every service in the order the lines
/// arrive, and each line is cut on the way out unless `--raw` is given.
fn follow(podup: &str, compose: &Path, args: &LogsArgs) -> ExitCode {
	let mut argv = vec!["logs".to_string(), "--follow".to_string()];
	argv.extend(args.range_argv());
	argv.extend(args.service.clone());
	let mut source = Source { argv, child: None };
	if let Err(code) = source.start(podup, compose) {
		return code;
	}
	let Some(mut reader) = source.reader() else {
		return ExitCode::FAILURE;
	};
	let mut out = io::stdout().lock();
	let copied = merge::copy_lines(&mut reader, !args.raw, &mut out);
	if copied.is_err() {
		source.kill();
		return finish(copied.map(|()| ExitCode::SUCCESS));
	}
	source.wait(compose)
}

/// The most bytes of one line that are held in memory. The message part is
/// cut at 500 characters (at most 2000 bytes) and the container name and time
/// before it are short, so this keeps all that a cut line shows. The rest of a
/// longer line is counted and dropped, or in `--raw` copied on to the output
/// without being held.
pub(super) const LINE_BYTES: usize = 8 * 1024;

/// A line read with at most [`LINE_BYTES`] bytes held.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Line {
	/// The start of the line, without its newline.
	pub(super) bytes: Vec<u8>,
	/// Bytes after those that were dropped (not in `--raw`).
	pub(super) omitted: u64,
	/// The line goes on in the reader (only in `--raw`); [`emit`] copies it.
	pub(super) pending: bool,
}

impl Line {
	/// The held start of the line as text; bytes that are not UTF-8 become
	/// the replacement character.
	pub(super) fn text(&self) -> std::borrow::Cow<'_, str> {
		String::from_utf8_lossy(&self.bytes)
	}
}

/// The next line of `reader`, or `None` at the end, holding at most `cap`
/// bytes. What follows them is dropped and counted, unless `keep_rest`, which
/// leaves it in the reader for [`emit`] to copy.
pub(super) fn next_line(
	reader: &mut impl BufRead,
	cap: usize,
	keep_rest: bool,
) -> io::Result<Option<Line>> {
	use std::io::Read;
	let mut bytes = Vec::new();
	let read = reader
		.by_ref()
		.take(cap as u64)
		.read_until(b'\n', &mut bytes)?;
	if read == 0 {
		return Ok(None);
	}
	if bytes.last() == Some(&b'\n') {
		bytes.pop();
		if bytes.last() == Some(&b'\r') {
			bytes.pop();
		}
		return Ok(Some(Line {
			bytes,
			..Line::default()
		}));
	}
	if bytes.len() < cap {
		// The end of the input came before a newline.
		return Ok(Some(Line {
			bytes,
			..Line::default()
		}));
	}
	if keep_rest {
		return Ok(Some(Line {
			bytes,
			omitted: 0,
			pending: true,
		}));
	}
	let omitted = pass_rest(reader, &mut io::sink())?;
	Ok(Some(Line {
		bytes,
		omitted,
		pending: false,
	}))
}

/// Move the rest of the current line, up to and without its newline, from
/// `reader` to `out` in the pieces the reader holds, and return how many
/// bytes it was.
fn pass_rest(reader: &mut impl BufRead, out: &mut impl Write) -> io::Result<u64> {
	let mut total = 0_u64;
	loop {
		let chunk = reader.fill_buf()?;
		if chunk.is_empty() {
			return Ok(total);
		}
		match chunk.iter().position(|byte| *byte == b'\n') {
			Some(at) => {
				out.write_all(&chunk[..at])?;
				total += at as u64;
				reader.consume(at + 1);
				return Ok(total);
			}
			None => {
				out.write_all(chunk)?;
				total += chunk.len() as u64;
				let length = chunk.len();
				reader.consume(length);
			}
		}
	}
}

/// Write one line and its newline: cut unless `cutting` is off, or, in
/// `--raw`, whole, copying what the reader still holds of it.
pub(super) fn emit(
	out: &mut impl Write,
	line: &Line,
	cutting: bool,
	reader: &mut impl BufRead,
) -> io::Result<()> {
	if cutting {
		return writeln!(
			out,
			"{}",
			line::cut(&line.text(), line::LINE_LIMIT, line.omitted)
		);
	}
	out.write_all(&line.bytes)?;
	if line.pending {
		pass_rest(reader, out)?;
	}
	out.write_all(b"\n")
}
