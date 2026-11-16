//! Reading several `podup logs` calls at once and writing their lines in
//! time order.

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use super::{LINE_BYTES, Line, Source, emit, line, next_line};

/// One service's lines, with the next one already read.
struct Stream<R> {
	reader: R,
	/// The next line and its time, or `None` once the service has no more.
	head: Option<(i128, Line)>,
	/// The time of the last line that had one: a line without a time (the
	/// rest of a message that has several lines) sorts right after it.
	last: i128,
	/// Whether a line is cut, so the rest of a long one is dropped and not
	/// left in the reader for [`emit`] to copy.
	cutting: bool,
}

impl<R: BufRead> Stream<R> {
	fn new(reader: R, cutting: bool) -> io::Result<Self> {
		let mut stream = Self {
			reader,
			head: None,
			last: i128::MIN,
			cutting,
		};
		stream.advance()?;
		Ok(stream)
	}

	/// Read the next line into `head`.
	fn advance(&mut self) -> io::Result<()> {
		self.head = next_line(&mut self.reader, LINE_BYTES, !self.cutting)?.map(|held| {
			if let Some(at) = line::stamp_of(&held.text()) {
				self.last = at;
			}
			(self.last, held)
		});
		Ok(())
	}
}

/// Write the lines of `readers` in time order. Lines with the same time keep
/// the order of the readers.
pub(super) fn merge_readers<R: BufRead>(
	readers: Vec<R>,
	cutting: bool,
	out: &mut impl Write,
) -> io::Result<()> {
	let mut streams = Vec::with_capacity(readers.len());
	for reader in readers {
		streams.push(Stream::new(reader, cutting)?);
	}
	loop {
		let mut next: Option<usize> = None;
		for (at, stream) in streams.iter().enumerate() {
			let Some((time, _)) = &stream.head else {
				continue;
			};
			let earlier = match next {
				Some(best) => streams[best]
					.head
					.as_ref()
					.is_some_and(|(held, _)| time < held),
				None => true,
			};
			if earlier {
				next = Some(at);
			}
		}
		let Some(at) = next else {
			return Ok(());
		};
		if let Some((_, held)) = streams[at].head.take() {
			emit(out, &held, cutting, &mut streams[at].reader)?;
		}
		streams[at].advance()?;
	}
}

/// Copy every line of `reader`, cut unless `cutting` is off, flushing each
/// one so a followed log shows up as it is written.
pub(super) fn copy_lines(
	reader: &mut impl BufRead,
	cutting: bool,
	out: &mut impl Write,
) -> io::Result<()> {
	while let Some(held) = next_line(reader, LINE_BYTES, !cutting)? {
		emit(out, &held, cutting, reader)?;
		out.flush()?;
	}
	Ok(())
}

/// Start every source, interleave them and report the first failure.
pub(super) fn interleave(
	podup: &str,
	compose: &Path,
	sources: &mut [Source],
	cutting: bool,
	out: &mut impl Write,
) -> io::Result<ExitCode> {
	let mut readers = Vec::with_capacity(sources.len());
	for source in sources.iter_mut() {
		if let Err(code) = source.start(podup, compose) {
			kill_all(sources);
			return Ok(code);
		}
		match source.reader() {
			Some(reader) => readers.push(reader),
			None => {
				kill_all(sources);
				return Ok(ExitCode::FAILURE);
			}
		}
	}
	let merged = merge_readers(readers, cutting, out);
	if merged.is_err() {
		kill_all(sources);
		merged?;
	}
	Ok(wait_all(compose, sources))
}

/// Run the sources one at a time, each to its end: the lines stay grouped by
/// service and the first failure stops the rest.
pub(super) fn one_after_the_other(
	podup: &str,
	compose: &Path,
	sources: &mut [Source],
	cutting: bool,
	out: &mut impl Write,
) -> io::Result<ExitCode> {
	for source in sources.iter_mut() {
		if let Err(code) = source.start(podup, compose) {
			return Ok(code);
		}
		let Some(mut reader) = source.reader() else {
			return Ok(ExitCode::FAILURE);
		};
		if let Err(error) = copy_lines(&mut reader, cutting, out) {
			source.kill();
			return Err(error);
		}
		let code = source.wait(compose);
		if code != ExitCode::SUCCESS {
			return Ok(code);
		}
	}
	Ok(ExitCode::SUCCESS)
}

fn kill_all(sources: &mut [Source]) {
	for source in sources {
		source.kill();
	}
}

/// Wait for every source; the first failure is the exit code.
fn wait_all(compose: &Path, sources: &mut [Source]) -> ExitCode {
	let mut result = ExitCode::SUCCESS;
	for source in sources {
		let code = source.wait(compose);
		if result == ExitCode::SUCCESS {
			result = code;
		}
	}
	result
}
