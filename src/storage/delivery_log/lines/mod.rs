//! Reading the delivery log a line at a time with a bound, and choosing the
//! day files a query needs.

/// The longest log line read. A record is a few hundred bytes plus the
/// caller's correlation map; a line past this is not one of ours.
pub(super) const MAX_LINE_BYTES: usize = 1 << 20;

/// What [`read_capped_line`] found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Line {
	/// A line is in the buffer, without its line ending.
	Read,
	/// A line longer than the cap: it was read through and dropped.
	TooLong,
	/// No more lines.
	End,
}

/// Read one `\n`-ended line into `line` holding at most `cap` bytes of it.
/// A longer line is consumed to its end without being kept, so a file with
/// no line ending at all costs the buffer size, not the file size.
pub(super) fn read_capped_line(
	reader: &mut impl std::io::BufRead,
	line: &mut Vec<u8>,
	cap: usize,
) -> std::io::Result<Line> {
	line.clear();
	let mut too_long = false;
	let mut seen_any = false;
	loop {
		let available = reader.fill_buf()?;
		if available.is_empty() {
			return Ok(match (seen_any, too_long) {
				(false, _) => Line::End,
				(true, true) => Line::TooLong,
				(true, false) => Line::Read,
			});
		}
		seen_any = true;
		let (content, used, done) = match available.iter().position(|byte| *byte == b'\n') {
			Some(at) => (&available[..at], at + 1, true),
			None => (available, available.len(), false),
		};
		if !too_long {
			if line.len() + content.len() > cap {
				too_long = true;
				line.clear();
			} else {
				line.extend_from_slice(content);
			}
		}
		reader.consume(used);
		if done {
			return Ok(if too_long { Line::TooLong } else { Line::Read });
		}
	}
}

/// Whether the file `name` (`YYYY-MM-DD.jsonl`) holds a day between `first`
/// and `last` (both `YYYY-MM-DD`, either open). A name that is not a day is
/// kept: it is read as before and its lines decide.
pub(super) fn day_in_window(name: &str, first: Option<&str>, last: Option<&str>) -> bool {
	let Some(day) = name.strip_suffix(".jsonl") else {
		return true;
	};
	first.is_none_or(|first| day >= first) && last.is_none_or(|last| day <= last)
}

#[cfg(test)]
mod tests;
