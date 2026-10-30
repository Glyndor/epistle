//! What an operator looked at when they accepted a break in one day.
//!
//! The text of a break (the line and the two hashes) says where the chain
//! stopped, not what the rest of the day held. An acknowledgement that named
//! only the text would go on covering whatever the day was rewritten to
//! afterwards. So an acknowledgement of such a break also carries a digest of
//! the day as it was: every line before the acknowledgement and the day's
//! checkpoint files. Change any of them and the break is back.

use std::io::{BufRead, BufReader};
use std::path::Path;

use super::super::chain::{CHAIN_DIR, day_file, open_day};
use super::super::checkpoint::{files, read_bounded};
use super::super::record::to_hex;
use super::Day;

/// The largest checkpoint file read.
const MAX_FILE: u64 = 1024 * 1024;

/// One field of the digest: its name (prefixed by its length), then its
/// length, then its bytes, or a length no bytes can have for a field that is
/// not there. Every field has a known size before the next one starts, so no
/// two different inputs can be read as the same sequence.
fn part(context: &mut ring::digest::Context, name: &str, bytes: Option<&[u8]>) {
	context.update(&[name.len() as u8]);
	context.update(name.as_bytes());
	match bytes {
		Some(bytes) => {
			context.update(&(bytes.len() as u64).to_be_bytes());
			context.update(bytes);
		}
		None => context.update(&u64::MAX.to_be_bytes()),
	}
}

/// A digest of `day` as it is: its lines (only those before line
/// `before_line` when given, which is where an acknowledgement sits in the
/// same day) and its checkpoint, signature and token. A file that is not
/// there and one that cannot be read are not the same input.
pub fn day_state(
	evidence_root: &Path,
	day: Day,
	before_line: Option<u64>,
) -> std::io::Result<String> {
	let mut context = ring::digest::Context::new(&ring::digest::SHA256);
	context.update(b"epistle evidence day state 3\n");
	match open_day(&day_file(&evidence_root.join(CHAIN_DIR), day)) {
		Ok(file) => {
			// The lines go through a digest of their own, so what follows
			// them in this one is a field of fixed size, however long the
			// day is or what it ends with.
			let mut lines = ring::digest::Context::new(&ring::digest::SHA256);
			let length = stream_lines(&mut lines, BufReader::new(file), before_line)?;
			lines.update(&length.to_be_bytes());
			part(&mut context, "day", Some(lines.finish().as_ref()));
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			part(&mut context, "day", None);
		}
		Err(error) => return Err(error),
	}
	let paths = files(evidence_root, day);
	for (name, path) in [
		("json", &paths.json),
		("sig", &paths.sig),
		("tsr", &paths.tsr),
	] {
		part(&mut context, name, read_bounded(path, MAX_FILE)?.as_deref());
	}
	Ok(to_hex(context.finish().as_ref()))
}

/// Feed the bytes of the lines before line `before_line` (all of them for
/// `None`) to `context`, a buffer at a time, and return how many bytes that
/// was. A line is never held: one with no end is hashed as it comes, so
/// the cost in memory is the buffer's, whatever the file holds, and two files
/// that differ only inside a line of any length have different digests.
fn stream_lines(
	context: &mut ring::digest::Context,
	mut reader: impl BufRead,
	before_line: Option<u64>,
) -> std::io::Result<u64> {
	// The complete lines wanted; the file's own end otherwise.
	let wanted = before_line.map(|before| before.saturating_sub(1));
	let (mut seen, mut length) = (0u64, 0u64);
	if wanted == Some(0) {
		return Ok(0);
	}
	loop {
		let buffer = reader.fill_buf()?;
		if buffer.is_empty() {
			return Ok(length);
		}
		let mut end = buffer.len();
		let mut reached = false;
		if let Some(wanted) = wanted {
			for (index, byte) in buffer.iter().enumerate() {
				if *byte == b'\n' {
					seen += 1;
					if seen == wanted {
						end = index + 1;
						reached = true;
						break;
					}
				}
			}
		}
		context.update(&buffer[..end]);
		length += end as u64;
		reader.consume(end);
		if reached {
			return Ok(length);
		}
	}
}

#[cfg(test)]
mod tests;
