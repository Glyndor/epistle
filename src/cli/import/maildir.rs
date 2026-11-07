//! Reading the message of a Maildir file, with its size bounded by the
//! message size limit.
//!
//! The file is read in chunks and the message is built as it comes, so a
//! file that goes past the limit is never read whole: the read stops at the
//! limit and the rest of the file is left alone.

use std::io::Read;
use std::path::Path;

/// The bytes read from the file at a time.
const CHUNK: usize = 16 * 1024;

/// Why a Maildir message could not be imported.
pub(super) enum ReadError {
	/// The file could not be read.
	Io(std::io::Error),
	/// The message goes past the limit.
	TooBig,
}

/// Read the message in `path`, normalizing bare LF to CRLF (Maildir files
/// are often stored LF-only; stored `.eml` and IMAP expect CRLF).
///
/// A message over `limit` bytes is refused: the file is read up to the
/// limit and no further.
pub(super) fn read_message(path: &Path, limit: usize) -> Result<Vec<u8>, ReadError> {
	let file = std::fs::File::open(path).map_err(ReadError::Io)?;
	let mut reader = std::io::BufReader::new(file);
	let mut out: Vec<u8> = Vec::new();
	let mut chunk = [0u8; CHUNK];
	let mut previous = 0u8;
	loop {
		let read = reader.read(&mut chunk).map_err(ReadError::Io)?;
		if read == 0 {
			break;
		}
		for &byte in &chunk[..read] {
			if byte == b'\n' && previous != b'\r' {
				push(&mut out, b'\r', limit)?;
			}
			push(&mut out, byte, limit)?;
			previous = byte;
		}
	}
	Ok(out)
}

/// Add one byte to the message, refusing it when it goes past the limit.
fn push(out: &mut Vec<u8>, byte: u8, limit: usize) -> Result<(), ReadError> {
	if out.len() >= limit {
		return Err(ReadError::TooBig);
	}
	out.push(byte);
	Ok(())
}
