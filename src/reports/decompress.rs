//! Bounded decompression of report attachments.
//!
//! DMARC aggregate and TLS-RPT reports arrive as attachments; large providers
//! send gzip, some send zip. Neither library we use reads a single archive
//! end-to-end against a hard cap, so this module is the one place that does,
//! and it is the bomb gate for the report ingest path.
//!
//! Two layers of bound protect the deliverer from a hostile report:
//!
//! - [`MAX_COMPRESSED`] caps the input the deliverer hands us. The caller
//!   (the part walker in `mime.rs`) measures the base64-decoded part against
//!   this before it ever reaches a decompressor, so a 100 MiB "gzip" cannot
//!   even start.
//! - [`MAX_DECOMPRESSED`] caps the output. The decoders run with a
//!   `Take<MAX_DECOMPRESSED>` so a small input that explodes to 20 MiB stops
//!   on the way out and turns into [`ReportError::TooLarge`].
//!
//! Both caps feed the `reports_dropped` counter; an over-cap report is
//! never persisted.

use std::io::Read;

use flate2::read::{DeflateDecoder, GzDecoder};

/// Largest base64-decoded part the deliverer will hand us. A normal DMARC
/// aggregate report fits in well under 1 MiB even at high volume; 2 MiB
/// absorbs Google-class senders without letting a bomb through the front
/// door.
pub const MAX_COMPRESSED: usize = 2 * 1024 * 1024;

/// Largest decompressed payload we accept. Defends against the "small
/// compressed, large decompressed" case (zeros in gzip compress to a few
/// KiB but expand to whatever the bomb asks for). Sized to cover a large
/// DMARC aggregate without leaving headroom for an adversarial archive.
pub const MAX_DECOMPRESSED: u64 = 20 * 1024 * 1024;

/// The encodings we recognise on inbound report attachments. Anything else
/// is [`ReportError::UnsupportedEncoding`] and drops the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
	/// `Content-Type: application/gzip` (also `application/x-gzip`).
	Gzip,
	/// `Content-Type: application/zip` (also `application/x-zip-compressed`).
	Zip,
}

/// Why we refused to turn a report attachment into bytes.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
	/// The input exceeds [`MAX_COMPRESSED`] or the decompressor exceeds
	/// [`MAX_DECOMPRESSED`]. The report is dropped and counted.
	#[error("report attachment too large")]
	TooLarge,
	/// The encoding on the part is none of the ones [`Encoding`] lists.
	/// Kept for the case where the MIME walker surfaces an unhandled
	/// encoding rather than picking a default.
	#[allow(dead_code)]
	#[error("unsupported report encoding")]
	UnsupportedEncoding,
	/// The bytes are not a valid archive of the claimed encoding, or the
	/// archive contains data the minimal zip reader refuses (general-purpose
	/// bit, encryption, multi-entry, data descriptor).
	#[error("malformed report archive: {0}")]
	Malformed(&'static str),
	/// The base64 decode of the part failed. Currently the MIME walker
	/// reports its own equivalent (`WalkError::InvalidBase64`); this
	/// variant stays for callers that decode outside the walker.
	#[allow(dead_code)]
	#[error("invalid base64 in report attachment")]
	InvalidBase64,
}

/// Decompress `bytes` as `kind` and return the resulting payload. Caps:
/// the caller must have measured `bytes.len() <= MAX_COMPRESSED` already;
/// this function enforces the output cap with a `Take` so a small input
/// that explodes cannot exhaust memory.
pub fn inflate_attachment(bytes: &[u8], kind: Encoding) -> Result<Vec<u8>, ReportError> {
	if bytes.len() > MAX_COMPRESSED {
		return Err(ReportError::TooLarge);
	}
	match kind {
		Encoding::Gzip => inflate_gzip(bytes),
		Encoding::Zip => inflate_zip(bytes),
	}
}

fn inflate_gzip(bytes: &[u8]) -> Result<Vec<u8>, ReportError> {
	let mut decoder = GzDecoder::new(bytes);
	let mut out = Vec::new();
	let read = decoder
		.by_ref()
		.take(MAX_DECOMPRESSED)
		.read_to_end(&mut out)
		.map_err(|_| ReportError::Malformed("gzip stream"))?;
	if (read as u64) > MAX_DECOMPRESSED {
		return Err(ReportError::TooLarge);
	}
	// `Take::read_to_end` stops at the cap without surfacing an error.
	// If we hit it exactly, probe one more byte to learn whether the
	// inner stream was actually exhausted (success) or still had data
	// (bomb).
	if (read as u64) >= MAX_DECOMPRESSED {
		let mut probe = [0u8; 1];
		let extra = decoder
			.read(&mut probe)
			.map_err(|_| ReportError::Malformed("gzip stream"))?;
		if extra > 0 {
			return Err(ReportError::TooLarge);
		}
	}
	Ok(out)
}

/// Local file header signature, ZIP spec §4.3.7.
const LOCAL_FILE_HEADER_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Method 0 (stored) and 8 (deflate) per ZIP spec §4.4.5.
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// Decompress a single-entry zip. The deliverer may receive a zip-shaped
/// part from a major provider; we do not depend on a zip crate, and a full
/// reader is overkill for what is in practice a single XML file inside a
/// store or deflate wrapper. We refuse anything that does not fit that
/// shape so a hostile archive cannot reach the deflate decoder with
/// mismatched sizes, an extra header field, or an encrypted entry.
fn inflate_zip(bytes: &[u8]) -> Result<Vec<u8>, ReportError> {
	if bytes.len() < 30 {
		return Err(ReportError::Malformed("zip too short"));
	}
	if bytes[..4] != LOCAL_FILE_HEADER_SIG {
		return Err(ReportError::Malformed("zip signature"));
	}
	// The fixed-size portion of the local file header is 30 bytes (ZIP
	// §4.3.7); everything else is variable length and depends on the
	// extra-field and filename lengths which we refuse to follow.
	let version_needed = read_u16(bytes, 4);
	if version_needed > 63 {
		// Anything needing more than the original 6.3 (the spec says
		// current = 63 for the basic feature set) is more than a stored
		// XML and we are not going to chase that compatibility story.
		return Err(ReportError::Malformed("zip version unsupported"));
	}
	let flags = read_u16(bytes, 6);
	// Bit 0 = encryption; bit 3 = data descriptor follows; bit 6 = strong
	// encryption. We refuse all three.
	if flags & 0b0000_0001 != 0 {
		return Err(ReportError::Malformed("encrypted zip"));
	}
	if flags & 0b0000_1000 != 0 {
		return Err(ReportError::Malformed("data descriptor"));
	}
	let method = read_u16(bytes, 8);
	let _mod_time = read_u16(bytes, 10);
	let _mod_date = read_u16(bytes, 12);
	let _crc32 = read_u32(bytes, 14);
	let compressed_size = read_u32(bytes, 18) as usize;
	let uncompressed_size = read_u32(bytes, 22) as usize;
	let filename_len = read_u16(bytes, 26) as usize;
	let extra_len = read_u16(bytes, 28) as usize;
	let data_offset = 30 + filename_len + extra_len;
	if data_offset > bytes.len() {
		return Err(ReportError::Malformed("zip header overruns buffer"));
	}
	if compressed_size > MAX_COMPRESSED {
		return Err(ReportError::TooLarge);
	}
	if data_offset + compressed_size > bytes.len() {
		return Err(ReportError::Malformed("zip data overruns buffer"));
	}
	let entry = &bytes[data_offset..data_offset + compressed_size];
	let payload = match method {
		METHOD_STORED => entry.to_vec(),
		METHOD_DEFLATE => {
			let mut decoder = DeflateDecoder::new(entry);
			let mut out = Vec::with_capacity(uncompressed_size.min(64 * 1024));
			let read = decoder
				.by_ref()
				.take(MAX_DECOMPRESSED)
				.read_to_end(&mut out)
				.map_err(|_| ReportError::Malformed("deflate stream"))?;
			if (read as u64) > MAX_DECOMPRESSED {
				return Err(ReportError::TooLarge);
			}
			if (read as u64) >= MAX_DECOMPRESSED {
				let mut probe = [0u8; 1];
				let extra = decoder
					.read(&mut probe)
					.map_err(|_| ReportError::Malformed("deflate stream"))?;
				if extra > 0 {
					return Err(ReportError::TooLarge);
				}
			}
			out
		}
		_ => return Err(ReportError::Malformed("unsupported zip method")),
	};
	Ok(payload)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
	u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
	u32::from_le_bytes([
		bytes[offset],
		bytes[offset + 1],
		bytes[offset + 2],
		bytes[offset + 3],
	])
}

#[cfg(test)]
#[path = "decompress_tests.rs"]
mod tests;
