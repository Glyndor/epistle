//! Decompressing a backup archive before its tar members are read, with a
//! ceiling on what the decompression may produce.
//!
//! The restore holds the whole archive and the tar in memory. Deflate can
//! expand about a thousand times, so a few megabytes of hostile or damaged
//! input would otherwise grow until the process is killed. What a backup
//! carries does not compress anywhere near that: messages, stored encrypted
//! or as text with base64 attachments, shrink at most a few times, and the
//! SQL dump of the database some ten times. The ceiling is a hundred times
//! the compressed size, and never less than [`FLOOR`] so a small archive of
//! a nearly empty data directory restores whatever its ratio.

use std::io::{self, Read};

/// How many times its compressed size an archive may expand.
pub(super) const MAX_RATIO: u64 = 100;

/// The ceiling for any archive, however small: 1 GiB.
pub(super) const FLOOR: u64 = 1 << 30;

/// The most bytes the decompression of an archive of `compressed` bytes may
/// produce.
pub(super) fn expansion_limit(compressed: usize) -> u64 {
	(compressed as u64).saturating_mul(MAX_RATIO).max(FLOOR)
}

/// Gunzip a backup archive and return its raw tar bytes, refusing one that
/// expands past [`expansion_limit`].
pub(super) fn gunzip_archive(data: &[u8]) -> io::Result<Vec<u8>> {
	gunzip_capped(data, expansion_limit(data.len()))
}

/// Gunzip `data`, failing once the output would pass `limit` bytes.
pub(super) fn gunzip_capped(data: &[u8], limit: u64) -> io::Result<Vec<u8>> {
	let mut out = Vec::new();
	flate2::read::GzDecoder::new(data)
		.take(limit.saturating_add(1))
		.read_to_end(&mut out)?;
	if out.len() as u64 > limit {
		return Err(io::Error::other(format!(
			"the archive expands past {limit} bytes, more than {MAX_RATIO} times its compressed size, so it is damaged or not a backup made by epistle; nothing was restored"
		)));
	}
	Ok(out)
}
