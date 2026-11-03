//! Entry point for the fuzz target of a hostile backup archive (see
//! `crate::fuzzing`).
//!
//! `epistle restore` reads an archive an operator was handed: it may be
//! damaged, or built to escape the data directory or exhaust memory. The
//! bytes are read the two ways a restore can see them, as the gzip stream
//! and as the tar inside it, and every member name goes through the check
//! that decides where a file is written.

use std::path::{Component, Path};

use super::gunzip::gunzip_capped;
use super::restore_files::relative_path;
use super::tar_format::{Entry, read_entries, tar_gz};

/// The decompression ceiling of the fuzz target. Small, so an input reaches
/// it; the restore derives its own from the archive size.
const GUNZIP_LIMIT: u64 = 256 * 1024;

/// Read `raw` as a backup archive, compressed and as a bare tar, and check
/// what the reader and the path check promise.
///
/// # Panics
///
/// When the reader or the path check breaks a promise. That is what the
/// fuzz target looks for.
pub(crate) fn archive_for_fuzzing(raw: &[u8]) {
	if let Ok(tar) = gunzip_capped(raw, GUNZIP_LIMIT) {
		assert!(tar.len() as u64 <= GUNZIP_LIMIT, "gunzip over its limit");
		check_tar(&tar);
	}
	check_tar(raw);
	check_tar(&with_valid_headers(raw));
	// The same check on the whole input as one member name, which reaches
	// names a tar header would take the fuzzer long to build.
	let name = String::from_utf8_lossy(raw);
	if let Ok(relative) = relative_path(&name) {
		check_destination(relative);
	}
}

/// `raw` with every header it reaches made readable: the magic, a mode and a
/// size that are octal, and the checksum set right. A random block passes
/// none of those checks, so without this the fuzzer rarely gets on to the
/// members, the PAX records and the names.
fn with_valid_headers(raw: &[u8]) -> Vec<u8> {
	let mut tar = raw.to_vec();
	let mut offset = 0usize;
	while let Some(block) = tar.get_mut(offset..offset + 512) {
		if block.iter().all(|&byte| byte == 0) {
			break;
		}
		block[257..263].copy_from_slice(b"ustar\0");
		if octal_field(&block[100..108]).is_none() {
			block[100..108].copy_from_slice(b"0000644\0");
		}
		let size = octal_field(&block[124..136]).unwrap_or_else(|| {
			block[124..136].copy_from_slice(b"00000000000\0");
			0
		});
		block[148..156].copy_from_slice(b"        ");
		let sum: u32 = block.iter().map(|&byte| u32::from(byte)).sum();
		block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
		offset += 512
			+ usize::try_from(size)
				.unwrap_or(usize::MAX / 2)
				.div_ceil(512)
				* 512;
	}
	tar
}

/// The value of an octal header field, read the way the restore reads it.
fn octal_field(field: &[u8]) -> Option<u64> {
	let text = std::str::from_utf8(field).ok()?;
	u64::from_str_radix(text.trim_matches(['\0', ' ']), 8).ok()
}

/// The entries of `tar`, their bounds, the destination check of every name,
/// and the same entries after a write and a read back.
fn check_tar(tar: &[u8]) {
	let Ok(entries) = read_entries(tar) else {
		return;
	};
	assert!(entries.len() <= tar.len() / 512, "more members than blocks");
	let content: usize = entries.iter().map(|(_, _, data)| data.len()).sum();
	assert!(content <= tar.len(), "members larger than the archive");
	for (name, _, _) in &entries {
		if let Ok(relative) = relative_path(name) {
			check_destination(relative);
		}
	}
	round_trip(&entries);
}

/// A name the restore accepts stays under the data directory: relative, made
/// only of plain components, none of them empty, `.` or `..`.
fn check_destination(relative: &Path) {
	assert!(relative.is_relative(), "absolute destination");
	assert!(
		relative
			.components()
			.all(|component| matches!(component, Component::Normal(_))),
		"destination leaves the data directory"
	);
	let text = relative.to_string_lossy();
	assert!(
		!text
			.split('/')
			.any(|part| part.is_empty() || part == "." || part == ".."),
		"destination with an empty, `.` or `..` part"
	);
}

/// What the restore read, written by the backup and read again, is the same.
/// A name with a NUL byte is left out: a ustar name field ends at the first
/// one, and only a PAX record can carry it.
fn round_trip(entries: &[Entry]) {
	if entries.iter().any(|(name, _, _)| name.contains('\0')) {
		return;
	}
	let archive = tar_gz(entries).expect("an archive of what was read is written");
	let tar = gunzip_capped(&archive, u64::MAX).expect("the written archive gunzips");
	let again = read_entries(&tar).expect("the written archive reads back");
	assert_eq!(
		again.len(),
		entries.len(),
		"member count after a round trip"
	);
	for ((name, mode, data), (name2, mode2, data2)) in entries.iter().zip(&again) {
		assert_eq!(name, name2, "name after a round trip");
		assert_eq!(mode & 0o7777, mode2 & 0o7777, "mode after a round trip");
		assert!(data == data2, "content after a round trip");
	}
}
