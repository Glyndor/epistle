//! `epistle backup`: write a consistent snapshot of an instance to a single
//! gzip-compressed tar (USTAR) on stdout or a file — the filesystem mail store
//! (`data_dir`, the canonical `.eml` files plus suppression and ACME state) and,
//! when a database is configured, a `pg_dump` of the metadata/antispam tables.
//! The index rebuilds from the `.eml` files, so it is not archived.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::config::Config;

/// Build the snapshot and write it to `out`.
pub(super) fn run(config: &Config, out: &mut impl Write) -> ExitCode {
	let mut entries = match collect_files(&config.data_dir) {
		Ok(entries) => entries,
		Err(error) => {
			eprintln!("error: reading data dir: {error}");
			return ExitCode::FAILURE;
		}
	};

	// Include a logical pg_dump of the database, if one is configured and
	// pg_dump is available (best-effort: a filesystem backup is still useful).
	if let Some(db) = &config.database {
		match pg_dump(&db.url) {
			Ok(dump) => entries.push(("database.sql".to_string(), dump)),
			Err(error) => eprintln!("warning: skipping pg_dump: {error}"),
		}
	}

	let archive = match tar_gz(&entries) {
		Ok(archive) => archive,
		Err(error) => {
			eprintln!("error: building archive: {error}");
			return ExitCode::FAILURE;
		}
	};
	if out.write_all(&archive).and_then(|()| out.flush()).is_err() {
		return ExitCode::FAILURE;
	}
	eprintln!("backed up {} files for this instance", entries.len());
	ExitCode::SUCCESS
}

/// Every regular file under `root`, as (archive-relative path, bytes).
fn collect_files(root: &Path) -> std::io::Result<Vec<(String, Vec<u8>)>> {
	let mut out = Vec::new();
	let mut stack = vec![root.to_path_buf()];
	while let Some(dir) = stack.pop() {
		let entries = match std::fs::read_dir(&dir) {
			Ok(entries) => entries,
			// A missing data dir yields an empty backup, not an error.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => return Err(error),
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if path.is_dir() {
				stack.push(path);
			} else if let Ok(relative) = path.strip_prefix(root) {
				let name = format!("data/{}", relative.to_string_lossy());
				out.push((name, std::fs::read(&path)?));
			}
		}
	}
	out.sort_by(|a, b| a.0.cmp(&b.0));
	Ok(out)
}

/// Run `pg_dump <url>` and return its SQL output.
fn pg_dump(url: &str) -> std::io::Result<Vec<u8>> {
	let output = std::process::Command::new("pg_dump").arg(url).output()?;
	if !output.status.success() {
		return Err(std::io::Error::other(
			String::from_utf8_lossy(&output.stderr).trim().to_string(),
		));
	}
	Ok(output.stdout)
}

/// Build a gzip-compressed USTAR archive from named byte entries.
fn tar_gz(entries: &[(String, Vec<u8>)]) -> std::io::Result<Vec<u8>> {
	let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
	for (name, data) in entries {
		encoder.write_all(&ustar_header(name, data.len())?)?;
		encoder.write_all(data)?;
		// Pad the file content to a 512-byte boundary.
		let pad = (512 - data.len() % 512) % 512;
		encoder.write_all(&vec![0u8; pad])?;
	}
	// Two zero blocks mark the end of the archive.
	encoder.write_all(&[0u8; 1024])?;
	encoder.finish()
}

/// One 512-byte USTAR header for a regular file.
fn ustar_header(name: &str, size: usize) -> std::io::Result<[u8; 512]> {
	if name.len() > 100 {
		return Err(std::io::Error::other(format!("path too long: {name}")));
	}
	let mut header = [0u8; 512];
	header[..name.len()].copy_from_slice(name.as_bytes());
	write_field(&mut header, 100, 8, "0000644"); // mode
	write_field(&mut header, 108, 8, "0000000"); // uid
	write_field(&mut header, 116, 8, "0000000"); // gid
	write_field(&mut header, 124, 12, &format!("{size:011o}")); // size (octal)
	write_field(&mut header, 136, 12, "00000000000"); // mtime
	header[156] = b'0'; // typeflag: regular file
	header[257..263].copy_from_slice(b"ustar\0");
	header[263..265].copy_from_slice(b"00");

	// Checksum: sum of all bytes with the checksum field treated as spaces.
	header[148..156].copy_from_slice(b"        ");
	let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
	let chksum = format!("{sum:06o}\0 ");
	header[148..148 + chksum.len()].copy_from_slice(chksum.as_bytes());
	Ok(header)
}

/// Write a NUL-terminated field into the header at `offset` (length `len`).
fn write_field(header: &mut [u8; 512], offset: usize, len: usize, value: &str) {
	let bytes = value.as_bytes();
	let n = bytes.len().min(len - 1);
	header[offset..offset + n].copy_from_slice(&bytes[..n]);
	// The remaining bytes stay NUL (already zeroed).
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
