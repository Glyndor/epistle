//! `epistle backup`: write a consistent snapshot of an instance to a single
//! gzip-compressed tar (USTAR) on stdout or a file — the filesystem mail store
//! (`data_dir`, the canonical `.eml` files plus suppression and ACME state) and,
//! when a database is configured, a `pg_dump` of the metadata/antispam tables.
//! The index rebuilds from the `.eml` files, so it is not archived.
//!
//! Diagnostic warnings about state the archive does NOT carry go to a separate
//! `warnings` sink (always stderr in the CLI dispatch). Mixing those messages
//! with the tar.gz stream on stdout would corrupt the archive.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::config::{BlobBackendConfig, Config};

/// Build the snapshot, write it to `out`, and emit diagnostics to `warnings`.
pub(super) fn run(config: &Config, out: &mut impl Write, warnings: &mut impl Write) -> ExitCode {
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
			Ok(dump) => entries.push(("database.sql".to_string(), 0o644, dump)),
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
	warn_externally_referenced(config, &entries.len(), warnings);
	eprintln!("backed up {} files for this instance", entries.len());
	ExitCode::SUCCESS
}

/// Write to `warnings` a description of every path the configuration references
/// but the archive does not contain. The archive covers `data_dir` only; keys
/// for TLS, DKIM, ARC, the at-rest message encryption, the S3 blob backend and
/// the DNS provider are typically kept outside that tree (by design, for
/// encryption-at-rest) and have to be backed up separately.
///
/// Two blocks when the at-rest key is involved: the general "outside data_dir"
/// list, and a separate, more prominent block that calls out the encryption key
/// because losing it makes the mail content in the archive permanently
/// unreadable.
fn warn_externally_referenced(config: &Config, archived: &usize, warnings: &mut impl Write) {
	let mut entries: Vec<String> = Vec::new();
	let mut encryption_key: Vec<String> = Vec::new();

	if let Some(tls) = &config.tls {
		entries.push(format!("[tls] cert_file = {}", tls.cert_file.display()));
		entries.push(format!("[tls] key_file = {}", tls.key_file.display()));
		if let Some(ca) = &tls.client_ca {
			entries.push(format!("[tls] client_ca = {}", ca.display()));
		}
	}
	if let Some(dkim) = &config.dkim {
		entries.push(format!("[dkim] key_file = {}", dkim.key_file.display()));
		if let Some(rsa) = &dkim.rsa_key_file {
			entries.push(format!("[dkim] rsa_key_file = {}", rsa.display()));
		}
	}
	if let Some(arc) = &config.arc {
		entries.push(format!("[arc] key_file = {}", arc.key_file.display()));
	}
	if let Some(storage) = &config.storage {
		if storage.encrypt_at_rest {
			if let Some(path) = &storage.encryption_key_file {
				encryption_key.push(format!(
					"[storage] encryption_key_file = {}",
					path.display()
				));
			}
			if let Some(var) = &storage.encryption_key_env {
				encryption_key.push(format!("[storage] encryption_key_env = ${var}"));
			}
			if encryption_key.is_empty() {
				encryption_key.push(
					"[storage] encrypt_at_rest = true (no encryption_key_file or encryption_key_env configured)"
						.to_string(),
				);
			}
		}
		if let Some(BlobBackendConfig::S3(s3)) = &storage.blobs {
			if let Some(path) = &s3.secret_access_key_file {
				entries.push(format!(
					"[storage.blobs] secret_access_key_file = {}",
					path.display()
				));
			}
			if let Some(var) = &s3.secret_access_key_env {
				entries.push(format!("[storage.blobs] secret_access_key_env = ${var}"));
			}
		}
	}
	if let Some(dns) = &config.dns {
		if let Some(path) = &dns.token_file {
			entries.push(format!("[dns] token_file = {}", path.display()));
		}
		if let Some(path) = &dns.credentials_file {
			entries.push(format!("[dns] credentials_file = {}", path.display()));
		}
	}

	if !entries.is_empty() {
		let _ = writeln!(
			warnings,
			"warning: this backup archives {archived} files under data_dir only. The configuration references the following paths outside data_dir that are NOT in this archive — back them up separately or the corresponding capability will not work after a restore:"
		);
		for entry in &entries {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}

	if !encryption_key.is_empty() {
		let _ = writeln!(
			warnings,
			"warning: this backup carries the on-disk mail encrypted at rest. The [storage] encryption key is intentionally not in data_dir (storage-keygen: \"Store it off the data disk ... never written into data_dir\"). Without it the mail content in this archive is unrecoverable — save the key separately:"
		);
		for entry in &encryption_key {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}
}

/// Every regular file under `root`, as (archive-relative path, source mode, bytes).
///
/// The mode is read from the file's metadata so the archive round-trips the
/// permission bits the operator set — including the 0o600 they relied on for
/// DKIM/ACME/TLS private keys.
fn collect_files(root: &Path) -> std::io::Result<Vec<(String, u32, Vec<u8>)>> {
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
				let metadata = std::fs::metadata(&path)?;
				let mode = metadata.permissions().mode();
				out.push((name, mode, std::fs::read(&path)?));
			}
		}
	}
	out.sort_by(|a, b| a.0.cmp(&b.0));
	Ok(out)
}

/// Run `pg_dump` against `url` and return its SQL output.
///
/// The connection password must never reach argv — `/proc/<pid>/cmdline` is
/// world-readable while pg_dump runs. Strip it from the URL and pass it through
/// `PGPASSWORD` in the child's environment instead.
fn pg_dump(url: &str) -> std::io::Result<Vec<u8>> {
	let mut command = std::process::Command::new("pg_dump");
	if let Ok(mut parsed) = url::Url::parse(url) {
		if let Some(password) = parsed.password().map(|encoded| {
			percent_encoding::percent_decode_str(encoded)
				.decode_utf8_lossy()
				.into_owned()
		}) {
			let _ = parsed.set_password(None);
			command.env("PGPASSWORD", password);
		}
		command.arg(parsed.as_str());
	} else {
		command.arg(url);
	}
	let output = command.output()?;
	if !output.status.success() {
		return Err(std::io::Error::other(
			String::from_utf8_lossy(&output.stderr).trim().to_string(),
		));
	}
	Ok(output.stdout)
}

/// Build a gzip-compressed USTAR archive from named byte entries.
fn tar_gz(entries: &[(String, u32, Vec<u8>)]) -> std::io::Result<Vec<u8>> {
	let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
	for (name, mode, data) in entries {
		encoder.write_all(&ustar_header(name, *mode, data.len())?)?;
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
///
/// `mode` is the permission bits to write into the header, masked to the lower
/// 12 bits (perm + setuid/setgid/sticky) so the file-type bits from
/// `Permissions::mode()` don't leak into the tar mode field.
fn ustar_header(name: &str, mode: u32, size: usize) -> std::io::Result<[u8; 512]> {
	if name.len() > 100 {
		return Err(std::io::Error::other(format!("path too long: {name}")));
	}
	let mut header = [0u8; 512];
	header[..name.len()].copy_from_slice(name.as_bytes());
	write_field(&mut header, 100, 8, &format!("{:07o}", mode & 0o7777)); // mode
	write_field(&mut header, 108, 8, "0000000"); // uid
	write_field(&mut header, 116, 8, "0000000"); // gid
	write_field(&mut header, 124, 12, &format!("{size:011o}")); // size (octal)
	write_field(&mut header, 136, 12, "00000000000"); // mtime
	header[156] = b'0'; // typeflag: regular file
	header[257..263].copy_from_slice(b"ustar\0");
	header[263..265].copy_from_slice(b"00");

	// Checksum: sum of all bytes with the checksum field treated as spaces.
	// Computed after the mode is written — a checksum over the wrong mode
	// produces a tar `tar` itself rejects.
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

/// Helpers shared between [`tests`] and [`tests_b`]: the in-process tar/gzip
/// reader and the extraction utility used by the round-trip restore test.
#[cfg(test)]
mod helpers {
	use std::io::Read;

	use flate2::read::GzDecoder;

	/// Gunzip an archive and return its raw tar bytes.
	pub(super) fn gunzip(data: &[u8]) -> Vec<u8> {
		let mut decoder = GzDecoder::new(data);
		let mut out = Vec::new();
		decoder.read_to_end(&mut out).expect("gunzip");
		out
	}

	/// Walk a tar's 512-byte blocks, returning (name, content) for each file.
	pub(super) fn read_tar(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
		read_tar_entries(tar)
			.into_iter()
			.map(|(name, _mode, content)| (name, content))
			.collect()
	}

	/// Walk a tar's 512-byte blocks, returning (name, mode, content) for each
	/// file. The mode is read from the 8-byte octal mode field at offset 100.
	pub(super) fn read_tar_entries(tar: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
		let mut out = Vec::new();
		let mut offset = 0;
		while offset + 512 <= tar.len() {
			let header = &tar[offset..offset + 512];
			if header.iter().all(|&b| b == 0) {
				break; // end-of-archive zero block
			}
			// USTAR magic must be present.
			assert_eq!(&header[257..262], b"ustar", "missing ustar magic");
			let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
			let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
			let mode_str = String::from_utf8_lossy(&header[100..108]);
			let mode = u32::from_str_radix(mode_str.trim_matches('\0').trim(), 8).unwrap_or(0);
			let size_str = String::from_utf8_lossy(&header[124..135]);
			let size = usize::from_str_radix(size_str.trim_matches('\0').trim(), 8).unwrap_or(0);
			offset += 512;
			out.push((name, mode, tar[offset..offset + size].to_vec()));
			offset += size.div_ceil(512) * 512;
		}
		out
	}

	/// Extract the gunzipped tar bytes into `target`, stripping the `data/`
	/// prefix `collect_files` adds so the result is laid out exactly like the
	/// source data_dir. The round-trip test treats the extracted tree as the
	/// "new" data_dir.
	pub(super) fn extract_to(archive_gz: &[u8], target: &std::path::Path) {
		let tar = gunzip(archive_gz);
		for (name, mode, content) in read_tar_entries(&tar) {
			let stripped = name.strip_prefix("data/").unwrap_or(&name);
			let dest = target.join(stripped);
			if let Some(parent) = dest.parent() {
				std::fs::create_dir_all(parent).expect("mkdir parent");
			}
			std::fs::write(&dest, &content).expect("write entry");
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))
					.expect("chmod");
			}
		}
	}
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "backup_restore_tests.rs"]
mod tests_b;
