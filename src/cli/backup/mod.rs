//! The `epistle backup` and `epistle restore` subcommands.
//!
//! The full module used to live in a single `backup.rs`. The dump
//! (and replay) of the database split out into `db_dump.rs` to keep
//! this file under the per-file 500-code-line cap; the test
//! modules are split into the same-named `*_tests_<topic>.rs`
//! siblings and re-pulled in with `#[path]` so each compile unit
//! stays small.

mod db_dump;
mod restore_files;

use restore_files::lay_files;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::config::{BlobBackendConfig, Config};

use db_dump::{DATABASE_SQL_NAME, collect_dump_with, load_dump_with};

/// Run the `backup` subcommand. Builds the entries, writes the tar.gz, emits
/// warnings. A configured database whose dump cannot be taken is a hard
/// error: an archive without the database is worse than no archive, because
/// the operator only finds out at restore time that the accounts and the
/// antispam state are gone.
pub(super) fn run(config: &Config, out: &mut impl Write, warnings: &mut impl Write) -> ExitCode {
	run_with(config, out, warnings, &db_dump::default_program_resolver)
}

/// Same as [`run`] with a custom program resolver. Tests use the
/// resolver to point `pg_dump` and `psql` at a stub in a tempdir
/// without touching the process `PATH`; production callers pass the
/// default, which is a no-op.
pub(super) fn run_with(
	config: &Config,
	out: &mut impl Write,
	warnings: &mut impl Write,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> ExitCode {
	let mut entries = match collect_files(&config.data_dir) {
		Ok(entries) => entries,
		Err(error) => {
			super::style::error(format_args!("reading data dir: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if let Some(db) = &config.database {
		let dump = match collect_dump_with(db, &config.data_dir, resolver) {
			Ok(dump) => dump,
			Err(error) => {
				super::style::error(format_args!("database dump: {error}"));
				return ExitCode::FAILURE;
			}
		};
		entries.push((DATABASE_SQL_NAME.to_string(), 0o644, dump));
	}
	let archive = match tar_gz(&entries) {
		Ok(archive) => archive,
		Err(error) => {
			super::style::error(format_args!("building archive: {error}"));
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

/// Run the `restore` subcommand. Reads a tar.gz from `archive`, lays the
/// `data/` entries down under `data_dir`, and replays `database.sql` against
/// the configured database when the archive carries one. The hard rule is
/// the same as the backup path: a `database.sql` in the archive that cannot
/// be loaded is a restore error, never a silent skip.
pub(super) fn run_restore(config: &Config, archive: &[u8], out: &mut impl Write) -> ExitCode {
	run_restore_with(config, archive, out, &db_dump::default_program_resolver)
}

/// Same as [`run_restore`] with a custom program resolver. The test
/// path passes a resolver that returns absolute paths to its stubs;
/// production callers pass the default, which is a no-op and lets
/// `Command::new` resolve through `PATH` exactly as it always has.
pub(super) fn run_restore_with(
	config: &Config,
	archive: &[u8],
	out: &mut impl Write,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> ExitCode {
	let tar = match gunzip_archive(archive) {
		Ok(tar) => tar,
		Err(error) => {
			super::style::error(format_args!("reading archive: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let entries = read_tar_entries_pub(&tar);
	if entries.is_empty() {
		super::style::error("archive is empty");
		return ExitCode::FAILURE;
	}
	if let Err(error) = lay_files(&entries, &config.data_dir) {
		super::style::error(format_args!("laying down files: {error}"));
		return ExitCode::FAILURE;
	}
	if let Some(db) = &config.database {
		let Some((_, sql)) = entries
			.iter()
			.find(|(name, _, _)| name == DATABASE_SQL_NAME)
			.map(|(n, _, c)| (n.clone(), c.clone()))
		else {
			super::style::error("archive has no database.sql but [database] is configured");
			return ExitCode::FAILURE;
		};
		if let Err(error) = load_dump_with(db, &config.data_dir, &sql, resolver) {
			super::style::error(format_args!("database load: {error}"));
			return ExitCode::FAILURE;
		}
	}
	writeln!(out, "restored {} entries", entries.len()).ok();
	ExitCode::SUCCESS
}

/// Gunzip an archive and return its raw tar bytes. Tiny wrapper over
/// `flate2::read::GzDecoder` so the call site in `run_restore` surfaces
/// any decode error with a real `io::Error` rather than a panic.
fn gunzip_archive(data: &[u8]) -> std::io::Result<Vec<u8>> {
	use std::io::Read;
	let mut decoder = flate2::read::GzDecoder::new(data);
	let mut out = Vec::new();
	decoder.read_to_end(&mut out)?;
	Ok(out)
}

/// Walk a tar's 512-byte blocks, returning (name, mode, content) for each
/// file. The mode is read from the 8-byte octal mode field at offset 100.
fn read_tar_entries_pub(tar: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
	let mut out = Vec::new();
	let mut offset = 0;
	while offset + 512 <= tar.len() {
		let header = &tar[offset..offset + 512];
		if header.iter().all(|&b| b == 0) {
			break; // end-of-archive zero block
		}
		if &header[257..262] != b"ustar" {
			break;
		}
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
		super::style::warn_to(
			warnings,
			format_args!(
				"this backup archives {archived} files under data_dir only. The configuration references the following paths outside data_dir that are NOT in this archive. Back them up separately or the corresponding capability will not work after a restore:"
			),
		);
		for entry in &entries {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}

	if !encryption_key.is_empty() {
		super::style::warn_to(
			warnings,
			"this backup carries the on-disk mail encrypted at rest. The [storage] encryption key is intentionally not in data_dir (storage-keygen: \"Store it off the data disk ... never written into data_dir\"). Without it the mail content in this archive is unrecoverable. Save the key separately:",
		);
		for entry in &encryption_key {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}
}

/// Every regular file under `root`, as (archive-relative path, source mode, bytes).
///
/// The mode is read from the file's metadata so the archive round-trips the
/// permission bits the operator set, including the 0o600 they relied on for
/// DKIM/ACME/TLS private keys.
fn collect_files(root: &Path) -> std::io::Result<Vec<(String, u32, Vec<u8>)>> {
	let _warnings = crate::util::fs_walk::warning_scope();
	let mut out = Vec::new();
	let mut stack = vec![root.to_path_buf()];
	while let Some(dir) = stack.pop() {
		let entries = match crate::util::fs_walk::read_dir(&dir) {
			Ok(entries) => entries,
			// A missing data dir yields an empty backup, not an error.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => return Err(error),
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if entry.file_type()?.is_dir() {
				stack.push(path);
			} else if entry.file_type()?.is_file()
				&& let Ok(relative) = path.strip_prefix(root)
			{
				let name = format!("data/{}", relative.to_string_lossy());
				let metadata = entry.metadata()?;
				let mode = metadata.permissions().mode();
				out.push((name, mode, crate::util::fs_walk::read(&path)?));
			}
		}
	}
	out.sort_by(|a, b| a.0.cmp(&b.0));
	Ok(out)
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
	// Computed after the mode is written, a checksum over the wrong mode
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

// The database dump/load code is split out into `db_dump` (the
// sibling module at the top of this file) so each compile unit
// stays under the per-file 500-line cap. Re-export the items the
// existing tests reach for so the test files' `use super::*;`
// glob keeps working unchanged.
#[allow(unused_imports)]
pub(crate) use db_dump::CapturedOutput;
#[allow(unused_imports)]
pub(super) use db_dump::collect_dump;
#[allow(unused_imports)]
pub(super) use db_dump::container_cp_into_spec;
#[allow(unused_imports)]
pub(super) use db_dump::container_pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::container_psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::host_pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::host_psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::load_dump;
#[allow(unused_imports)]
pub(super) use db_dump::load_dump_container;
#[allow(unused_imports)]
pub(super) use db_dump::pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::run_command_capturing_stdout;
// Test-only re-exports: the existing test files use `use super::*;`
// to reach `BackupError`, `CommandSpec`, and `split_url_password`.
// `pub(crate)` is the widest visibility a child of a non-public
// module can give; the test files are grandchildren of `crate::cli`
// and the re-export must reach them.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use db_dump::{BackupError, CommandSpec, split_url_password};

#[cfg(test)]
mod helpers {
	use std::path::Path;

	/// Gunzip an archive and return its raw tar bytes. Kept under
	/// `helpers` so the existing `use super::helpers::*;` glob in the
	/// sibling test files picks it up unchanged.
	pub(super) fn gunzip(data: &[u8]) -> Vec<u8> {
		let mut decoder = flate2::read::GzDecoder::new(data);
		let mut out = Vec::new();
		std::io::Read::read_to_end(&mut decoder, &mut out).expect("gunzip");
		out
	}

	/// Walk a tar's 512-byte blocks, returning (name, content) for each
	/// file.
	pub(super) fn read_tar(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
		read_tar_entries(tar)
			.into_iter()
			.map(|(name, _mode, content)| (name, content))
			.collect()
	}

	/// Walk a tar's 512-byte blocks, returning (name, mode, content).
	pub(super) fn read_tar_entries(tar: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
		let mut out = Vec::new();
		let mut offset = 0;
		while offset + 512 <= tar.len() {
			let header = &tar[offset..offset + 512];
			if header.iter().all(|&b| b == 0) {
				break; // end-of-archive zero block
			}
			if &header[257..262] != b"ustar" {
				break;
			}
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
	/// prefix `collect_files` adds.
	pub(super) fn extract_to(archive_gz: &[u8], target: &Path) {
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
#[path = "../backup_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../backup_restore_tests.rs"]
mod tests_b;

#[cfg(test)]
#[path = "../backup_pg_tests.rs"]
mod tests_pg;

#[cfg(test)]
#[path = "../backup_container_tests.rs"]
mod tests_container;

#[cfg(test)]
#[path = "../backup_restore_run_tests.rs"]
mod tests_restore_run;

#[cfg(test)]
#[path = "../backup_tests_paths.rs"]
mod tests_paths;
