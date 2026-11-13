//! What goes into a backup: the files under `data_dir`, and the warning
//! about every path the configuration keeps outside it.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config::{BlobBackendConfig, Config};

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
pub(super) fn warn_externally_referenced(
	config: &Config,
	archived: &usize,
	warnings: &mut impl Write,
) {
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
		// A domain's own keys are made under data_dir and are in the archive;
		// one the operator pointed elsewhere is not.
		for entry in &dkim.domain {
			for file in std::iter::once(&entry.key_file).chain(entry.rsa_key_file.as_ref()) {
				if !file.starts_with(&config.data_dir) {
					entries.push(format!(
						"[[dkim.domain]] {} key file = {}",
						entry.name,
						file.display()
					));
				}
			}
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
	for dns in &config.dns {
		let section = if config.dns.scoped() {
			format!("[[dns]] zone = {}", dns.zone)
		} else {
			"[dns]".to_string()
		};
		if let Some(path) = &dns.token_file {
			entries.push(format!("{section} token_file = {}", path.display()));
		}
		if let Some(path) = &dns.credentials_file {
			entries.push(format!("{section} credentials_file = {}", path.display()));
		}
	}

	if !entries.is_empty() {
		crate::cli::style::warn_to(
			warnings,
			format_args!(
				"this backup archives {archived} files under data_dir only. The configuration references the following paths outside data_dir that are NOT in this archive. Back them up separately or the corresponding capability will not work after a restore:"
			),
		);
		for entry in &entries {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}

	encryption_key.extend(super::keys_note::tenant_and_retired_keys(config));
	if !encryption_key.is_empty() {
		crate::cli::style::warn_to(
			warnings,
			"this backup carries the on-disk mail encrypted at rest. The [storage] encryption key is intentionally not in data_dir (storage-keygen: \"Store it off the data disk ... never written into data_dir\"). Without it the mail content in this archive is unrecoverable. Save the key separately:",
		);
		for entry in &encryption_key {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}
}

/// What `rotate --all` keeps under `rotate/` that a restore may bring back:
/// the journal of a run and the record of the last one. Everything else
/// there stays out, by name: the new secrets of an unfinished run are
/// plaintext and live only until the run hands them over, their staging
/// copies (`.secrets.json.<id>.tmp`) are the same bytes, and the lock is not
/// data. A file the command adds later is left out until it is named here.
const ROTATION_ARCHIVED: &[&str] = &["rotate/journal.json", "rotate/last-run.json"];

/// Whether a file under `data_dir` at `relative` belongs in the archive as far
/// as the rotation directory is concerned.
fn archived_from_rotation(relative: &Path) -> bool {
	!relative.starts_with("rotate")
		|| ROTATION_ARCHIVED
			.iter()
			.any(|name| relative == Path::new(name))
}

/// Every regular file under `root`, as (archive-relative path, source mode, bytes).
///
/// The mode is read from the file's metadata so the archive round-trips the
/// permission bits the operator set, including the 0o600 they relied on for
/// DKIM/ACME/TLS private keys.
pub(super) fn collect_files(root: &Path) -> std::io::Result<Vec<(String, u32, Vec<u8>)>> {
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
				// The lease file a running command holds is not data: the restore would skip
				// it anyway, and a copy records nothing but who was running.
				if relative == Path::new(".store.lock") {
					continue;
				}
				if !archived_from_rotation(relative) {
					continue;
				}
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
