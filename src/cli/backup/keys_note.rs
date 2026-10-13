//! What `backup` and `restore` tell the operator about the keys `init` keeps
//! beside data_dir rather than in it (see `init::host_secrets`).

use std::io::Write;
use std::path::Path;

use crate::cli::init::host_secrets;

/// After a backup: name the storage and OAuth signing keys found beside
/// data_dir, which the archive does not carry. Says nothing when neither
/// is there.
pub(super) fn after_backup(data_dir: &Path, warnings: &mut impl Write) {
	let present: Vec<_> = [
		host_secrets::storage_key(data_dir),
		host_secrets::oauth_signing_key(data_dir),
	]
	.into_iter()
	.filter(|path| path.is_file())
	.collect();
	if present.is_empty() {
		return;
	}
	super::super::style::warn_to(
		warnings,
		"the storage key and the OAuth signing key are kept outside data_dir and are not in this \
		 archive. Mail encrypted at rest is unreadable without the storage key. Save them \
		 separately, apart from the archive:",
	);
	for path in present {
		let _ = writeln!(warnings, "  - {}", path.display());
	}
}

/// After a restore: say where the keys must be before the stack starts, or,
/// for an archive from before they moved, that `stack update` moves the
/// copies it just laid down under data_dir.
pub(super) fn after_restore(
	data_dir: &Path,
	entries: &[(String, u32, Vec<u8>)],
	status: &mut impl Write,
) {
	let legacy: Vec<_> = [host_secrets::STORAGE_KEY, host_secrets::OAUTH_SIGNING_KEY]
		.into_iter()
		.filter(|name| {
			entries
				.iter()
				.any(|(entry, _, _)| *entry == format!("data/keys/{name}"))
		})
		.map(|name| host_secrets::legacy(data_dir, name))
		.collect();
	if legacy.is_empty() {
		let _ = writeln!(
			status,
			"backups do not carry the storage key or the OAuth signing key; put the ones this \
			 install used back at {} and {} (mode 0600, owned by the service account) before \
			 `epistle stack up`; without the storage key, mail encrypted at rest stays unreadable",
			host_secrets::storage_key(data_dir).display(),
			host_secrets::oauth_signing_key(data_dir).display(),
		);
	} else {
		let names: Vec<String> = legacy
			.iter()
			.map(|path| path.display().to_string())
			.collect();
		let _ = writeln!(
			status,
			"this archive is from before the keys moved out of data_dir; {} were restored there, \
			 and `epistle stack update` moves them to {}",
			names.join(" and "),
			host_secrets::dir(data_dir).display(),
		);
	}
}

#[cfg(test)]
#[path = "keys_note_tests.rs"]
mod tests;
