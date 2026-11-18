//! Compose rewrite lock acquisition.

use crate::config::Config;

/// The lock that guards a rewrite of the generated compose file.
///
/// It is taken after the common lock, never before it: a command that
/// holds the common lock and waits for this one, and a command that holds
/// this one and waits for the common one, would wait for each other. Every
/// command that writes the generated file takes the two locks in that
/// order, so a rewrite of the file never loses the change another writer
/// made.
///
/// `None` when the install has no generated file (a host install): there is
/// nothing to guard, and the command writes no file.
pub(in crate::cli::dns_provider) fn lock_compose(
	config: &Config,
) -> Result<Option<crate::storage::lock::FileLock>, String> {
	let path = crate::cli::init::compose_file_path(&config.data_dir);
	if !path.exists() {
		return Ok(None);
	}
	let lock = crate::storage::locked::lock_path(&path);
	Ok(Some(crate::cli::compose::lock::acquire(&lock)?))
}
