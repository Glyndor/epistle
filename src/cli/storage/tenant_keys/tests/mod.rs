pub use super::*;

pub(super) mod base;
mod exclusion;
mod resume_safety;

/// Exercise the production traversal under the same lease as the CLI.
fn migrate(
	data_dir: &Path,
	crypto: &MessageCrypto,
	options: &Options,
	hooks: &mut dyn Hooks,
	out: &mut impl Write,
	status: &mut impl Write,
) -> ExitCode {
	let _store = match crate::storage::lock::FileLock::store_exclusive(data_dir) {
		Ok(guard) => guard,
		Err(error) => return fail(status, error),
	};
	migrate_locked(data_dir, crypto, options, hooks, out, status)
}

mod blob_coverage;
mod owners;
mod remote;
