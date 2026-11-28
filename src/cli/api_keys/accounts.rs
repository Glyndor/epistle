//! The accounts `epistle api-key create --account` binds a key to.

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::AccountStore;

/// The accounts of this server, static and dynamic. The API resolves an
/// account-bound key to its account through the same directory delivery and
/// IMAP use, so either kind can hold one. A store that cannot be opened is an
/// operation failure, not an unknown name.
pub(super) fn open_accounts(config: &Config) -> Result<AccountStore, ExitCode> {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| {
		crate::cli::style::error(format_args!("opening account store: {error}"));
		ExitCode::FAILURE
	})
}
