//! Opening the account store for a CLI action.

use super::*;

/// Open the store the action will mutate. Centralising the error
/// handling keeps the per-action branches focused on their mutator.
/// `[auth] scram` is applied here because `account password` derives (or,
/// with SCRAM off, drops) the verifier from the store's flag.
pub(super) fn open_store(config: &Config) -> Result<AccountStore, StoreError> {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map(|store| store.with_scram_enabled(config.auth.scram))
	.map(|store| store.with_password_policy(crate::password::Policy::from_config(&config.auth)))
}

/// `handle_error` lives in `actions`; the umbrella module only
/// re-exports it so callers can write `account::handle_error`.
/// Common prelude every mutating action shares: [`prepare_show`], then
/// refuse a static account with the config-file hint. Returns the open
/// store, or has already printed the error and returns
/// `ExitCode::FAILURE` so the caller can early-return. Both refusals run
/// before anything is read from stdin, so nobody types a password for a
/// name that cannot take one.
pub(in crate::cli) fn prepare(config_path: &Path, name: &str) -> Result<AccountStore, ExitCode> {
	let store = prepare_show(config_path, name)?;
	if store.is_static(name) {
		return Err(crate::cli::exit::policy(format_args!(
			"account {name}: edit the config file to change a static account"
		)));
	}
	Ok(store)
}

/// Load the config, open the store and refuse a name that is neither a
/// static nor a dynamic account with `no such account: <name>`. Static
/// accounts pass: `account show` reports their public view and changes
/// nothing.
pub(in crate::cli) fn prepare_show(
	config_path: &Path,
	name: &str,
) -> Result<AccountStore, ExitCode> {
	let config = match Config::load(config_path) {
		Ok(config) => config,
		Err(error) => {
			style::error(error);
			return Err(ExitCode::FAILURE);
		}
	};
	let store = match open_store(&config) {
		Ok(store) => store,
		Err(error) => {
			style::error(format_args!("account {name}: {error}"));
			return Err(ExitCode::FAILURE);
		}
	};
	if !store.account_known(name) {
		return Err(crate::cli::exit::refused(format_args!(
			"no such account: {name}"
		)));
	}
	Ok(store)
}

/// Load the server's log pseudonym key so the pseudonyms this command
/// prints are the ones the running server writes to its log.
pub(super) fn init_log_id(config_path: &Path) -> Result<(), ExitCode> {
	let config = Config::load(config_path).map_err(|error| {
		style::error(error);
		ExitCode::FAILURE
	})?;
	crate::log_id::init(&config.data_dir).map_err(|error| {
		style::error(format_args!("cannot open the log pseudonym key: {error}"));
		ExitCode::FAILURE
	})
}
