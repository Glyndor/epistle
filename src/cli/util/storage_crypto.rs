//! At-rest encryption setup shared by the CLI commands that open the store.

use std::process::ExitCode;

/// Build the at-rest [`MessageCrypto`] from a loaded config, printing the
/// fail-closed error and returning `Err(FAILURE)` if the key cannot be loaded.
pub(in crate::cli) fn message_crypto(
	config: &crate::config::Config,
) -> Result<crate::storage::MessageCrypto, ExitCode> {
	let crypto = crate::storage::MessageCrypto::from_full_config(config).map_err(|error| {
		crate::cli::style::error(error);
		ExitCode::FAILURE
	})?;
	attach_config_accounts(&crypto, config).map_err(|error| {
		crate::cli::style::error(format!(
			"cannot read the accounts to pick tenant keys: {error}"
		));
		ExitCode::FAILURE
	})?;
	Ok(crypto)
}

/// Attach file-backed account sources when tenant-key selection needs them.
/// SQL/LDAP-only owners are not loaded here. Migration attaches these sources
/// unconditionally and refuses any owner they cannot resolve.
fn attach_config_accounts(
	crypto: &crate::storage::MessageCrypto,
	config: &crate::config::Config,
) -> std::io::Result<()> {
	if !config
		.tenants
		.iter()
		.any(|tenant| tenant.encryption_key_file.is_some())
	{
		return Ok(());
	}
	attach_file_accounts(crypto, config)
}

/// Attach static accounts and accounts.toml even for a server-only rotation.
pub(crate) fn attach_file_accounts(
	crypto: &crate::storage::MessageCrypto,
	config: &crate::config::Config,
) -> std::io::Result<()> {
	let store = crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| std::io::Error::other(error.to_string()))?;
	crypto.attach_accounts(std::sync::Arc::new(store.handle()));
	Ok(())
}

/// `epistle storage-keygen`: print a fresh base64 32-byte at-rest encryption key
/// to stdout for the operator to place in an env var or key file (off the data
/// disk). Mirrors `dkim-keygen`; never writes into `data_dir`.
pub(in crate::cli) fn storage_keygen(json: bool) -> ExitCode {
	match crate::storage::generate_key_base64() {
		Some(key) if json => super::output::print_json(&serde_json::json!({ "key": key })),
		Some(key) => {
			println!("{key}");
			ExitCode::SUCCESS
		}
		None => {
			crate::cli::style::error("system CSPRNG unavailable");
			ExitCode::FAILURE
		}
	}
}
