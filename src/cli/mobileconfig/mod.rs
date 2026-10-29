//! `mail mobileconfig`: emit an Apple `.mobileconfig` configuration profile for
//! an account, so an iOS/macOS user can auto-configure Mail by installing it
//! (the profile is distributed to the user, e.g. emailed or downloaded). The
//! autoconfig listener serves the same profile at `/mobileconfig?email=`.

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::AccountStore;

/// Write the profile for `account` to `out`. IMAP over implicit TLS (993) and
/// submission over STARTTLS (587), both authenticated with the account address.
pub(super) fn run(config: &Config, account: &str, out: &mut impl std::io::Write) -> ExitCode {
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening account store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let Some((_, addresses, _)) = store
		.account_views()
		.into_iter()
		.find(|(name, _, _)| name == account)
	else {
		super::style::error(format_args!("no such account \"{account}\""));
		return ExitCode::FAILURE;
	};
	let Some(email) = addresses.first() else {
		super::style::error(format_args!("account \"{account}\" has no address"));
		return ExitCode::FAILURE;
	};

	let profile = crate::autodiscovery::mobileconfig::profile(account, email, &config.hostname);
	if out.write_all(profile.as_bytes()).is_err() {
		super::style::error("writing profile");
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
mod tests;
