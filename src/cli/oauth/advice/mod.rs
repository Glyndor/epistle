//! What an operator of a bearer-token sign-in should know about the
//! configuration, said where they look after an edit (`config-check`,
//! `status`) and once at startup.

use crate::config::Config;

/// Whether `[oauth]` names an external provider: the section is there and
/// has no signing key of its own.
fn external(config: &Config) -> Option<&crate::config::Oauth> {
	config
		.oauth
		.as_ref()
		.filter(|oauth| oauth.signing_key.is_none() && oauth.signing_key_file.is_none())
}

/// What an external provider has to do for its users to get in, as a line to
/// read and not a fault to fix: the provider may well emit the claim.
pub(in crate::cli) fn notice(config: &Config) -> Option<String> {
	external(config)
		.filter(|oauth| !oauth.allow_unverified_email)
		.map(|_| {
			"[oauth] bearer sign-in takes the address from the email claim and needs email_verified to be true; if the provider does not emit it, the log says so on the first refused token and allow_unverified_email = true accepts it"
				.to_string()
		})
}

/// The warnings about `[oauth]`, in the order they print. Empty without an
/// external provider: the built-in authorization server's tokens carry the
/// account and come after the second factor.
pub(in crate::cli) fn advice(config: &Config) -> Vec<String> {
	if external(config).is_none() {
		return Vec::new();
	}
	let store = crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	);
	match store {
		// The directory enforces a TOTP secret only for the accounts of the
		// account store, which is where every secret lives.
		Ok(store) => advice_for(
			config,
			store
				.dynamic_accounts()
				.iter()
				.filter(|account| account.totp_secret.is_some())
				.count(),
		),
		Err(error) => vec![format!(
			"[oauth] the account store cannot be read ({error}), so accounts with a TOTP secret, which cannot sign in with a bearer token, are not counted"
		)],
	}
}

/// Build the verifier of `[oauth]` and say the advisories in the log, once
/// at startup.
pub(in crate::cli) async fn build_and_say(
	config: &Config,
) -> std::io::Result<Option<std::sync::Arc<crate::oauth::OauthVerifier>>> {
	let verifier = crate::cli::serve::tasks::build_oauth_verifier(config).await?;
	if let Some(line) = notice(config) {
		tracing::info!("{line}");
	}
	for line in advice(config) {
		tracing::warn!("{line}");
	}
	Ok(verifier)
}

/// [`advice`] for a known number of accounts with a TOTP secret.
fn advice_for(config: &Config, two_factor: usize) -> Vec<String> {
	let Some(oauth) = external(config) else {
		return Vec::new();
	};
	if two_factor > 0 && !oauth.idp_enforces_second_factor {
		return vec![format!(
			"[oauth] {two_factor} account(s) have a TOTP secret and cannot sign in with a bearer token; set idp_enforces_second_factor = true only if the provider enforces its own second factor"
		)];
	}
	Vec::new()
}

#[cfg(test)]
mod tests;
