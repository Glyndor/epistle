//! What an operator of a bearer-token sign-in should know about the
//! configuration, said where they look after an edit (`config-check`,
//! `status`) and once at startup.

use crate::config::Config;

/// The advisories about `[oauth]`, in the order they print. Empty without
/// the section, and for the built-in authorization server, whose tokens carry
/// the account and come after the second factor.
pub(super) fn advice(config: &Config) -> Vec<String> {
	if config.oauth.is_none() {
		return Vec::new();
	}
	let store = crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	);
	let two_factor = store.map_or(0, |store| {
		store
			.dynamic_accounts()
			.iter()
			.filter(|account| account.totp_secret.is_some())
			.count()
	});
	advice_for(config, two_factor)
}

/// Build the verifier of `[oauth]` and say the advisories in the log, once
/// at startup.
pub(super) async fn build_and_say(
	config: &Config,
) -> std::io::Result<Option<std::sync::Arc<crate::oauth::OauthVerifier>>> {
	let verifier = super::serve_tasks::build_oauth_verifier(config).await?;
	for line in advice(config) {
		tracing::warn!("{line}");
	}
	Ok(verifier)
}

/// [`advice`] for a known number of accounts with a TOTP secret.
fn advice_for(config: &Config, two_factor: usize) -> Vec<String> {
	let Some(oauth) = &config.oauth else {
		return Vec::new();
	};
	if oauth.signing_key.is_some() || oauth.signing_key_file.is_some() {
		return Vec::new();
	}
	let mut lines = Vec::new();
	if !oauth.allow_unverified_email {
		lines.push(
			"[oauth] bearer sign-in needs a token whose email_verified claim is true; if the provider does not emit it, sign-ins fail until allow_unverified_email = true is set"
				.to_string(),
		);
	}
	if two_factor > 0 && !oauth.idp_enforces_second_factor {
		lines.push(format!(
			"[oauth] {two_factor} account(s) have a TOTP secret and cannot sign in with a bearer token; set idp_enforces_second_factor = true only if the provider enforces its own second factor"
		));
	}
	lines
}

#[cfg(test)]
#[path = "oauth_advice_tests.rs"]
mod tests;
