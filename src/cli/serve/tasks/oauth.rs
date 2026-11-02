//! OAuth2/OIDC verifier and authorization-server wiring for `serve`.

use std::sync::Arc;

use crate::config::Config;

/// Build the OAuth2/OIDC token verifier from `[oauth]`, fetching the JWKS once
/// and spawning an hourly refresh when OIDC discovery is configured. A malformed
/// configuration or an initial fetch failure is fatal (fail closed). Returns
/// `Ok(None)` when no `[oauth]` section is present.
pub(in crate::cli) async fn build_oauth_verifier(
	config: &Config,
) -> std::io::Result<Option<Arc<crate::oauth::OauthVerifier>>> {
	let Some(oauth) = &config.oauth else {
		return Ok(None);
	};
	oauth
		.validate()
		.map_err(|e| std::io::Error::other(format!("oauth config: {e}")))?;
	let verifier = match (&oauth.public_key, &oauth.discovery_url) {
		(Some(public_key), _) => crate::oauth::OauthVerifier::new(
			&oauth.issuer,
			&oauth.audience,
			&oauth.algorithm,
			public_key,
		)
		.map_err(|e| std::io::Error::other(format!("oauth config: {e:?}")))?,
		(None, Some(discovery_url)) => {
			let default_alg = parse_oauth_alg(&oauth.algorithm)?;
			let discovery_url = crate::oauth::oidc::parse_endpoint(discovery_url)
				.map_err(|e| std::io::Error::other(format!("oauth config: {e}")))?;
			let keys = crate::oauth::oidc::fetch_keys(
				&crate::oauth::oidc::client_builder,
				&discovery_url,
				default_alg,
				oauth.allow_private_jwks,
				&crate::oauth::oidc::SystemResolver,
			)
			.await
			.map_err(|e| std::io::Error::other(format!("oauth discovery: {e}")))?;
			let verifier =
				crate::oauth::OauthVerifier::from_jwks(&oauth.issuer, &oauth.audience, keys);
			spawn_jwks_refresh(
				verifier.jwks_cache(),
				discovery_url,
				default_alg,
				oauth.allow_private_jwks,
			);
			verifier
		}
		(None, None) => unreachable!("validate() rejects the no-source case"),
	};
	Ok(Some(Arc::new(verifier.declared_by(oauth))))
}

/// Build the built-in OAuth authorization server from `[oauth] signing_key` or
/// `signing_key_file`, or
/// `None` when no signing key is configured (the `/oauth/*` grant routes then
/// stay unmounted — fail closed). The signed tokens carry the configured
/// issuer/audience and verify against the configured `public_key`.
pub(in crate::cli::serve) fn build_authz_server(
	config: &Config,
) -> std::io::Result<Option<crate::api::oauth::AuthzServer>> {
	let Some(oauth) = config.oauth.as_ref() else {
		return Ok(None);
	};
	let Some(signing_key) = oauth.signing_key_material()? else {
		return Ok(None);
	};
	Ok(crate::api::oauth::AuthzServer::new(
		&signing_key,
		&oauth.issuer,
		&oauth.audience,
	))
}

/// Map the configured algorithm name to a [`crate::jwt::Algorithm`], the default
/// applied to a JWKS key that omits its own `alg`.
fn parse_oauth_alg(algorithm: &str) -> std::io::Result<crate::jwt::Algorithm> {
	match algorithm.to_ascii_uppercase().as_str() {
		"RS256" => Ok(crate::jwt::Algorithm::Rs256),
		"ES256" => Ok(crate::jwt::Algorithm::Es256),
		_ => Err(std::io::Error::other("oauth config: unsupported algorithm")),
	}
}

/// Spawn the hourly JWKS refresh: re-fetch the IdP's keys and swap them into the
/// shared cache so rotated keys are picked up without a restart. A failed fetch
/// keeps the previous keys (it does not clear the cache).
fn spawn_jwks_refresh(
	cache: Option<Arc<std::sync::RwLock<Vec<crate::oauth::Jwk>>>>,
	discovery_url: crate::net::HttpsUrl,
	default_alg: crate::jwt::Algorithm,
	allow_private_jwks: bool,
) {
	let Some(cache) = cache else {
		return;
	};
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		let resolver = crate::oauth::oidc::SystemResolver;
		loop {
			ticker.tick().await;
			match crate::oauth::oidc::fetch_keys(
				&crate::oauth::oidc::client_builder,
				&discovery_url,
				default_alg,
				allow_private_jwks,
				&resolver,
			)
			.await
			{
				Ok(keys) => {
					if let Ok(mut guard) = cache.write() {
						*guard = keys;
					}
				}
				Err(error) => tracing::warn!(%error, "oidc jwks refresh failed"),
			}
		}
	});
}
