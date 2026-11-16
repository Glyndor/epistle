//! Token lifetimes of the built-in authorization server (`[oauth]
//! access_token_ttl_secs` and `refresh_token_ttl_secs`).
//!
//! The defaults are what the server did before they were settings: an access
//! token lives one hour and no refresh token exists. The bounds are the floor
//! and ceiling the loader enforces. An access token shorter than a minute
//! cannot be used by a client that polls once a minute, and one longer than a
//! day outlives a revoked grant for too long, because an access token is only
//! checked against the revocation list and the account, not renewed. A
//! refresh token is rotated on every use, so its lifetime is how long an idle
//! client stays signed in, and a year is the most the loader allows.

use super::oauth::{Oauth, OauthConfigError};

/// Access token lifetime when `access_token_ttl_secs` is absent.
pub const DEFAULT_ACCESS_TTL_SECS: u64 = 3600;
/// Shortest access token lifetime the loader accepts.
pub const MIN_ACCESS_TTL_SECS: u64 = 60;
/// Longest access token lifetime the loader accepts.
pub const MAX_ACCESS_TTL_SECS: u64 = 86_400;
/// Shortest refresh token lifetime the loader accepts.
pub const MIN_REFRESH_TTL_SECS: u64 = 3600;
/// Longest refresh token lifetime the loader accepts.
pub const MAX_REFRESH_TTL_SECS: u64 = 31_536_000;

impl Oauth {
	/// The access token lifetime in seconds: the configured one, or an hour.
	pub fn access_token_ttl(&self) -> u64 {
		self.access_token_ttl_secs
			.unwrap_or(DEFAULT_ACCESS_TTL_SECS)
	}

	/// The refresh token lifetime in seconds, or `None` when refresh tokens
	/// are not issued.
	pub fn refresh_token_ttl(&self) -> Option<u64> {
		self.refresh_token_ttl_secs
	}

	/// Refuse a lifetime outside its bounds, one set without a signing key,
	/// and a refresh token that would expire before its access token.
	pub(super) fn validate_lifetimes(&self) -> Result<(), OauthConfigError> {
		let issues = self.signing_key.is_some() || self.signing_key_file.is_some();
		if !issues
			&& (self.access_token_ttl_secs.is_some() || self.refresh_token_ttl_secs.is_some())
		{
			return Err(OauthConfigError::LifetimeWithoutSigningKey);
		}
		if let Some(access) = self.access_token_ttl_secs
			&& !(MIN_ACCESS_TTL_SECS..=MAX_ACCESS_TTL_SECS).contains(&access)
		{
			return Err(OauthConfigError::AccessLifetimeOutOfRange(access));
		}
		if let Some(refresh) = self.refresh_token_ttl_secs {
			if !(MIN_REFRESH_TTL_SECS..=MAX_REFRESH_TTL_SECS).contains(&refresh) {
				return Err(OauthConfigError::RefreshLifetimeOutOfRange(refresh));
			}
			if refresh < self.access_token_ttl() {
				return Err(OauthConfigError::RefreshShorterThanAccess);
			}
		}
		Ok(())
	}
}

impl OauthConfigError {
	/// The message of a lifetime error, or `None` for any other.
	pub(super) fn lifetime_message(&self) -> Option<String> {
		Some(match self {
			Self::LifetimeWithoutSigningKey => "`access_token_ttl_secs` and \
				`refresh_token_ttl_secs` need `signing_key` or `signing_key_file`: without \
				one no token is issued"
				.to_string(),
			Self::AccessLifetimeOutOfRange(value) => format!(
				"`access_token_ttl_secs` ({value}) must be between {MIN_ACCESS_TTL_SECS} and \
				 {MAX_ACCESS_TTL_SECS} seconds"
			),
			Self::RefreshLifetimeOutOfRange(value) => format!(
				"`refresh_token_ttl_secs` ({value}) must be between {MIN_REFRESH_TTL_SECS} and \
				 {MAX_REFRESH_TTL_SECS} seconds"
			),
			Self::RefreshShorterThanAccess => "`refresh_token_ttl_secs` must not be shorter \
				than `access_token_ttl_secs`"
				.to_string(),
			_ => return None,
		})
	}
}

#[cfg(test)]
mod tests;
