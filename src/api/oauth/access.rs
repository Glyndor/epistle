//! Only locally issued, scoped access tokens authenticate JMAP.

use crate::api::{ApiState, Credential, Principal};
use crate::jwt::{self, Algorithm, Claims, Validation};

impl super::AuthzServer {
	/// Verify before interpreting any application claims. Refusals disclose nothing.
	pub(super) fn access_claims(&self, token: &str, now: u64) -> Option<Claims> {
		if token.is_empty()
			|| token.len() > 1024
			|| self.issuer.is_empty()
			|| self.audience.is_empty()
		{
			return None;
		}
		let claims = jwt::validate(
			token,
			Algorithm::Es256,
			&self.public_key,
			&Validation {
				now,
				issuer: Some(&self.issuer),
				audience: Some(&self.audience),
			},
		)
		.ok()?;
		let issued = claims.raw.get("iat")?.as_u64()?;
		let expires = claims.raw.get("exp")?.as_u64()?;
		if let Some(nbf) = claims.raw.get("nbf")
			&& nbf.as_u64()? > now
		{
			return None;
		}
		if issued > now || expires <= issued || expires - issued > super::ACCESS_TOKEN_TTL_SECS {
			return None;
		}
		let subject = claims.string("sub")?;
		if subject.is_empty() || subject.chars().any(char::is_control) {
			return None;
		}
		super::scopes::Scopes::parse(claims.string("scope")?)?;
		let id = claims.string("jti")?;
		if id.len() != 43
			|| !id
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
		{
			return None;
		}
		Some(claims)
	}
}

impl ApiState {
	/// Called at HTTP authentication and again when a long-lived stream rechecks.
	pub(in crate::api) fn oauth_principal(
		&self,
		token: &str,
		client_ip: Option<std::net::IpAddr>,
	) -> Option<Principal> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.ok()?
			.as_secs();
		let claims = self.authz()?.access_claims(token, now)?;
		if !super::revocation::is_live(self.data_dir(), claims.string("jti")?, now) {
			return None;
		}
		let account = claims.string("sub")?;
		if self.store().is_locked(account) || !self.accounts().iter().any(|a| a.name == account) {
			return None;
		}
		let scopes = super::scopes::Scopes::parse(claims.string("scope")?)?.into_vec();
		Some(Principal::of_oauth(
			account.to_owned(),
			scopes,
			Credential {
				token: token.to_owned(),
				client_ip,
			},
		))
	}
}

pub(in crate::api) fn is_jmap_path(path: &str) -> bool {
	path == "/.well-known/jmap" || path.starts_with("/jmap/")
}
