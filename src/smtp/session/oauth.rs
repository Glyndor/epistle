//! OAUTHBEARER / XOAUTH2 SASL over SMTP AUTH (RFC 7628), backed by the
//! configured OAuth token verifier.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::super::directory::bearer_proof;
use super::super::reply::Reply;
use super::{Action, Session};

impl Session {
	/// Attach an OAuth token verifier (enables OAUTHBEARER/XOAUTH2).
	pub fn with_oauth(mut self, verifier: std::sync::Arc<crate::oauth::OauthVerifier>) -> Self {
		self.oauth = Some(verifier);
		self
	}

	/// The advertised `AUTH` capability line, including the OAuth mechanisms
	/// when a verifier is configured.
	pub(super) fn auth_capability(&self) -> String {
		// Shared mechanism set: -PLUS only with a bound certificate hash, the
		// OAuth mechanisms only with a configured verifier.
		let mut mechs = String::from("AUTH");
		for mechanism in crate::sasl::available(
			self.client_identity.is_some(),
			self.cbind_data.is_some(),
			self.scram_enabled,
			self.oauth.is_some(),
		) {
			mechs.push(' ');
			mechs.push_str(mechanism.name());
		}
		mechs
	}

	/// Authenticate with an OAUTHBEARER/XOAUTH2 bearer token. The token must be
	/// supplied as the initial SASL response (SASL-IR).
	pub(super) fn oauth_bearer(&mut self, _mechanism: &str, initial: Option<String>) -> Action {
		let Some(verifier) = self.oauth.clone() else {
			return Action::Continue(Reply::single(504, "5.5.4 mechanism not supported"));
		};
		let proof = bearer_proof(Some(&verifier));
		let outcome = initial
			.as_deref()
			.and_then(parse_bearer)
			.and_then(|token| verifier.verify_identity(&token, unix_now()))
			.and_then(|verified| verified.account(&self.directory))
			.and_then(|account| {
				// The account rules (disabled, protocol allowlist) apply to a
				// bearer token as to a password: the token proves who the
				// caller is, not that the account may sign in. A refusal
				// answers like a wrong token, so the wire response does not
				// reveal that the account exists.
				self.directory
					.admit_login(&account, self.auth_protocol, proof)
					.then_some(account)
			});
		match outcome {
			Some(account) => {
				self.authenticated = Some(account);
				Action::Continue(Reply::single(235, "2.7.0 authentication successful"))
			}
			None => self.oauth_failure(),
		}
	}

	fn oauth_failure(&mut self) -> Action {
		self.auth_failures += 1;
		tracing::warn!(
			failures = self.auth_failures,
			"SMTP OAuth authentication failed"
		);
		let reply = Reply::single(535, "5.7.8 authentication credentials invalid");
		if self.auth_failures >= 3 {
			Action::Close(reply)
		} else {
			Action::Continue(reply)
		}
	}
}

/// Extract the bearer token from a base64 OAUTHBEARER/XOAUTH2 initial response.
/// Both encode `...auth=Bearer <token>\x01...`.
fn parse_bearer(encoded: &str) -> Option<String> {
	let decoded = BASE64.decode(encoded).ok()?;
	let text = String::from_utf8(decoded).ok()?;
	let rest = text.split("auth=Bearer ").nth(1)?;
	let token = rest.split('\x01').next()?.trim();
	if token.is_empty() {
		return None;
	}
	Some(token.to_string())
}

fn unix_now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}
