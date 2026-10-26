//! IMAP AUTHENTICATE OAUTHBEARER and XOAUTH2 (RFC 7628), with or without a
//! SASL-IR initial response (RFC 4959).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::smtp::directory::bearer_proof;

use super::auth::{PendingAuth, continuation, decode};
use super::state::State;
use super::{Output, Session};

/// The failure document of RFC 7628 section 3.2.2, sent as the error
/// challenge. It names no scope and no discovery URL: the server has none to
/// offer, and the status alone tells the client the token was not accepted.
const ERROR_CHALLENGE: &str = r#"{"status":"invalid_token"}"#;

impl Session {
	/// Start an OAuth exchange. With an initial response the token is checked
	/// at once; without one the server sends an empty continuation and reads
	/// the client's message on the next line, as PLAIN does.
	pub(super) fn oauth_begin(&mut self, tag: &str, initial: Option<String>) -> Output {
		match initial {
			Some(_) => self.oauth_bearer(tag, initial),
			None => {
				self.pending_auth = Some(PendingAuth::Bearer {
					tag: tag.to_string(),
				});
				continuation("")
			}
		}
	}

	/// Authenticate with the bearer token in a base64 OAUTHBEARER/XOAUTH2
	/// client message.
	pub(super) fn oauth_bearer(&mut self, tag: &str, initial: Option<String>) -> Output {
		let proof = bearer_proof(self.oauth.as_deref());
		let outcome = self
			.oauth
			.clone()
			.zip(initial)
			.and_then(|(verifier, enc)| {
				let token = parse_bearer(&enc)?;
				verifier
					.verify_identity(&token, unix_now())?
					.account(&self.directory)
			})
			.and_then(|account| {
				// The account rules (disabled, protocol allowlist) apply to a
				// bearer token as to a password, with the same wire outcome as
				// an unverifiable token.
				self.directory
					.admit_login(&account, self.auth_protocol, proof)
					.then_some(account)
			});
		match outcome {
			Some(account) => self.auth_success(tag, account, "AUTHENTICATE completed"),
			None => self.oauth_failure(tag),
		}
	}

	/// A token that did not open the account: send the RFC 7628 error
	/// challenge and wait for the client's acknowledgement, which then ends
	/// in the usual `NO` and is the one counted as the failed attempt. The
	/// attempt that would close the connection skips the challenge and
	/// closes at once.
	fn oauth_failure(&mut self, tag: &str) -> Output {
		let last_attempt = matches!(
			self.state,
			State::NotAuthenticated { login_failures } if login_failures + 1 >= 3
		);
		if last_attempt {
			return self.auth_failure(tag);
		}
		self.pending_auth = Some(PendingAuth::BearerError {
			tag: tag.to_string(),
		});
		continuation(&BASE64.encode(ERROR_CHALLENGE))
	}
}

/// Extract the bearer token from a base64 OAUTHBEARER/XOAUTH2 initial response.
fn parse_bearer(encoded: &str) -> Option<String> {
	let text = decode(encoded)?;
	let token = text
		.split("auth=Bearer ")
		.nth(1)?
		.split('\x01')
		.next()?
		.trim();
	(!token.is_empty()).then(|| token.to_string())
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}
