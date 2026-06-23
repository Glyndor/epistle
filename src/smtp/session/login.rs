//! Password-based SMTP authentication: SASL PLAIN and the LOGIN mechanism
//! (legacy clients), both verified through the directory (password + TOTP).

use base64::Engine;

use super::{Action, Reply, Session};

impl Session {
	/// Verify a SASL PLAIN response (`\0authcid\0password`).
	pub(super) fn verify_plain(&mut self, encoded: &str) -> Action {
		let Ok(credentials) = super::super::auth::parse_plain(encoded) else {
			return self.auth_fail();
		};
		// Password + any TOTP second factor, or an app password (CIDR-checked
		// against the peer IP); no oracle (unknown user == bad pw).
		match self.directory.authenticate_with_ip(
			&credentials.authcid,
			&credentials.password,
			self.peer_ip,
		) {
			Some(account) => self.auth_success(account),
			None => self.auth_fail(),
		}
	}

	/// AUTH LOGIN: record the (base64) username and prompt for the password.
	pub(super) fn login_username(&mut self, encoded: &str) -> Action {
		let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
			return self.auth_fail();
		};
		self.pending_login = Some(Some(String::from_utf8_lossy(&bytes).into_owned()));
		Action::CollectAuthResponse(Reply::single(334, "UGFzc3dvcmQ6"))
	}

	/// AUTH LOGIN: verify the (base64) password against the recorded username.
	pub(super) fn login_password(&mut self, user: &str, encoded: &str) -> Action {
		let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
			return self.auth_fail();
		};
		match self.directory.authenticate_with_ip(
			user,
			&String::from_utf8_lossy(&bytes),
			self.peer_ip,
		) {
			Some(account) => self.auth_success(account),
			None => self.auth_fail(),
		}
	}

	/// SASL EXTERNAL: authenticate as the identity in the verified client
	/// certificate. The optional authzid (base64, or `=`/empty) must be empty or
	/// equal the certificate identity — no acting as another user.
	pub(super) fn verify_external(&mut self, encoded: &str) -> Action {
		let Some(identity) = self.client_identity.clone() else {
			// EXTERNAL without a verified client certificate: never succeeds.
			return self.auth_fail();
		};
		let trimmed = encoded.trim();
		let authzid = if trimmed.is_empty() || trimmed == "=" {
			String::new()
		} else {
			match base64::engine::general_purpose::STANDARD.decode(trimmed) {
				Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
				Err(_) => return self.auth_fail(),
			}
		};
		if !authzid.is_empty() && authzid != identity {
			return self.auth_fail();
		}
		// Resolve the certificate's email identity to a local account.
		match crate::smtp::address::Address::parse(&identity) {
			Ok(address) => match self.directory.resolve(&address) {
				crate::smtp::directory::Resolution::Account(account) => self.auth_success(account),
				_ => self.auth_fail(),
			},
			Err(_) => self.auth_fail(),
		}
	}

	fn auth_success(&mut self, account: String) -> Action {
		self.authenticated = Some(account);
		Action::Continue(Reply::single(235, "2.7.0 authentication successful"))
	}
}
