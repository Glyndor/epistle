//! Password-based SMTP authentication: SASL PLAIN and the LOGIN mechanism
//! (legacy clients), both verified through the directory (password + TOTP).

use base64::Engine;

use super::super::directory::Proof;
use super::super::directory::hash_gate::Verdict;
use super::{Action, Reply, Session};

impl Session {
	/// The password checks are queued to the limit: a temporary failure, not
	/// a wrong credential, and not counted as one.
	fn auth_busy(&mut self) -> Action {
		Action::Continue(Reply::single(454, "4.7.0 Temporary authentication failure"))
	}

	/// Verify a SASL PLAIN response (`\0authcid\0password`).
	pub(super) fn verify_plain(&mut self, encoded: &str) -> Action {
		let Ok(credentials) = super::super::auth::parse_plain(encoded) else {
			return self.auth_fail();
		};
		// Password + any TOTP second factor, or an app password (CIDR-checked
		// against the peer IP); no oracle (unknown user == bad pw). The
		// protocol tag is the listener kind this session serves (Submission
		// or Submissions), so a per-account `allowed_protocols` that does
		// not include it rejects exactly like an unknown login.
		match self.directory.authenticate_verdict(
			&credentials.authcid,
			&credentials.password,
			self.peer_ip,
			self.auth_protocol,
		) {
			Verdict::Admitted { account, label } => self.auth_success(account, label),
			Verdict::Refused => self.auth_fail(),
			Verdict::Busy => self.auth_busy(),
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
		match self.directory.authenticate_verdict(
			user,
			&String::from_utf8_lossy(&bytes),
			self.peer_ip,
			self.auth_protocol,
		) {
			Verdict::Admitted { account, label } => self.auth_success(account, label),
			Verdict::Refused => self.auth_fail(),
			Verdict::Busy => self.auth_busy(),
		}
	}

	/// SASL EXTERNAL: authenticate as the identity in the verified client
	/// certificate. The optional authzid (base64, or `=`/empty) must be empty or
	/// equal the certificate identity — no acting as another user.
	pub(super) fn verify_external(&mut self, encoded: &str) -> Action {
		let Some(identity) = self.client_identity.clone() else {
			// EXTERNAL without a verified client certificate: never succeeds.
			return self.auth_fail_external();
		};
		let trimmed = encoded.trim();
		let authzid = if trimmed.is_empty() || trimmed == "=" {
			String::new()
		} else {
			match base64::engine::general_purpose::STANDARD.decode(trimmed) {
				Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
				Err(_) => return self.auth_fail_external(),
			}
		};
		if !authzid.is_empty() && authzid != identity {
			return self.auth_fail_external();
		}
		// Resolve the certificate's email identity to a local account, then
		// apply the account rules (disabled, protocol allowlist) for this
		// session's listener kind. EXTERNAL reaches the directory through
		// resolve(), not authenticate_with_ip, so the rules have to be asked
		// for here, with the same outcome as a missing or untrusted
		// certificate.
		let account = match crate::smtp::address::Address::parse(&identity) {
			Ok(address) => match self.directory.resolve_exact(&address) {
				Some(account) => account,
				None => return self.auth_fail_external(),
			},
			Err(_) => return self.auth_fail_external(),
		};
		if !self
			.directory
			.admit_login(&account, self.auth_protocol, Proof::Federated)
		{
			return self.auth_fail_external();
		}
		// The exchange succeeded. The line that says so at the default
		// level: the password path writes the audit channel instead, and
		// this mechanism never reached it.
		crate::smtp::session_log::authentication(
			&crate::log_id::account(&account),
			self.auth_protocol.as_str(),
			"EXTERNAL",
			crate::smtp::session_log::SUCCEEDED,
			self.auth_failures,
		);
		self.auth_success(account, None)
	}

	/// A refused SASL EXTERNAL exchange. The attempt is recorded at the
	/// default level, and the account is not named: the wire answer
	/// does not say which account the client tried to be either.
	fn auth_fail_external(&mut self) -> Action {
		self.auth_failures += 1;
		crate::smtp::session_log::authentication(
			crate::smtp::session_log::UNKNOWN,
			self.auth_protocol.as_str(),
			"EXTERNAL",
			crate::smtp::session_log::FAILED,
			self.auth_failures,
		);
		self.auth_fail_counted()
	}

	fn auth_success(&mut self, account: String, label: Option<String>) -> Action {
		self.authenticated = Some(account);
		self.auth_app_password_label = label;
		Action::Continue(Reply::single(235, "2.7.0 authentication successful"))
	}
}
