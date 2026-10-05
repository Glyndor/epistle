//! SCRAM-SHA-256 authentication exchange over SMTP AUTH (RFC 4954 + 5802).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::super::directory::bans::BanOutcome;
use super::super::reply::Reply;
use super::super::scram::{ChannelBinding, ScramCredentials, ScramServer, username_of};
use super::{Action, Session};

/// In-flight SCRAM state between AUTH rounds.
#[derive(Debug)]
pub(super) enum PendingScram {
	/// Server sent `334 ` (empty); awaiting the client-first message. Carries
	/// the channel-binding policy chosen for the mechanism the client picked.
	ClientFirst(ChannelBinding),
	/// Server sent the server-first challenge; awaiting the client-final.
	ClientFinal {
		server: Box<ScramServer>,
		credentials: Box<ScramCredentials>,
		account: String,
	},
}

impl Session {
	/// Inject a fixed SCRAM server nonce (tests/determinism).
	pub fn with_scram_nonce(mut self, nonce: &str) -> Self {
		self.scram_nonce = Some(nonce.to_string());
		self
	}

	/// The channel-binding policy for a SCRAM exchange: `-PLUS` binds to the
	/// certificate hash; plain SCRAM over a bound link rejects downgrades;
	/// without a known binding (cleartext) it is unsupported.
	pub(super) fn scram_binding(&self, plus: bool) -> ChannelBinding {
		match (&self.cbind_data, plus) {
			(Some(hash), true) => ChannelBinding::Required(hash.clone()),
			(Some(_), false) => ChannelBinding::Supported,
			(None, _) => ChannelBinding::Unsupported,
		}
	}

	/// Begin SCRAM-SHA-256(-PLUS): process the optional initial client-first, or
	/// prompt for it with an empty challenge.
	pub(super) fn scram_begin(&mut self, initial: Option<String>, plus: bool) -> Action {
		let binding = self.scram_binding(plus);
		match initial {
			Some(client_first) => self.scram_client_first(&client_first, binding),
			None => {
				self.pending_scram = Some(PendingScram::ClientFirst(binding));
				Action::CollectAuthResponse(Reply::single(334, ""))
			}
		}
	}

	/// Process the base64 client-first message: look up the user's SCRAM
	/// credentials and answer with the server-first challenge.
	pub(super) fn scram_client_first(&mut self, encoded: &str, binding: ChannelBinding) -> Action {
		let Some(client_first) = decode(encoded) else {
			// A malformed client-first (invalid base64) still counts as
			// an authentication failure for the shared ban accounting.
			// The login and the resolved account are both unknown, so
			// the IP-side strike is the only one recorded.
			self.record_scram_outcome("", None, false);
			return self.scram_failure();
		};
		let Some(username) = username_of(&client_first) else {
			// A well-formed base64 client-first without a username tag
			// is still a malformed client-first for ban accounting.
			self.record_scram_outcome("", None, false);
			return self.scram_failure();
		};
		// Ban check before any credential lookup: an active ban on the
		// client IP or on the account short-circuits the exchange with the
		// same wire outcome as a wrong SCRAM proof (a 334 with a fake
		// server-first, then 535 at client-final), and the SCRAM
		// credential lookup never happens. A ban refusal is distinct from
		// a credential failure: the strike count and ban expiry do not
		// move, so the ban keeps ending when it was going to end. The
		// fake server-first keeps the refusal indistinguishable from a
		// normal exchange on the wire; the fake credentials make every
		// client proof fail the same way a wrong password would.
		let resolved = match self
			.directory
			.check_ban(&username, self.peer_ip, self.auth_protocol)
		{
			BanOutcome::Banned => {
				return self.scram_ban_refusal(&client_first, binding, &username);
			}
			BanOutcome::Clear { account } => account,
		};
		// From here on, any failure records a strike against the IP and
		// against the account the credential check resolved. The account
		// starts as whatever the ban check saw and is replaced once
		// `scram_credentials` confirms it.
		let mut account_for_record = resolved;
		// Resolve credentials and the canonical account name (no oracle: a
		// missing user fails exactly like a bad password later).
		let Some(credentials) = self.directory.scram_credentials(&username) else {
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.scram_failure();
		};
		let Some((account, _)) = self.directory.credentials(&username) else {
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.scram_failure();
		};
		account_for_record = Some(account.clone());
		// SCRAM reaches the directory through scram_credentials(), not
		// authenticate_with_ip — the per-account `allowed_protocols` check
		// has to be issued here too. A restricted account fails closed
		// with the same wire outcome as a wrong SCRAM proof.
		if !self
			.directory
			.is_protocol_allowed(&account, self.auth_protocol)
		{
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.scram_failure();
		}

		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure: fail closed rather than use a predictable nonce.
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.scram_failure();
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) = server.first(&client_first, &credentials) else {
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.scram_failure();
		};
		self.pending_scram = Some(PendingScram::ClientFinal {
			server: Box::new(server),
			credentials: Box::new(credentials),
			account,
		});
		Action::CollectAuthResponse(Reply::single(334, &BASE64.encode(server_first)))
	}

	/// A ban refusal at client-first: build a server-first from fake
	/// SCRAM credentials so the wire reply is the same `334` a normal
	/// exchange produces, then stash the fake server and credentials in
	/// `pending_scram` so the client-final handler will see the proof
	/// fail exactly like a wrong password. The strike count and ban
	/// expiry stay where they were: a ban refusal is distinct from a
	/// credential failure, and no `record_ban_outcome` call follows.
	/// The username from the client-first is stashed as the account so
	/// the client-final ban recheck can resolve and consult the same
	/// account ban the client-first check saw.
	fn scram_ban_refusal(
		&mut self,
		client_first: &str,
		binding: ChannelBinding,
		username: &str,
	) -> Action {
		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure while building the fake server-first: the
			// no-oracle fallback is the immediate 535 a malformed
			// exchange would produce. A banned subject still cannot
			// authenticate, the ban is unchanged, and the refusal
			// remains indistinguishable from a wrong-password 535.
			return self.scram_failure();
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) = server.first(client_first, &fake_scram_credentials())
		else {
			return self.scram_failure();
		};
		self.pending_scram = Some(PendingScram::ClientFinal {
			server: Box::new(server),
			credentials: Box::new(fake_scram_credentials()),
			account: username.to_string(),
		});
		Action::CollectAuthResponse(Reply::single(334, &BASE64.encode(server_first)))
	}

	/// Process the base64 client-final message: verify the proof and, on
	/// success, authenticate and return the server signature.
	pub(super) fn scram_client_final(
		&mut self,
		encoded: &str,
		mut server: ScramServer,
		credentials: ScramCredentials,
		account: &str,
	) -> Action {
		// Recheck the ban before evaluating the proof: a ban triggered
		// between client-first and client-final must not be bypassed by a
		// pending proof. The ban refusal is distinct from a credential
		// failure: no strike is recorded, so a banned subject that
		// completes a SCRAM exchange cannot clear its own ban with a
		// valid proof and cannot extend the ban with a bad one.
		if matches!(
			self.directory
				.check_ban(account, self.peer_ip, self.auth_protocol),
			BanOutcome::Banned
		) {
			return self.scram_failure();
		}
		let Some(client_final) = decode(encoded) else {
			self.record_scram_outcome(account, Some(account), false);
			return self.scram_failure();
		};
		match server.finish(&client_final, &credentials) {
			Ok(server_final) => {
				// Clear the ban store for both subjects on a successful
				// proof; the ban check at client-first already consulted
				// the same store with the same keys, so the success here
				// undoes any in-flight strikes the same way the PLAIN path
				// does.
				self.record_scram_outcome(account, Some(account), true);
				self.authenticated = Some(account.to_string());
				Action::Continue(Reply::single(
					235,
					&format!("2.7.0 {}", BASE64.encode(server_final)),
				))
			}
			Err(_) => {
				self.record_scram_outcome(account, Some(account), false);
				self.scram_failure()
			}
		}
	}

	/// A failed SCRAM step: clear state, count the failure, and reply 535
	/// (closing after repeated failures), with no user/password oracle.
	fn scram_failure(&mut self) -> Action {
		self.pending_scram = None;
		self.auth_failures += 1;
		tracing::warn!(
			failures = self.auth_failures,
			"SMTP SCRAM authentication failed"
		);
		let reply = Reply::single(535, "5.7.8 authentication credentials invalid");
		if self.auth_failures >= 3 {
			Action::Close(reply)
		} else {
			Action::Continue(reply)
		}
	}

	/// Write the outcome of a SCRAM authentication attempt back to the
	/// shared ban store, keyed exactly as the PLAIN path keys it
	/// (`ip:<peer>` and the account the credential check resolved). A
	/// success clears both subjects; a failure records a strike against
	/// both. The ban check at the start of the exchange already decided
	/// whether to refuse the attempt; a ban refusal never reaches this
	/// helper, so the strike count and ban expiry stay where they were.
	fn record_scram_outcome(&self, login: &str, account: Option<&str>, success: bool) {
		self.directory.record_ban_outcome(
			login,
			account,
			success,
			self.peer_ip,
			self.auth_protocol,
		);
	}

	/// The SCRAM server nonce: the injected one in tests, else fresh randomness.
	/// `None` if the CSPRNG fails (fail closed).
	fn fresh_nonce(&self) -> Option<String> {
		if let Some(nonce) = &self.scram_nonce {
			return Some(nonce.clone());
		}
		use ring::rand::SecureRandom;
		let mut bytes = [0u8; 18];
		ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
		Some(BASE64.encode(bytes))
	}
}

fn decode(encoded: &str) -> Option<String> {
	String::from_utf8(BASE64.decode(encoded).ok()?).ok()
}

/// SCRAM credentials with a fixed salt and zero keys, used only to
/// build a server-first message the client can echo back. The
/// `StoredKey` is all zeros, so any client proof that comes back will
/// fail the verifier exactly like a wrong password — which is the
/// point: the ban refusal looks like a wrong password on the wire.
fn fake_scram_credentials() -> super::super::scram::ScramCredentials {
	super::super::scram::ScramCredentials {
		salt: vec![0u8; 16],
		iterations: 4096,
		stored_key: [0u8; 32],
		server_key: [0u8; 32],
	}
}
