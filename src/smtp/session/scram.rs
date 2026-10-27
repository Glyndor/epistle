//! SCRAM-SHA-256 authentication exchange over SMTP AUTH (RFC 4954 + 5802).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::super::directory::bans::BanOutcome;
use super::super::directory::{ScramPlan, ScramRefusal};
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
		/// `Some` when the server-first was built on decoy credentials: the
		/// exchange cannot succeed, and the refusal says whether it still
		/// counts as a failed attempt (see [`ScramRefusal`]). A banned
		/// subject who completes the exchange must not clear the ban with a
		/// valid proof nor extend it with a bad one.
		refusal: Option<ScramRefusal>,
	},
}

impl Session {
	/// Inject a fixed SCRAM server nonce, so tests are deterministic.
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
			// A malformed client-first (invalid base64) is a failure, but
			// the IP ban is consulted first so a banned peer cannot extend
			// its own ban by sending garbage: refused attempts never record
			// a strike. With no username there is no account row to check,
			// so the ban is the IP ban only.
			if self.is_ip_banned() {
				return self.scram_failure();
			}
			self.record_scram_outcome("", None, false, false);
			return self.scram_failure();
		};
		let Some(username) = username_of(&client_first) else {
			// A well-formed base64 client-first without a username tag is
			// still a malformed client-first. The same IP-ban-first rule
			// applies: a banned peer must not be able to extend its own
			// ban by sending repeated tag-less garbage.
			if self.is_ip_banned() {
				return self.scram_failure();
			}
			self.record_scram_outcome("", None, false, false);
			return self.scram_failure();
		};
		// The directory plans the whole exchange: the ban check comes before
		// any credential lookup, and an account that may not sign in with
		// SCRAM (disabled, second factor, protocol not allowed) or a login
		// under a ban gets decoy credentials. Either way the wire shows the
		// same `334` and then a `535` at client-final, exactly as a wrong
		// proof would, so nothing tells a refusal from a bad password.
		let plan = self
			.directory
			.plan_scram(&username, self.peer_ip, self.auth_protocol);
		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure: fail closed rather than use a predictable nonce.
			self.count_scram_failure(&username, &plan);
			return self.scram_failure();
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) = server.first(&client_first, &plan.credentials) else {
			self.count_scram_failure(&username, &plan);
			return self.scram_failure();
		};
		self.pending_scram = Some(PendingScram::ClientFinal {
			server: Box::new(server),
			credentials: Box::new(plan.credentials),
			account: plan.account,
			refusal: plan.refusal,
		});
		Action::CollectAuthResponse(Reply::single(334, &BASE64.encode(server_first)))
	}

	/// Count a failure that ends an exchange before the proof, unless a ban
	/// caused it: a ban refusal never moves the strike count.
	fn count_scram_failure(&self, username: &str, plan: &ScramPlan) {
		match &plan.refusal {
			Some(ScramRefusal::Banned) => {}
			Some(ScramRefusal::Denied { account }) => {
				self.record_scram_outcome(username, account.as_deref(), false, false);
			}
			None => self.record_scram_outcome(username, Some(&plan.account), false, false),
		}
	}

	/// Process the base64 client-final message: verify the proof and, on
	/// success, authenticate and return the server signature.
	pub(super) fn scram_client_final(
		&mut self,
		encoded: &str,
		mut server: ScramServer,
		credentials: ScramCredentials,
		account: &str,
		refusal: Option<ScramRefusal>,
	) -> Action {
		// A refused exchange stays refused at client-final. A ban that was in
		// force at client-first holds even if it has since expired: a banned
		// subject must not clear the row with a valid proof (the credentials
		// here are decoys) nor extend it with a bad one (no strike is
		// recorded). An account the rules refuse ends as one failed attempt.
		// The recheck below catches a ban that fires after the client-first.
		match refusal {
			Some(ScramRefusal::Banned) => return self.scram_failure(),
			Some(ScramRefusal::Denied { account: counted }) => {
				self.record_scram_outcome(account, counted.as_deref(), false, false);
				return self.scram_failure();
			}
			None => {}
		}
		// The recheck at client-final: a ban that fired between
		// client-first and client-final still refuses the exchange,
		// because `Banned` is only emitted when the ban is in force at
		// the time of the check.
		// The flag that decides whether the success lifts the ban rows
		// comes from THIS check, not from any value carried from
		// client-first: between the two messages a ban can fire
		// (turning a `Clear` into a `Banned` that the recheck refuses)
		// or lapse (turning a `BannedButKnown` into a `Clear` that
		// lifts the ban as a normal success would).
		let bypassed = match self
			.directory
			.check_ban(account, self.peer_ip, self.auth_protocol)
		{
			BanOutcome::Banned => return self.scram_failure(),
			BanOutcome::BannedButKnown { .. } => true,
			BanOutcome::Clear { .. } => false,
		};
		let Some(client_final) = decode(encoded) else {
			self.record_scram_outcome(account, Some(account), false, false);
			return self.scram_failure();
		};
		match server.finish(&client_final, &credentials) {
			Ok(server_final) => {
				// Clear the ban store for both subjects on a successful
				// proof; the ban check at client-first already consulted
				// the same store with the same keys, so the success here
				// undoes any in-flight strikes the same way the PLAIN path
				// does. A bypass lift keeps the ban row in force: only
				// the bypass list gets refreshed.
				self.record_scram_outcome(account, Some(account), true, bypassed);
				self.authenticated = Some(account.to_string());
				Action::Continue(Reply::single(
					235,
					&format!("2.7.0 {}", BASE64.encode(server_final)),
				))
			}
			Err(_) => {
				self.record_scram_outcome(account, Some(account), false, false);
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
	/// success clears both subjects unless the proof was a bypass lift
	/// (`bypassed = true`), in which case only the bypass list is
	/// refreshed; a failure records a strike against both. The ban
	/// check at the start of the exchange already decided whether to
	/// refuse the attempt; a ban refusal never reaches this helper, so
	/// the strike count and ban expiry stay where they were.
	fn record_scram_outcome(
		&self,
		login: &str,
		account: Option<&str>,
		success: bool,
		bypassed: bool,
	) {
		self.directory.record_ban_outcome(
			login,
			account,
			success,
			bypassed,
			self.peer_ip,
			self.auth_protocol,
		);
	}

	/// Whether the peer IP is currently banned. Used by the malformed
	/// client-first branches, which never see a username and so cannot
	/// consult the account ban: only the IP ban can refuse them. A
	/// banned IP must not be able to extend its own ban by sending
	/// garbage, so the branches short-circuit here before recording a
	/// strike.
	fn is_ip_banned(&self) -> bool {
		matches!(
			self.directory
				.check_ban("", self.peer_ip, self.auth_protocol),
			BanOutcome::Banned
		)
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
