//! IMAP AUTHENTICATE: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS (RFC 5802,
//! RFC 7677).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::smtp::directory::bans::BanOutcome;
use crate::smtp::directory::{ScramPlan, ScramRefusal};
use crate::smtp::scram::{ChannelBinding, ScramCredentials, ScramServer, username_of};

use super::super::{Output, Session};
use super::PendingAuth;
use super::mechanisms::{continuation, decode};

impl Session {
	/// The channel-binding policy for a SCRAM exchange (mirrors the SMTP side):
	/// `-PLUS` binds to the certificate hash; plain SCRAM over a bound link
	/// rejects downgrades; without a binding it is unsupported.
	fn scram_binding(&self, plus: bool) -> ChannelBinding {
		match (&self.cbind_data, plus) {
			(Some(hash), true) => ChannelBinding::Required(hash.clone()),
			(Some(_), false) => ChannelBinding::Supported,
			(None, _) => ChannelBinding::Unsupported,
		}
	}

	/// Begin SCRAM-SHA-256(-PLUS): process the optional SASL-IR client-first, or
	/// prompt for it with an empty continuation.
	pub(in crate::imap::session) fn scram_begin(
		&mut self,
		tag: &str,
		initial: Option<String>,
		plus: bool,
	) -> Output {
		let binding = self.scram_binding(plus);
		match initial {
			Some(client_first) => self.scram_first(tag, &client_first, binding),
			None => {
				self.pending_auth = Some(PendingAuth::ScramFirst {
					tag: tag.to_string(),
					binding,
				});
				continuation("")
			}
		}
	}

	pub(in crate::imap::session) fn scram_first(
		&mut self,
		tag: &str,
		encoded: &str,
		binding: ChannelBinding,
	) -> Output {
		let Some(client_first) = decode(encoded) else {
			// A malformed client-first (invalid base64) is a failure, but
			// the IP ban is consulted first so a banned peer cannot extend
			// its own ban by sending garbage: refused attempts never record
			// a strike. With no username there is no account row to check,
			// so the ban is the IP ban only.
			if self.is_ip_banned() {
				return self.auth_failure(tag);
			}
			self.record_scram_outcome("", None, false, false);
			return self.auth_failure(tag);
		};
		let Some(username) = username_of(&client_first) else {
			// A well-formed base64 client-first without a username tag is
			// still a malformed client-first. The same IP-ban-first rule
			// applies: a banned peer must not be able to extend its own
			// ban by sending repeated tag-less garbage.
			if self.is_ip_banned() {
				return self.auth_failure(tag);
			}
			self.record_scram_outcome("", None, false, false);
			return self.auth_failure(tag);
		};
		// The directory plans the whole exchange: the ban check comes before
		// any credential lookup, and an account that may not sign in with
		// SCRAM (disabled, second factor, protocol not allowed) or a login
		// under a ban gets decoy credentials. Either way the wire shows the
		// same `+` continuation and then a `NO` at client-final, exactly as a
		// wrong proof would, so nothing tells a refusal from a bad password.
		let plan = self
			.directory
			.plan_scram(&username, self.peer_ip, self.auth_protocol);
		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure: fail closed rather than use a predictable nonce.
			self.count_scram_failure(&username, &plan);
			return self.auth_failure(tag);
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) = server.first(&client_first, &plan.credentials) else {
			self.count_scram_failure(&username, &plan);
			return self.auth_failure(tag);
		};
		self.pending_auth = Some(PendingAuth::ScramFinal {
			tag: tag.to_string(),
			server: Box::new(server),
			credentials: Box::new(plan.credentials),
			account: plan.account,
			refusal: plan.refusal,
		});
		continuation(&BASE64.encode(server_first))
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

	#[allow(clippy::too_many_arguments)]
	pub(in crate::imap::session) fn scram_final(
		&mut self,
		tag: &str,
		encoded: &str,
		mut server: ScramServer,
		credentials: ScramCredentials,
		account: &str,
		refusal: Option<ScramRefusal>,
	) -> Output {
		// A refused exchange stays refused at client-final. A ban that was in
		// force at client-first holds even if it has since expired: a banned
		// subject must not clear the row with a valid proof (the credentials
		// here are decoys) nor extend it with a bad one (no strike is
		// recorded). An account the rules refuse ends as one failed attempt.
		// The recheck below catches a ban that fires after the client-first.
		match refusal {
			Some(ScramRefusal::Banned) => return self.auth_failure(tag),
			Some(ScramRefusal::Denied { account: counted }) => {
				self.record_scram_outcome(account, counted.as_deref(), false, false);
				return self.auth_failure(tag);
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
			BanOutcome::Banned => return self.auth_failure(tag),
			BanOutcome::BannedButKnown { .. } => true,
			BanOutcome::Clear { .. } => false,
		};
		let Some(client_final) = decode(encoded) else {
			self.record_scram_outcome(account, Some(account), false, false);
			return self.auth_failure(tag);
		};
		match server.finish(&client_final, &credentials) {
			Ok(server_final) => {
				// Clear the ban store for both subjects on a successful
				// proof; the ban check at client-first already consulted
				// the store with the same keys, so the success here undoes
				// any in-flight strikes the same way the PLAIN path does.
				// A bypass lift keeps the ban row in force: only the
				// bypass list gets refreshed.
				self.record_scram_outcome(account, Some(account), true, bypassed);
				self.auth_success(
					tag,
					account.to_string(),
					&format!(
						"[SASL {}] AUTHENTICATE completed",
						BASE64.encode(server_final)
					),
				)
			}
			Err(_) => {
				self.record_scram_outcome(account, Some(account), false, false);
				self.auth_failure(tag)
			}
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

	fn fresh_nonce(&self) -> Option<String> {
		if let Some(nonce) = &self.scram_nonce {
			return Some(nonce.clone());
		}
		use ring::rand::SecureRandom;
		let mut bytes = [0u8; 18];
		// Fail closed if the CSPRNG cannot produce a nonce.
		ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
		Some(BASE64.encode(bytes))
	}
}
