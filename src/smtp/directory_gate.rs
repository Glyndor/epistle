//! The account rules every proof of identity passes before a session opens.
//!
//! A login reaches the directory in one of three ways: a secret checked by
//! [`Directory::authenticate_with_ip`] (PLAIN, LOGIN, POP3, ManageSieve,
//! WebDAV, the API), a SCRAM exchange driven by the session, or an identity
//! asserted by something else (an OAuth bearer token, a TLS client
//! certificate). The rules about the account itself must not depend on which
//! way it was: [`Directory::admit_login`] is the single place that states
//! them, and every path ends by asking it.

use ring::hmac;

use super::bans::BanOutcome;
use super::*;
use crate::smtp::scram::{SCRAM_ITERATIONS, ScramCredentials};

/// What proved the identity that asks to be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
	/// A password or app password checked by the directory, with the TOTP
	/// code its account requires.
	Password,
	/// A SCRAM exchange. The proof is derived from the password alone, so
	/// there is no room for a TOTP code.
	Scram,
	/// An identity vouched for by a bearer token or a client certificate. The
	/// second factor, if any, belongs to whoever issued it.
	Federated,
}

/// How a SCRAM exchange that cannot succeed is carried on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScramRefusal {
	/// A ban is in force: the exchange runs on decoy credentials and moves
	/// no strike count.
	Banned,
	/// The account may not sign in this way: the exchange runs on decoy
	/// credentials and ends as one failed attempt against `account`.
	Denied {
		/// The account the attempt is counted against, when the login named one.
		account: Option<String>,
	},
}

/// What the server answers to a SCRAM client-first message.
#[derive(Debug)]
pub struct ScramPlan {
	/// The credentials the server-first and the proof check use: the
	/// account's own, or decoys that no proof can satisfy.
	pub credentials: ScramCredentials,
	/// The name the exchange runs under: the resolved account, or the login
	/// as presented when there is none.
	pub account: String,
	/// `None` for a real exchange.
	pub refusal: Option<ScramRefusal>,
}

impl Directory {
	/// Whether `account` may open a session on `protocol` now that `proof`
	/// has identified it. The rules, in one place for every mechanism:
	///
	/// - an administratively disabled account never signs in;
	/// - the account's protocol allowlist must include `protocol`;
	/// - SCRAM is refused for an account with a second factor, because the
	///   proof cannot carry the code and accepting it would skip the factor.
	///
	/// A login by an address in a switched-off domain is refused earlier, when
	/// the address fails to resolve to an account.
	pub fn admit_login(
		&self,
		account: &str,
		protocol: crate::config::Protocol,
		proof: Proof,
	) -> bool {
		let account = account.to_ascii_lowercase();
		if self.disabled.contains(&account) {
			return false;
		}
		if !self.is_protocol_allowed(&account, protocol) {
			return false;
		}
		!(proof == Proof::Scram && self.totp.contains_key(&account))
	}

	/// Plan the answer to a SCRAM client-first message for `username`. Bans
	/// are consulted before any credential lookup. A login that cannot finish
	/// the exchange (a ban, an account the rules refuse, a login nobody holds,
	/// an account with no SCRAM verifier) gets decoy credentials, so the
	/// exchange looks like a wrong password from outside and nothing says why
	/// it failed, or whether the login exists.
	pub fn plan_scram(
		&self,
		username: &str,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) -> ScramPlan {
		let resolved = match self.check_ban(username, ip, protocol) {
			BanOutcome::Banned => {
				return ScramPlan {
					credentials: self.decoy_scram_credentials(username),
					account: username.to_string(),
					refusal: Some(ScramRefusal::Banned),
				};
			}
			// A banned account from a known network falls through to the
			// credential lookup: the exchange must succeed or fail on
			// the proof, the same way it would without the ban. The
			// SCRAM credential the planner returns is the same it would
			// return for the same account from any other network, so the
			// server-first the client sees does not depend on whether the
			// network was on the bypass list.
			BanOutcome::BannedButKnown { account } => Some(account),
			BanOutcome::Clear { account } => account,
		};
		if let Some(credentials) = self.scram_credentials(username)
			&& let Some((account, _)) = self.credentials(username)
			&& self.admit_login(&account, protocol, Proof::Scram)
		{
			return ScramPlan {
				credentials,
				account,
				refusal: None,
			};
		}
		ScramPlan {
			credentials: self.decoy_scram_credentials(username),
			account: username.to_string(),
			refusal: Some(ScramRefusal::Denied { account: resolved }),
		}
	}

	/// Credentials that exist only to build a server-first message and never
	/// verify: both keys are zero, so no client proof matches. The salt is a
	/// keyed hash of the login under a per-process random key, so it is stable
	/// for one login (a second attempt sees the same salt, as it would for a
	/// real account) and cannot be recomputed from the login by a client. The
	/// iteration count is the one a real verifier carries.
	///
	/// If the CSPRNG cannot produce the key it is all zeros. That is harmless
	/// here: the same failure stops the session from drawing a server nonce,
	/// and it closes the exchange before any decoy is sent.
	fn decoy_scram_credentials(&self, username: &str) -> ScramCredentials {
		#[cfg(test)]
		self.count_scram_decoy();
		static KEY: std::sync::OnceLock<hmac::Key> = std::sync::OnceLock::new();
		let key = KEY.get_or_init(|| {
			let bytes: [u8; 32] = ring::rand::generate(&ring::rand::SystemRandom::new())
				.map(|random| random.expose())
				.unwrap_or([0u8; 32]);
			hmac::Key::new(hmac::HMAC_SHA256, &bytes)
		});
		let tag = hmac::sign(key, username.to_ascii_lowercase().as_bytes());
		ScramCredentials {
			salt: tag.as_ref()[..16].to_vec(),
			iterations: SCRAM_ITERATIONS,
			stored_key: [0u8; 32],
			server_key: [0u8; 32],
		}
	}
}
