//! SCRAM-SHA-256 authentication exchange over SMTP AUTH (RFC 4954 + 5802).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::super::reply::Reply;
use super::super::scram::{ScramCredentials, ScramServer, username_of};
use super::{Action, Session};

/// In-flight SCRAM state between AUTH rounds.
#[derive(Debug)]
pub(super) enum PendingScram {
	/// Server sent `334 ` (empty); awaiting the client-first message.
	ClientFirst,
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

	/// Begin SCRAM-SHA-256: process the optional initial client-first, or
	/// prompt for it with an empty challenge.
	pub(super) fn scram_begin(&mut self, initial: Option<String>) -> Action {
		match initial {
			Some(client_first) => self.scram_client_first(&client_first),
			None => {
				self.pending_scram = Some(PendingScram::ClientFirst);
				Action::CollectAuthResponse(Reply::single(334, ""))
			}
		}
	}

	/// Process the base64 client-first message: look up the user's SCRAM
	/// credentials and answer with the server-first challenge.
	pub(super) fn scram_client_first(&mut self, encoded: &str) -> Action {
		let Some(client_first) = decode(encoded) else {
			return self.scram_failure();
		};
		let Some(username) = username_of(&client_first) else {
			return self.scram_failure();
		};
		// Resolve credentials and the canonical account name (no oracle: a
		// missing user fails exactly like a bad password later).
		let Some(credentials) = self.directory.scram_credentials(&username) else {
			return self.scram_failure();
		};
		let Some((account, _)) = self.directory.credentials(&username) else {
			return self.scram_failure();
		};

		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure: fail closed rather than use a predictable nonce.
			return self.scram_failure();
		};
		let mut server = ScramServer::new(nonce);
		let Ok((_user, server_first)) = server.first(&client_first, &credentials) else {
			return self.scram_failure();
		};
		self.pending_scram = Some(PendingScram::ClientFinal {
			server: Box::new(server),
			credentials: Box::new(credentials),
			account,
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
		let Some(client_final) = decode(encoded) else {
			return self.scram_failure();
		};
		match server.finish(&client_final, &credentials) {
			Ok(server_final) => {
				self.authenticated = Some(account.to_string());
				Action::Continue(Reply::single(
					235,
					&format!("2.7.0 {}", BASE64.encode(server_final)),
				))
			}
			Err(_) => self.scram_failure(),
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
