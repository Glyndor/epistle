//! SCRAM-SHA-256 server exchange (RFC 5802, RFC 7677).
//!
//! SCRAM authenticates without the password ever crossing the wire and without
//! the server storing anything password-equivalent: it keeps only a salt, an
//! iteration count, and the `StoredKey`/`ServerKey` derived once when the
//! password is set. This is the pure protocol core; credential storage and
//! AUTH wiring layer on top.

use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::{digest, hmac, pbkdf2};

/// The per-account SCRAM credentials, derived from the password at set time.
#[derive(Debug, Clone)]
pub struct ScramCredentials {
	pub salt: Vec<u8>,
	pub iterations: u32,
	pub stored_key: [u8; 32],
	pub server_key: [u8; 32],
}

impl ScramCredentials {
	/// Derive credentials from a password (RFC 5802 §3). Store the result, not
	/// the password.
	pub fn derive(password: &str, salt: &[u8], iterations: u32) -> ScramCredentials {
		let mut salted = [0u8; 32];
		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA256,
			NonZeroU32::new(iterations).unwrap_or(NonZeroU32::MIN),
			salt,
			password.as_bytes(),
			&mut salted,
		);
		let client_key = hmac_sha256(&salted, b"Client Key");
		let server_key = hmac_sha256(&salted, b"Server Key");
		ScramCredentials {
			salt: salt.to_vec(),
			iterations,
			stored_key: sha256(&client_key),
			server_key,
		}
	}
}

/// Why a SCRAM exchange failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScramError {
	/// A message did not parse as SCRAM.
	Malformed,
	/// The client proof did not match: wrong password.
	AuthenticationFailed,
}

/// Server-side SCRAM-SHA-256 state machine: feed `first` then `finish`.
pub struct ScramServer {
	server_nonce: String,
	client_first_bare: Option<String>,
	server_first: Option<String>,
	combined_nonce: Option<String>,
}

impl ScramServer {
	/// Create a server with a freshly generated server nonce (caller supplies
	/// randomness so the core stays pure and testable).
	pub fn new(server_nonce: impl Into<String>) -> Self {
		ScramServer {
			server_nonce: server_nonce.into(),
			client_first_bare: None,
			server_first: None,
			combined_nonce: None,
		}
	}

	/// Process the client-first message (`n,,n=user,r=nonce`), returning the
	/// username and the server-first message to send back.
	pub fn first(
		&mut self,
		client_first: &str,
		credentials: &ScramCredentials,
	) -> Result<(String, String), ScramError> {
		// Strip the GS2 channel-binding header (`n,,` / `y,,`): the bare part
		// is everything after the second comma.
		let bare = nth_comma_rest(client_first, 2).ok_or(ScramError::Malformed)?;
		let username = tag(bare, "n=").ok_or(ScramError::Malformed)?;
		let client_nonce = tag(bare, "r=").ok_or(ScramError::Malformed)?;

		let combined_nonce = format!("{client_nonce}{}", self.server_nonce);
		let server_first = format!(
			"r={combined_nonce},s={},i={}",
			BASE64.encode(&credentials.salt),
			credentials.iterations,
		);

		self.client_first_bare = Some(bare.to_string());
		self.server_first = Some(server_first.clone());
		self.combined_nonce = Some(combined_nonce);
		Ok((username.to_string(), server_first))
	}

	/// Process the client-final message (`c=biws,r=nonce,p=proof`), verifying
	/// the client proof and returning the server-final message (`v=...`).
	pub fn finish(
		&mut self,
		client_final: &str,
		credentials: &ScramCredentials,
	) -> Result<String, ScramError> {
		let (client_first_bare, server_first, combined_nonce) = match (
			&self.client_first_bare,
			&self.server_first,
			&self.combined_nonce,
		) {
			(Some(a), Some(b), Some(c)) => (a, b, c),
			_ => return Err(ScramError::Malformed),
		};

		// The nonce must be echoed unchanged.
		if tag(client_final, "r=") != Some(combined_nonce.as_str()) {
			return Err(ScramError::Malformed);
		}
		let proof = BASE64
			.decode(tag(client_final, "p=").ok_or(ScramError::Malformed)?)
			.map_err(|_| ScramError::Malformed)?;
		if proof.len() != 32 {
			return Err(ScramError::Malformed);
		}

		// client-final-without-proof is everything before `,p=`.
		let without_proof = client_final
			.rsplit_once(",p=")
			.map(|(head, _)| head)
			.ok_or(ScramError::Malformed)?;
		let auth_message = format!("{client_first_bare},{server_first},{without_proof}");

		let client_signature = hmac_sha256(&credentials.stored_key, auth_message.as_bytes());
		// ClientKey = ClientProof XOR ClientSignature; verify SHA256 matches.
		let mut client_key = [0u8; 32];
		for i in 0..32 {
			client_key[i] = proof[i] ^ client_signature[i];
		}
		if sha256(&client_key) != credentials.stored_key {
			return Err(ScramError::AuthenticationFailed);
		}

		let server_signature = hmac_sha256(&credentials.server_key, auth_message.as_bytes());
		Ok(format!("v={}", BASE64.encode(server_signature)))
	}
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
	let key = hmac::Key::new(hmac::HMAC_SHA256, key);
	let tag = hmac::sign(&key, message);
	let mut out = [0u8; 32];
	out.copy_from_slice(tag.as_ref());
	out
}

fn sha256(data: &[u8]) -> [u8; 32] {
	let digest = digest::digest(&digest::SHA256, data);
	let mut out = [0u8; 32];
	out.copy_from_slice(digest.as_ref());
	out
}

/// The value of a `key=value` SCRAM attribute (e.g. `r=`), reading to the next
/// comma.
fn tag<'a>(message: &'a str, key: &str) -> Option<&'a str> {
	message.split(',').find_map(|field| field.strip_prefix(key))
}

/// Everything after the `n`-th comma in `text`.
fn nth_comma_rest(text: &str, n: usize) -> Option<&str> {
	let mut rest = text;
	for _ in 0..n {
		rest = rest.split_once(',')?.1;
	}
	Some(rest)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Compute the client side of the exchange to drive the server in tests.
	fn client_proof(password: &str, credentials: &ScramCredentials, auth_message: &str) -> Vec<u8> {
		let mut salted = [0u8; 32];
		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA256,
			NonZeroU32::new(credentials.iterations).unwrap(),
			&credentials.salt,
			password.as_bytes(),
			&mut salted,
		);
		let client_key = hmac_sha256(&salted, b"Client Key");
		let stored_key = sha256(&client_key);
		let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
		(0..32)
			.map(|i| client_key[i] ^ client_signature[i])
			.collect()
	}

	fn run_exchange(password: &str, login_password: &str) -> Result<String, ScramError> {
		let credentials = ScramCredentials::derive(password, b"saltsalt", 4096);
		let mut server = ScramServer::new("servernonce");
		let client_first = "n,,n=alice,r=clientnonce";
		let (user, server_first) = server.first(client_first, &credentials)?;
		assert_eq!(user, "alice");

		let without_proof = "c=biws,r=clientnonceservernonce";
		let auth_message = format!("n=alice,r=clientnonce,{server_first},{without_proof}");
		// The client computes its proof from the *login* password.
		let proof = client_proof(login_password, &credentials, &auth_message);
		let client_final = format!("{without_proof},p={}", BASE64.encode(&proof));
		server.finish(&client_final, &credentials)
	}

	#[test]
	fn correct_password_authenticates() {
		let result = run_exchange("hunter2", "hunter2").expect("authenticated");
		assert!(result.starts_with("v="));
	}

	#[test]
	fn wrong_password_fails() {
		assert_eq!(
			run_exchange("hunter2", "wrong"),
			Err(ScramError::AuthenticationFailed)
		);
	}

	#[test]
	fn server_first_carries_salt_and_iterations() {
		let credentials = ScramCredentials::derive("pw", b"saltsalt", 4096);
		let mut server = ScramServer::new("SN");
		let (_, server_first) = server.first("n,,n=bob,r=CN", &credentials).expect("first");
		assert_eq!(
			server_first,
			format!("r=CNSN,s={},i=4096", BASE64.encode(b"saltsalt"))
		);
	}

	#[test]
	fn altered_nonce_is_rejected() {
		let credentials = ScramCredentials::derive("pw", b"saltsalt", 4096);
		let mut server = ScramServer::new("SN");
		server.first("n,,n=bob,r=CN", &credentials).expect("first");
		// A client-final echoing the wrong nonce is malformed.
		let bad = "c=biws,r=WRONG,p=AAAA";
		assert_eq!(server.finish(bad, &credentials), Err(ScramError::Malformed));
	}

	#[test]
	fn malformed_client_first_is_rejected() {
		let credentials = ScramCredentials::derive("pw", b"saltsalt", 4096);
		let mut server = ScramServer::new("SN");
		assert_eq!(
			server.first("garbage", &credentials),
			Err(ScramError::Malformed)
		);
	}
}
