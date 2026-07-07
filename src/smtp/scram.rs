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

/// SCRAM credentials in a form suitable for persistence (base64 fields).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScramStored {
	/// Base64 salt.
	pub salt: String,
	pub iterations: u32,
	/// Base64 StoredKey (SHA-256 of ClientKey).
	pub stored_key: String,
	/// Base64 ServerKey.
	pub server_key: String,
}

impl ScramStored {
	/// Serialize derived credentials for storage.
	pub fn from_credentials(credentials: &ScramCredentials) -> Self {
		ScramStored {
			salt: BASE64.encode(&credentials.salt),
			iterations: credentials.iterations,
			stored_key: BASE64.encode(credentials.stored_key),
			server_key: BASE64.encode(credentials.server_key),
		}
	}

	/// Reconstruct credentials, or `None` if any field is malformed.
	pub fn to_credentials(&self) -> Option<ScramCredentials> {
		let stored_key = BASE64.decode(&self.stored_key).ok()?.try_into().ok()?;
		let server_key = BASE64.decode(&self.server_key).ok()?.try_into().ok()?;
		Some(ScramCredentials {
			salt: BASE64.decode(&self.salt).ok()?,
			iterations: self.iterations,
			stored_key,
			server_key,
		})
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

/// Channel-binding policy for an exchange (RFC 5802 §6, RFC 5929).
///
/// The default, `Unsupported`, is plain SCRAM-SHA-256 with no binding check —
/// used on cleartext links and unchanged from before. The other two are used on
/// TLS, where the server also advertises `SCRAM-SHA-256-PLUS`: `Supported` is
/// the non-PLUS mechanism (a client that asks for it must not bind, and a `y`
/// flag is rejected as a downgrade), and `Required` is the `-PLUS` mechanism
/// (the client must bind to the given data — the `tls-server-end-point`, i.e.
/// the hash of the server's certificate).
#[derive(Debug, Clone, Default)]
pub enum ChannelBinding {
	/// No channel binding offered (cleartext); the `c=` field is not checked.
	#[default]
	Unsupported,
	/// TLS, plain SCRAM-SHA-256: the client must send `n,,` (no binding); `y`
	/// or `p` is rejected.
	Supported,
	/// TLS, SCRAM-SHA-256-PLUS: the client must bind to this data
	/// (`tls-server-end-point`).
	Required(Vec<u8>),
}

/// Server-side SCRAM-SHA-256 state machine: feed `first` then `finish`.
#[derive(Debug)]
pub struct ScramServer {
	server_nonce: String,
	client_first_bare: Option<String>,
	server_first: Option<String>,
	combined_nonce: Option<String>,
	channel_binding: ChannelBinding,
	/// The GS2 header (`<flag>,<authzid>,`) from the client-first message,
	/// captured so the client's `c=` can be verified against it.
	gs2_header: Option<String>,
}

impl ScramServer {
	/// Create a server with a freshly generated server nonce (caller supplies
	/// randomness so the core stays pure and testable). Channel binding is
	/// unsupported unless set with [`ScramServer::with_channel_binding`].
	pub fn new(server_nonce: impl Into<String>) -> Self {
		ScramServer {
			server_nonce: server_nonce.into(),
			client_first_bare: None,
			server_first: None,
			combined_nonce: None,
			channel_binding: ChannelBinding::Unsupported,
			gs2_header: None,
		}
	}

	/// Set the channel-binding policy for this exchange.
	pub fn with_channel_binding(mut self, channel_binding: ChannelBinding) -> Self {
		self.channel_binding = channel_binding;
		self
	}

	/// Process the client-first message (`n,,n=user,r=nonce`), returning the
	/// username and the server-first message to send back.
	pub fn first(
		&mut self,
		client_first: &str,
		credentials: &ScramCredentials,
	) -> Result<(String, String), ScramError> {
		// Strip the GS2 channel-binding header (`<flag>,<authzid>,`): the bare
		// part is everything after the second comma.
		let bare = nth_comma_rest(client_first, 2).ok_or(ScramError::Malformed)?;
		let gs2_header = &client_first[..client_first.len() - bare.len()];

		// Enforce the channel-binding flag for this policy (RFC 5802 §6).
		let flag = client_first.split(',').next().unwrap_or("");
		match self.channel_binding {
			// Plain SCRAM on a link that also offers -PLUS: the client must not
			// claim binding. `y` (saw no -PLUS) is a downgrade; `p` is wrong.
			ChannelBinding::Supported if flag != "n" => return Err(ScramError::Malformed),
			// -PLUS: the client must bind to tls-server-end-point.
			ChannelBinding::Required(_) if flag != "p=tls-server-end-point" => {
				return Err(ScramError::Malformed);
			}
			_ => {}
		}

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
		self.gs2_header = Some(gs2_header.to_string());
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

		// Verify the channel binding: `c=` must be base64(gs2-header || data),
		// where data is the tls-server-end-point for -PLUS and empty otherwise.
		// `Unsupported` keeps the prior behavior (no `c=` check).
		if !matches!(self.channel_binding, ChannelBinding::Unsupported) {
			let gs2_header = self.gs2_header.as_deref().ok_or(ScramError::Malformed)?;
			let cbind = BASE64
				.decode(tag(client_final, "c=").ok_or(ScramError::Malformed)?)
				.map_err(|_| ScramError::Malformed)?;
			let mut expected = gs2_header.as_bytes().to_vec();
			if let ChannelBinding::Required(data) = &self.channel_binding {
				expected.extend_from_slice(data);
			}
			if cbind != expected {
				return Err(ScramError::Malformed);
			}
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

/// The username (`n=` tag) from a client-first message, before any exchange.
pub fn username_of(client_first: &str) -> Option<String> {
	let bare = nth_comma_rest(client_first, 2)?;
	tag(bare, "n=").map(str::to_string)
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
	fn stored_credentials_roundtrip() {
		let credentials = ScramCredentials::derive("hunter2", b"saltsalt", 4096);
		let stored = ScramStored::from_credentials(&credentials);
		let restored = stored.to_credentials().expect("decode");
		assert_eq!(restored.salt, credentials.salt);
		assert_eq!(restored.iterations, credentials.iterations);
		assert_eq!(restored.stored_key, credentials.stored_key);
		assert_eq!(restored.server_key, credentials.server_key);
	}

	#[test]
	fn malformed_stored_credentials_rejected() {
		let stored = ScramStored {
			salt: "not base64!!!".to_string(),
			iterations: 4096,
			stored_key: "x".to_string(),
			server_key: "y".to_string(),
		};
		assert!(stored.to_credentials().is_none());
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

	/// Drive a full exchange with an explicit GS2 header and channel-binding
	/// data, returning the server-final or the first error.
	fn run_cb_exchange(
		cb: ChannelBinding,
		client_header: &str,
		client_cbind: &[u8],
	) -> Result<String, ScramError> {
		let credentials = ScramCredentials::derive("hunter2", b"saltsalt", 4096);
		let mut server = ScramServer::new("servernonce").with_channel_binding(cb);
		let client_first = format!("{client_header}n=alice,r=clientnonce");
		let (_, server_first) = server.first(&client_first, &credentials)?;
		let mut c = client_header.as_bytes().to_vec();
		c.extend_from_slice(client_cbind);
		let without_proof = format!("c={},r=clientnonceservernonce", BASE64.encode(&c));
		let auth_message = format!("n=alice,r=clientnonce,{server_first},{without_proof}");
		let proof = client_proof("hunter2", &credentials, &auth_message);
		let client_final = format!("{without_proof},p={}", BASE64.encode(&proof));
		server.finish(&client_final, &credentials)
	}

	const CERT_HASH: &[u8] = b"0123456789abcdef0123456789abcdef";

	#[test]
	fn plus_with_correct_binding_authenticates() {
		let result = run_cb_exchange(
			ChannelBinding::Required(CERT_HASH.to_vec()),
			"p=tls-server-end-point,,",
			CERT_HASH,
		);
		assert!(result.expect("authenticated").starts_with("v="));
	}

	#[test]
	fn plus_with_wrong_binding_fails() {
		let result = run_cb_exchange(
			ChannelBinding::Required(CERT_HASH.to_vec()),
			"p=tls-server-end-point,,",
			b"a-different-32-byte-certificate!!",
		);
		assert_eq!(result, Err(ScramError::Malformed));
	}

	#[test]
	fn plus_requires_the_p_flag() {
		// A -PLUS exchange where the client does not actually bind.
		let result = run_cb_exchange(ChannelBinding::Required(CERT_HASH.to_vec()), "n,,", b"");
		assert_eq!(result, Err(ScramError::Malformed));
	}

	#[test]
	fn supported_rejects_downgrade_flag() {
		// `y,,` on the non-PLUS mechanism when the server offers -PLUS is a
		// downgrade attempt.
		let result = run_cb_exchange(ChannelBinding::Supported, "y,,", b"");
		assert_eq!(result, Err(ScramError::Malformed));
	}

	#[test]
	fn supported_accepts_unbound_client() {
		let result = run_cb_exchange(ChannelBinding::Supported, "n,,", b"");
		assert!(result.expect("authenticated").starts_with("v="));
	}

	#[test]
	fn supported_rejects_tampered_binding() {
		// The header says `n,,` but the c= carries extra bytes.
		let result = run_cb_exchange(ChannelBinding::Supported, "n,,", b"extra");
		assert_eq!(result, Err(ScramError::Malformed));
	}
}
