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

/// Salt length in bytes for a freshly derived SCRAM secret.
const SALT_LEN: usize = 16;

/// SCRAM-SHA-256 iteration count for freshly-derived verifiers. The value
/// matches the OWASP 2023 PBKDF2-HMAC-SHA256 recommendation: 600000 rounds
/// is the floor that aligns the verifier's work factor with the account's
/// argon2id password hash, so a reader of `accounts.toml` cannot pick the
/// cheaper PBKDF2 verifier over the argon2 one. Stored verifiers keep the
/// count they were derived with (the SCRAM protocol exchanges it in
/// server-first, RFC 5802 `i=`, so the client always uses the stored value);
/// the directory upgrades a low-iteration verifier transparently the next
/// time the account authenticates with a cleartext password mechanism.
pub const SCRAM_ITERATIONS: u32 = 600_000;

/// The per-account SCRAM credentials, derived from the password at set time.
#[derive(Debug, Clone)]
pub struct ScramCredentials {
	/// Salt fed to PBKDF2 when deriving `SaltedPassword`. Should be freshly
	/// generated random per account; never reused across accounts.
	pub salt: Vec<u8>,
	/// PBKDF2 iteration count (RFC 7677 mandates ≥ 4096 for SHA-256).
	pub iterations: u32,
	/// `H(ClientKey)` stored as `StoredKey`; the verifier compares the
	/// client's proof against this.
	pub stored_key: [u8; 32],
	/// `HMAC(SaltedPassword, "Server Key")` used to authenticate the
	/// server's final message.
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
	/// PBKDF2 iteration count (RFC 7677 mandates ≥ 4096 for SHA-256).
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

	/// Derive stored SCRAM-SHA-256 credentials for `password` under a fresh
	/// random salt at [`SCRAM_ITERATIONS`]. `None` when the CSPRNG
	/// cannot produce one, so the caller fails closed rather than storing
	/// credentials under a predictable salt.
	///
	/// The salt comes back from `ring::rand::generate` already filled. The
	/// three call sites this replaces each declared `[0u8; 16]` and then
	/// overwrote it, which left a window — brief, but real — where a
	/// deterministic salt sat in the buffer that was about to be used.
	pub fn with_fresh_salt(password: &str) -> Option<Self> {
		let salt: [u8; SALT_LEN] = ring::rand::generate(&ring::rand::SystemRandom::new())
			.ok()?
			.expose();
		Some(Self::from_credentials(&ScramCredentials::derive(
			password,
			&salt,
			SCRAM_ITERATIONS,
		)))
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
		if !crate::util::constant_time::eq(&sha256(&client_key), &credentials.stored_key) {
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
mod tests;
