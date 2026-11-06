//! The client side of the SCRAM-SHA-256 exchange that
//! [`super::sasl_exchange`] drives: an account made from random bytes, and
//! the proofs and server signatures a client that knows its password
//! computes (RFC 5802 section 3).

/// The account the SCRAM exchange logs in to, and what its client knows.
pub(super) struct Account {
	/// What the server stores.
	pub(super) credentials: crate::smtp::scram::ScramCredentials,
	/// `HMAC(SaltedPassword, "Client Key")`, which only the password gives.
	client_key: [u8; 32],
	/// The server nonce.
	pub(super) nonce: String,
	/// The `tls-server-end-point` data of the -PLUS mechanism.
	pub(super) end_point: Vec<u8>,
}

/// One account per process, from random bytes: no key or password is
/// written down anywhere.
pub(super) fn account() -> &'static Account {
	use base64::Engine;
	static ACCOUNT: std::sync::OnceLock<Account> = std::sync::OnceLock::new();
	ACCOUNT.get_or_init(|| {
		let random = ring::rand::SystemRandom::new();
		let draw = || -> [u8; 32] {
			ring::rand::generate(&random)
				.expect("no randomness for the fuzz account")
				.expose()
		};
		let encode = |bytes: [u8; 32]| base64::engine::general_purpose::STANDARD.encode(bytes);
		let password = encode(draw());
		let salt = draw();
		// RFC 7677 asks for 4096 at least; the account is derived once.
		let iterations = 4096;
		let credentials =
			crate::smtp::scram::ScramCredentials::derive(&password, &salt, iterations);
		let mut salted = [0u8; 32];
		ring::pbkdf2::derive(
			ring::pbkdf2::PBKDF2_HMAC_SHA256,
			std::num::NonZeroU32::new(iterations).unwrap_or(std::num::NonZeroU32::MIN),
			&salt,
			password.as_bytes(),
			&mut salted,
		);
		Account {
			credentials,
			client_key: hmac_sha256(&salted, b"Client Key"),
			nonce: encode(draw()),
			end_point: draw().to_vec(),
		}
	})
}

/// The client side of one SCRAM exchange, after server-first.
pub(super) struct Exchange {
	account: &'static Account,
	/// `client-first-bare,server-first,` of the auth message.
	prefix: String,
	/// The `c=` value: the GS2 header and, for -PLUS, the binding data.
	cbind: String,
}

impl Exchange {
	pub(super) fn new(
		account: &'static Account,
		first: &str,
		server_first: &str,
		binding: &crate::smtp::scram::ChannelBinding,
	) -> Self {
		use base64::Engine;
		let bare = first.splitn(3, ',').nth(2).unwrap_or("");
		let mut cbind = first.as_bytes()[..first.len() - bare.len()].to_vec();
		if let crate::smtp::scram::ChannelBinding::Required(data) = binding {
			cbind.extend_from_slice(data);
		}
		Self {
			account,
			prefix: format!("{bare},{server_first},"),
			cbind: base64::engine::general_purpose::STANDARD.encode(cbind),
		}
	}

	/// client-final-without-proof with `nonce`.
	pub(super) fn without_proof(&self, nonce: &str) -> String {
		format!("c={},r={nonce}", self.cbind)
	}

	/// The signature over the auth message that ends in `without_proof`.
	fn signature(&self, without_proof: &str, key: &[u8; 32]) -> [u8; 32] {
		hmac_sha256(key, format!("{}{without_proof}", self.prefix).as_bytes())
	}

	/// The base64 proof the password gives for `without_proof`.
	pub(super) fn proof(&self, without_proof: &str) -> String {
		self.encoded_proof(without_proof, 0)
	}

	/// [`Exchange::proof`] with its first bit flipped.
	pub(super) fn flipped(&self, without_proof: &str) -> String {
		self.encoded_proof(without_proof, 1)
	}

	fn encoded_proof(&self, without_proof: &str, flip: u8) -> String {
		use base64::Engine;
		let signature = self.signature(without_proof, &self.account.credentials.stored_key);
		let mut proof = self.account.client_key;
		for (byte, mask) in proof.iter_mut().zip(signature) {
			*byte ^= mask;
		}
		proof[0] ^= flip;
		base64::engine::general_purpose::STANDARD.encode(proof)
	}

	/// The client-final message the password signs.
	pub(super) fn signed(&self, without_proof: &str) -> String {
		format!("{without_proof},p={}", self.proof(without_proof))
	}

	/// The server-final message for `without_proof`.
	pub(super) fn server_final(&self, without_proof: &str) -> String {
		use base64::Engine;
		let signature = self.signature(without_proof, &self.account.credentials.server_key);
		format!(
			"v={}",
			base64::engine::general_purpose::STANDARD.encode(signature)
		)
	}
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
	let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), message);
	let mut out = [0u8; 32];
	out.copy_from_slice(tag.as_ref());
	out
}
