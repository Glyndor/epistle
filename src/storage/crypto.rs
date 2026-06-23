//! At-rest encryption of stored message files.
//!
//! Messages on disk (`.eml` bodies, the outbound spool, JMAP blobs) are
//! optionally wrapped in an authenticated-encryption envelope so a stolen disk
//! or backup never exposes mail content. This protects against **offline**
//! disk/backup theft only: the server holds the key in memory and decrypts
//! transparently, so it still serves IMAP/POP3/JMAP and runs delivery-time
//! processing (Sieve, antispam). It complements — never replaces — full-disk
//! encryption (LUKS); the two defend different threats.
//!
//! For the key to be worth anything against disk theft it must live **off the
//! encrypted disk**: [`MessageCrypto::from_config`] sources it from an
//! environment variable or an operator-managed key file (ideally outside
//! `data_dir`), never auto-generated inside the data directory. With encryption
//! enabled and no usable key, construction fails closed (the server refuses to
//! start).
//!
//! # Envelope format
//!
//! An encrypted file is `MAGIC ‖ nonce ‖ ciphertext+tag`:
//!
//! - `MAGIC` — [`MAGIC`] (`b"EPENC1\0"`, 7 bytes), a version-tagged marker that
//!   lets encrypted and legacy plaintext files coexist in the same store. A file
//!   that does not start with `MAGIC` is treated as plaintext and returned
//!   verbatim by [`MessageCrypto::decode`], so a store can be migrated in place
//!   with no flag-day.
//! - `nonce` — 12 random bytes from the system CSPRNG, fresh per write.
//! - `ciphertext+tag` — ChaCha20-Poly1305 over the plaintext, with the 16-byte
//!   Poly1305 tag appended (`ring::aead`). The envelope adds a fixed
//!   [`OVERHEAD`] bytes over the plaintext.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

/// Magic prefix marking an encrypted message file. The trailing version digit
/// and NUL let the format evolve without ambiguity against plaintext mail.
pub const MAGIC: &[u8] = b"EPENC1\0";

/// Required key length in bytes (ChaCha20-Poly1305 uses a 256-bit key).
pub const KEY_LEN: usize = 32;

/// Bytes the envelope adds over the plaintext: magic, nonce and the AEAD tag.
pub const OVERHEAD: usize = MAGIC.len() + NONCE_LEN + 16;

/// Errors building a [`MessageCrypto`] from configuration. Each is fatal at
/// startup: encryption that cannot load its key must never silently fall back to
/// writing plaintext.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
	/// `encrypt_at_rest = true` but neither key source was configured.
	#[error(
		"encrypt_at_rest is enabled but no key source is configured; set encryption_key_env or encryption_key_file"
	)]
	NoKeySource,
	/// The configured key file could not be read.
	#[error("cannot read encryption key file {path}: {source}")]
	KeyFile {
		path: std::path::PathBuf,
		source: std::io::Error,
	},
	/// The configured environment variable is not set.
	#[error("encryption key environment variable ${0} is not set")]
	KeyEnvMissing(String),
	/// The key material did not base64-decode to exactly [`KEY_LEN`] bytes.
	#[error("encryption key must be a base64-encoded {KEY_LEN}-byte value")]
	KeyMalformed,
}

/// Transparent at-rest encryption of stored message files. Cheap to clone (an
/// `Arc` internally), so it can be threaded into every component that reads or
/// writes message bytes (delivery, spool, IMAP/POP3 mailboxes, the JMAP state
/// and the CLI commands).
#[derive(Clone)]
pub struct MessageCrypto {
	inner: Arc<Inner>,
}

struct Inner {
	/// The AEAD key, when one is loaded. Held even when `enabled` is false so
	/// already-encrypted files still decode after encryption is turned off.
	key: Option<LessSafeKey>,
	/// Whether new writes are encrypted. Reads always honour the on-disk format.
	enabled: bool,
	rng: SystemRandom,
}

impl std::fmt::Debug for MessageCrypto {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Never print key material.
		f.debug_struct("MessageCrypto")
			.field("enabled", &self.inner.enabled)
			.field("has_key", &self.inner.key.is_some())
			.finish()
	}
}

impl MessageCrypto {
	/// A no-op crypto: encryption off, no key. [`encode`](Self::encode) returns
	/// plaintext unchanged and [`decode`](Self::decode) passes plaintext through.
	/// A file that nonetheless carries [`MAGIC`] cannot be read (no key) and
	/// fails closed rather than returning ciphertext.
	pub fn disabled() -> Self {
		MessageCrypto {
			inner: Arc::new(Inner {
				key: None,
				enabled: false,
				rng: SystemRandom::new(),
			}),
		}
	}

	/// Build the crypto from the optional `[storage]` configuration.
	///
	/// Fails closed: if `encrypt_at_rest` is set, a usable [`KEY_LEN`]-byte key
	/// must resolve from `encryption_key_env` or `encryption_key_file`, or this
	/// returns an error and the server must refuse to start. When encryption is
	/// off but a key source is configured, the key is still loaded so previously
	/// encrypted files remain readable after a config change.
	pub fn from_config(storage: Option<&crate::config::Storage>) -> Result<Self, CryptoError> {
		let Some(storage) = storage else {
			return Ok(Self::disabled());
		};
		let key_bytes = load_key_bytes(storage)?;
		if storage.encrypt_at_rest && key_bytes.is_none() {
			return Err(CryptoError::NoKeySource);
		}
		let key = match key_bytes {
			Some(bytes) => Some(build_key(&bytes)?),
			None => None,
		};
		Ok(MessageCrypto {
			inner: Arc::new(Inner {
				key,
				enabled: storage.encrypt_at_rest,
				rng: SystemRandom::new(),
			}),
		})
	}

	/// Build a crypto from raw key bytes with encryption enabled. For tests.
	#[cfg(test)]
	pub fn for_test(key: &[u8]) -> Self {
		MessageCrypto {
			inner: Arc::new(Inner {
				key: Some(build_key(key).expect("valid test key")),
				enabled: true,
				rng: SystemRandom::new(),
			}),
		}
	}

	/// Whether new writes are encrypted.
	pub fn enabled(&self) -> bool {
		self.inner.enabled
	}

	/// Encode `plaintext` for storage. With encryption enabled and a key, returns
	/// `MAGIC ‖ nonce ‖ ciphertext+tag`; otherwise returns the plaintext
	/// unchanged so an unencrypted deployment writes exactly the bytes it always
	/// did.
	///
	/// # Errors
	/// Only when the system CSPRNG cannot produce a nonce or the AEAD fails — both
	/// fatal for that write, never a silent fallback to plaintext.
	pub fn encode(&self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
		let Some(key) = self.inner.key.as_ref().filter(|_| self.inner.enabled) else {
			return Ok(plaintext.to_vec());
		};
		let mut nonce_bytes = [0u8; NONCE_LEN];
		self.inner
			.rng
			.fill(&mut nonce_bytes)
			.map_err(|_| std::io::Error::other("CSPRNG failure generating nonce"))?;
		let nonce = Nonce::assume_unique_for_key(nonce_bytes);
		let mut buffer = plaintext.to_vec();
		key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
			.map_err(|_| std::io::Error::other("AEAD sealing failed"))?;
		let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
		out.extend_from_slice(MAGIC);
		out.extend_from_slice(&nonce_bytes);
		out.extend_from_slice(&buffer);
		Ok(out)
	}

	/// Decode `stored` bytes read from disk. A buffer starting with [`MAGIC`] is
	/// decrypted; anything else is returned verbatim (legacy plaintext), so reads
	/// stay correct across a half-migrated store regardless of the enabled flag.
	///
	/// # Errors
	/// Fails closed when an encrypted file is encountered with no key loaded, when
	/// the envelope is truncated, or when authentication fails (tamper or wrong
	/// key) — it never returns undecrypted ciphertext as if it were plaintext.
	pub fn decode(&self, stored: &[u8]) -> std::io::Result<Vec<u8>> {
		if !stored.starts_with(MAGIC) {
			return Ok(stored.to_vec());
		}
		let key = self.inner.key.as_ref().ok_or_else(|| {
			std::io::Error::other("encrypted message but no decryption key loaded")
		})?;
		let rest = &stored[MAGIC.len()..];
		if rest.len() < NONCE_LEN {
			return Err(std::io::Error::other("encrypted message: truncated nonce"));
		}
		let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
		let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
			.map_err(|_| std::io::Error::other("encrypted message: bad nonce"))?;
		let mut buffer = ciphertext.to_vec();
		let plaintext = key
			.open_in_place(nonce, Aad::empty(), &mut buffer)
			.map_err(|_| std::io::Error::other("encrypted message: authentication failed"))?;
		Ok(plaintext.to_vec())
	}

	/// The plaintext length of a stored file of `file_len` bytes at `path`,
	/// without fully decrypting it. Used for IMAP `RFC822.SIZE` and quota
	/// accounting, which must report the message size a client sees, not the
	/// on-disk envelope size.
	///
	/// Fast path: with no key loaded the store is plaintext, so `file_len` is
	/// returned without touching the file. Otherwise the file's first bytes are
	/// peeked for [`MAGIC`]; an encrypted file's plaintext length is
	/// `file_len - OVERHEAD`. Any read error or a too-short file falls back to
	/// `file_len`.
	pub fn stored_plaintext_len(&self, path: &Path, file_len: u64) -> u64 {
		if self.inner.key.is_none() {
			return file_len;
		}
		if file_len < OVERHEAD as u64 || !file_has_magic(path) {
			return file_len;
		}
		file_len - OVERHEAD as u64
	}
}

/// Whether the file at `path` begins with [`MAGIC`] (a cheap prefix peek).
fn file_has_magic(path: &Path) -> bool {
	use std::io::Read;
	let Ok(mut file) = std::fs::File::open(path) else {
		return false;
	};
	let mut prefix = [0u8; MAGIC.len()];
	file.read_exact(&mut prefix).is_ok() && prefix == MAGIC
}

/// Resolve the raw key bytes from the configured source, if any. The file source
/// takes precedence over the environment variable when both are set.
fn load_key_bytes(storage: &crate::config::Storage) -> Result<Option<Vec<u8>>, CryptoError> {
	if let Some(path) = &storage.encryption_key_file {
		let raw = std::fs::read_to_string(path).map_err(|source| CryptoError::KeyFile {
			path: path.clone(),
			source,
		})?;
		return Ok(Some(decode_key_text(raw.trim())?));
	}
	if let Some(var) = &storage.encryption_key_env {
		let raw = std::env::var(var).map_err(|_| CryptoError::KeyEnvMissing(var.clone()))?;
		return Ok(Some(decode_key_text(raw.trim())?));
	}
	Ok(None)
}

/// Base64-decode a key string to exactly [`KEY_LEN`] bytes.
fn decode_key_text(text: &str) -> Result<Vec<u8>, CryptoError> {
	let bytes = base64::engine::general_purpose::STANDARD
		.decode(text)
		.map_err(|_| CryptoError::KeyMalformed)?;
	if bytes.len() != KEY_LEN {
		return Err(CryptoError::KeyMalformed);
	}
	Ok(bytes)
}

/// Build a sealing/opening key from exactly [`KEY_LEN`] raw bytes.
fn build_key(bytes: &[u8]) -> Result<LessSafeKey, CryptoError> {
	if bytes.len() != KEY_LEN {
		return Err(CryptoError::KeyMalformed);
	}
	let unbound =
		UnboundKey::new(&CHACHA20_POLY1305, bytes).map_err(|_| CryptoError::KeyMalformed)?;
	Ok(LessSafeKey::new(unbound))
}

/// Generate a fresh base64-encoded [`KEY_LEN`]-byte key, or `None` if the system
/// CSPRNG cannot produce bytes (fail closed). Backs the `storage-keygen` CLI.
pub fn generate_key_base64() -> Option<String> {
	let mut bytes = [0u8; KEY_LEN];
	SystemRandom::new().fill(&mut bytes).ok()?;
	Some(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
