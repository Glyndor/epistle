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
//! Two envelope versions coexist on disk, both ChaCha20-Poly1305 with a fresh
//! 12-byte nonce per write and the 16-byte tag appended (`ring::aead`):
//!
//! - Version 1, `MAGIC ‖ nonce ‖ ciphertext+tag` with [`MAGIC`]
//!   (`b"EPENC1\0"`), sealed with the raw server key. It names no key, so a
//!   reader tries the server key and then any retired server key; the tag
//!   tells them apart.
//! - Version 2, `MAGIC_V2 ‖ key id ‖ nonce ‖ ciphertext+tag`, sealed with a
//!   key expanded from the one the 16-byte id names (see [`keyring`]). This
//!   is what a tenant key writes, and what lets a store hold files under
//!   several keys without guessing which one opens which file.
//!
//! A file that starts with neither magic is plaintext from before encryption
//! was on and is returned verbatim by [`MessageCrypto::decode`], so a store
//! can be migrated in place with no flag-day.

use std::path::Path;
use std::sync::{Arc, RwLock};

use base64::Engine;
use ring::aead::NONCE_LEN;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

mod envelope;
pub mod keyring;
mod tenant;

pub use envelope::{EnvelopeKind, MAGIC_V2, MAX_OVERHEAD, OVERHEAD_V2, is_envelope, kind};
pub use keyring::{KeyId, KeyOwner};
pub use tenant::{AccountAddresses, TenantChoice};

use keyring::{Keyring, StoredKey};

/// Magic prefix marking a version 1 encrypted message file. The trailing
/// version digit and NUL let the format evolve without ambiguity against
/// plaintext mail.
pub const MAGIC: &[u8] = b"EPENC1\0";

/// Required key length in bytes (ChaCha20-Poly1305 uses a 256-bit key).
pub const KEY_LEN: usize = 32;

/// Bytes a version 1 envelope adds over the plaintext: magic, nonce and the
/// AEAD tag. A version 2 envelope adds [`OVERHEAD_V2`].
pub const OVERHEAD: usize = MAGIC.len() + NONCE_LEN + 16;

/// Errors building a [`MessageCrypto`] from configuration. Each is fatal at
/// startup: encryption that cannot load its key must never silently fall back
/// to writing plaintext. No variant carries key material.
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
		/// Path that was attempted.
		path: std::path::PathBuf,
		/// Underlying I/O error returned by `std::fs`.
		source: std::io::Error,
	},
	/// A tenant or retired key file is readable by group or others.
	#[error(
		"encryption key file {path} is group/world-accessible (mode {mode:#o}); restrict it to 0600"
	)]
	KeyFilePermissions {
		/// The file.
		path: std::path::PathBuf,
		/// Its permission bits.
		mode: u32,
	},
	/// The configured environment variable is not set.
	#[error("encryption key environment variable ${0} is not set")]
	KeyEnvMissing(String),
	/// The key material did not base64-decode to exactly [`KEY_LEN`] bytes.
	#[error("encryption key must be a base64-encoded {KEY_LEN}-byte value")]
	KeyMalformed,
	/// Two owners were given the same key.
	#[error("{first} and {second} are the same key; give each its own (epistle storage-keygen)")]
	DuplicateKey {
		/// The owner loaded first.
		first: String,
		/// The owner that repeated it.
		second: String,
	},
	/// A `[[tenant]]` sets `encryption_key_file` without a `name`.
	#[error("a [[tenant]] with encryption_key_file needs a name, which the key is known by")]
	TenantUnnamed,
	/// Tenant keys are configured but the server key is not.
	#[error(
		"[[tenant]] encryption_key_file needs a [storage] key as well (encryption_key_file or encryption_key_env)"
	)]
	TenantWithoutServerKey,
}

/// Errors raised by the AEAD envelope that aren't I/O. Folding them into
/// `std::io::Result` would lose the distinction between "tamper detected"
/// and a real file problem, so the helpers that distinguish survive on their
/// own; the high-level `encode` / `decode` keep returning `io::Result` so the
/// rest of the codebase is unchanged.
#[derive(Debug, thiserror::Error)]
pub enum CryptoAuthError {
	/// The on-disk bytes carry no envelope and the operation required one.
	#[error("expected an encrypted envelope but the data does not start with the envelope magic")]
	NotEncrypted,
	/// An encrypted envelope was given but the AEAD authentication failed:
	/// either the bytes were tampered with, the wrong key was loaded, or
	/// the associated data does not match what the file was sealed under.
	#[error("envelope authentication failed: wrong key, tamper, or wrong associated data")]
	AuthenticationFailed,
	/// The envelope is truncated: not even the header and nonce fit.
	#[error("encrypted envelope is truncated")]
	Truncated,
	/// The envelope is encrypted but no key is loaded, so it cannot be read.
	#[error("encrypted envelope but no key is loaded")]
	NoKey,
	/// A version 2 envelope names a key that is not loaded.
	#[error("encrypted envelope sealed with storage key {}, which is not loaded", .0.short())]
	UnknownKey(KeyId),
}

impl From<envelope::OpenError> for CryptoAuthError {
	fn from(error: envelope::OpenError) -> Self {
		match error {
			envelope::OpenError::NoKey => CryptoAuthError::NoKey,
			envelope::OpenError::UnknownKey(id) => CryptoAuthError::UnknownKey(id),
			envelope::OpenError::Truncated => CryptoAuthError::Truncated,
			envelope::OpenError::Authentication => CryptoAuthError::AuthenticationFailed,
		}
	}
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
	/// Every loaded key. Held even when `enabled` is false so
	/// already-encrypted files still decode after encryption is turned off.
	keys: Keyring,
	/// Whether new writes are encrypted. Reads always honour the on-disk format.
	enabled: bool,
	rng: SystemRandom,
	/// Account to address lookup, attached once the directory exists.
	accounts: RwLock<Option<Arc<dyn AccountAddresses>>>,
}

impl std::fmt::Debug for MessageCrypto {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Never print key material.
		f.debug_struct("MessageCrypto")
			.field("enabled", &self.inner.enabled)
			.field("has_key", &self.inner.keys.server.is_some())
			.field("tenant_keys", &self.inner.keys.tenants.len())
			.finish()
	}
}

impl MessageCrypto {
	fn build(keys: Keyring, enabled: bool) -> Self {
		MessageCrypto {
			inner: Arc::new(Inner {
				keys,
				enabled,
				rng: SystemRandom::new(),
				accounts: RwLock::new(None),
			}),
		}
	}

	/// A no-op crypto: encryption off, no key. [`encode`](Self::encode) returns
	/// plaintext unchanged and [`decode`](Self::decode) passes plaintext through.
	/// A file that nonetheless carries an envelope cannot be read (no key) and
	/// fails closed rather than returning ciphertext.
	pub fn disabled() -> Self {
		Self::build(Keyring::default(), false)
	}

	/// Build the crypto from the optional `[storage]` configuration alone,
	/// with no tenant keys. See [`from_parts`](Self::from_parts).
	pub fn from_config(storage: Option<&crate::config::Storage>) -> Result<Self, CryptoError> {
		Self::from_parts(storage, &[])
	}

	/// Build the crypto from a whole configuration: `[storage]` and the key
	/// of every `[[tenant]]` that has one.
	pub fn from_full_config(config: &crate::config::Config) -> Result<Self, CryptoError> {
		Self::from_parts(config.storage.as_ref(), &config.tenants)
	}

	/// Build the crypto from `[storage]` and the `[[tenant]]` blocks.
	///
	/// Fails closed: if `encrypt_at_rest` is set, a usable [`KEY_LEN`]-byte key
	/// must resolve from `encryption_key_env` or `encryption_key_file`, or this
	/// returns an error and the server must refuse to start. When encryption is
	/// off but a key source is configured, the key is still loaded so previously
	/// encrypted files remain readable after a config change. Tenant keys load
	/// the same way, and a tenant key without a server key is refused.
	pub fn from_parts(
		storage: Option<&crate::config::Storage>,
		tenants: &[crate::config::Tenant],
	) -> Result<Self, CryptoError> {
		let has_tenant_keys = tenants
			.iter()
			.any(|tenant| tenant.encryption_key_file.is_some());
		let Some(storage) = storage else {
			if has_tenant_keys {
				return Err(CryptoError::TenantWithoutServerKey);
			}
			return Ok(Self::disabled());
		};
		let key_bytes = load_key_bytes(storage)?;
		if storage.encrypt_at_rest && key_bytes.is_none() {
			return Err(CryptoError::NoKeySource);
		}
		let mut keys = Keyring::default();
		match key_bytes {
			Some(bytes) => keys.insert(StoredKey::new(&bytes, KeyOwner::Server)?)?,
			None if has_tenant_keys => return Err(CryptoError::TenantWithoutServerKey),
			None => {}
		}
		tenant::load(&mut keys, tenants)?;
		Ok(Self::build(keys, storage.encrypt_at_rest))
	}

	/// Build a crypto from raw key bytes with encryption enabled. For tests.
	#[cfg(test)]
	pub fn for_test(key: &[u8]) -> Self {
		let mut keys = Keyring::default();
		keys.insert(StoredKey::new(key, KeyOwner::Server).expect("valid test key"))
			.expect("one key");
		Self::build(keys, true)
	}

	/// Whether new writes are encrypted.
	pub fn enabled(&self) -> bool {
		self.inner.enabled
	}

	/// Attach the account to address lookup that tells a write which tenant
	/// an account belongs to. Every clone sees it.
	pub fn attach_accounts(&self, accounts: Arc<dyn AccountAddresses>) {
		if let Ok(mut slot) = self.inner.accounts.write() {
			*slot = Some(accounts);
		}
	}

	/// The tenant `account` resolves to, from its addresses.
	pub fn tenant_of_account(&self, account: &str) -> TenantChoice {
		let accounts = self
			.inner
			.accounts
			.read()
			.ok()
			.and_then(|slot| slot.clone());
		let addresses = accounts
			.map(|accounts| accounts.addresses_for(account))
			.unwrap_or_default();
		tenant::choose(&self.inner.keys, &addresses)
	}

	/// Every loaded key with its owner: the server key, retired server keys
	/// and tenant keys. Ids are public; nothing here is key material.
	pub fn key_listing(&self) -> Vec<(KeyOwner, KeyId)> {
		self.inner.keys.listing()
	}

	/// Encode `plaintext` for storage. With encryption enabled and a key, returns
	/// a version 1 envelope under the server key; otherwise returns the
	/// plaintext unchanged so an unencrypted deployment writes exactly the
	/// bytes it always did.
	///
	/// # Errors
	/// Only when the system CSPRNG cannot produce a nonce or the AEAD fails — both
	/// fatal for that write, never a silent fallback to plaintext.
	pub fn encode(&self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
		self.encode_with_aad(plaintext, &[])
	}

	/// Decode `stored` bytes read from disk. A buffer carrying an envelope is
	/// decrypted with the key its header calls for; anything else is returned
	/// verbatim (legacy plaintext), so reads stay correct across a
	/// half-migrated store regardless of the enabled flag.
	///
	/// # Errors
	/// Fails closed when an encrypted file is encountered and its key is not
	/// loaded, when the envelope is truncated, or when authentication fails
	/// (tamper or wrong key) — it never returns undecrypted ciphertext as if it
	/// were plaintext.
	pub fn decode(&self, stored: &[u8]) -> std::io::Result<Vec<u8>> {
		match envelope::open(&self.inner.keys, stored, &[]) {
			Ok(Some(plain)) => Ok(plain),
			Ok(None) => Ok(stored.to_vec()),
			Err(error) => Err(std::io::Error::other(error.to_string())),
		}
	}

	/// Encode `plaintext` for storage, binding it to `aad` so a sealed envelope
	/// cannot be silently rebound to a different context. With encryption
	/// enabled and a key, returns a version 1 envelope under the server key;
	/// otherwise returns the plaintext unchanged. When binding to a
	/// per-message id, pass `id.as_bytes()`.
	///
	/// # Errors
	/// Only when the system CSPRNG cannot produce a nonce or the AEAD fails,
	/// both fatal for that write, never a silent fallback to plaintext.
	pub fn encode_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> std::io::Result<Vec<u8>> {
		let Some(key) = self
			.inner
			.keys
			.server
			.as_ref()
			.filter(|_| self.inner.enabled)
		else {
			return Ok(plaintext.to_vec());
		};
		envelope::seal_v1(key, &self.inner.rng, plaintext, aad)
	}

	/// Seal `plaintext` as a version 2 envelope under the key `owner` holds,
	/// whatever the enabled flag says. The building block of tenant writes
	/// and of re-encryption, which choose the owner themselves.
	///
	/// # Errors
	/// When `owner` has no loaded key, or the CSPRNG or the AEAD fails.
	pub fn seal_v2_for(
		&self,
		owner: &KeyOwner,
		plaintext: &[u8],
		aad: &[u8],
	) -> std::io::Result<Vec<u8>> {
		let key = self.key_of(owner).ok_or_else(|| {
			std::io::Error::other(format!(
				"{owner} is not loaded, nothing can be sealed with it"
			))
		})?;
		envelope::seal_v2(key, &self.inner.rng, plaintext, aad)
	}

	/// The loaded key `owner` holds.
	fn key_of(&self, owner: &KeyOwner) -> Option<&Arc<StoredKey>> {
		let keys = &self.inner.keys;
		match owner {
			KeyOwner::Server => keys.server.as_ref(),
			KeyOwner::Retired(index) => keys.retired.get(*index),
			KeyOwner::Tenant(name) => keys.tenants.get(name),
		}
	}

	/// Decode `stored` bytes read from disk, requiring `aad` to match what the
	/// envelope was sealed under. A buffer with no envelope returns
	/// [`CryptoAuthError::NotEncrypted`] (fails closed) so callers can
	/// distinguish "legacy plaintext" from a tampered or wrong-key case.
	///
	/// # Errors
	/// Fails closed when the envelope is truncated, when authentication fails
	/// (tamper, wrong key, or `aad` mismatch), or with
	/// [`CryptoAuthError::NoKey`] / [`CryptoAuthError::UnknownKey`] when the
	/// key the envelope needs is not loaded.
	pub fn decode_with_aad(&self, stored: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoAuthError> {
		match envelope::open(&self.inner.keys, stored, aad) {
			Ok(Some(plain)) => Ok(plain),
			Ok(None) => Err(CryptoAuthError::NotEncrypted),
			Err(error) => Err(error.into()),
		}
	}

	/// The plaintext length of a stored file of `file_len` bytes at `path`,
	/// without fully decrypting it. Used for IMAP `RFC822.SIZE` and quota
	/// accounting, which must report the message size a client sees, not the
	/// on-disk envelope size.
	///
	/// Fast path: with no key loaded the store is plaintext, so `file_len` is
	/// returned without touching the file. Otherwise the header is peeked; an
	/// encrypted file's plaintext length is `file_len` less the overhead of
	/// its envelope version. A read error or a too-short file gives `file_len`.
	pub fn stored_plaintext_len(&self, path: &Path, file_len: u64) -> u64 {
		if self.inner.keys.is_empty() {
			return file_len;
		}
		let overhead = match file_header_kind(path) {
			Some(EnvelopeKind::V1) => OVERHEAD,
			Some(EnvelopeKind::V2(_)) => OVERHEAD_V2,
			_ => return file_len,
		};
		file_len.checked_sub(overhead as u64).unwrap_or(file_len)
	}
}

/// The envelope kind of the file at `path`, from a peek at its header.
fn file_header_kind(path: &Path) -> Option<EnvelopeKind> {
	use std::io::Read;
	let header_len = MAGIC_V2.len() + keyring::KEY_ID_LEN;
	let file = std::fs::File::open(path).ok()?;
	let mut header = Vec::with_capacity(header_len);
	file.take(header_len as u64).read_to_end(&mut header).ok()?;
	Some(kind(&header))
}

/// Resolve the raw key bytes from the configured source, if any. The file source
/// takes precedence over the environment variable when both are set.
///
/// The returned bytes and the intermediate base64 string (read from file or env)
/// are wrapped in [`Zeroizing`] so the buffers are overwritten when dropped,
/// shrinking the window in which the master key sits in freed memory, in a
/// core dump, or on the swap device. This is a best-effort mitigation, not a
/// guarantee: the allocator may have copied the buffer while it was live, the
/// kernel may have paged it out before the drop ran, and the live keys inside
/// [`MessageCrypto`] keep their own copy for the life of the process. Closing
/// those gaps takes locked memory and is a separate piece of work.
fn load_key_bytes(
	storage: &crate::config::Storage,
) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
	if let Some(path) = &storage.encryption_key_file {
		let raw: Zeroizing<String> =
			Zeroizing::new(std::fs::read_to_string(path).map_err(|source| {
				CryptoError::KeyFile {
					path: path.clone(),
					source,
				}
			})?);
		return Ok(Some(decode_key_text(raw.trim())?));
	}
	if let Some(var) = &storage.encryption_key_env {
		let raw: Zeroizing<String> = Zeroizing::new(
			std::env::var(var).map_err(|_| CryptoError::KeyEnvMissing(var.clone()))?,
		);
		return Ok(Some(decode_key_text(raw.trim())?));
	}
	Ok(None)
}

/// Base64-decode a key string to exactly [`KEY_LEN`] bytes. The decoded buffer
/// is wrapped in [`Zeroizing`] for the same reason as in [`load_key_bytes`].
fn decode_key_text(text: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
	let bytes = Zeroizing::new(
		base64::engine::general_purpose::STANDARD
			.decode(text)
			.map_err(|_| CryptoError::KeyMalformed)?,
	);
	if bytes.len() != KEY_LEN {
		return Err(CryptoError::KeyMalformed);
	}
	Ok(bytes)
}

/// Generate a fresh base64-encoded [`KEY_LEN`]-byte key, or `None` if the system
/// CSPRNG cannot produce bytes (fail closed). Backs the `storage-keygen` CLI.
pub fn generate_key_base64() -> Option<String> {
	let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
	SystemRandom::new().fill(bytes.as_mut()).ok()?;
	Some(base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()))
}

#[cfg(test)]
mod tests;
