//! The persisted dynamic account record.

use serde::{Deserialize, Serialize};

use super::StoreError;
use crate::config::Protocol;
use crate::password::Policy;

/// A dynamic account as persisted in `accounts.toml`. `Default` is an
/// empty record for test fixtures and API constructors to fill with
/// `..DynamicAccount::default()`; it is not a valid account on its own
/// (`AccountStore::add` requires a password hash and an address).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicAccount {
	/// Account login name (the local part used by IMAP/SMTP AUTH, without
	/// the `@domain`). Lowercase ASCII, no leading hyphen; validated by
	/// `AccountStore::add`.
	pub name: String,
	/// Delivery addresses (full `user@domain`) this account owns. At least
	/// one, all in configured domains.
	pub addresses: Vec<String>,
	/// Argon2id hash of the account's password (the encoding used by
	/// `smtp::auth::hash_password`). Stored, never the plaintext.
	pub password_hash: String,
	/// SCRAM credentials, derived from the password at set time (RFC 5802).
	#[serde(default)]
	pub scram: Option<crate::smtp::scram::ScramStored>,
	/// Base32 TOTP secret for two-factor auth (RFC 6238). Absent disables 2FA.
	#[serde(default)]
	pub totp_secret: Option<String>,
	/// Account is administratively disabled (kept on disk; never
	/// authenticates). Set by SCIM `active: false` and other paths that need
	/// to suspend an account without removing its mailbox.
	#[serde(default)]
	pub disabled: bool,
	/// Storage quota (bytes) for this account. `None` (the default, and the
	/// value on `accounts.toml` files written before the field existed)
	/// falls back to the domain quota, then the server default, exactly the
	/// way static `Account::quota_bytes = None` does. IMAP `GETQUOTAROOT` and
	/// the delivery quota check both read the rebuilt directory's quota map.
	#[serde(default)]
	pub quota_bytes: Option<u64>,
	/// Restrict which authentication protocols this account may sign in
	/// through. `None` (the default) means every protocol the directory
	/// knows about — the pre-restriction behaviour. When set, only the
	/// listed protocols authenticate this account; every other path rejects
	/// identically to an unknown login, so the wire response never reveals
	/// that the account exists.
	#[serde(default)]
	pub allowed_protocols: Option<Vec<Protocol>>,
	/// External addresses this account's mail is also forwarded to.
	/// Empty (the default) disables forwarding. Mirrors the static
	/// `Account::forward` field; dynamic forwards chain onto static ones
	/// in the directory builder so the two pools compose at delivery time.
	#[serde(default)]
	pub forward: Vec<String>,
	/// Domains for which this account receives mail addressed to otherwise
	/// unknown local users (catch-all). Empty (the default) opts out; mirrors
	/// the static `Account::catch_all` field.
	#[serde(default)]
	pub catch_all: Vec<String>,
	/// The person's name, free text used as the sender name (JMAP
	/// `Identity.name`, the `From` that `/api/v1/send` builds). Stored as
	/// given (trimmed), never lowercased; `None` when unset. Checked by
	/// [`super::display_name::validate`].
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub display_name: Option<String>,
	/// Whether messages the account submits are saved to its `Sent`
	/// folder. `None` (the default and the value on `accounts.toml`
	/// files written before the field existed) defaults to "on"; an
	/// explicit `Some(false)` disables the save for this account
	/// unless an app password on the credential overrides it.
	/// Per-request (`/api/v1/send`, JMAP `EmailSubmission`) and
	/// per-credential (app password) overrides win over the
	/// account-wide setting.
	#[serde(default)]
	pub save_sent: Option<bool>,
	/// Whether the account may send mail. `None` (the default and the value
	/// on `accounts.toml` files written before the field existed) means it
	/// may; `Some(false)` turns sending off. Never `Some(true)` on disk:
	/// switching back on clears the field so an untouched file gains no key.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub send: Option<bool>,
	/// Whether mail addressed to the account is accepted. Same encoding as
	/// [`DynamicAccount::send`].
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub receive: Option<bool>,
}

impl DynamicAccount {
	/// Build an account from a plaintext password, deriving the argon2id hash
	/// and SCRAM-SHA-256 credentials (fresh random salt,
	/// [`crate::smtp::scram::SCRAM_ITERATIONS`] rounds). When
	/// `scram_enabled` is `false`, the SCRAM verifier is omitted (`None`);
	/// a future password change with `scram_enabled` `false` keeps it
	/// `None`.
	///
	/// `policy` decides whether `password` is NFKC-normalised before hashing
	/// and SCRAM derivation. With `Policy::ASCII_ONLY` (the default) the
	/// input is hashable as-is; with `Policy::unicode` the prepare step
	/// canonicalises it (RFC 8265 OpaqueString), so a password set with one
	/// keyboard verifies from another.
	pub fn with_password(
		name: String,
		addresses: Vec<String>,
		password: &str,
		policy: &Policy,
		scram_enabled: bool,
	) -> Result<Self, StoreError> {
		let prepared = policy
			.prepare(password)
			.map_err(|rejection| StoreError::Invalid(rejection.message().to_string()))?;
		let password_hash = crate::smtp::auth::hash_password(prepared.as_ref())
			.map_err(|_| StoreError::Invalid("cannot hash password".to_string()))?;
		let scram = if scram_enabled {
			let stored = crate::smtp::scram::ScramStored::with_fresh_salt(prepared.as_ref())
				.ok_or_else(|| StoreError::Invalid("cannot generate salt".to_string()))?;
			Some(stored)
		} else {
			None
		};
		Ok(DynamicAccount {
			name,
			addresses,
			password_hash,
			scram,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			forward: Vec::new(),
			catch_all: Vec::new(),
			display_name: None,
			save_sent: None,
			send: None,
			receive: None,
		})
	}
}
