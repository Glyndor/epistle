//! Stable pseudonyms for account names in server logs.
//!
//! A log line that names an account is personal data that outlives the
//! account: log files get shipped, archived and read by people who never
//! needed the mailbox owner's name. Log sites therefore identify an account
//! by `acct-<12 hex>`, the first 6 bytes of an HMAC-SHA256 over the account
//! name under a per-server key kept in `<data_dir>/log-pseudonym.key`.
//!
//! The pseudonym is stable for one name on one server (the same account
//! always maps to the same string, so its lines can be followed), differs
//! between names and between servers, and cannot be reversed without the
//! key. The operator, who holds the key, maps in either direction with
//! `epistle account show <name>` and `epistle account find-log-id <id>`.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// File under the data directory that holds the 32-byte pseudonym key.
const KEY_FILE: &str = "log-pseudonym.key";
/// Prefix that marks a string as a log pseudonym.
const PREFIX: &str = "acct-";
/// How many bytes of the MAC are shown (twice that many hex characters).
const SHOWN_BYTES: usize = 6;
/// Directory component under which every account root lives.
const ACCOUNTS_DIR: &str = "accounts";

/// Derives the log pseudonym of an account name under one key.
pub struct Pseudonymizer {
	key: hmac::Key,
}

impl Pseudonymizer {
	/// Build one from an explicit 32-byte key. Tests use this to avoid the
	/// filesystem.
	pub fn with_key(key: [u8; 32]) -> Self {
		Pseudonymizer {
			key: hmac::Key::new(hmac::HMAC_SHA256, &key),
		}
	}

	/// Load the per-server key from `data_dir`, generating and persisting a
	/// fresh `0600` key on first use, the same way the other data-directory
	/// keys are handled.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let key = crate::storage::load_or_create_key_file(data_dir, KEY_FILE)?;
		Ok(Self::with_key(key))
	}

	/// The pseudonym of `name`: `acct-` plus 12 lowercase hex characters.
	pub fn account(&self, name: &str) -> String {
		let tag = hmac::sign(&self.key, name.as_bytes());
		let mut id = String::from(PREFIX);
		for byte in &tag.as_ref()[..SHOWN_BYTES] {
			id.push_str(&format!("{byte:02x}"));
		}
		id
	}

	/// `path` for a log line, with the account directory name (the component
	/// right after `accounts`) replaced by that account's pseudonym.
	pub fn path(&self, path: &Path) -> String {
		let mut shown = PathBuf::new();
		let mut after_accounts = false;
		for component in path.components() {
			match component {
				Component::Normal(part) if after_accounts => {
					shown.push(self.account(&part.to_string_lossy()));
				}
				other => shown.push(other.as_os_str()),
			}
			after_accounts = matches!(component, Component::Normal(part) if part == ACCOUNTS_DIR);
		}
		shown.display().to_string()
	}
}

static PROCESS: OnceLock<Pseudonymizer> = OnceLock::new();

/// Install the process-wide key from `data_dir`. Called once at startup by
/// `epistle serve` and by the account commands, before anything logs. A
/// second call keeps the first key.
pub fn init(data_dir: &Path) -> std::io::Result<()> {
	if PROCESS.get().is_none() {
		let pseudonymizer = Pseudonymizer::open(data_dir)?;
		let _ = PROCESS.set(pseudonymizer);
	}
	Ok(())
}

fn process() -> &'static Pseudonymizer {
	PROCESS.get_or_init(|| {
		// Not initialised (library use, unit tests): an ephemeral key keeps
		// the name out of the logs, at the cost of a pseudonym that changes
		// with the process.
		let mut key = [0u8; 32];
		let _ = SystemRandom::new().fill(&mut key);
		Pseudonymizer::with_key(key)
	})
}

/// Pseudonym of `name` under the process key.
pub fn account(name: &str) -> String {
	process().account(name)
}

/// `path` for a log line, account directory replaced by its pseudonym.
pub fn path(path: &Path) -> String {
	process().path(path)
}

#[cfg(test)]
#[path = "log_id_tests.rs"]
mod tests;
