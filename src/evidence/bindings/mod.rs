//! Default classes bound to accounts and credentials.
//!
//! `epistle account set <a> --default-class C` binds a class to an account;
//! `--class C` on `app-password add` and `api-key create` binds one to the
//! credential. A credential is named by the SHA-256 of its stored hash, not
//! by its label: a label that is reused for a new credential does not
//! inherit the class of the old one.
//!
//! The bindings live in `<data_dir>/class-bindings.json` (`0600`). The
//! server rereads the file when it changes; a file it cannot trust (not
//! owner-only, unreadable, malformed) keeps the last good bindings in force
//! and is reported.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::MailClass;
use super::record::{sha256, to_hex};

const FILE: &str = "class-bindings.json";
/// The most bindings the file may hold.
pub const MAX_BINDINGS: usize = 100_000;

/// The bindings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
	/// Account name to its default class.
	#[serde(default)]
	pub accounts: BTreeMap<String, MailClass>,
	/// Credential key (see [`app_password_key`], [`api_key_key`]) to class.
	#[serde(default)]
	pub credentials: BTreeMap<String, MailClass>,
}

/// The key of an app password: the SHA-256 of its stored PHC hash.
pub fn app_password_key(phc_hash: &str) -> String {
	format!("app:{}", to_hex(&sha256(phc_hash.as_bytes())))
}

/// The key of an API key: its stored `sha256:<hex>` digest.
pub fn api_key_key(stored_hash: &str) -> String {
	format!("api:{stored_hash}")
}

/// The key of the API key whose token is `token`.
pub fn api_key_key_of_token(token: &str) -> String {
	api_key_key(&format!("sha256:{}", to_hex(&sha256(token.as_bytes()))))
}

fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(FILE)
}

/// Read the bindings under `data_dir`: empty when there are none. A file
/// that is a link, not owned by this user, writable by others, too large
/// or malformed is refused.
pub fn load(data_dir: &Path) -> std::io::Result<Bindings> {
	use std::os::unix::fs::MetadataExt;
	let path = path(data_dir);
	let meta = match std::fs::symlink_metadata(&path) {
		Ok(meta) => meta,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			return Ok(Bindings::default());
		}
		Err(error) => return Err(error),
	};
	// SAFETY: geteuid has no preconditions and cannot fail.
	let me = unsafe { libc::geteuid() };
	if !meta.file_type().is_file() || meta.uid() != me || meta.mode() & 0o022 != 0 {
		return Err(std::io::Error::new(
			std::io::ErrorKind::PermissionDenied,
			"class bindings are writable by other users: refused",
		));
	}
	let bytes = super::checkpoint::read_bounded(&path, 16 * 1024 * 1024)?.unwrap_or_default();
	let bindings: Bindings = serde_json::from_slice(&bytes)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	if bindings.accounts.len() + bindings.credentials.len() > MAX_BINDINGS {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			"too many class bindings",
		));
	}
	Ok(bindings)
}

/// Change the bindings under `data_dir` with `edit`, under an exclusive
/// lock so two CLI runs do not lose each other's change.
pub fn update(data_dir: &Path, edit: impl FnOnce(&mut Bindings)) -> std::io::Result<()> {
	let lock = crate::storage::lock::FileLock::acquire(&data_dir.join(".class-bindings.lock"))?;
	let mut bindings = load(data_dir)?;
	edit(&mut bindings);
	let bytes = serde_json::to_vec_pretty(&bindings).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(data_dir), &bytes)?;
	drop(lock);
	Ok(())
}

/// The bindings the server reads, reloaded when the file changes.
#[derive(Debug)]
pub struct BindingSet {
	data_dir: PathBuf,
	state: RwLock<(Option<SystemTime>, Bindings, Option<String>)>,
}

impl BindingSet {
	/// Load the bindings under `data_dir`. One that cannot be read refuses
	/// to start: there is no last good copy yet.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let bindings = load(data_dir)?;
		Ok(BindingSet {
			data_dir: data_dir.to_path_buf(),
			state: RwLock::new((modified(data_dir), bindings, None)),
		})
	}

	fn refresh(&self) {
		let now = modified(&self.data_dir);
		let stale = self
			.state
			.read()
			.map(|state| state.0 != now)
			.unwrap_or(false);
		if !stale {
			return;
		}
		let loaded = load(&self.data_dir);
		if let Ok(mut state) = self.state.write() {
			state.0 = now;
			match loaded {
				Ok(bindings) => {
					state.1 = bindings;
					state.2 = None;
				}
				Err(error) => {
					tracing::warn!(%error, "class bindings unreadable; keeping the last good ones");
					state.2 = Some(error.to_string());
				}
			}
		}
	}

	/// The default class of `account`.
	pub fn account(&self, account: &str) -> Option<MailClass> {
		self.refresh();
		let state = self.state.read().ok()?;
		state.1.accounts.get(&account.to_ascii_lowercase()).copied()
	}

	/// The class bound to the credential `key`.
	pub fn credential(&self, key: &str) -> Option<MailClass> {
		self.refresh();
		let state = self.state.read().ok()?;
		state.1.credentials.get(key).copied()
	}

	/// Why the file could not be reread, when it could not.
	pub fn error(&self) -> Option<String> {
		self.state.read().ok().and_then(|state| state.2.clone())
	}
}

fn modified(data_dir: &Path) -> Option<SystemTime> {
	std::fs::symlink_metadata(path(data_dir))
		.and_then(|meta| meta.modified())
		.ok()
}

#[cfg(test)]
mod tests;
