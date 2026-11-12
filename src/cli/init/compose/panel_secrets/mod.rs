//! The two secrets the panel container reads: its API key and its session
//! secret.
//!
//! Both are files in the host secrets directory, beside `data_dir`, so `mail`
//! (which mounts `data_dir` read-write) and `epistle backup` (which archives
//! it) never hold them. The stack mounts each into the panel container and the
//! panel reads them through `EPISTLE_API_TOKEN_FILE` and
//! `EPISTLE_PANEL_SESSION_SECRET_FILE`; a value in the environment would show
//! in `podman inspect`.
//!
//! Neither secret is ever printed or logged. The report and the plan carry
//! paths and a verb, and a test searches both for the value just written.
//!
//! `paths` names every file this module owns, so a function that removes the
//! panel's secrets and revokes its key has one list to work from.

mod held;
mod key;
mod session;

use std::path::{Path, PathBuf};

use super::super::apply::{ApplyError, Report};
use crate::api::ApiKeyStore;

pub(crate) use key::KeyAction;
pub(crate) use session::SessionAction;

/// The label of the panel's API key.
pub(crate) const LABEL: &str = "panel";

/// The scopes of the panel's key: it lists and changes accounts, domains and
/// the queue, and sends no mail and provisions nothing, so `send` and `scim`
/// stay out.
pub(crate) const SCOPES: [&str; 2] = ["read", "write"];

/// How long a new or renewed key lives.
pub(crate) const KEY_LIFETIME_SECS: u64 = 365 * 24 * 60 * 60;

/// A key with less than this left is replaced by `stack update`.
pub(crate) const RENEW_WITHIN_SECS: u64 = 30 * 24 * 60 * 60;

/// The random bytes of a new session secret; the panel asks for 32 or more.
pub(crate) const SESSION_SECRET_BYTES: usize = 48;

/// The file name of the API key, under the host secrets directory.
pub(crate) const API_TOKEN_FILE: &str = "panel_api_token";

/// The file name of the session secret, under the host secrets directory.
pub(crate) const SESSION_SECRET_FILE: &str = "panel_session_secret";

/// Where the panel's API key is kept.
pub(crate) fn api_token_path(data_dir: &Path) -> PathBuf {
	super::super::host_secrets::dir(data_dir).join(API_TOKEN_FILE)
}

/// Where the panel's session secret is kept.
pub(crate) fn session_secret_path(data_dir: &Path) -> PathBuf {
	super::super::host_secrets::dir(data_dir).join(SESSION_SECRET_FILE)
}

/// Every file this module writes.
pub(crate) fn paths(data_dir: &Path) -> [PathBuf; 2] {
	[api_token_path(data_dir), session_secret_path(data_dir)]
}

/// What a run would do with each secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decision {
	/// What happens to the API key.
	pub(crate) key: KeyAction,
	/// What happens to the session secret.
	pub(crate) session: SessionAction,
}

/// Decide what [`ensure`] would do at `now` (epoch seconds), without writing:
/// the plan reads this, and `ensure` acts on the same answer, so the two
/// cannot disagree. An existing secret that cannot be used is an error here
/// too, before the operator confirms anything.
pub(crate) fn decide(data_dir: &Path, now: u64) -> Result<Decision, ApplyError> {
	let store = open_store(data_dir)?;
	let token = held::read(&api_token_path(data_dir))?;
	let session = held::read(&session_secret_path(data_dir))?;
	Ok(Decision {
		key: key::decide(&store, &token, now)?,
		session: session::decide(&session, &session_secret_path(data_dir))?,
	})
}

/// Lay down the panel's API key and session secret, or reuse what is there.
///
/// The session secret is never replaced once it exists: a new one only logs
/// every panel user out. The API key is minted when no `panel` key exists,
/// and replaced, with the secret file written first, when its file was lost or
/// altered or when fewer than [`RENEW_WITHIN_SECS`] remain. A `panel` key with
/// other scopes, domains or an account is refused rather than rewritten.
///
/// A secret file that is a link, a directory, empty or unreadable is an
/// error, as for the database password, and nothing is written over it.
pub(crate) fn ensure(data_dir: &Path, now: u64, report: &mut Report) -> Result<(), ApplyError> {
	let dir = super::super::host_secrets::dir(data_dir);
	crate::storage::create_private_dir(&dir).map_err(|error| ApplyError::KeyWrite(dir, error))?;
	let mut store = open_store(data_dir)?;
	let token_path = api_token_path(data_dir);
	let session_path = session_secret_path(data_dir);
	let token = held::read(&token_path)?;
	let session = held::read(&session_path)?;
	// Both decisions come before either write, so a refusal of one leaves the
	// other untouched.
	let key_action = key::decide(&store, &token, now)?;
	let session_action = session::decide(&session, &session_path)?;
	key::apply(
		&mut store,
		key_action,
		&token_path,
		&token,
		&key::Clock { data_dir, now },
		report,
	)?;
	session::apply(session_action, &session_path, report)
}

/// Seconds since the epoch, for the callers that have no clock of their own.
pub(crate) fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0)
}

fn open_store(data_dir: &Path) -> Result<ApiKeyStore, ApplyError> {
	ApiKeyStore::open(data_dir)
		.map_err(|error| ApplyError::KeyWrite(data_dir.join("api_keys.toml"), error))
}

#[cfg(test)]
mod tests;
