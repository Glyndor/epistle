//! The files the panel container reads: its API key, its session secret and
//! its admin id.
//!
//! Both are files in the host secrets directory, beside `data_dir`, so `mail`
//! (which mounts `data_dir` read-write) and `epistle backup` (which archives
//! it) never hold them. The stack mounts each into the panel container and the
//! panel reads them through `EPISTLE_API_TOKEN_FILE` and
//! `EPISTLE_PANEL_SESSION_SECRET_FILE`; a value in the environment would show
//! in `podman inspect`. The admin id (see [`admin_id`]) is read through
//! `EPISTLE_PANEL_ADMIN_ID_FILE` and is not a cryptographic secret, but is
//! handled like one.
//!
//! None of the three is ever printed or logged, except by the one command
//! that shows the admin id on purpose. The report and the plan carry
//! paths and a verb, and a test searches both for the value just written.
//!
//! `paths` names every file this module owns, so a function that removes the
//! panel's secrets and revokes its key has one list to work from.

mod admin_id;
mod held;
mod key;
mod rotation;
mod session;

use std::path::{Path, PathBuf};

use super::super::apply::{ApplyError, Report};
use crate::api::ApiKeyStore;

pub(crate) use admin_id::{AdminIdAction, read as read_admin_id};
pub(crate) use key::KeyAction;
pub(crate) use rotation::{held_api_token, replace_api_token};
#[cfg(test)]
pub(crate) use rotation::{install_for_tests, key_is_kept_for_tests};
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

/// The file name of the admin id, under the host secrets directory.
pub(crate) const ADMIN_ID_FILE: &str = "panel_admin_id";

/// Where the panel's API key is kept.
pub(crate) fn api_token_path(data_dir: &Path) -> PathBuf {
	super::super::host_secrets::dir(data_dir).join(API_TOKEN_FILE)
}

/// Where the panel's session secret is kept.
pub(crate) fn session_secret_path(data_dir: &Path) -> PathBuf {
	super::super::host_secrets::dir(data_dir).join(SESSION_SECRET_FILE)
}

/// Where the panel's admin id is kept.
pub(crate) fn admin_id_path(data_dir: &Path) -> PathBuf {
	super::super::host_secrets::dir(data_dir).join(ADMIN_ID_FILE)
}

/// Every file this module writes.
pub(crate) fn paths(data_dir: &Path) -> [PathBuf; 3] {
	[
		api_token_path(data_dir),
		session_secret_path(data_dir),
		admin_id_path(data_dir),
	]
}

/// What a run would do with each secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decision {
	/// What happens to the API key.
	pub(crate) key: KeyAction,
	/// What happens to the session secret.
	pub(crate) session: SessionAction,
	/// What happens to the admin id.
	pub(crate) admin_id: AdminIdAction,
}

/// Decide what [`ensure`] would do at `now` (epoch seconds), without writing:
/// the plan reads this, and `ensure` acts on the same answer, so the two
/// cannot disagree. An existing secret that cannot be used is an error here
/// too, before the operator confirms anything.
pub(crate) fn decide(data_dir: &Path, now: u64) -> Result<Decision, ApplyError> {
	let store = open_store(data_dir)?;
	let token = held::read(&api_token_path(data_dir))?;
	let session = held::read(&session_secret_path(data_dir))?;
	let admin_id = held::read(&admin_id_path(data_dir))?;
	Ok(Decision {
		key: key::decide(&store, &token, now)?,
		session: session::decide(&session, &session_secret_path(data_dir))?,
		admin_id: admin_id::decide(&admin_id, &admin_id_path(data_dir))?,
	})
}

/// Lay down the panel's API key, session secret and admin id, or reuse what is
/// there.
///
/// The session secret is never replaced once it exists: a new one only logs
/// every panel user out. The admin id is never replaced once it exists and is
/// valid: a new one moves the admin area to another address. The API key is minted when no `panel` key exists,
/// and replaced, with the secret file written first, when its file was lost or
/// altered or when fewer than [`RENEW_WITHIN_SECS`] remain. A `panel` key with
/// other scopes, domains or an account is refused rather than rewritten.
///
/// A secret file that is a link, a directory, empty or unreadable is an
/// error, as for the database password, and nothing is written over it. So is
/// an admin id file that holds anything but an id.
pub(crate) fn ensure(data_dir: &Path, now: u64, report: &mut Report) -> Result<(), ApplyError> {
	let dir = super::super::host_secrets::dir(data_dir);
	crate::storage::create_private_dir(&dir).map_err(|error| ApplyError::KeyWrite(dir, error))?;
	let mut store = open_store(data_dir)?;
	let token_path = api_token_path(data_dir);
	let session_path = session_secret_path(data_dir);
	let admin_path = admin_id_path(data_dir);
	let token = held::read(&token_path)?;
	let session = held::read(&session_path)?;
	let admin = held::read(&admin_path)?;
	// Every decision comes before any write, so a refusal of one leaves the
	// others untouched.
	let key_action = key::decide(&store, &token, now)?;
	let session_action = session::decide(&session, &session_path)?;
	let admin_action = admin_id::decide(&admin, &admin_path)?;
	key::apply(
		&mut store,
		key_action,
		&token_path,
		&token,
		&key::Clock { data_dir, now },
		report,
	)?;
	session::apply(session_action, &session_path, report)?;
	admin_id::apply(admin_action, &admin_path, report)
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
