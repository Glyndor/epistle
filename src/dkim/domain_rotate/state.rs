//! The rotation state of one domain's key, and which key that domain signs
//! with.
//!
//! Each domain keeps its state beside its key files, in
//! `<data_dir>/keys/dkim/<domain>/rotation.json`, with the same shape and the
//! same last good copy (`rotation.json.bak`) as the `[dkim]` key's
//! `dkim-rotation.json`. No state means the domain has not rotated: its
//! `[[dkim.domain]]` entry names the key in service.

use std::path::{Path, PathBuf};

use crate::config::DkimDomain;
use crate::dkim::rotate::{ActiveKey, RotateError, RotationState, decode_state};

/// The state file inside the domain's key directory.
pub const STATE_FILE: &str = "rotation.json";
/// The last good state, the one [`STATE_FILE`] held before its latest save.
pub const STATE_BACKUP_FILE: &str = "rotation.json.bak";
/// Why the last rotation of the domain was withdrawn or failed.
pub const ERROR_FILE: &str = "rotate.error";
/// An operator's request to rotate the domain's key now.
pub const REQUEST_FILE: &str = "rotate.request";

/// The directory that holds `domain`'s keys and rotation state.
pub fn state_dir(data_dir: &Path, domain: &str) -> Result<PathBuf, RotateError> {
	crate::dkim::domain_keys::key_dir(data_dir, domain).map_err(RotateError::from_reason)
}

/// Read the state in `dir`. `Ok(None)` when there is none or it names no
/// key (the domain has not rotated). An unreadable or invalid file is an
/// error: reading it as absent would sign with the configured key while the
/// rotated one is what DNS was told about, and would start a second rotation
/// over the first.
pub fn read_state(dir: &Path) -> Result<Option<RotationState>, RotateError> {
	parse(&dir.join(STATE_FILE))
}

fn parse(path: &Path) -> Result<Option<RotationState>, RotateError> {
	match std::fs::read(path) {
		Ok(bytes) => decode_state(path, &bytes),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(RotateError::from_reason(format!(
			"read {}: {error}",
			path.display()
		))),
	}
}

/// The state the signer follows: [`read_state`], or the last good copy when
/// the state cannot be read. The copy is at most one save behind, and every
/// key it names is still published: a selector leaves the state only after
/// its record is gone.
pub(super) fn signing_state(dir: &Path) -> Result<Option<RotationState>, RotateError> {
	match read_state(dir) {
		Ok(state) => Ok(state),
		Err(error) => match parse(&dir.join(STATE_BACKUP_FILE)) {
			Ok(Some(backup)) => {
				tracing::warn!(
					%error,
					selector = %backup.selector,
					"per-domain DKIM rotation state is unreadable; signing with the last good copy",
				);
				Ok(Some(backup))
			}
			_ => Err(error),
		},
	}
}

/// Save `state` in `dir`, keeping the state it replaces as the last good
/// copy.
pub(super) fn save_state(dir: &Path, state: &RotationState) -> std::io::Result<()> {
	crate::dkim::rotate::save_state_file(&dir.join(STATE_FILE), &dir.join(STATE_BACKUP_FILE), state)
}

/// The keys one domain signs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainActive {
	/// The ed25519 key in service.
	pub ed: ActiveKey,
	/// The RSA key in service, when the entry dual-signs.
	pub rsa: Option<ActiveKey>,
}

/// The keys `entry`'s domain signs with: the ones its rotation state names,
/// the ones the entry configures when the domain has not rotated. Startup,
/// `dkim show` and the rotation itself all call this, so they cannot
/// disagree about which key is in service.
pub fn active_keys(entry: &DkimDomain, data_dir: &Path) -> Result<DomainActive, RotateError> {
	let dir = state_dir(data_dir, &entry.name)?;
	let state = signing_state(&dir)?;
	Ok(active_from(entry, data_dir, state.as_ref()))
}

/// [`active_keys`] for a state already read.
pub(super) fn active_from(
	entry: &DkimDomain,
	data_dir: &Path,
	state: Option<&RotationState>,
) -> DomainActive {
	let ed = match state.filter(|state| !state.selector.is_empty()) {
		Some(state) => ActiveKey {
			selector: state.selector.clone(),
			key_file: data_dir.join(&state.key_file),
		},
		None => ActiveKey {
			selector: entry.selector.clone(),
			key_file: entry.key_file.clone(),
		},
	};
	let rsa = match (&entry.rsa_selector, &entry.rsa_key_file) {
		(Some(selector), Some(key_file)) => Some(match state.and_then(|s| s.rsa.as_ref()) {
			Some(rsa) => ActiveKey {
				selector: rsa.selector.clone(),
				key_file: data_dir.join(&rsa.key_file),
			},
			None => ActiveKey {
				selector: selector.clone(),
				key_file: key_file.clone(),
			},
		}),
		_ => None,
	};
	DomainActive { ed, rsa }
}

/// When the configured key of `entry` was made: its file's modification
/// time, epoch seconds. A domain that has not rotated counts its interval
/// from there, so a key `init`, `domain add` or `dkim split` just made is
/// not replaced on the server's first tick.
pub(super) fn configured_since(entry: &DkimDomain) -> Option<u64> {
	let modified = std::fs::metadata(&entry.key_file).ok()?.modified().ok()?;
	modified
		.duration_since(std::time::UNIX_EPOCH)
		.ok()
		.map(|elapsed| elapsed.as_secs())
}

/// The selectors the next rotation of `entry`'s domain takes at `now`: the
/// ed25519 one (`own<day>`) and, when `dual_signing`, the RSA one
/// (`ownrsa<day>`), each followed by `x2`, `x3`... when the name is taken. A
/// name is taken when it is in `reserved`, when the entry configures it, or
/// when `state` names it (in service or still published as the replaced
/// selector): publishing a new key there would replace the record of a key
/// that may still verify mail.
pub fn next_selectors(
	entry: &DkimDomain,
	state: Option<&RotationState>,
	reserved: &[String],
	dual_signing: bool,
	now: u64,
) -> (String, Option<String>) {
	let mut taken = reserved.to_vec();
	taken.push(entry.selector.clone());
	taken.extend(entry.rsa_selector.clone());
	if let Some(state) = state {
		taken.push(state.selector.clone());
		taken.extend(state.rsa.iter().map(|rsa| rsa.selector.clone()));
		if let Some(previous) = &state.previous {
			taken.push(previous.selector.clone());
			taken.extend(previous.rsa.iter().map(|rsa| rsa.selector.clone()));
		}
	}
	let day = now / 86_400;
	let selector = crate::dkim::domain_keys::free_selector("own", day, &taken);
	taken.push(selector.clone());
	let rsa = dual_signing.then(|| crate::dkim::domain_keys::free_selector("ownrsa", day, &taken));
	(selector, rsa)
}
