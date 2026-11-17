//! Refresh tokens (RFC 6749 section 6) with rotation and reuse detection.
//!
//! They exist only when `[oauth] refresh_token_ttl_secs` is set. Every grant
//! then answers with a refresh token next to the access token, and each use of
//! it returns a new one and retires the old one. A token is 32 bytes from the
//! CSPRNG; only its SHA-256 reaches the disk, in `oauth_refresh.json`, written
//! through the locked store so every process sees the same state.
//!
//! A *family* is the chain of tokens that descend from one grant. Presenting a
//! token that was already rotated means two parties hold it, so the whole
//! family is deleted and both are signed out (RFC 6819 section 5.2.2.3). The
//! price is that a client that retries a refresh whose answer it lost, after
//! the server had rotated, signs itself out; the answer is the same
//! `invalid_grant` as for an unknown token and the user signs in again.
//!
//! A family also ends when the account is disabled, removed or locked, and
//! when its password was changed or reset since the grant: each record keeps a
//! digest of the password hash the account held at issue time, and a refresh
//! compares it with the one it holds now, whichever path changed the password.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::api::ApiState;

const FILE: &str = "oauth_refresh.json";

/// A refresh token is 32 bytes in base64url, 43 characters; anything longer
/// is no token of ours and is refused before it is hashed or the store read.
pub(super) const MAX_REFRESH_TOKEN_CHARS: usize = 128;

/// How many refresh families one account may hold and what happens at the
/// cap. A client keeps one family for its whole life, so a person with ten
/// apps and a few retired devices is far below the default of 50; by default
/// the oldest family makes room for a new one beyond it.
pub(super) struct SessionCap {
	/// The cap in force and the scope that set it; `None` is no cap.
	pub(super) cap: Option<crate::limits::Cap>,
	/// Refuse the new session instead of ending the oldest.
	pub(super) refuse: bool,
}

impl SessionCap {
	/// The cap that applied before it was configurable: 50 families, the
	/// oldest ended to make room.
	#[cfg(test)]
	pub(super) fn legacy() -> Self {
		Self {
			cap: Some(crate::limits::Cap {
				value: crate::limits::DEFAULT_SESSIONS,
				set_by: "the server".into(),
			}),
			refuse: false,
		}
	}
}

/// What starting a family came to.
pub(super) enum Started {
	/// The family was stored, the oldest one ended if the account was full.
	Opened,
	/// The account is at its cap and the policy refuses a new session: how
	/// many it holds and the cap.
	Full {
		held: usize,
		cap: crate::limits::Cap,
	},
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
	/// Keyed by the SHA-256 of the token.
	tokens: HashMap<String, Record>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
	family: String,
	account: String,
	/// The scope the grant carried, space separated.
	scope: String,
	/// Digest of the account's password hash at issue time; empty when it has none.
	credential: String,
	expires_at: u64,
	/// Already exchanged for a newer token. Kept until its own expiry so that
	/// presenting it again is recognised as reuse.
	rotated: bool,
}

/// What presenting a refresh token came to.
pub(super) enum Outcome {
	/// Exchanged: the account and the scope the family was granted.
	Rotated { account: String, scope: String },
	/// Unknown, expired or revoked.
	Refused,
	/// The request asked for more scope than the family holds; nothing changed.
	ScopeTooWide,
	/// An already rotated token came back: the family is gone.
	Reuse,
	/// The account was disabled, removed or locked, or its password changed.
	AccountChanged,
}

fn hash(token: &str) -> String {
	crate::api::api_keys::sha256_hash(token)
}

fn edit<R>(dir: &Path, mutate: impl FnOnce(&mut Store) -> R) -> std::io::Result<R> {
	let mut result = None;
	crate::storage::locked::edit(
		&dir.join(FILE),
		|text| serde_json::from_str::<Store>(text).map_err(std::io::Error::other),
		|store| serde_json::to_string(store).map_err(std::io::Error::other),
		Store::default,
		|store| -> std::io::Result<()> {
			result = Some(mutate(store));
			Ok(())
		},
	)
	.map_err(|error| std::io::Error::other(format!("{error:?}")))?;
	result.ok_or_else(|| std::io::Error::other("refresh store not edited"))
}

/// Drop what expired, so the file does not grow with the age of the server.
fn sweep(store: &mut Store, now: u64) {
	store.tokens.retain(|_, record| record.expires_at > now);
}

fn drop_family(store: &mut Store, family: &str) {
	store.tokens.retain(|_, record| record.family != family);
}

/// The first token of a new family and what it is bound to.
#[derive(Clone, Copy)]
pub(super) struct FirstToken<'a> {
	pub(super) token: &'a str,
	pub(super) family: &'a str,
	pub(super) account: &'a str,
	pub(super) scope: &'a str,
	/// Digest of the account's password hash right now.
	pub(super) credential: &'a str,
}

/// Start a family for `account`: store `token` as its first member. When the
/// account is already at its cap, the family that expires first is deleted to
/// make room, or the new one is refused, as `session` says. The count and the
/// insert are one step under the store's lock, so racing grants admit exactly
/// the cap.
pub(super) fn start_family(
	dir: &Path,
	first: &FirstToken<'_>,
	expires_at: u64,
	now: u64,
	session: &SessionCap,
) -> std::io::Result<Started> {
	let FirstToken {
		token,
		family,
		account,
		scope,
		credential,
	} = *first;
	edit(dir, |store| {
		sweep(store, now);
		let mut latest: HashMap<String, u64> = HashMap::new();
		for record in store.tokens.values().filter(|r| r.account == account) {
			let end = latest.entry(record.family.clone()).or_insert(0);
			*end = (*end).max(record.expires_at);
		}
		if let Some(cap) = &session.cap {
			if session.refuse || cap.value == 0 {
				if latest.len() as u64 >= cap.value {
					return Started::Full {
						held: latest.len(),
						cap: cap.clone(),
					};
				}
			} else {
				while latest.len() as u64 >= cap.value {
					let Some(oldest) = latest
						.iter()
						.min_by_key(|(_, end)| **end)
						.map(|(family, _)| family.clone())
					else {
						break;
					};
					latest.remove(&oldest);
					drop_family(store, &oldest);
				}
			}
		}
		store.tokens.insert(
			hash(token),
			Record {
				family: family.to_string(),
				account: account.to_string(),
				scope: scope.to_string(),
				credential: credential.to_string(),
				expires_at,
				rotated: false,
			},
		);
		Started::Opened
	})
}

/// Whether the store holds `presented`, read without the lock: a guess at a
/// refresh token must not cost a locked write. `Ok(false)` only when absence is
/// confirmed: the token is empty or too long to be one of ours, the store does
/// not exist, or it was read and does not list the token. A store that cannot
/// be read or parsed is an `Err`, never "absent", so a real token is not
/// reported as handled when nothing could be looked at.
fn holds(dir: &Path, presented: &str) -> std::io::Result<bool> {
	if presented.is_empty() || presented.len() > MAX_REFRESH_TOKEN_CHARS {
		return Ok(false);
	}
	let bytes = match std::fs::read(dir.join(FILE)) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
		Err(error) => return Err(error),
	};
	let store = serde_json::from_slice::<Store>(&bytes).map_err(std::io::Error::other)?;
	Ok(store.tokens.contains_key(&hash(presented)))
}

/// Exchange `presented` for `next`, in one locked step. `still_valid` says
/// whether the account of a record may still use it, and `scope_ok` whether the
/// scope it grants covers what the request asked for.
pub(super) fn rotate(
	dir: &Path,
	presented: &str,
	next: &str,
	ttl: u64,
	now: u64,
	still_valid: impl FnOnce(&str, &str) -> bool,
	scope_ok: impl FnOnce(&str) -> bool,
) -> std::io::Result<Outcome> {
	if !holds(dir, presented)? {
		return Ok(Outcome::Refused);
	}
	edit(dir, |store| {
		sweep(store, now);
		let key = hash(presented);
		let Some(record) = store.tokens.get(&key).cloned() else {
			return Outcome::Refused;
		};
		if record.rotated {
			drop_family(store, &record.family);
			return Outcome::Reuse;
		}
		if !still_valid(&record.account, &record.credential) {
			drop_family(store, &record.family);
			return Outcome::AccountChanged;
		}
		if !scope_ok(&record.scope) {
			return Outcome::ScopeTooWide;
		}
		if let Some(old) = store.tokens.get_mut(&key) {
			old.rotated = true;
		}
		store.tokens.insert(
			hash(next),
			Record {
				expires_at: now.saturating_add(ttl),
				rotated: false,
				..record.clone()
			},
		);
		Outcome::Rotated {
			account: record.account,
			scope: record.scope,
		}
	})
}

/// Delete the family `presented` belongs to (RFC 7009), whether it is the
/// current token or an older one. Unknown, empty and oversized tokens change
/// nothing and take no lock: the endpoint has no credential, so a guess must
/// not cost a locked write.
pub(super) fn revoke(dir: &Path, presented: &str, now: u64) -> std::io::Result<()> {
	if !holds(dir, presented)? {
		return Ok(());
	}
	edit(dir, |store| {
		sweep(store, now);
		if let Some(family) = store.tokens.get(&hash(presented)).map(|r| r.family.clone()) {
			drop_family(store, &family);
		}
	})
}

/// Whether the account behind a record may still use it: it exists, is not
/// disabled or locked, and holds the credentials it held at issue time. An
/// account that gives no marker, or a record that kept none, never matches:
/// when the change cannot be told, the token is refused.
pub(super) fn account_unchanged(state: &ApiState, account: &str, credential: &str) -> bool {
	if state.store().is_locked(account) || !state.accounts().iter().any(|a| a.name == account) {
		return false;
	}
	matches_marker(state.store().credential_fingerprint(account), credential)
}

/// Whether the marker an account gives now is the one a record kept. Absent
/// and empty markers match nothing, not even each other.
pub(super) fn matches_marker(now: Option<String>, kept: &str) -> bool {
	!kept.is_empty() && now.is_some_and(|now| !now.is_empty() && now == kept)
}

/// Number of live records in the store. Test-only.
#[cfg(test)]
pub(super) fn live_records(dir: &Path) -> usize {
	std::fs::read_to_string(dir.join(FILE))
		.ok()
		.and_then(|text| serde_json::from_str::<Store>(&text).ok())
		.map_or(0, |store| store.tokens.len())
}
