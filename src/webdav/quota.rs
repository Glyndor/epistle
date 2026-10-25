//! The account storage quota as WebDAV writes see it.
//!
//! What an account stores is its mail, measured exactly as IMAP QUOTA reports
//! it, plus everything under its DAV tree. A write that would push the total
//! over the quota in force ([`crate::smtp::quota::limit_for`]: the account's,
//! else its domain's, else the server default; `0` is no limit) is refused
//! with `507 Insufficient Storage` and the `DAV:sufficient-disk-space`
//! precondition (RFC 4918 §9.7.1, RFC 4331). A write that does not grow the
//! account is never refused for being over quota.
//!
//! Every file and every collection of the DAV tree costs at least
//! [`MIN_ENTRY_BYTES`], about what the disk gives it, so empty files and
//! collections are not free. The change log of a calendar or addressbook
//! counts for [`LOG_RESERVE`]. The bounds on entries per collection and on
//! depth are in [`super::bounds`] and hold with or without a quota.
//!
//! The check and the write that follows it happen under one lock per
//! account, so concurrent writes of one account cannot each pass the check
//! against the same free space. `DELETE` and `MOVE` take the same lock. Sizes
//! are the real ones: the body already read for a `PUT`, the files on disk for
//! a `COPY`. The totals are not walked for every write: the DAV total is kept
//! per account and updated by each write (a walk refreshes it when it is
//! older than five minutes or after a `DELETE` or `MOVE`), and the mail total
//! is measured at most once in ten seconds, outside the write lock.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::WebDavState;
use crate::storage::MessageCrypto;

/// The least a file or a collection counts for, in bytes.
pub const MIN_ENTRY_BYTES: u64 = 4096;

/// What the change log of a calendar or an addressbook counts for: the most
/// entries it keeps, at a generous size each. Its real size is not tracked
/// write by write, so the room is taken when the collection is made and every
/// measure of the tree counts the log at this size.
pub const LOG_RESERVE: u64 = super::sync::MAX_ENTRIES as u64 * 270;

/// How long a measure of the mail an account stores is reused.
const MAIL_TTL: Duration = Duration::from_secs(10);

/// How long the kept total of the DAV tree is trusted before a walk.
const DAV_TTL: Duration = Duration::from_secs(300);

/// Per-account state, shared by every request of the account.
#[derive(Default)]
struct Account {
	/// Held from the check to the end of the write, with or without a quota.
	write: Arc<Mutex<()>>,
	/// Held by the one request that re-measures the mail, so a burst of
	/// requests after the measure expires does not walk the mailbox each.
	mail_gate: Mutex<()>,
	usage: std::sync::Mutex<Usage>,
}

#[derive(Default)]
struct Usage {
	mail: Option<(u64, Instant)>,
	dav: Option<(u64, Instant)>,
	/// How many times the DAV tree was walked to measure it.
	walks: u32,
	/// How many times the mail was measured.
	mail_walks: u32,
}

/// The state of every account that has a quota, by its DAV root.
static ACCOUNTS: LazyLock<std::sync::Mutex<HashMap<PathBuf, Arc<Account>>>> =
	LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn account_for(dav_root: &Path) -> Arc<Account> {
	let mut accounts = ACCOUNTS.lock().unwrap_or_else(|poison| poison.into_inner());
	Arc::clone(accounts.entry(dav_root.to_path_buf()).or_default())
}

/// What a write adds to and frees from the account's DAV tree.
#[derive(Default)]
pub(super) struct Change {
	/// Bytes the write adds outright (a `PUT` body, a new collection).
	pub(super) bytes: u64,
	/// A tree the write copies; its size is measured under the lock.
	pub(super) copies: Option<PathBuf>,
	/// A file or tree the write replaces; its size is freed.
	pub(super) replaces: Option<PathBuf>,
}

/// The quota of one authenticated account.
pub(super) struct Quota {
	account: Arc<Account>,
	limit: Option<u64>,
	data_dir: PathBuf,
	dav_root: PathBuf,
	crypto: MessageCrypto,
	members: usize,
}

/// Held while a quota-checked write runs.
pub(super) struct Reservation {
	_guard: Option<OwnedMutexGuard<()>>,
	account: Option<Arc<Account>>,
	stale: bool,
}

impl Reservation {
	/// The kept total of the DAV tree is no longer to be trusted: the write
	/// failed, or it removed or moved things.
	pub(super) fn invalidate(&mut self) {
		self.stale = true;
	}
}

impl Drop for Reservation {
	fn drop(&mut self) {
		if self.stale
			&& let Some(account) = &self.account
		{
			account
				.usage
				.lock()
				.unwrap_or_else(|poison| poison.into_inner())
				.dav = None;
		}
	}
}

impl Quota {
	pub(super) fn new(state: &WebDavState, account: &str, dav_root: &Path) -> Self {
		let limit =
			crate::smtp::quota::limit_for(&state.directory.current(), account, state.quota_default);
		Self {
			account: account_for(dav_root),
			limit,
			data_dir: state.data_dir.clone(),
			dav_root: dav_root.to_path_buf(),
			crypto: state.crypto.clone(),
			members: super::bounds::MAX_MEMBERS,
		}
	}

	/// Check the structural bounds for creating `target` (see
	/// [`super::bounds`]); `subtree` is the tree a `COPY` or `MOVE` brings.
	pub(super) async fn check_create(
		&self,
		target: &Path,
		subtree: Option<&Path>,
	) -> Result<(), Box<Response>> {
		super::bounds::check_create(&self.dav_root, target, subtree, self.members)
			.await
			.map_err(|refusal| Box::new(super::bounds::refusal_response(refusal)))
	}

	/// How many times the mail was measured.
	#[cfg(test)]
	pub(super) fn mail_walks(&self) -> u32 {
		self.account
			.usage
			.lock()
			.unwrap_or_else(|poison| poison.into_inner())
			.mail_walks
	}

	/// How many times the DAV tree was walked to measure it.
	#[cfg(test)]
	pub(super) fn walks(&self) -> u32 {
		self.account
			.usage
			.lock()
			.unwrap_or_else(|poison| poison.into_inner())
			.walks
	}

	/// Take the account's write lock for a `DELETE` or a `MOVE`, which change
	/// the DAV tree without a check.
	/// The lock is taken whether or not the account has a quota: the bounds
	/// on depth and entries are checked under it.
	pub(super) async fn exclusive(&self) -> Reservation {
		Reservation {
			_guard: Some(Arc::clone(&self.account.write).lock_owned().await),
			account: Some(Arc::clone(&self.account)),
			stale: true,
		}
	}

	/// Take the account's write lock and check that `change` fits. `Err` is
	/// the response to send.
	pub(super) async fn admit(&self, change: Change) -> Result<Reservation, Box<Response>> {
		let Some(limit) = self.limit else {
			// No quota to measure, but the write still goes one at a time.
			return Ok(Reservation {
				_guard: Some(Arc::clone(&self.account.write).lock_owned().await),
				account: None,
				stale: false,
			});
		};
		let mail = self.mail_usage().await;
		let guard = Arc::clone(&self.account.write).lock_owned().await;
		let kept = self
			.account
			.usage
			.lock()
			.unwrap_or_else(|poison| poison.into_inner())
			.dav
			.filter(|(_, at)| at.elapsed() < DAV_TTL)
			.map(|(total, _)| total);
		let dav_root = self.dav_root.clone();
		let measured = tokio::task::spawn_blocking(move || {
			let walked = kept.is_none();
			let dav = kept.unwrap_or_else(|| tree_cost(&dav_root, false));
			let freed = change
				.replaces
				.as_deref()
				.map_or(0, |path| tree_cost(path, true));
			let added = change
				.bytes
				.saturating_add(change.copies.as_deref().map_or(0, |p| tree_cost(p, true)));
			(dav, freed, added, walked)
		})
		.await;
		let Ok((dav, freed, added, walked)) = measured else {
			return Err(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()));
		};
		let after = dav.saturating_sub(freed).saturating_add(added);
		{
			let mut usage = self
				.account
				.usage
				.lock()
				.unwrap_or_else(|poison| poison.into_inner());
			usage.walks += u32::from(walked);
			if walked {
				usage.dav = Some((dav, Instant::now()));
			}
		}
		let grows = added > freed;
		if grows && mail.saturating_add(after) > limit {
			return Err(Box::new(insufficient_storage()));
		}
		self.account
			.usage
			.lock()
			.unwrap_or_else(|poison| poison.into_inner())
			.dav
			.get_or_insert((dav, Instant::now()))
			.0 = after;
		Ok(Reservation {
			_guard: Some(guard),
			account: Some(Arc::clone(&self.account)),
			stale: false,
		})
	}

	/// The bytes of mail the account stores, measured at most once per
	/// ten seconds and never while the write lock is held.
	async fn mail_usage(&self) -> u64 {
		let fresh = self
			.account
			.usage
			.lock()
			.unwrap_or_else(|poison| poison.into_inner())
			.mail
			.filter(|(_, at)| at.elapsed() < MAIL_TTL);
		if let Some((bytes, _)) = fresh {
			return bytes;
		}
		let _gate = self.account.mail_gate.lock().await;
		let again = self
			.account
			.usage
			.lock()
			.unwrap_or_else(|poison| poison.into_inner())
			.mail
			.filter(|(_, at)| at.elapsed() < MAIL_TTL);
		if let Some((bytes, _)) = again {
			return bytes;
		}
		let (data_dir, crypto) = (self.data_dir.clone(), self.crypto.clone());
		let name = self
			.dav_root
			.parent()
			.and_then(|dir| dir.file_name())
			.map(|name| name.to_string_lossy().into_owned())
			.unwrap_or_default();
		let bytes = tokio::task::spawn_blocking(move || {
			crate::imap::mailbox::account_usage(&data_dir, &name, &crypto)
		})
		.await
		.unwrap_or(u64::MAX);
		let mut usage = self
			.account
			.usage
			.lock()
			.unwrap_or_else(|poison| poison.into_inner());
		usage.mail = Some((bytes, Instant::now()));
		usage.mail_walks += 1;
		bytes
	}
}

/// `507` carrying the `DAV:sufficient-disk-space` precondition.
fn insufficient_storage() -> Response {
	(
		StatusCode::INSUFFICIENT_STORAGE,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error xmlns:D=\"DAV:\"><D:sufficient-disk-space/></D:error>",
	)
		.into_response()
}

/// What the file or tree at `path` counts for: every file its size or
/// [`MIN_ENTRY_BYTES`] if that is more, every collection [`MIN_ENTRY_BYTES`]
/// (the one at `path` too when `include_self`). Symlinks are not followed and
/// count for nothing; a missing path is empty.
pub(super) fn tree_cost(path: &Path, include_self: bool) -> u64 {
	let mut total = 0u64;
	let mut pending = vec![(path.to_path_buf(), include_self)];
	while let Some((next, counted)) = pending.pop() {
		let Ok(meta) = std::fs::symlink_metadata(&next) else {
			continue;
		};
		if meta.is_file() {
			let size = if next
				.file_name()
				.is_some_and(|name| name == super::sync::CHANGELOG)
			{
				LOG_RESERVE
			} else {
				meta.len().max(MIN_ENTRY_BYTES)
			};
			total = total.saturating_add(size);
		} else if meta.is_dir() {
			if counted {
				total = total.saturating_add(MIN_ENTRY_BYTES);
			}
			if let Ok(entries) = std::fs::read_dir(&next) {
				pending.extend(entries.flatten().map(|entry| (entry.path(), true)));
			}
		}
	}
	total
}

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
