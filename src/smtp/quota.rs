//! Mailbox quota as mail delivery sees it: the bytes an account stores,
//! measured exactly as IMAP QUOTA reports them (archived messages
//! included), against the account's quota, else its domain's, else the
//! server default.
//!
//! SMTP refuses a recipient whose mailbox is already full at `RCPT TO`
//! (`452 4.2.2`, that recipient only). A message that would push an
//! account over its quota is caught at the end of DATA, once its size is
//! known; SMTP has no per-recipient reply there (that is LMTP), so when
//! other recipients can take it the message is accepted for them and the
//! sender gets a DSN for the full mailbox, and only when every recipient
//! is full is the whole message refused with `552 5.2.2`. The API refuses
//! the request instead.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use super::address::Address;
use super::directory::{Directory, Resolution};
use crate::storage::MessageCrypto;

/// The quota in force for `account`: its own, else its domain's, else
/// `default` (the server's `quota_bytes`, 5 GiB when unset). A quota of 0
/// at any of these levels means no limit: `None`. IMAP QUOTA, JMAP
/// `Quota/get`, and every delivery path read the quota through here.
pub fn limit_for(directory: &Directory, account: &str, default: u64) -> Option<u64> {
	match directory.quota_for(account).unwrap_or(default) {
		0 => None,
		bytes => Some(bytes),
	}
}

/// How many bytes an account stores.
pub type UsageProbe = Arc<dyn Fn(&str) -> u64 + Send + Sync>;

type DeliveryLocks = Mutex<HashMap<String, Weak<Mutex<()>>>>;
type StoreLocks = Mutex<HashMap<PathBuf, Arc<DeliveryLocks>>>;

/// Listeners using the same mail store share quota admission locks. The
/// map of a store is kept for the life of the process: a lock a caller
/// released must be the same lock the next caller takes, whether that
/// caller is the delivery path or one of the paths that stores a message
/// or a blob on the account's behalf.
static ON_DISK_LOCKS: OnceLock<StoreLocks> = OnceLock::new();

/// The admission locks of the mail store rooted at `data_dir`. Every path
/// that writes into that store takes its per-account locks from here, so
/// a quota check and the write it guards cannot interleave with another
/// path's.
pub(crate) fn delivery_lock_for(data_dir: &Path, account: &str) -> Arc<Mutex<()>> {
	account_lock(&store_locks(data_dir), account)
}

/// The admission-lock map of the mail store rooted at `data_dir`.
fn store_locks(data_dir: &Path) -> Arc<DeliveryLocks> {
	let root = data_dir
		.canonicalize()
		.unwrap_or_else(|_| data_dir.to_path_buf());
	let mut stores = ON_DISK_LOCKS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.unwrap_or_else(|e| e.into_inner());
	Arc::clone(stores.entry(root).or_default())
}

/// The lock of one account in `locks`. The caller must hold the returned
/// handle for as long as it holds the lock: the map only keeps a weak
/// reference to it, so a handle nobody holds is dropped and the next
/// caller gets a lock of its own.
fn account_lock(locks: &DeliveryLocks, account: &str) -> Arc<Mutex<()>> {
	let mut locks = locks.lock().unwrap_or_else(|e| e.into_inner());
	locks.retain(|_, lock| lock.strong_count() > 0);
	let entry = locks.entry(account.to_string()).or_default();
	let lock = entry.upgrade().unwrap_or_else(|| Arc::new(Mutex::new(())));
	*entry = Arc::downgrade(&lock);
	lock
}

/// Bytes reserved per account by writers that passed the quota check and
/// have not stored their bytes yet.
type Reservations = Mutex<HashMap<String, u64>>;

/// The reservation map of each mail store, by the root of the store.
type StoreReservations = Mutex<HashMap<PathBuf, Arc<Reservations>>>;

/// The bytes reserved for each account of each mail store by writers that
/// passed the quota check and have not stored their bytes yet. The map
/// lives for the life of the process: a reservation that is released has to
/// be seen by the next writer, whoever it is.
static RESERVED_BYTES: OnceLock<StoreReservations> = OnceLock::new();

/// The reservation map of the mail store rooted at `data_dir`. The account
/// is reserved inside its own store: the same account name in two stores
/// is two different accounts with two different quotas.
fn store_reservations(data_dir: &Path) -> Arc<Reservations> {
	let root = data_dir
		.canonicalize()
		.unwrap_or_else(|_| data_dir.to_path_buf());
	let mut stores = RESERVED_BYTES
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.unwrap_or_else(|e| e.into_inner());
	Arc::clone(stores.entry(root).or_default())
}

/// Bytes reserved for one account by a writer that passed the quota check
/// and has not stored them yet. The reservation is released when the guard
/// is dropped, so a write that fails or is cancelled does not leave the
/// account charged.
pub(crate) struct Reservation {
	reservations: Arc<Reservations>,
	account: String,
	size: u64,
	/// The bytes reserved for the account the moment this one was added,
	/// this one included.
	reserved: u64,
}

impl Reservation {
	/// The bytes reserved for the account when this reservation was made,
	/// counting this one: what the usage read afterwards must be added to.
	pub(crate) fn reserved(&self) -> u64 {
		self.reserved
	}
}

impl Drop for Reservation {
	fn drop(&mut self) {
		let mut reserved = self.reservations.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(bytes) = reserved.get_mut(&self.account) {
			*bytes = bytes.saturating_sub(self.size);
			if *bytes == 0 {
				reserved.remove(&self.account);
			}
		}
	}
}

/// Reserve `size` bytes for `account` of the mail store rooted at
/// `data_dir`, before the usage of the account is read.
///
/// The order is what closes the race. The reservation is added first, so
/// every writer that reserves after this one sees it. Then the caller reads
/// the usage, and refuses when `usage + reservation.reserved()` is over the
/// limit. A writer that finished in between had stored its bytes before it
/// dropped its reservation, so either its reservation is still counted in
/// `reserved()`, or its bytes are already in the usage read after it: at
/// worst it is counted twice, which refuses a little more and never less.
///
/// The returned guard releases the reservation when it is dropped, so a
/// refusal, a failed write or a cancelled request does not leave the account
/// charged. The map is held for the arithmetic only: no I/O and no await
/// happens under it.
pub(crate) fn reserve(data_dir: &Path, account: &str, size: u64) -> Reservation {
	let reservations = store_reservations(data_dir);
	let reserved = {
		let mut reserved = reservations.lock().unwrap_or_else(|e| e.into_inner());
		let entry = reserved.entry(account.to_string()).or_default();
		*entry = entry.saturating_add(size);
		*entry
	};
	Reservation {
		reservations,
		account: account.to_string(),
		size,
		reserved,
	}
}

/// The bytes reserved for `account` in the store rooted at `data_dir` by
/// uploads that passed the quota check and have not stored their blob yet.
/// Every check that compares usage with a quota adds them, so a reservation
/// counts for whoever asks while the blob is on its way.
pub(crate) fn reserved_bytes(data_dir: &Path, account: &str) -> u64 {
	store_reservations(data_dir)
		.lock()
		.unwrap_or_else(|e| e.into_inner())
		.get(account)
		.copied()
		.unwrap_or(0)
}

/// Quota checks for local accounts.
pub struct MailboxQuota {
	usage: UsageProbe,
	default_bytes: u64,
	delivery_locks: Arc<DeliveryLocks>,
}

impl std::fmt::Debug for MailboxQuota {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MailboxQuota")
			.field("default_bytes", &self.default_bytes)
			.finish_non_exhaustive()
	}
}

impl MailboxQuota {
	/// Quota checks reading usage from `usage`, with `default_bytes` for an
	/// account that has no quota of its own or of its domain.
	pub fn new(usage: impl Fn(&str) -> u64 + Send + Sync + 'static, default_bytes: u64) -> Self {
		MailboxQuota {
			usage: Arc::new(usage),
			default_bytes,
			delivery_locks: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	/// Quota checks reading the mail stored under `data_dir`, the way IMAP
	/// QUOTA measures it.
	pub fn on_disk(data_dir: PathBuf, crypto: MessageCrypto, default_bytes: u64) -> Self {
		let delivery_locks = store_locks(&data_dir);
		let mut quota = MailboxQuota::new(
			move |account| {
				// The reservations first, the usage after: see `reserve`.
				let reserved = reserved_bytes(&data_dir, account);
				crate::imap::mailbox::account_usage(&data_dir, account, &crypto)
					.saturating_add(reserved)
			},
			default_bytes,
		);
		quota.delivery_locks = delivery_locks;
		quota
	}

	/// The quota in force for `account`; `None` is no limit.
	pub fn limit(&self, directory: &Directory, account: &str) -> Option<u64> {
		limit_for(directory, account, self.default_bytes)
	}

	/// Whether `account` already stores at least its quota.
	pub fn is_full(&self, directory: &Directory, account: &str) -> bool {
		self.limit(directory, account)
			.is_some_and(|limit| (self.usage)(account) >= limit)
	}

	/// Whether `size` more bytes would put `account` over its quota.
	pub fn would_overflow(&self, directory: &Directory, account: &str, size: u64) -> bool {
		self.limit(directory, account)
			.is_some_and(|limit| (self.usage)(account).saturating_add(size) > limit)
	}

	/// The shared lock for one final account's synchronous copy admission.
	pub(crate) fn delivery_lock(&self, account: &str) -> Arc<Mutex<()>> {
		account_lock(&self.delivery_locks, account)
	}

	/// The recipients among `recipients` that are a local account `size`
	/// more bytes would put over its quota.
	pub fn overflowing(
		&self,
		directory: &Directory,
		recipients: &[String],
		size: u64,
	) -> Vec<String> {
		recipients
			.iter()
			.filter(|recipient| {
				let account = Address::parse(recipient)
					.ok()
					.map(|address| directory.resolve(&address));
				matches!(account, Some(Resolution::Account(name)) if self.would_overflow(directory, &name, size))
			})
			.cloned()
			.collect()
	}
}

#[cfg(test)]
mod tests;
