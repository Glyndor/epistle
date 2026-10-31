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
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

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

type DeliveryLocks = Mutex<HashMap<String, Weak<AsyncMutex<()>>>>;
type StoreLocks = Mutex<HashMap<PathBuf, Weak<DeliveryLocks>>>;

/// Listeners using the same mail store share quota admission locks.
static ON_DISK_LOCKS: OnceLock<StoreLocks> = OnceLock::new();

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
		let root = data_dir.canonicalize().unwrap_or_else(|_| data_dir.clone());
		let delivery_locks = {
			let mut stores = ON_DISK_LOCKS
				.get_or_init(|| Mutex::new(HashMap::new()))
				.lock()
				.unwrap_or_else(|e| e.into_inner());
			stores.retain(|_, locks| locks.strong_count() > 0);
			let entry = stores.entry(root).or_default();
			let locks = entry
				.upgrade()
				.unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));
			*entry = Arc::downgrade(&locks);
			locks
		};
		let mut quota = MailboxQuota::new(
			move |account| crate::imap::mailbox::account_usage(&data_dir, account, &crypto),
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

	/// Hold each recipient account's quota until its delivery finishes. Accounts
	/// are locked in order, once each, so overlapping recipient sets can wait
	/// without deadlocking. Waiting yields the task; other accounts stay available.
	pub(crate) async fn lock_delivery(
		&self,
		directory: &Directory,
		recipients: &[String],
	) -> Vec<OwnedMutexGuard<()>> {
		let mut accounts: Vec<String> = recipients
			.iter()
			.filter_map(|recipient| Address::parse(recipient).ok())
			.filter_map(|address| directory.final_recipients(&address))
			.flatten()
			.map(|(account, _)| account)
			.filter(|account| self.limit(directory, account).is_some())
			.collect();
		accounts.sort_unstable();
		accounts.dedup();
		let locks: Vec<_> = {
			let mut locks = self
				.delivery_locks
				.lock()
				.unwrap_or_else(|e| e.into_inner());
			locks.retain(|_, lock| lock.strong_count() > 0);
			accounts
				.into_iter()
				.map(|account| {
					let entry = locks.entry(account).or_default();
					let lock = entry
						.upgrade()
						.unwrap_or_else(|| Arc::new(AsyncMutex::new(())));
					*entry = Arc::downgrade(&lock);
					lock
				})
				.collect()
		};
		let mut held = Vec::with_capacity(locks.len());
		for lock in locks {
			held.push(lock.lock_owned().await);
		}
		held
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
