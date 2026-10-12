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

use std::path::PathBuf;
use std::sync::Arc;

use super::address::Address;
use super::directory::{Directory, Resolution};
use crate::storage::MessageCrypto;

/// How many bytes an account stores.
pub type UsageProbe = Arc<dyn Fn(&str) -> u64 + Send + Sync>;

/// Quota checks for local accounts.
pub struct MailboxQuota {
	usage: UsageProbe,
	default_bytes: u64,
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
		}
	}

	/// Quota checks reading the mail stored under `data_dir`, the way IMAP
	/// QUOTA measures it.
	pub fn on_disk(data_dir: PathBuf, crypto: MessageCrypto, default_bytes: u64) -> Self {
		MailboxQuota::new(
			move |account| crate::imap::mailbox::account_usage(&data_dir, account, &crypto),
			default_bytes,
		)
	}

	/// The quota in force for `account`.
	pub fn limit(&self, directory: &Directory, account: &str) -> u64 {
		directory.quota_for(account).unwrap_or(self.default_bytes)
	}

	/// Whether `account` already stores at least its quota.
	pub fn is_full(&self, directory: &Directory, account: &str) -> bool {
		(self.usage)(account) >= self.limit(directory, account)
	}

	/// Whether `size` more bytes would put `account` over its quota.
	pub fn would_overflow(&self, directory: &Directory, account: &str, size: u64) -> bool {
		(self.usage)(account).saturating_add(size) > self.limit(directory, account)
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
