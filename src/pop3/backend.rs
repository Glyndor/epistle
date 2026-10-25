//! The real POP3 [`Backend`]: credential verification against the account
//! directory and message access on the local filesystem.
//!
//! This is I/O glue over the directory and maildir; the protocol logic it
//! feeds lives in `session` and is unit-tested there. Excluded from the
//! no-filesystem coverage gate.

use std::path::PathBuf;

use crate::directory_store::DirectoryHandle;
use crate::imap::mailbox::mailbox_dir;
use crate::storage::MessageCrypto;

use super::bounds::{MAX_MESSAGE_OCTETS, MAX_SESSION_MESSAGES};
use super::session::Backend;
use crate::smtp::directory::hash_gate::Verdict;

/// Backs a POP3 session with the live account directory and on-disk inbox.
pub struct MailboxBackend {
	directory: DirectoryHandle,
	data_dir: PathBuf,
	crypto: MessageCrypto,
}

impl MailboxBackend {
	/// Build a backend sharing the server's directory handle and data dir, with
	/// no at-rest encryption. The encrypting variant is
	/// [`MailboxBackend::new_with_crypto`].
	pub fn new(directory: DirectoryHandle, data_dir: PathBuf) -> Self {
		Self::new_with_crypto(directory, data_dir, MessageCrypto::disabled())
	}

	/// Build a backend that decodes stored message bodies through `crypto`.
	pub fn new_with_crypto(
		directory: DirectoryHandle,
		data_dir: PathBuf,
		crypto: MessageCrypto,
	) -> Self {
		Self {
			directory,
			data_dir,
			crypto,
		}
	}
}

impl MailboxBackend {
	/// [`Backend::fetch`] under a cap of `cap` octets.
	fn fetch_within(&self, account: &str, uid: &str, cap: usize) -> Option<Vec<u8>> {
		// The id comes from the index, but keep the path inside the inbox
		// whatever the caller passes.
		if uid.is_empty() || uid.contains(['/', '\\', '\0']) || uid.starts_with('.') {
			return None;
		}
		let path = mailbox_dir(&self.data_dir, account, "INBOX")?.join(format!("{uid}.eml"));
		let size = std::fs::symlink_metadata(&path).ok()?.len();
		let envelope = if self.crypto.enabled() {
			crate::storage::OVERHEAD
		} else {
			0
		};
		if size > (cap + envelope) as u64 {
			return None;
		}
		let stored = crate::util::fs_walk::read(&path).ok()?;
		// Fail closed: refuse a message that cannot be decrypted rather than
		// serving ciphertext as if it were the message.
		self.crypto.decode(&stored).ok()
	}
}

impl Backend for MailboxBackend {
	fn verify(&self, user: &str, pass: &str, peer_ip: Option<std::net::IpAddr>) -> Option<String> {
		// Route through the directory's ban-aware path: it consults the
		// shared ban store before any hashing, records the failure on miss,
		// and clears on success, so POP3 participates in the same audit and
		// ban accounting as every other listener.
		self.directory.current().authenticate_with_ip(
			user,
			pass,
			peer_ip,
			crate::config::Protocol::Pop3s,
		)
	}

	fn verify_checked(&self, user: &str, pass: &str, peer_ip: Option<std::net::IpAddr>) -> Verdict {
		self.directory.current().authenticate_verdict(
			user,
			pass,
			peer_ip,
			crate::config::Protocol::Pop3s,
		)
	}

	fn list(&self, account: &str) -> Vec<(String, usize)> {
		let Some(dir) = mailbox_dir(&self.data_dir, account, "INBOX") else {
			return Vec::new();
		};
		let mut index: Vec<(String, usize)> = match crate::util::fs_walk::read_dir(&dir) {
			Ok(entries) => entries
				.flatten()
				.filter_map(|entry| {
					let name = entry.file_name();
					let stem = name.to_str()?.strip_suffix(".eml")?.to_string();
					let meta = entry.metadata().ok().filter(std::fs::Metadata::is_file)?;
					let octets = self.crypto.stored_plaintext_len(&entry.path(), meta.len());
					Some((stem, usize::try_from(octets).unwrap_or(usize::MAX)))
				})
				.collect(),
			Err(_) => Vec::new(),
		};
		// UUIDv7 filenames sort lexically in arrival order.
		index.sort();
		index.truncate(MAX_SESSION_MESSAGES);
		index
	}

	fn fetch(&self, account: &str, uid: &str) -> Option<Vec<u8>> {
		self.fetch_within(account, uid, MAX_MESSAGE_OCTETS)
	}

	fn remove(&self, account: &str, uids: &[String]) {
		use crate::imap::changelog::{Change, Op};
		let Some(dir) = mailbox_dir(&self.data_dir, account, "INBOX") else {
			return;
		};
		let mut changes = Vec::new();
		for uid in uids {
			if std::fs::remove_file(dir.join(format!("{uid}.eml"))).is_ok()
				&& let Ok(id) = uuid::Uuid::parse_str(uid)
			{
				changes.push(Change::email(Op::Destroyed, id));
			}
		}
		if !changes.is_empty() {
			changes.push(Change::mailbox(Op::Updated, "INBOX"));
			if let Some(root) = crate::util::path_component::AccountName::new(account)
				.ok()
				.and_then(|name| name.root(&self.data_dir).ok())
			{
				crate::imap::changelog::note(root.as_path(), &changes);
			}
		}
	}
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
