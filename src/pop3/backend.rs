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

use super::session::Backend;

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

impl Backend for MailboxBackend {
	fn verify(&self, user: &str, pass: &str) -> Option<String> {
		// Hold the directory snapshot for the whole lookup: credentials()
		// borrows from it. No oracle — a wrong user and a wrong password both
		// yield None.
		let directory = self.directory.current();
		directory
			.credentials(user)
			.filter(|(_, hash)| crate::smtp::auth::verify_password(hash, pass))
			.map(|(account, _)| account)
	}

	fn load(&self, account: &str) -> Vec<(String, Vec<u8>)> {
		let Some(dir) = mailbox_dir(&self.data_dir, account, "INBOX") else {
			return Vec::new();
		};
		let mut stems: Vec<String> = match std::fs::read_dir(&dir) {
			Ok(entries) => entries
				.flatten()
				.filter_map(|entry| {
					entry
						.file_name()
						.to_str()
						.and_then(|name| name.strip_suffix(".eml"))
						.map(str::to_string)
				})
				.collect(),
			Err(_) => Vec::new(),
		};
		// UUIDv7 filenames sort lexically in arrival order.
		stems.sort();
		stems
			.into_iter()
			.filter_map(|stem| {
				let stored = std::fs::read(dir.join(format!("{stem}.eml"))).ok()?;
				// Fail closed: drop a message that cannot be decrypted rather than
				// serving ciphertext as if it were the message.
				let data = self.crypto.decode(&stored).ok()?;
				Some((stem, data))
			})
			.collect()
	}

	fn remove(&self, account: &str, uids: &[String]) {
		let Some(dir) = mailbox_dir(&self.data_dir, account, "INBOX") else {
			return;
		};
		for uid in uids {
			let _ = std::fs::remove_file(dir.join(format!("{uid}.eml")));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	fn backend(dir: &std::path::Path) -> MailboxBackend {
		let directory = DirectoryHandle::new(
			crate::smtp::directory::Directory::new(
				["example.org".to_string()],
				[("alice@example.org".to_string(), "alice".to_string())],
			)
			.with_password_hashes(HashMap::from([(
				"alice".to_string(),
				crate::smtp::auth::tests::hash("secret"),
			)])),
		);
		MailboxBackend::new(directory, dir.to_path_buf())
	}

	#[test]
	fn verify_checks_credentials_without_oracle() {
		let dir = tempfile::tempdir().expect("tempdir");
		let backend = backend(dir.path());
		assert_eq!(
			backend.verify("alice@example.org", "secret").as_deref(),
			Some("alice")
		);
		// Wrong password and unknown user both fail the same way.
		assert!(backend.verify("alice@example.org", "wrong").is_none());
		assert!(backend.verify("ghost@example.org", "secret").is_none());
	}

	#[test]
	fn load_returns_messages_in_arrival_order() {
		let dir = tempfile::tempdir().expect("tempdir");
		let backend = backend(dir.path());
		// No INBOX yet → empty.
		assert!(backend.load("alice").is_empty());

		crate::imap::mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[],
			b"Subject: one\r\n\r\na\r\n",
			&MessageCrypto::disabled(),
		)
		.expect("append one");
		crate::imap::mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[],
			b"Subject: two\r\n\r\nb\r\n",
			&MessageCrypto::disabled(),
		)
		.expect("append two");

		let messages = backend.load("alice");
		assert_eq!(messages.len(), 2);
		// UUIDv7 stems sort in arrival order.
		assert!(messages[0].1.windows(3).any(|w| w == b"one"));
		assert!(messages[1].1.windows(3).any(|w| w == b"two"));
	}

	#[test]
	fn remove_deletes_named_messages() {
		let dir = tempfile::tempdir().expect("tempdir");
		let backend = backend(dir.path());
		crate::imap::mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[],
			b"x\r\n",
			&MessageCrypto::disabled(),
		)
		.expect("append");
		let messages = backend.load("alice");
		assert_eq!(messages.len(), 1);
		let uid = messages[0].0.clone();

		backend.remove("alice", &[uid]);
		assert!(backend.load("alice").is_empty());
		// Removing from a missing account is a harmless no-op.
		backend.remove("nobody", &["whatever".to_string()]);
	}
}
