//! The real POP3 [`Backend`]: credential verification against the account
//! directory and message access on the local filesystem.
//!
//! This is I/O glue over the directory and maildir; the protocol logic it
//! feeds lives in `session` and is unit-tested there. Excluded from the
//! no-filesystem coverage gate.

use std::path::PathBuf;

use crate::directory_store::DirectoryHandle;
use crate::imap::mailbox::mailbox_dir;

use super::session::Backend;

/// Backs a POP3 session with the live account directory and on-disk inbox.
pub struct MailboxBackend {
	directory: DirectoryHandle,
	data_dir: PathBuf,
}

impl MailboxBackend {
	/// Build a backend sharing the server's directory handle and data dir.
	pub fn new(directory: DirectoryHandle, data_dir: PathBuf) -> Self {
		Self {
			directory,
			data_dir,
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
				std::fs::read(dir.join(format!("{stem}.eml")))
					.ok()
					.map(|data| (stem, data))
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
