//! The world one fuzz run happens in: a data directory of its own on a
//! RAM-backed filesystem, mail for the two accounts in it, and a way to
//! photograph a part of that directory so a step can be compared with the
//! one before it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use libfuzzer_sys::arbitrary::Unstructured;

use epistle::imap::mailbox;
use epistle::storage::MessageCrypto;

use crate::accounts::{Account, DOMAIN};

/// A fresh data directory, removed when dropped. It sits on `/dev/shm` when
/// the machine has one: a store write fsyncs, and on a disk that is most of
/// the cost of a run.
pub struct DataDir(pub PathBuf);

impl DataDir {
	pub fn new() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		let shm = Path::new("/dev/shm");
		let base = if shm.is_dir() {
			shm.to_path_buf()
		} else {
			std::env::temp_dir()
		};
		let n = NEXT.fetch_add(1, Ordering::Relaxed);
		let path = base.join(format!("epistle-imap-session-{}-{n}", std::process::id()));
		let _ = std::fs::remove_dir_all(&path);
		std::fs::create_dir_all(&path).expect("create the data directory");
		DataDir(path)
	}

	pub fn account(&self, name: &str) -> PathBuf {
		self.0.join("accounts").join(name)
	}
}

impl Drop for DataDir {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}

/// Every account starts with mail in its inbox and in one folder of its own,
/// each message carrying the account's marker. The inbox is never empty, and
/// one input byte per account decides how much mail there is.
pub fn seed(u: &mut Unstructured, dir: &Path, accounts: &[Account]) {
	let crypto = MessageCrypto::disabled();
	for account in accounts {
		let folder = format!("{}-Box", account.marker);
		mailbox::create(dir, account.name, &folder).expect("seed a folder");
		let shape = u.arbitrary::<u8>().unwrap_or(0);
		let counts = [1 + shape % 3, (shape / 3) % 3];
		for (target, count) in [("INBOX", counts[0]), (folder.as_str(), counts[1])] {
			for i in 0..count {
				let body = format!(
					"From: {name}@{DOMAIN}\r\nSubject: {marker} {i}\r\nMessage-ID: <{marker}.{i}@{DOMAIN}>\r\n\r\n{marker}\r\n",
					name = account.name,
					marker = account.marker,
				)
				.into_bytes();
				mailbox::append(dir, account.name, target, &[], &body, &crypto)
					.expect("seed a message");
			}
		}
	}
}

/// Every file under `root` with its bytes, and every directory, by path
/// relative to `root`. Two pictures that differ mean something wrote there.
pub type Picture = BTreeMap<PathBuf, Option<Vec<u8>>>;

pub fn picture(root: &Path, skip: &[PathBuf]) -> Picture {
	let mut out = Picture::new();
	let mut stack = vec![root.to_path_buf()];
	while let Some(dir) = stack.pop() {
		let Ok(entries) = std::fs::read_dir(&dir) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if skip.contains(&path) {
				continue;
			}
			let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
			let Ok(kind) = entry.file_type() else {
				continue;
			};
			if kind.is_dir() {
				out.insert(relative, None);
				stack.push(path);
			} else {
				out.insert(relative, Some(std::fs::read(&path).unwrap_or_default()));
			}
		}
	}
	out
}

/// The paths whose entry differs between two pictures, for a failure message.
pub fn changed(a: &Picture, b: &Picture) -> Vec<PathBuf> {
	let mut out: Vec<PathBuf> = a
		.iter()
		.filter(|(path, value)| b.get(*path) != Some(*value))
		.map(|(path, _)| path.clone())
		.collect();
	out.extend(b.keys().filter(|path| !a.contains_key(*path)).cloned());
	out
}
