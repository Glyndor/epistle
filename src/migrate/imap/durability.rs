//! Durability barriers used before publishing migration checkpoints.

use std::fs::File;
use std::io;

/// Synchronize an open file or directory. Test hooks inject errors at the same barrier.
pub(super) fn sync(file: &File, _kind: &'static str) -> io::Result<()> {
	#[cfg(test)]
	tests::before_sync(_kind)?;
	file.sync_all()?;
	#[cfg(test)]
	tests::record(_kind);
	Ok(())
}

/// Persist the body and sidecars of one message.
pub(super) fn files(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	id: uuid::Uuid,
) -> io::Result<()> {
	let dir = crate::imap::mailbox::mailbox_dir(data_dir, account, mailbox)
		.ok_or_else(|| io::Error::other("invalid migration mailbox"))?;
	for (extension, kind) in [("eml", "message"), ("flags", "flags"), ("zone", "zone")] {
		let path = dir.join(format!("{id}.{extension}"));
		match File::open(path) {
			Ok(file) => sync(&file, kind)?,
			Err(error) if extension != "eml" && error.kind() == io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
	}
	Ok(())
}

/// Persist the mailbox directory and every parent up to the data directory,
/// which makes the names of all the files created in it durable at once.
pub(super) fn hierarchy(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
) -> io::Result<()> {
	let root = data_dir.canonicalize()?;
	let dir = crate::imap::mailbox::mailbox_dir(&root, account, mailbox)
		.ok_or_else(|| io::Error::other("invalid migration mailbox"))?;
	let mut parent = dir.as_path();
	loop {
		sync(
			&File::open(parent)?,
			if parent == dir {
				"mailbox-directory"
			} else {
				"mailbox-parent"
			},
		)?;
		if parent == root {
			break;
		}
		parent = parent
			.parent()
			.filter(|path| path.starts_with(&root))
			.ok_or_else(|| io::Error::other("migration mailbox is outside the data directory"))?;
	}
	Ok(())
}

/// Persist the body, sidecars and containing hierarchy before confirming a UID.
pub(super) fn message(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	id: uuid::Uuid,
) -> io::Result<()> {
	let root = data_dir.canonicalize()?;
	files(&root, account, mailbox, id)?;
	hierarchy(&root, account, mailbox)
}

#[cfg(test)]
#[path = "durability_tests.rs"]
pub(super) mod tests;
