//! Initial personal mailboxes shared by delivery and IMAP authentication.

use std::io;
use std::path::Path;

pub(crate) fn ensure_defaults(data_dir: &Path, account: &str) -> io::Result<()> {
	let root = data_dir.join("accounts").join(account);
	std::fs::create_dir_all(root.join("new"))?;
	std::fs::create_dir_all(root.join("tmp"))?;
	let folders = root.join("folders");
	std::fs::create_dir_all(&folders)?;
	for name in ["Rejects", "Sent", "Drafts", "Trash", "Archive"] {
		let folder = folders.join(name);
		// Existing folders belong to the user, including their contents and metadata.
		match std::fs::create_dir(&folder) {
			Ok(()) => std::fs::create_dir(folder.join("new"))?,
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
			Err(error) => return Err(error),
		}
	}
	Ok(())
}
