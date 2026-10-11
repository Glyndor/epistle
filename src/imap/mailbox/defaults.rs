//! Initial personal mailboxes shared by delivery and IMAP authentication.

use std::io;
use std::path::Path;

use crate::util::path_component::{AccountName, FixedDir};
use crate::util::path_containment::{contained_child, contained_subdir};

pub(crate) fn ensure_defaults(data_dir: &Path, account: &str) -> io::Result<()> {
	let root = AccountName::new(account)?.root(data_dir)?;
	std::fs::create_dir_all(root.child(FixedDir::New)?)?;
	std::fs::create_dir_all(root.child(FixedDir::Tmp)?)?;
	let folders = root.child(FixedDir::Folders)?;
	std::fs::create_dir_all(&folders)?;
	for name in ["Rejects", "Sent", "Drafts", "Trash", "Archive"] {
		let folder = contained_subdir(&folders, name)?;
		// Existing folders belong to the user, including their contents and metadata.
		match std::fs::create_dir(&folder) {
			Ok(()) => std::fs::create_dir(contained_child(&folder, "new")?)?,
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
			Err(error) => return Err(error),
		}
	}
	Ok(())
}
