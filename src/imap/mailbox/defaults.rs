//! Initial personal mailboxes shared by delivery and IMAP authentication.

use std::io;
use std::path::Path;

use crate::imap::changelog::{Change, Op};
use crate::imap::special_use::{FolderPolicy, Role, Roles};
use crate::util::path_component::{AccountName, FixedDir};
use crate::util::path_containment::{contained_child, contained_subdir};

/// [`ensure_defaults_with`] under the default policy: English names, spam in
/// `Rejects`.
pub(crate) fn ensure_defaults(data_dir: &Path, account: &str) -> io::Result<()> {
	ensure_defaults_with(data_dir, account, &FolderPolicy::default())
}

/// Create the folders an account starts with, named as `policy` says. A role
/// whose name is one the name table already knows (`Sent`, `Rejects`) is
/// created when that folder is missing, as it always was. A role the operator
/// gave another name is created only when the account has no folder with that
/// role, and recorded in the account, so a folder named in the domain's
/// language does not appear next to the English one the account already has.
pub(crate) fn ensure_defaults_with(
	data_dir: &Path,
	account: &str,
	policy: &FolderPolicy,
) -> io::Result<()> {
	let root = AccountName::new(account)?.root(data_dir)?;
	std::fs::create_dir_all(root.child(FixedDir::New)?)?;
	std::fs::create_dir_all(root.child(FixedDir::Tmp)?)?;
	let folders = root.child(FixedDir::Folders)?;
	std::fs::create_dir_all(&folders)?;
	let mut created = Vec::new();
	let mut recorded = Vec::new();
	let roles = Roles::load(data_dir, account);
	for role in Role::ALL {
		// A role the account recorded is the account's choice, and the folder
		// a user renamed must not come back under its old name.
		if roles.recorded(role).is_some() {
			continue;
		}
		let name = policy.name_for(account, role);
		let derivable = Role::of_name(&name) == Some(role);
		if !derivable && has_role(data_dir, account, &roles, role) {
			continue;
		}
		let folder = contained_subdir(&folders, &name)?;
		// Existing folders belong to the user, including their contents and metadata.
		match std::fs::create_dir(&folder) {
			Ok(()) => {
				std::fs::create_dir(contained_child(&folder, "new")?)?;
				created.push(Change::mailbox(Op::Created, &name));
				if !derivable {
					recorded.push((role, name));
				}
			}
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
			Err(error) => return Err(error),
		}
	}
	for (role, name) in recorded {
		crate::imap::special_use::roles::set(data_dir, account, role, &name)?;
	}
	if !created.is_empty() {
		crate::imap::changelog::note(root.as_path(), &created);
	}
	Ok(())
}

/// Whether the account has a folder with `role`, recorded or by its name.
fn has_role(data_dir: &Path, account: &str, roles: &Roles, role: Role) -> bool {
	super::list(data_dir, account)
		.iter()
		.any(|name| roles.role_of(name) == Some(role))
}
