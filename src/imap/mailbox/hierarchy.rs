//! The mailbox hierarchy on top of the flat folder store: superiors made on
//! demand, children found by name, and a rename that carries a whole subtree.
//!
//! Every folder is one directory under `folders/` whatever its depth (see
//! [`crate::util::mailbox_path`]), so a parent and its children are siblings
//! on disk and the hierarchy is only in their names.

use std::io;
use std::path::Path;

use crate::imap::changelog::{Change, Op};
use crate::util::mailbox_path;
use crate::util::path_component::{AccountName, MailboxName};
use crate::util::path_containment::contained_child;

use super::journal;

fn invalid() -> io::Error {
	io::Error::other("invalid mailbox name")
}

/// Create every missing superior of `name` as an empty mailbox, shortest
/// first, and return one `Created` change per mailbox made (RFC 9051 §6.3.4).
/// The inbox is never a superior that needs creating.
pub(super) fn create_superiors(
	data_dir: &Path,
	account: &AccountName<'_>,
	name: &str,
) -> io::Result<Vec<Change>> {
	let mut changes = Vec::new();
	for ancestor in mailbox_path::ancestors(name) {
		if ancestor.eq_ignore_ascii_case("INBOX") {
			continue;
		}
		let dir = MailboxName::folder(ancestor)
			.map_err(|_| invalid())?
			.messages_dir(account, data_dir)?;
		if !dir.is_dir() {
			make_mailbox(&dir)?;
			changes.push(Change::mailbox(Op::Created, ancestor));
		}
	}
	Ok(changes)
}

/// Make the messages directory of a new mailbox and give the mailbox its
/// UIDVALIDITY. The state file also keeps an empty mailbox in a backup, which
/// archives files and not directories: a superior made for its children has
/// no message of its own.
pub(super) fn make_mailbox(messages_dir: &Path) -> io::Result<()> {
	std::fs::create_dir_all(messages_dir)?;
	crate::imap::uidvalidity::read_or_init(messages_dir);
	Ok(())
}

/// Whether any existing mailbox lies below `name`.
pub(super) fn has_children(data_dir: &Path, account: &str, name: &str) -> bool {
	super::list(data_dir, account)
		.iter()
		.any(|other| other != name && mailbox_path::is_within(other, name))
}

/// Rename the folder `from` and every folder below it to `to` (RFC 9051
/// §6.3.6), creating the missing superiors of `to`. Nothing moves unless
/// every new name is valid and free; a failure part way through puts back the
/// folders already moved.
pub(super) fn rename_subtree(
	data_dir: &Path,
	account: &AccountName<'_>,
	from: &str,
	to: &str,
) -> io::Result<()> {
	let cannot = || io::Error::other("cannot rename");
	if MailboxName::folder(from).is_err() || MailboxName::folder(to).is_err() {
		return Err(cannot());
	}
	if mailbox_path::is_within(to, from) {
		return Err(cannot());
	}
	let source = folder_dir(data_dir, account, from).ok_or_else(cannot)?;
	if !source.is_dir() {
		return Err(io::Error::other("no such mailbox"));
	}
	let mut moves = Vec::new();
	for name in super::list(data_dir, account.as_str()) {
		if !mailbox_path::is_within(&name, from) {
			continue;
		}
		let target = format!("{to}{}", &name[from.len()..]);
		let (Some(old_dir), Some(new_dir)) = (
			folder_dir(data_dir, account, &name),
			folder_dir(data_dir, account, &target),
		) else {
			return Err(cannot());
		};
		if new_dir.exists() {
			return Err(cannot());
		}
		moves.push((name, target, old_dir, new_dir));
	}
	let mut changes = create_superiors(data_dir, account, to)?;
	for (done, (_, _, old_dir, new_dir)) in moves.iter().enumerate() {
		if let Err(error) = std::fs::rename(old_dir, new_dir) {
			for (_, _, old_dir, new_dir) in moves[..done].iter().rev() {
				let _ = std::fs::rename(new_dir, old_dir);
			}
			journal::note(data_dir, account, &changes);
			return Err(error);
		}
	}
	// A mailbox id is its name, so each moved mailbox is destroyed under the
	// old name and created under the new one; every message keeps its id but
	// its `mailboxIds` changed.
	for (old, new, _, new_dir) in &moves {
		changes.push(Change::mailbox(Op::Destroyed, old));
		changes.push(Change::mailbox(Op::Created, new));
		changes.extend(
			journal::message_ids(&contained_child(new_dir, "new")?)
				.into_iter()
				.map(|id| Change::email(Op::Updated, id)),
		);
	}
	journal::note(data_dir, account, &changes);
	Ok(())
}

fn folder_dir(
	data_dir: &Path,
	account: &AccountName<'_>,
	name: &str,
) -> Option<std::path::PathBuf> {
	MailboxName::folder(name)
		.ok()?
		.folder_dir(account, data_dir)
		.ok()
		.flatten()
}
