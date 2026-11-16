//! Reading and writing `<account>/.roles`: one `role<TAB>mailbox` per line.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use super::Role;
use crate::util::mailbox_path::{self, canonical};
use crate::util::path_component::AccountName;

const FILE: &str = ".roles";

fn file(data_dir: &Path, account: &str) -> io::Result<PathBuf> {
	AccountName::new(account)?.root(data_dir)?.file(FILE)
}

pub(super) fn read(data_dir: &Path, account: &str) -> BTreeMap<Role, String> {
	let Ok(path) = file(data_dir, account) else {
		return BTreeMap::new();
	};
	let text = match std::fs::read_to_string(&path) {
		Ok(text) => text,
		Err(error) if error.kind() == io::ErrorKind::NotFound => return BTreeMap::new(),
		Err(error) => {
			tracing::warn!(%error, "cannot read the folder roles of an account; the names decide");
			return BTreeMap::new();
		}
	};
	text.lines()
		.filter_map(|line| line.split_once('\t'))
		.filter_map(|(role, name)| {
			let name = canonical(name);
			let role = Role::parse(role)?;
			mailbox_path::valid_folder(&name).then(|| (role, name.into_owned()))
		})
		.collect()
}

fn write(data_dir: &Path, account: &str, map: &BTreeMap<Role, String>) -> io::Result<()> {
	let root = AccountName::new(account)?.root(data_dir)?;
	let path = root.file(FILE)?;
	if map.is_empty() {
		return match std::fs::remove_file(&path) {
			Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
			_ => Ok(()),
		};
	}
	let text: String = map
		.iter()
		.map(|(role, name)| format!("{}\t{name}\n", role.key()))
		.collect();
	let staged = root.file(&format!("{FILE}.{}.tmp", uuid::Uuid::now_v7()))?;
	std::fs::write(&staged, text)?;
	std::fs::rename(&staged, &path).inspect_err(|_| {
		let _ = std::fs::remove_file(&staged);
	})
}

/// Record `mailbox` as the folder of `role`. The mailbox must exist, and a
/// folder holds one role: any other role it had is dropped.
pub fn set(data_dir: &Path, account: &str, role: Role, mailbox: &str) -> io::Result<()> {
	let mailbox = canonical(mailbox).into_owned();
	if !mailbox_path::valid_folder(&mailbox)
		|| !crate::imap::mailbox::exists(data_dir, account, &mailbox)
	{
		return Err(io::Error::new(
			io::ErrorKind::NotFound,
			"no such mailbox for a role",
		));
	}
	let mut map = read(data_dir, account);
	map.retain(|_, name| !name.eq_ignore_ascii_case(&mailbox));
	map.insert(role, mailbox);
	write(data_dir, account, &map)
}

/// Drop the record of `role`, so the name table answers for it again.
pub fn clear(data_dir: &Path, account: &str, role: Role) -> io::Result<()> {
	let mut map = read(data_dir, account);
	if map.remove(&role).is_some() {
		write(data_dir, account, &map)?;
	}
	Ok(())
}

/// A mailbox `from` and everything below it became `to`: the roles recorded
/// for them follow.
pub fn moved(data_dir: &Path, account: &str, from: &str, to: &str) {
	let from = canonical(from);
	let to = canonical(to);
	let mut map = read(data_dir, account);
	let mut changed = false;
	for name in map.values_mut() {
		if mailbox_path::is_within(name, &from) {
			*name = format!("{to}{}", &name[from.len()..]);
			changed = true;
		}
	}
	if changed && let Err(error) = write(data_dir, account, &map) {
		tracing::warn!(%error, "cannot move the folder roles of a renamed mailbox");
	}
}

/// A mailbox `name` was deleted: the roles recorded for it go too, so a
/// later delivery does not create it again.
pub fn forget(data_dir: &Path, account: &str, name: &str) {
	let name = canonical(name);
	let mut map = read(data_dir, account);
	let before = map.len();
	map.retain(|_, recorded| !mailbox_path::is_within(recorded, &name));
	if map.len() != before
		&& let Err(error) = write(data_dir, account, &map)
	{
		tracing::warn!(%error, "cannot drop the folder roles of a deleted mailbox");
	}
}
