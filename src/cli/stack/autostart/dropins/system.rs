//! The system drop-in: written and removed by root, never by the account.

use std::path::Path;

use super::{Change, Host, MOUNTINFO, Scope, own_mount, sync, system_path, system_text};
use crate::config::Boot;

/// The refusal of a process that is not root.
fn needs_root(path: &Path) -> String {
	format!(
		"{} is under /etc/systemd/system, so only root writes it; run it with sudo",
		path.display()
	)
}

/// Leave the system drop-in of the user manager of `uid` as `boot` says:
/// written when `order_after_network` is on, removed when it is off. It
/// asks for root first and writes nothing without it.
pub(in crate::cli) fn ensure_system(
	host: &mut impl Host,
	uid: u32,
	boot: &Boot,
	data_dir: &Path,
) -> Result<Change, String> {
	let path = system_path(uid);
	if !host.is_root() {
		return Err(needs_root(&path));
	}
	let text = if boot.order_after_network {
		let table = host.read(Path::new(MOUNTINFO)).ok().flatten();
		let mount = table.and_then(|table| own_mount(&table, data_dir));
		// A data_dir that cannot be written safely stops here: nothing is
		// written, and a drop-in written before stays as it was.
		Some(system_text(mount.as_deref())?)
	} else {
		None
	};
	sync(host, Scope::System, &path, text.as_deref())
}

/// Remove the system drop-in of the user manager of `uid`.
pub(in crate::cli) fn remove_system(host: &mut impl Host, uid: u32) -> Result<Change, String> {
	let path = system_path(uid);
	if !host.is_root() {
		return Err(needs_root(&path));
	}
	sync(host, Scope::System, &path, None)
}
