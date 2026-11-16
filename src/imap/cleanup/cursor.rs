//! Where the last run stopped, `<data_dir>/cleanup-cursor`: the name of the
//! account it was in when the cap ran out. The next run starts there, so a
//! backlog is worked off over several runs instead of starting from the first
//! account every time.

use std::io;
use std::path::{Path, PathBuf};

const FILE: &str = "cleanup-cursor";

fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(FILE)
}

/// The account to start from, if a run stopped part way.
pub(super) fn read(data_dir: &Path) -> Option<String> {
	let text = std::fs::read_to_string(path(data_dir)).ok()?;
	let name = text.trim();
	(!name.is_empty()).then(|| name.to_string())
}

/// Remember `account` as where the next run starts, or forget the cursor.
pub(super) fn write(data_dir: &Path, account: Option<&str>) -> io::Result<()> {
	let target = path(data_dir);
	let Some(account) = account else {
		return match std::fs::remove_file(&target) {
			Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
			_ => Ok(()),
		};
	};
	let staged = data_dir.join(format!("{FILE}.{}.tmp", uuid::Uuid::now_v7()));
	std::fs::write(&staged, format!("{account}\n"))?;
	std::fs::rename(&staged, &target).inspect_err(|_| {
		let _ = std::fs::remove_file(&staged);
	})
}
