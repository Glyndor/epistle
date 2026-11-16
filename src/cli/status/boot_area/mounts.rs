//! `data_dir` and the container storage are where the stack expects them
//! when the unit starts.

use std::path::Path;

use super::host::BootHost;
use crate::cli::status::report::{Item, Level};
use crate::config::Config;

const FSTAB: &str = "/etc/fstab";
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// The mount point of an `/etc/fstab` entry that covers `path` and is not
/// mounted, from the mount table `mountinfo` lists. `noauto` and `swap` lines
/// are not expected to be mounted at boot.
pub(super) fn unmounted(fstab: &str, mountinfo: &str, path: &Path) -> Option<String> {
	let mounted: Vec<&str> = mountinfo
		.lines()
		.filter_map(|line| line.split_whitespace().nth(4))
		.collect();
	fstab
		.lines()
		.map(str::trim)
		.filter(|line| !line.starts_with('#'))
		.filter_map(|line| {
			let fields: Vec<&str> = line.split_whitespace().collect();
			let (point, kind, options) = (fields.get(1)?, fields.get(2)?, fields.get(3)?);
			let skipped = *kind == "swap" || options.split(',').any(|word| word == "noauto");
			(!skipped && *point != "/" && path.starts_with(point)).then(|| point.to_string())
		})
		.find(|point| !mounted.contains(&point.as_str()))
}

/// Both directories exist and no `/etc/fstab` mount that covers one of them
/// is missing from the mount table.
pub(super) fn mounted(host: &mut impl BootHost, config: &Config) -> Item {
	let paths = [
		("data_dir", config.data_dir.clone()),
		("container storage", host.storage_dir()),
	];
	let fstab = host
		.read(Path::new(FSTAB))
		.ok()
		.flatten()
		.unwrap_or_default();
	let table = match host.read(Path::new(MOUNTINFO)) {
		Ok(Some(text)) => text,
		_ => {
			return Item::new("mounts", Level::Warn, format!("cannot read {MOUNTINFO}"));
		}
	};
	let mut problems = Vec::new();
	for (name, path) in &paths {
		if !host.exists(path) {
			problems.push(format!("{name} {} does not exist", path.display()));
		} else if let Some(point) = unmounted(&fstab, &table, path) {
			problems.push(format!(
				"{name} {} is under {point}, which is not mounted",
				path.display()
			));
		}
	}
	if problems.is_empty() {
		return Item::new(
			"mounts",
			Level::Ok,
			"data_dir and the container storage are in place",
		);
	}
	Item::new(
		"mounts",
		Level::Warn,
		format!(
			"{}; the unit can run before the disk is there, so mount it first (`sudo mount -a`) and give the unit `RequiresMountsFor=` for it",
			problems.join("; ")
		),
	)
}
