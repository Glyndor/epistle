//! Archive helpers shared by the backup and restore tests: unpack what
//! `backup` wrote and lay it down the way a test needs.

use std::path::Path;

/// Gunzip an archive and return its raw tar bytes. Kept under
/// `helpers` so the existing `use super::helpers::*;` glob in the
/// sibling test files picks it up unchanged.
pub(super) fn gunzip(data: &[u8]) -> Vec<u8> {
	let mut decoder = flate2::read::GzDecoder::new(data);
	let mut out = Vec::new();
	std::io::Read::read_to_end(&mut decoder, &mut out).expect("gunzip");
	out
}

/// Walk a tar's 512-byte blocks, returning (name, content) for each
/// file.
pub(super) fn read_tar(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
	read_tar_entries(tar)
		.into_iter()
		.map(|(name, _mode, content)| (name, content))
		.collect()
}

/// Every entry of the tar, as the restore reads it.
pub(super) fn read_tar_entries(tar: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
	super::tar_format::read_entries(tar).expect("read archive")
}

/// Extract the gunzipped tar bytes into `target`, stripping the `data/`
/// prefix `collect_files` adds.
pub(super) fn extract_to(archive_gz: &[u8], target: &Path) {
	let tar = gunzip(archive_gz);
	for (name, mode, content) in read_tar_entries(&tar) {
		let stripped = name.strip_prefix("data/").unwrap_or(&name);
		let dest = target.join(stripped);
		if let Some(parent) = dest.parent() {
			std::fs::create_dir_all(parent).expect("mkdir parent");
		}
		std::fs::write(&dest, &content).expect("write entry");
		// Private-key material lands at 0600 even if the archive
		// recorded it at 0644; ordinary files keep the archive's mode.
		// The same classifier [`restore_files`] uses in production
		// drives both paths, so an honest restore and a test restore
		// apply the same floor.
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let mode = crate::cli::backup::restore_files::enforced_mode_for(
				std::path::Path::new(stripped),
				mode,
			);
			std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode)).expect("chmod");
		}
	}
}
