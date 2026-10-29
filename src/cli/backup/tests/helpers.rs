//! Archive helpers shared by the backup and restore tests: unpack what
//! `backup` wrote and lay it down the way a test needs.

use std::path::Path;

use super::BackupError;

/// How many extra attempts a spawn gets when the kernel refuses the exec
/// of a stub the test wrote moments earlier.
const TEXT_FILE_BUSY_ATTEMPTS: usize = 4;

/// Run `attempt`, and run it again only while it keeps failing with
/// `ETXTBSY`. Writing a shell stub and exec'ing it back to back loses that
/// race in about one spawn in twenty when the test binary runs its tests in
/// parallel: this host's `/tmp` is a tmpfs and the kernel still sees a
/// writer on the inode at exec time. The refusal belongs to the harness, not
/// to the code under test, so every other outcome is returned untouched.
pub(in super::super) fn retry_on_text_file_busy<T>(
	mut attempt: impl FnMut() -> Result<T, BackupError>,
) -> Result<T, BackupError> {
	for _ in 0..TEXT_FILE_BUSY_ATTEMPTS {
		let result = attempt();
		let refused = matches!(
			&result,
			Err(BackupError::CommandFailed { stderr, code: None }) if stderr.contains("Text file busy")
		);
		if !refused {
			return result;
		}
		std::thread::sleep(std::time::Duration::from_millis(25));
	}
	attempt()
}

/// Gunzip an archive and return its raw tar bytes. Kept under
/// `helpers` so the existing `use super::helpers::*;` glob in the
/// sibling test files picks it up unchanged.
pub(in super::super) fn gunzip(data: &[u8]) -> Vec<u8> {
	let mut decoder = flate2::read::GzDecoder::new(data);
	let mut out = Vec::new();
	std::io::Read::read_to_end(&mut decoder, &mut out).expect("gunzip");
	out
}

/// Walk a tar's 512-byte blocks, returning (name, content) for each
/// file.
pub(in super::super) fn read_tar(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
	read_tar_entries(tar)
		.into_iter()
		.map(|(name, _mode, content)| (name, content))
		.collect()
}

/// Every entry of the tar, as the restore reads it.
pub(in super::super) fn read_tar_entries(tar: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
	super::tar_format::read_entries(tar).expect("read archive")
}

/// Extract the gunzipped tar bytes into `target`, stripping the `data/`
/// prefix `collect_files` adds.
pub(in super::super) fn extract_to(archive_gz: &[u8], target: &Path) {
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
