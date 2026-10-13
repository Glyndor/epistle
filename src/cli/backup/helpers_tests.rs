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

/// Walk a tar's 512-byte blocks, returning (name, mode, content).
pub(super) fn read_tar_entries(tar: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
	let mut out = Vec::new();
	let mut offset = 0;
	while offset + 512 <= tar.len() {
		let header = &tar[offset..offset + 512];
		if header.iter().all(|&b| b == 0) {
			break; // end-of-archive zero block
		}
		if &header[257..262] != b"ustar" {
			break;
		}
		let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
		let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
		let mode_str = String::from_utf8_lossy(&header[100..108]);
		let mode = u32::from_str_radix(mode_str.trim_matches('\0').trim(), 8).unwrap_or(0);
		let size_str = String::from_utf8_lossy(&header[124..135]);
		let size = usize::from_str_radix(size_str.trim_matches('\0').trim(), 8).unwrap_or(0);
		offset += 512;
		out.push((name, mode, tar[offset..offset + size].to_vec()));
		offset += size.div_ceil(512) * 512;
	}
	out
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
