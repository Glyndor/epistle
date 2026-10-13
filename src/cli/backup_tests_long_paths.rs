//! Paths longer than the 100 bytes a plain ustar header holds. The
//! correspondent store alone writes `correspondents/<64 hex>/<64 hex>`, so
//! `backup` failed with "path too long" on any install that had sent mail.

use super::*;
use std::os::unix::fs::PermissionsExt;

fn config_for(data_dir: &Path) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	))
	.expect("config")
}

/// Every regular file under `root`, as (relative path, mode, bytes).
fn tree(root: &Path) -> Vec<(String, u32, Vec<u8>)> {
	let mut out = Vec::new();
	let mut stack = vec![root.to_path_buf()];
	while let Some(dir) = stack.pop() {
		for entry in std::fs::read_dir(&dir).unwrap().flatten() {
			let path = entry.path();
			if path.is_dir() {
				stack.push(path);
			} else {
				let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
				let relative = path.strip_prefix(root).unwrap().display().to_string();
				out.push((relative, mode, std::fs::read(&path).unwrap()));
			}
		}
	}
	out.sort();
	out
}

#[test]
fn paths_over_100_and_over_255_bytes_round_trip_byte_for_byte() {
	let source = tempfile::tempdir().unwrap();
	let data_dir = source.path().join("data");
	let marker = format!("correspondents/{}/{}", "a".repeat(64), "b".repeat(64));
	let deep = format!(
		"accounts/alice/{}/{}/{}/m1.eml",
		"x".repeat(90),
		"y".repeat(90),
		"z".repeat(90)
	);
	assert!(format!("data/{marker}").len() > 100 && format!("data/{deep}").len() > 255);
	for (relative, bytes) in [
		(marker.as_str(), b"marker".to_vec()),
		(deep.as_str(), (0..=255u8).cycle().take(70_000).collect()),
		("accounts.toml", b"short".to_vec()),
	] {
		let path = data_dir.join(relative);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(&path, bytes).unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	}

	let mut archive = Vec::new();
	let mut warnings = Vec::new();
	assert_eq!(
		run(&config_for(&data_dir), &mut archive, &mut warnings),
		ExitCode::SUCCESS,
		"{}",
		String::from_utf8_lossy(&warnings)
	);

	let target = tempfile::tempdir().unwrap();
	let restored = target.path().join("data");
	std::fs::create_dir_all(&restored).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	assert_eq!(
		run_restore(
			&config_for(&restored),
			&archive,
			true,
			false,
			&mut out,
			&mut status
		),
		ExitCode::SUCCESS,
		"{}",
		String::from_utf8_lossy(&status)
	);
	assert_eq!(tree(&restored), tree(&data_dir));
}
