//! What a restore refuses before it writes, and that `--dry-run` refuses the
//! same archives instead of listing them as restorable.

use super::*;

fn archive(names: &[&str]) -> Vec<u8> {
	let entries: Vec<(String, u32, Vec<u8>)> = names
		.iter()
		.map(|name| ((*name).to_string(), 0o644, b"x".to_vec()))
		.collect();
	tar_gz(&entries).expect("tar_gz")
}

fn config(data_dir: &Path) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	))
	.expect("config")
}

fn restore(names: &[&str], dry_run: bool) -> (ExitCode, String, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let exit = run_restore(
		&config(&data_dir),
		&archive(names),
		false,
		dry_run,
		&mut out,
		&mut status,
	);
	(exit, String::from_utf8(out).expect("utf8"), dir)
}

#[test]
fn dry_run_refuses_a_path_the_restore_would_refuse() {
	let (exit, out, _dir) = restore(&["data/../x"], true);
	assert_eq!(exit, ExitCode::FAILURE);
	assert!(!out.contains("would restore"), "{out}");
}

#[test]
fn dry_run_refuses_colliding_paths() {
	let (exit, out, _dir) = restore(&["data/a", "data/a/b"], true);
	assert_eq!(exit, ExitCode::FAILURE);
	assert!(!out.contains("would restore"), "{out}");
}

#[test]
fn a_restore_with_colliding_paths_writes_nothing() {
	for names in [
		&["data/a", "data/a/b"][..],
		&["data/a/b", "data/a"][..],
		&["data/a", "data/a"][..],
	] {
		let (exit, _out, dir) = restore(names, false);
		assert_eq!(exit, ExitCode::FAILURE, "{names:?}");
		let written = std::fs::read_dir(dir.path().join("data"))
			.expect("dir")
			.count();
		assert_eq!(written, 0, "{names:?} must leave data_dir as it was");
	}
}

#[test]
fn paths_that_only_share_a_prefix_are_not_collisions() {
	let (exit, out, _dir) = restore(&["data/a", "data/ab", "data/c/x", "data/c/y"], true);
	assert_eq!(exit, ExitCode::SUCCESS, "{out}");
	assert!(out.contains("would restore 4 entries"), "{out}");
}
