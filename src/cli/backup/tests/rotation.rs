//! A backup leaves out the plaintext secrets of an unfinished `rotate --all`.

use crate::cli::backup::collect::collect_files;

#[test]
fn the_new_secrets_and_the_lock_of_an_unfinished_rotation_stay_out_of_the_archive() {
	let root = tempfile::tempdir().expect("dir");
	let rotate = root.path().join("rotate");
	std::fs::create_dir(&rotate).expect("mkdir");
	for name in ["journal.json", "secrets.json", "lock", "last-run.json"] {
		std::fs::write(rotate.join(name), b"{}").expect("file");
	}
	std::fs::write(root.path().join("api_keys.toml"), b"").expect("file");
	let names: Vec<String> = collect_files(root.path())
		.expect("collect")
		.into_iter()
		.map(|(name, ..)| name)
		.collect();
	assert_eq!(
		names,
		[
			"data/api_keys.toml",
			"data/rotate/journal.json",
			"data/rotate/last-run.json"
		]
	);
}
