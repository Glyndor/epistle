//! The temporary copies an envelope rewrite leaves under `tmp/` are swept at
//! start-up, and nothing else is.

use super::FsSpool;
use uuid::Uuid;

#[test]
fn only_the_temporary_copies_of_an_envelope_rewrite_are_swept() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let tmp = dir.path().join("spool/tmp");
	std::fs::create_dir_all(&tmp).expect("tmp");
	let id = Uuid::now_v7();
	let rewrite = tmp.join(format!("{id}.{}.json", Uuid::now_v7()));
	let staged = tmp.join(format!("{id}.json"));
	let body = tmp.join(format!("{id}.eml"));
	let foreign = tmp.join("notes.json");
	let half = tmp.join(format!("{id}.not-a-uuid.json"));
	for path in [&rewrite, &staged, &body, &foreign, &half] {
		std::fs::write(path, b"x").expect("file");
	}
	assert_eq!(spool.sweep_envelope_rewrites().expect("sweep"), 1);
	assert!(!rewrite.exists());
	for kept in [&staged, &body, &foreign, &half] {
		assert!(kept.exists(), "{} must stay", kept.display());
	}
	assert_eq!(spool.sweep_envelope_rewrites().expect("again"), 0);
}
