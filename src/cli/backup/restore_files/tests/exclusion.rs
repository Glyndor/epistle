use super::*;

#[test]
fn tk02_restore_preserves_the_live_store_lock_inode() {
	use crate::storage::lock::FileLock;
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join(".store.lock");
	let _holder = FileLock::acquire(&path).unwrap();
	lay_files(&[("data/.store.lock".into(), 0o600, vec![])], dir.path()).unwrap();
	assert!(
		FileLock::try_acquire(&path).unwrap().is_none(),
		"restore replaced the locked inode"
	);
}
