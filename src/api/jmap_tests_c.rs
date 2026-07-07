//! JMAP blob quota/usage and reclamation tests (RFC 8620 §6).

#[test]
fn account_usage_bytes_sums_mail_and_blobs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	// 5 bytes of stored mail.
	let inbox = path.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	std::fs::write(
		inbox.join(format!("{}.eml", uuid::Uuid::now_v7())),
		b"hello",
	)
	.expect("write");
	// 10 bytes across the shared blob pool.
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");
	std::fs::write(blobs.join(uuid::Uuid::now_v7().to_string()), b"0123456789").expect("write");

	assert_eq!(
		super::jmap::account_usage_bytes(path, "alice", &crate::storage::MessageCrypto::disabled()),
		15
	);
}

#[test]
fn reclaim_blobs_drops_stale_keeps_fresh_and_spares_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");

	// A stale blob (payload + sidecar) backdated past the TTL.
	let stale = uuid::Uuid::now_v7().to_string();
	std::fs::write(blobs.join(&stale), b"old").expect("write");
	std::fs::write(blobs.join(format!("{stale}.type")), b"image/png").expect("write");
	let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
	filetime_set(&blobs.join(&stale), old);

	// A fresh blob written just now.
	let fresh = uuid::Uuid::now_v7().to_string();
	std::fs::write(blobs.join(&fresh), b"new").expect("write");

	// Stored mail that must never be reclaimed.
	let inbox = path.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let msg = inbox.join(format!("{}.eml", uuid::Uuid::now_v7()));
	std::fs::write(&msg, b"keep me").expect("write");

	let removed = super::jmap::reclaim_blobs(path, std::time::Duration::from_secs(24 * 3600));
	assert_eq!(removed, 1);
	assert!(!blobs.join(&stale).exists(), "stale blob should be gone");
	assert!(
		!blobs.join(format!("{stale}.type")).exists(),
		"stale sidecar should be gone"
	);
	assert!(blobs.join(&fresh).exists(), "fresh blob should be kept");
	assert!(msg.exists(), "stored mail must be untouched");
}

/// Backdate a file's mtime by writing through `std::fs::File::set_modified`.
fn filetime_set(path: &std::path::Path, when: std::time::SystemTime) {
	let file = std::fs::OpenOptions::new()
		.write(true)
		.open(path)
		.expect("open");
	file.set_modified(when).expect("set mtime");
}
