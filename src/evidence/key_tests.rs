use super::*;

#[test]
fn the_key_is_generated_once_and_kept_owner_only() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let first = EvidenceKey::load_or_create(dir.path()).expect("create");
	let again = EvidenceKey::load_or_create(dir.path()).expect("load");
	assert_eq!(first.public_key(), again.public_key());
	let mode = std::fs::metadata(dir.path().join(KEY_FILE))
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(mode & 0o777, 0o600);
	let pem = std::fs::read_to_string(public_key_path(dir.path(), &first.id())).expect("pem");
	assert_eq!(parse_public_pem(&pem), Some(first.public_key()));
}

#[test]
fn signatures_verify_only_for_the_signed_bytes_and_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("create");
	let signature = key.sign(b"checkpoint");
	assert!(verify(&key.public_key(), b"checkpoint", &signature));
	assert!(!verify(&key.public_key(), b"checkpoinT", &signature));
	let other = tempfile::tempdir().expect("tempdir");
	let other = EvidenceKey::load_or_create(other.path()).expect("create");
	assert!(!verify(&other.public_key(), b"checkpoint", &signature));
	assert_ne!(key.id(), other.id());
}

#[test]
fn processes_racing_to_create_the_key_end_up_with_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	let ids: Vec<String> = (0..8)
		.map(|_| {
			let root = root.clone();
			std::thread::spawn(move || EvidenceKey::load_or_create(&root).expect("key").id())
		})
		.collect::<Vec<_>>()
		.into_iter()
		.map(|thread| thread.join().expect("thread"))
		.collect();
	assert!(ids.windows(2).all(|pair| pair[0] == pair[1]), "keys differ");
	let leftovers = std::fs::read_dir(&root)
		.expect("list")
		.filter_map(Result::ok)
		.filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
		.count();
	assert_eq!(leftovers, 0);
}

#[test]
fn the_pem_is_what_openssl_reads_and_only_ed25519_parses() {
	let raw = [7u8; 32];
	let pem = public_pem(&raw);
	assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA"));
	assert_eq!(parse_public_pem(&pem), Some(raw));
	assert_eq!(
		parse_public_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
		None
	);
	assert_eq!(key_id(&raw).len(), 64);
}

#[test]
fn a_key_file_others_can_read_is_refused() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	EvidenceKey::load_or_create(dir.path()).expect("create");
	let path = dir.path().join(KEY_FILE);
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
	let refused = EvidenceKey::load_or_create(dir.path()).expect_err("a readable key");
	assert_eq!(
		refused.to_string(),
		"the evidence key file is readable or writable by others: it stays 0600"
	);
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	EvidenceKey::load_or_create(dir.path()).expect("0600 loads");
}
