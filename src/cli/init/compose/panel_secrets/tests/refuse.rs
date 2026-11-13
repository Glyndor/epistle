//! What is refused instead of overwritten, and that a refusal writes nothing.

use super::*;

/// Make the secrets directory and return the token path.
fn token_path(layout: &Layout) -> PathBuf {
	let path = api_token_path(&layout.data);
	std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
	path
}

fn assert_nothing_written(layout: &Layout) {
	assert!(
		!session_secret_path(&layout.data).exists(),
		"the session secret must not be written when the key is refused"
	);
	assert_eq!(count_keys(layout), 0, "no key row on a refusal");
}

#[test]
fn a_symlink_in_place_of_the_token_is_refused_and_left_alone() {
	let layout = layout();
	let path = token_path(&layout);
	let target = layout.data.join("elsewhere");
	std::fs::write(&target, "kept").expect("write");
	std::os::unix::fs::symlink(&target, &path).expect("symlink");
	let message = refusal(&layout, NOW);
	assert!(message.contains(&path.display().to_string()), "{message}");
	assert!(message.contains("path is a symlink"), "{message}");
	assert_eq!(text(&target), "kept");
	assert!(
		std::fs::symlink_metadata(&path)
			.expect("meta")
			.file_type()
			.is_symlink()
	);
	assert_nothing_written(&layout);
}

#[test]
fn a_directory_in_place_of_the_token_is_refused() {
	let layout = layout();
	std::fs::create_dir_all(api_token_path(&layout.data)).expect("dir");
	let message = refusal(&layout, NOW);
	assert!(message.contains("path is not a regular file"), "{message}");
	assert_nothing_written(&layout);
}

#[test]
fn an_empty_token_file_is_refused() {
	let layout = layout();
	std::fs::write(token_path(&layout), "").expect("write");
	let message = refusal(&layout, NOW);
	assert!(message.contains("file is empty"), "{message}");
	assert_nothing_written(&layout);
}

#[test]
fn a_symlink_or_an_empty_file_in_place_of_the_session_secret_is_refused() {
	let layout = layout();
	let path = session_secret_path(&layout.data);
	std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
	std::fs::write(&path, "").expect("write");
	assert!(refusal(&layout, NOW).contains("file is empty"));
	std::fs::remove_file(&path).expect("remove");
	std::os::unix::fs::symlink("/nonexistent", &path).expect("symlink");
	assert!(refusal(&layout, NOW).contains("path is a symlink"));
	assert_eq!(
		count_keys(&layout),
		0,
		"the key is not minted behind a refused session secret"
	);
}

#[test]
fn a_session_secret_under_32_bytes_is_refused_not_replaced() {
	let layout = layout();
	let path = session_secret_path(&layout.data);
	std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
	std::fs::write(&path, "b".repeat(31)).expect("write");
	let message = refusal(&layout, NOW);
	assert!(message.contains("at least 32 bytes"), "{message}");
	assert_eq!(text(&path), "b".repeat(31));
	assert_eq!(count_keys(&layout), 0);
	// Just inside the limit it is accepted.
	std::fs::write(&path, "b".repeat(32)).expect("write");
	run(&layout, NOW);
}

fn foreign(label: &str, scopes: &[&str], domains: &[&str], account: Option<&str>) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash("theirs"),
		expires_at: Some(NOW + 400 * DAY),
		ip_cidr: None,
		scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
		domains: domains.iter().map(|s| (*s).to_string()).collect(),
		account: account.map(str::to_string),
	}
}

#[test]
fn a_panel_key_with_another_reach_is_refused_and_its_secret_is_not_replaced() {
	let cases = [
		foreign(LABEL, &["read", "write", "send"], &[], None),
		foreign(LABEL, &["read"], &[], None),
		foreign(LABEL, &["write"], &[], None),
		foreign(LABEL, &["read", "write", "scim"], &[], None),
		foreign(LABEL, &["read", "write"], &["example.org"], None),
		foreign(LABEL, &["read", "write"], &[], Some("alice")),
	];
	for key in cases {
		let layout = layout();
		let shape = format!("{key:?}");
		ApiKeyStore::open(&layout.data)
			.expect("open")
			.add(key)
			.expect("add");
		let message = refusal(&layout, NOW);
		assert!(
			message.contains("exists with other settings than the panel's"),
			"{shape}: {message}"
		);
		assert!(
			message.contains("epistle api-key revoke panel"),
			"{message}"
		);
		assert!(!api_token_path(&layout.data).exists(), "{shape}");
		assert!(!session_secret_path(&layout.data).exists(), "{shape}");
		assert_eq!(
			row(&layout).hash,
			crate::api::api_keys::sha256_hash("theirs"),
			"{shape}"
		);
	}
}

#[test]
fn a_panel_key_whose_scopes_are_listed_in_the_other_order_is_the_panels() {
	let layout = layout();
	let mut key = foreign(LABEL, &["write", "read"], &[], None);
	key.ip_cidr = Some("203.0.113.0/24".to_string());
	ApiKeyStore::open(&layout.data)
		.expect("open")
		.add(key)
		.expect("add");
	run(&layout, NOW);
	assert_eq!(
		row(&layout).ip_cidr.as_deref(),
		Some("203.0.113.0/24"),
		"a narrower key stays narrower"
	);
}

#[test]
fn a_key_with_another_label_is_never_touched() {
	let layout = layout();
	ApiKeyStore::open(&layout.data)
		.expect("open")
		.add(foreign("ci", &["read", "write", "send"], &[], None))
		.expect("add");
	run(&layout, NOW);
	assert_eq!(count_keys(&layout), 2);
	let store = ApiKeyStore::open(&layout.data).expect("open");
	let ci = store
		.keys()
		.iter()
		.find(|key| key.label == "ci")
		.expect("ci");
	assert_eq!(ci.hash, crate::api::api_keys::sha256_hash("theirs"));
}
