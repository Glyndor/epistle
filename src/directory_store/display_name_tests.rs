//! Display names are kept as written (trimmed), bounded, and free of
//! control characters; they can be set, shown and cleared.

use super::super::*;

fn store(dir: &std::path::Path) -> AccountStore {
	let carol = Account {
		name: "carol".to_string(),
		addresses: vec!["carol@example.org".to_string()],
		password_hash: None,
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
		display_name: Some("Carol Static".to_string()),
	};
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![carol],
	)
	.expect("open")
}

fn bob(display_name: Option<&str>) -> DynamicAccount {
	DynamicAccount {
		name: "bob".to_string(),
		addresses: vec!["bob@example.org".to_string()],
		password_hash: "$argon2id$x".to_string(),
		display_name: display_name.map(str::to_string),
		..DynamicAccount::default()
	}
}

#[test]
fn add_keeps_the_display_name_as_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	store.add(bob(Some("  Ana MARÍA Núñez  "))).expect("add");
	assert_eq!(
		store.display_name("bob").as_deref(),
		Some("Ana MARÍA Núñez")
	);
	let on_disk = std::fs::read_to_string(dir.path().join("accounts.toml")).expect("file");
	assert!(
		on_disk.contains("display_name = \"Ana MARÍA Núñez\""),
		"{on_disk}"
	);
	assert_eq!(store.display_name("carol").as_deref(), Some("Carol Static"));
}

#[test]
fn add_refuses_a_line_break_and_an_overlong_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let error = store
		.add(bob(Some("Bob\r\nBcc: victim@example.net")))
		.expect_err("header injection");
	assert_eq!(
		error.to_string(),
		"invalid account: the display name must not contain control characters or line breaks"
	);
	let error = store
		.add(bob(Some(&"x".repeat(129))))
		.expect_err("too long");
	assert_eq!(
		error.to_string(),
		"invalid account: the display name is 129 characters; the maximum is 128"
	);
	assert!(store.dynamic("bob").is_none(), "nothing was written");
}

#[test]
fn set_display_name_sets_and_clears() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	store.add(bob(None)).expect("add");
	assert_eq!(store.display_name("bob"), None);
	assert_eq!(
		store
			.set_display_name("bob", " Bob Smith ")
			.expect("set")
			.as_deref(),
		Some("Bob Smith")
	);
	assert_eq!(store.display_name("bob").as_deref(), Some("Bob Smith"));
	assert_eq!(store.set_display_name("bob", "").expect("clear"), None);
	assert_eq!(store.display_name("bob"), None);
	assert!(matches!(
		store.set_display_name("carol", "x"),
		Err(StoreError::NotFound(name)) if name == "carol"
	));
	assert!(matches!(
		store.set_display_name("bob", "a\tb"),
		Err(StoreError::Invalid(_))
	));
}
