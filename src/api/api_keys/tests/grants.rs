//! The four scopes, how a key stores them, and what 0.14.0 makes of the file.

use super::v014::v014_load;
use super::*;
use crate::api::api_keys::grants::{ALL, expand_legacy, validate_loaded};

fn key_with(scopes: &[&str], grants: &[&str]) -> ApiKey {
	ApiKey {
		label: "k".to_string(),
		hash: sha256_hash("secret"),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes.iter().map(|name| (*name).to_string()).collect(),
		grants: grants.iter().map(|name| (*name).to_string()).collect(),
		domains: Vec::new(),
		account: None,
		auto_submitted: false,
	}
}

/// Every non-empty subset of the seven scopes.
fn every_set() -> Vec<Vec<Scope>> {
	(1u32..(1 << ALL.len()))
		.map(|bits| {
			ALL.iter()
				.enumerate()
				.filter(|(index, _)| bits & (1 << index) != 0)
				.map(|(_, scope)| *scope)
				.collect()
		})
		.collect()
}

#[test]
fn legacy_names_expand_to_both_halves() {
	assert_eq!(
		expand_legacy("read").expect("read"),
		[Scope::ManageRead, Scope::MailRead]
	);
	assert_eq!(
		expand_legacy("write").expect("write"),
		[Scope::ManageWrite, Scope::MailWrite]
	);
	for name in ["send", "scim", "alias"] {
		assert_eq!(expand_legacy(name).expect(name).len(), 1);
	}
	assert!(expand_legacy("manage:read").is_err());
}

#[test]
fn legacy_key_reaches_what_it_reached() {
	let key = key_with(&["read"], &[]);
	assert_eq!(key.reach(), Some(vec![Scope::ManageRead, Scope::MailRead]));
	assert!(key.covers_any(&[Scope::ManageRead]));
	assert!(key.covers_any(&[Scope::MailRead]));
	assert!(!key.covers_any(&[Scope::ManageWrite, Scope::MailWrite]));
	assert_eq!(key_with(&[], &[]).reach(), None, "no scope is every scope");
}

#[test]
fn grants_win_over_scopes() {
	// `scopes` says `write`, `grants` says only the mail half.
	let key = key_with(&["write"], &["mail:write"]);
	assert_eq!(key.reach(), Some(vec![Scope::MailWrite]));
	assert!(!key.covers_any(&[Scope::ManageWrite]));
}

#[test]
fn grants_refuse_legacy_names() {
	assert!(validate_loaded(&key_with(&["read"], &["read"])).is_err());
	assert!(validate_loaded(&key_with(&["read"], &["mail:read"])).is_ok());
	// A name this build cannot read holds nothing, never everything.
	assert_eq!(key_with(&["read"], &["nonsense"]).reach(), Some(Vec::new()));
}

#[test]
fn scopes_refuse_new_names() {
	// What keeps the file one 0.14.0 can load.
	assert!(validate_loaded(&key_with(&["mail:read"], &[])).is_err());
}

#[test]
fn key_with_grants_needs_scopes() {
	assert!(validate_loaded(&key_with(&[], &["mail:read"])).is_err());
}

#[test]
fn writers_never_leave_scopes_empty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	for (index, set) in every_set().into_iter().enumerate() {
		let names: Vec<String> = set.iter().map(|scope| scope.as_str().to_string()).collect();
		let (scopes, grants) = stored_form(&names, false).expect("stored form");
		assert!(!scopes.is_empty(), "{names:?}");
		assert_eq!(grants, names, "{names:?}");
		// Create.
		let mut key = key_with(&[], &[]);
		key.label = format!("created-{index}");
		key.hash = sha256_hash(&format!("secret-{index}"));
		key.grants = names.clone();
		store.add(key).expect("add");
		// Set.
		store
			.set_scopes(&format!("created-{index}"), &names)
			.expect("set");
		// Rotate keeps both fields.
		store
			.rotate(&format!("created-{index}"), sha256_hash("rotated"))
			.expect("rotate");
	}
	for key in store.keys() {
		assert!(!key.scopes.is_empty(), "{}", key.label);
		assert!(!key.grants.is_empty(), "{}", key.label);
		let reach = key.reach().expect("explicit scopes");
		assert_eq!(
			legacy_cover(&reach)
				.iter()
				.map(|s| s.to_string())
				.collect::<Vec<_>>(),
			key.scopes,
			"{}",
			key.label
		);
	}
}

#[test]
fn legacy_cover_is_the_narrowest_names() {
	assert_eq!(legacy_cover(&[Scope::MailRead]), ["read"]);
	assert_eq!(
		legacy_cover(&[Scope::ManageWrite, Scope::Send]),
		["write", "send"]
	);
	assert_eq!(
		legacy_cover(&[Scope::ManageRead, Scope::MailRead, Scope::Alias]),
		["read", "alias"]
	);
	assert!(legacy_cover(&[]).is_empty());
}

#[test]
fn a_bound_key_gets_the_mail_half_of_read_and_write() {
	let names = vec!["read".to_string(), "write".to_string()];
	let (scopes, grants) = stored_form(&names, true).expect("bound");
	assert_eq!(grants, ["mail:read", "mail:write"]);
	assert_eq!(scopes, ["read", "write"]);
	let (_, wide) = stored_form(&names, false).expect("wide");
	assert_eq!(wide.len(), 4);
}

#[test]
fn unknown_and_empty_names_are_refused() {
	assert_eq!(stored_form(&[], false), Err(ScopeInputError::Empty));
	assert_eq!(
		stored_form(&["reed".to_string()], false),
		Err(ScopeInputError::Unknown("reed".to_string()))
	);
}

#[test]
fn v014_reader_loads_what_v015_writes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	for (index, set) in every_set().into_iter().enumerate() {
		let mut key = key_with(&[], &[]);
		key.label = format!("key-{index}");
		key.hash = sha256_hash(&format!("secret-{index}"));
		key.grants = set.iter().map(|scope| scope.as_str().to_string()).collect();
		store.add(key).expect("add");
	}
	let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("read");
	assert!(text.contains("grants"), "the new field is written");
	let loaded = v014_load(&text).expect("0.14.0 loads the file");
	assert_eq!(loaded.keys.len(), (1 << ALL.len()) - 1);
	for key in &loaded.keys {
		// An empty list is every scope to 0.14.0: it must never see one.
		assert!(!key.scopes.is_empty(), "{} would be every scope", key.label);
	}
}

#[test]
fn v014_reader_is_not_fooled_by_new_names_in_scopes() {
	// The frozen reader does refuse them, which is why `scopes` holds only
	// the old names; this pins that the copy is the strict loader.
	let text = "[[keys]]\nlabel = \"k\"\nhash = \"sha256:00\"\nscopes = [\"mail:read\"]\n";
	assert!(v014_load(text).is_err());
}

#[test]
fn the_v015_loader_reads_what_v014_wrote() {
	let text = "[[keys]]\nlabel = \"old\"\nhash = \"sha256:00\"\nscopes = [\"read\", \"send\"]\n";
	let file: ApiKeyFile = toml::from_str(text).expect("parse");
	validate_loaded(&file.keys[0]).expect("valid");
	let reach = file.keys[0].reach().expect("explicit");
	assert!(reach.contains(&Scope::ManageRead) && reach.contains(&Scope::MailRead));
	assert!(reach.contains(&Scope::Send) && !reach.contains(&Scope::ManageWrite));
}
