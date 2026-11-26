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
		let mut cover: Vec<String> = legacy_cover(&reach).iter().map(|s| s.to_string()).collect();
		// A key that holds only scopes 0.14.0 had no name for carries a
		// placeholder, and is held so that 0.14.0 refuses it.
		if cover.is_empty() {
			assert!(key.unusable_in_v014(), "{}", key.label);
			cover = vec!["read".to_string()];
		}
		assert_eq!(cover, key.scopes, "{}", key.label);
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

// --- A key 0.14.0 has no scope for -------------------------------------------

fn ip(text: &str) -> IpAddr {
	text.parse().expect("ip")
}

fn held_store(dir: &std::path::Path, label: &str, grants: &[&str], cidr: Option<&str>) -> String {
	let mut store = ApiKeyStore::open(dir).expect("open");
	let mut key = key_with(&[], grants);
	key.label = label.to_string();
	key.hash = sha256_hash(&format!("secret-{label}"));
	key.ip_cidr = cidr.map(str::to_string);
	store.add(key).expect("add");
	std::fs::read_to_string(dir.join("api_keys.toml")).expect("read")
}

#[test]
fn a_scope_0_14_0_had_no_name_for_gives_no_name() {
	assert!(legacy_cover(&[Scope::Ban]).is_empty());
	assert_eq!(legacy_cover(&[Scope::Ban, Scope::Send]), ["send"]);
	assert_eq!(Scope::Ban.v014_name(), None);
	for scope in ALL {
		assert_eq!(
			scope.v014_name().is_none(),
			matches!(scope, Scope::Ban | Scope::Health),
			"{scope:?}: a scope added later says here what 0.14.0 makes of it"
		);
	}
}

/// What a rollback does to a key that holds only `ban`: 0.14.0 loads the file and
/// refuses the key from every address, and 0.15.0 puts it back.
#[test]
fn a_ban_key_taken_back_to_0_14_0_can_neither_read_nor_write_and_comes_back() {
	for (cidr, scope) in [
		(None, "ban"),
		(Some("10.0.0.0/8"), "ban"),
		(None, "health"),
		(Some("10.0.0.0/8"), "health"),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let text = held_store(dir.path(), "banner", &[scope], cidr);
		let loaded = v014_load(&text).expect("0.14.0 loads the file");
		let key = &loaded.keys[0];
		assert_eq!(key.scopes, ["read"], "a placeholder, never an empty list");
		for ip in [None, Some("10.1.2.3"), Some("192.0.2.1"), Some("::1")] {
			let ip = ip.map(|ip| ip.parse().expect("ip"));
			assert!(!key.usable_from(ip, 1_000), "{ip:?} is refused by 0.14.0");
		}
		// Back on 0.15.0: the key is what it was.
		let store = ApiKeyStore::open(dir.path()).expect("reopen");
		let key = &store.keys()[0];
		let held: Scope = scope.parse().expect("scope");
		assert_eq!(key.reach(), Some(vec![held]));
		assert_eq!(key.ip_cidr.as_deref(), cidr);
		assert!(
			key.admits_any("secret-banner", Some(ip("10.1.2.3")), 1_000, &[held]) || cidr.is_none()
		);
		if cidr.is_none() {
			assert!(key.admits_any("secret-banner", None, 1_000, &[held]));
		}
	}
}

#[test]
fn a_key_that_has_a_name_in_0_14_0_is_not_held() {
	let dir = tempfile::tempdir().expect("tempdir");
	let text = held_store(
		dir.path(),
		"mixed",
		&["ban", "manage:read"],
		Some("10.0.0.0/8"),
	);
	assert!(!text.contains("rollback_hold"), "{text}");
	let loaded = v014_load(&text).expect("loads");
	assert_eq!(loaded.keys[0].scopes, ["read"]);
	assert_eq!(loaded.keys[0].ip_cidr.as_deref(), Some("10.0.0.0/8"));
	assert!(loaded.keys[0].usable_from(Some(ip("10.1.2.3")), 1_000));
}

#[test]
fn narrowing_a_held_key_to_a_scope_with_a_name_releases_it_and_the_other_way_holds_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	held_store(dir.path(), "k", &["ban"], Some("10.0.0.0/8"));
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	store
		.set_scopes("k", &["manage:read".to_string()])
		.expect("set");
	let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("read");
	assert!(
		!text.contains("rollback_hold") && !text.contains("held-until"),
		"{text}"
	);
	assert_eq!(
		v014_load(&text).expect("loads").keys[0].ip_cidr.as_deref(),
		Some("10.0.0.0/8")
	);
	store.set_scopes("k", &["ban".to_string()]).expect("set");
	let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("read");
	assert!(!v014_load(&text).expect("loads").keys[0].usable_from(Some(ip("10.1.2.3")), 1_000));
	assert_eq!(
		ApiKeyStore::open(dir.path()).expect("open").keys()[0]
			.ip_cidr
			.as_deref(),
		Some("10.0.0.0/8")
	);
}

/// 0.14.0 drops what it does not know when it writes the file, so the table that
/// restores the key can be gone. The key then stays refused, here and there.
#[test]
fn a_held_key_that_0_14_0_rewrote_stays_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let text = held_store(dir.path(), "banner", &["ban"], None);
	let rewritten = toml::to_string_pretty(&v014_load(&text).expect("loads")).expect("write");
	assert!(!rewritten.contains("rollback_hold") && !rewritten.contains("grants"));
	std::fs::write(dir.path().join("api_keys.toml"), rewritten).expect("rewrite");
	let store = ApiKeyStore::open(dir.path()).expect("0.15.0 loads it");
	let key = &store.keys()[0];
	assert!(!key.admits_any(
		"secret-banner",
		Some(ip("10.1.2.3")),
		1_000,
		&[Scope::ManageRead]
	));
	assert!(!key.admits_any("secret-banner", None, 1_000, &[Scope::ManageRead]));
}

#[test]
fn the_held_marker_is_no_network_for_either_release() {
	assert!(crate::cidr::Cidr::parse(super::super::held::HELD).is_none());
}
