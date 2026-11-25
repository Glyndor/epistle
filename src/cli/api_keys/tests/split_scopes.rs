//! The management and mail scopes at the command line: the seven names, what
//! `read` and `write` still do, what a key bound to an account refuses, and how
//! a key is split.

use super::*;
use crate::api::ApiKeyStore;
use crate::api::api_keys::Scope;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn make(
	config: &Config,
	label: &str,
	scopes: &[&str],
	account: Option<&str>,
) -> (ExitCode, String) {
	let mut err = Vec::new();
	let code = create(
		config,
		NewKey {
			label: label.to_string(),
			scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
			account: account.map(str::to_string),
			domains: if account.is_some() {
				Vec::new()
			} else {
				vec!["example.org".to_string()]
			},
			..NewKey::default()
		},
		false,
		&mut Vec::new(),
		&mut err,
	);
	(code, String::from_utf8(err).expect("utf8"))
}

#[test]
fn the_seven_names_and_the_two_old_ones_are_taken() {
	for name in [
		"manage:read",
		"manage:write",
		"mail:read",
		"mail:write",
		"send",
		"scim",
		"alias",
		"read",
		"write",
	] {
		assert!(parse_scope(name).is_ok(), "{name}");
	}
	let error = parse_scope("manage").expect_err("not a scope");
	assert!(
		error.contains("manage:read") && error.contains("alias, ban, health or key"),
		"{error}"
	);
}

#[test]
fn a_new_name_is_stored_in_both_vocabularies() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let (code, err) = make(&config, "mailbox", &["mail:read", "send"], None);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!err.contains("management and mail"), "no warning: {err}");
	let store = ApiKeyStore::open(dir.path()).expect("open");
	let key = &store.keys()[0];
	assert_eq!(key.grants, ["mail:read", "send"]);
	assert_eq!(key.scopes, ["read", "send"], "what 0.14.0 reads");
	assert!(!key.covers_any(&[Scope::ManageRead]));
}

#[test]
fn read_still_works_and_says_it_opens_both() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let (code, err) = make(&config, "old", &["read"], None);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(err.contains("management and mail"), "{err}");
	assert!(err.contains("0.17.0"), "{err}");
	let store = ApiKeyStore::open(dir.path()).expect("open");
	let key = &store.keys()[0];
	assert_eq!(key.grants, ["manage:read", "mail:read"]);
	assert_eq!(key.scopes, ["read"]);
}

#[test]
fn a_bound_key_refuses_the_management_scopes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	for scope in ["manage:read", "manage:write", "scim", "alias"] {
		let (code, _) = make(&config, "bound", &[scope], Some("alice"));
		assert_eq!(code, ExitCode::from(crate::cli::exit::POLICY), "{scope}");
	}
	assert!(
		ApiKeyStore::open(dir.path())
			.expect("open")
			.keys()
			.is_empty()
	);
}

#[test]
fn a_bound_key_takes_read_and_write_as_their_mail_half_without_a_warning() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let (code, err) = make(&config, "bound", &["read", "write", "send"], Some("alice"));
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!err.contains("management and mail"), "{err}");
	let store = ApiKeyStore::open(dir.path()).expect("open");
	assert_eq!(store.keys()[0].grants, ["mail:read", "mail:write", "send"]);
}

#[test]
fn set_scope_splits_a_wide_key_and_keeps_the_rest() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(
		make(&config, "wide", &["read", "write"], None).0,
		ExitCode::SUCCESS
	);
	let before = ApiKeyStore::open(dir.path()).expect("open").keys()[0].clone();
	let code = set_scopes(
		&config,
		"wide",
		vec!["manage:read".to_string(), "manage:write".to_string()],
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let store = ApiKeyStore::open(dir.path()).expect("open");
	let key = &store.keys()[0];
	assert_eq!(key.grants, ["manage:read", "manage:write"]);
	assert_eq!(key.scopes, ["read", "write"]);
	assert_eq!((&key.hash, &key.domains), (&before.hash, &before.domains));
	assert!(!key.spans_manage_and_mail());
	assert!(before.spans_manage_and_mail());
}

#[test]
fn set_scope_on_a_bound_key_refuses_management() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(
		make(&config, "bound", &["mail:read"], Some("alice")).0,
		ExitCode::SUCCESS
	);
	let code = set_scopes(
		&config,
		"bound",
		vec!["manage:write".to_string()],
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::POLICY));
	let store = ApiKeyStore::open(dir.path()).expect("open");
	assert_eq!(store.keys()[0].grants, ["mail:read"], "unchanged");
}

#[test]
fn set_scope_of_a_missing_key_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let code = set_scopes(
		&config,
		"nobody",
		vec!["send".to_string()],
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	);
	assert_ne!(code, ExitCode::SUCCESS);
}
