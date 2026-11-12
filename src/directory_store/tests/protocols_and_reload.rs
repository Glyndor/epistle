//! Allowed protocols reach the directory, and reload swaps what changed.

use super::base::*;
use super::*;
use crate::smtp::auth::tests::base::{fixture_password, wrong_password};
use crate::smtp::directory::Resolution;

/// A static account with `allowed_protocols` set propagates into the
/// directory the store rebuilds, so the gate in
/// `Directory::authenticate_with_ip` sees the restriction. The store
/// pulls the option from the static config; the directory unit tests
/// in `smtp::directory::protocol_tests` exercise the gate directly.
#[test]
fn static_allowed_protocols_propagates_to_directory() {
	use crate::config::Protocol;
	let dir = tempfile::tempdir().expect("tempdir");
	let static_account = Account {
		send: None,
		receive: None,
		name: "service".to_string(),
		addresses: vec!["service@example.org".to_string()],
		password_hash: Some(crate::smtp::auth::tests::base::hash(fixture_password())),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		display_name: None,
		allowed_protocols: Some(vec![Protocol::Api]),
	};
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![static_account],
	)
	.expect("open store");
	let directory = store.handle().current();
	// The static config's allowlist flows into the rebuilt directory:
	// the allowed protocol admits, the unlisted one rejects.
	assert_eq!(
		directory
			.authenticate("service", fixture_password(), Protocol::Api)
			.as_deref(),
		Some("service"),
	);
	assert!(
		directory
			.authenticate("service", fixture_password(), Protocol::Imaps)
			.is_none(),
		"static allowed_protocols must restrict authentication"
	);
}

/// A dynamic account with `allowed_protocols` set propagates into the
/// directory after `add` swaps the rebuilt handle. The store rebuilds
/// the directory on every mutation (see `AccountStore::add`); this
/// test pins that the rebuild also picks up the dynamic account's
/// allowlist, not just the static one.
#[test]
fn dynamic_allowed_protocols_propagates_to_directory() {
	use crate::config::Protocol;
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	let mut dynamic_account = dynamic("service", "service@example.org");
	// The `dynamic` helper seeds a stub hash so other tests can poke
	// `set_password_hash`; replace it with a real argon2id hash so the
	// directory's password check matches the test password.
	dynamic_account.password_hash = crate::smtp::auth::tests::base::hash(fixture_password());
	dynamic_account.allowed_protocols = Some(vec![Protocol::Api]);
	store.add(dynamic_account).expect("add");
	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate("service", fixture_password(), Protocol::Api)
			.as_deref(),
		Some("service"),
	);
	assert!(
		directory
			.authenticate("service", fixture_password(), Protocol::Imaps)
			.is_none(),
		"dynamic allowed_protocols must restrict authentication"
	);
}

/// `reload_accounts_from` parses `accounts.toml` text, swaps the
/// in-memory dynamic set, and rebuilds the directory the running
/// handle points at, the same path the file watcher takes when a
/// sibling process (the CLI) rewrote the file out of band. The test
/// drives the helper directly so it stays independent of the
/// watcher poll loop; the watcher tests in
/// `src/directory_store/file_watcher/tests/base.rs` cover the live path.
#[test]
fn reload_accounts_from_swaps_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	let handle = store.handle();
	assert_eq!(
		resolves(&handle, "carol@example.org"),
		Resolution::UnknownUser
	);

	let text = r#"
		[[accounts]]
		name = "carol"
		addresses = ["carol@example.org"]
		password_hash = "stub"
	"#;
	store.reload_accounts_from(text).expect("reload");
	assert_eq!(
		resolves(&handle, "carol@example.org"),
		Resolution::Account("carol".to_string())
	);
}

/// The reload refuses to swap on a parse failure so a CLI or operator
/// typo that half-writes a TOML cannot replace the running
/// directory. The previous good state keeps serving requests.
#[test]
fn reload_accounts_from_keeps_directory_on_parse_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let handle = store.handle();
	assert_eq!(
		resolves(&handle, "bob@example.org"),
		Resolution::Account("bob".to_string())
	);

	let bad = "this is not valid toml = = =";
	assert!(matches!(
		store.reload_accounts_from(bad),
		Err(StoreError::Invalid(_))
	));
	assert_eq!(
		resolves(&handle, "bob@example.org"),
		Resolution::Account("bob".to_string()),
		"bad reload must not invalidate the running directory"
	);
}

/// Reload round-trip: the open-on-restart path and the watcher
/// path must produce identical directories, so an edit made through
/// the CLI reaches the running server without the server seeing a
/// divergent snapshot.
#[test]
fn reload_accounts_from_matches_reopen() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	let text = r#"
		[[accounts]]
		name = "carol"
		addresses = ["carol@example.org"]
		password_hash = "stub"
	"#;
	store.reload_accounts_from(text).expect("reload");
	crate::storage::write_secret(&dir.path().join("accounts.toml"), text.as_bytes())
		.expect("write accounts.toml");
	let reopened = open_store(dir.path());
	assert_eq!(
		resolves(&store.handle(), "carol@example.org"),
		resolves(&reopened.handle(), "carol@example.org"),
	);
}

/// `reload_app_passwords_from` swaps the in-memory mirror without
/// persisting (the watcher has already seen the file on disk) and
/// rebuilds the directory so a freshly-issued secondary credential
/// resolves from the next authentication attempt. The verification
/// goes through `Directory::authenticate` because that is the path
/// the SMTP / IMAP / ManageSieve / WebDAV / API listeners actually
/// drive; a credential that survives the reload has to make it past
/// the full local-authentication flow, not just an internal map
/// lookup.
#[test]
fn reload_app_passwords_from_swaps_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut static_alice = static_account();
	// `credentials` returns `None` when the login has no hash, which
	// would short-circuit `authenticate_local` before the app-password
	// fallback ran. Give the test account a real argon2id hash so the
	// credential path reaches the `app_passwords` map.
	static_alice.password_hash = Some(crate::smtp::auth::tests::base::hash(wrong_password()));
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![static_alice],
	)
	.expect("open");
	let secret = uuid::Uuid::now_v7().simple().to_string();
	let hash = crate::smtp::auth::tests::base::hash(&secret);
	let text = format!(
		r#"[accounts.alice]
passwords = [
  {{ label = "phone", hash = "{hash}" }}
]
"#
	);
	store.reload_app_passwords_from(&text).expect("reload");
	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate("alice", &secret, crate::config::Protocol::Api)
			.as_deref(),
		Some("alice"),
		"app password from the reload must authenticate",
	);
}

/// The masked reload replaces the entries map wholesale, which is
/// exactly what the watcher needs: a brand-new address the CLI
/// minted appears on the rebuilt directory the next poll picks up.
#[test]
fn reload_masked_from_swaps_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	let text = r#"{
		"addresses": {
			"shop.abcd1234@example.org": {
				"address": "shop.abcd1234@example.org",
				"account": "alice",
				"label": "shop",
				"created_at": 1700000000,
				"enabled": true
			}
		}
	}"#;
	store.reload_masked_from(text).expect("reload");
	assert_eq!(
		resolves(&store.handle(), "shop.abcd1234@example.org"),
		Resolution::Account("alice".to_string())
	);
}

/// The alias reload rehydrates the disabled overlay from the on-disk
/// JSON; a disabled alias falls out of the directory the same way a
/// `set_alias_enabled(false)` set on the running server does.
#[test]
fn reload_aliases_from_swaps_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path()).with_aliases(vec![crate::config::Alias {
		address: "team@example.org".to_string(),
		members: vec!["alice@example.org".to_string()],
		senders: Vec::new(),
		hidden: true,
		list_id: None,
	}]);
	let handle = store.handle();
	assert!(matches!(
		resolves(&handle, "team@example.org"),
		Resolution::Alias(_)
	));

	let text = r#"{ "addresses": ["team@example.org"] }"#;
	store.reload_aliases_from(text).expect("reload");
	assert_eq!(
		resolves(&handle, "team@example.org"),
		Resolution::UnknownUser,
		"disabled alias must fall through after the reload"
	);
}
