//! Tests for merging SQL-sourced accounts into the directory and the
//! static-over-SQL precedence. These need no database: they exercise the
//! row→directory mapping by feeding [`SqlAccount`] values directly into the
//! store. The async loader itself is covered by the gated integration tests in
//! `tests/database.rs`.

use super::SqlAccount;
use crate::config::Account;
use crate::directory_store::AccountStore;
use crate::smtp::directory::Resolution;

fn static_account(name: &str, address: &str, password: Option<&str>) -> Account {
	Account {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: password.map(crate::smtp::auth::tests::hash),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
	}
}

fn store_with(static_accounts: Vec<Account>) -> AccountStore {
	let dir = tempfile::tempdir().expect("tempdir");
	AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		static_accounts,
	)
	.expect("open store")
}

fn sql(name: &str, address: &str, password: Option<&str>) -> SqlAccount {
	SqlAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: password.map(crate::smtp::auth::tests::hash),
	}
}

#[test]
fn sql_accounts_resolve_and_authenticate() {
	let store = store_with(Vec::new()).with_sql_accounts(vec![sql(
		"carol",
		"carol@example.org",
		Some("hunter2"),
	)]);
	let directory = store.handle().current();

	assert_eq!(
		directory.resolve(&crate::smtp::address::Address::parse("carol@example.org").unwrap()),
		Resolution::Account("carol".to_string())
	);
	assert_eq!(
		directory.authenticate("carol@example.org", "hunter2"),
		Some("carol".to_string())
	);
	assert_eq!(directory.authenticate("carol@example.org", "wrong"), None);
}

#[test]
fn receive_only_sql_account_cannot_authenticate() {
	let store = store_with(Vec::new()).with_sql_accounts(vec![sql("dan", "dan@example.org", None)]);
	let directory = store.handle().current();
	assert_eq!(
		directory.resolve(&crate::smtp::address::Address::parse("dan@example.org").unwrap()),
		Resolution::Account("dan".to_string())
	);
	assert_eq!(directory.authenticate("dan@example.org", "anything"), None);
}

#[test]
fn static_account_takes_precedence_over_sql() {
	// Same name and address in both sources, different passwords: the static
	// account's credentials must win.
	let store = store_with(vec![static_account(
		"shared",
		"shared@example.org",
		Some("static-pass"),
	)])
	.with_sql_accounts(vec![sql("shared", "shared@example.org", Some("sql-pass"))]);
	let directory = store.handle().current();

	assert_eq!(
		directory.authenticate("shared@example.org", "static-pass"),
		Some("shared".to_string())
	);
	assert_eq!(
		directory.authenticate("shared@example.org", "sql-pass"),
		None
	);
}

#[test]
fn refresh_replaces_sql_accounts() {
	let store =
		store_with(Vec::new()).with_sql_accounts(vec![sql("old", "old@example.org", Some("pw"))]);
	// A refresh with a new set drops the previous SQL accounts entirely.
	store.set_sql_accounts(vec![sql("new", "new@example.org", Some("pw"))]);
	let directory = store.handle().current();

	assert_eq!(
		directory.resolve(&crate::smtp::address::Address::parse("old@example.org").unwrap()),
		Resolution::UnknownUser
	);
	assert_eq!(
		directory.resolve(&crate::smtp::address::Address::parse("new@example.org").unwrap()),
		Resolution::Account("new".to_string())
	);
}

#[test]
fn a_sql_account_whose_name_escapes_the_data_dir_is_dropped() {
	// The account name doubles as a directory name under `<data_dir>/accounts/`
	// and `mailbox_dir` joins it without checking — it validates the mailbox
	// name and trusts the account. Config accounts and API/SCIM accounts are
	// validated on the way in; SQL rows were not, so a directory returning
	// `../..` reached the filesystem through the authenticated session.
	let store = store_with(Vec::new());
	store.set_sql_accounts(vec![
		sql("../../etc", "escape@example.org", Some("secret")),
		sql("ok", "ok@example.org", Some("secret")),
	]);
	let resolve = |address: &str| {
		store
			.handle()
			.current()
			.resolve(&crate::smtp::address::Address::parse(address).expect("address"))
	};
	assert!(
		matches!(resolve("ok@example.org"), Resolution::Account(ref n) if n == "ok"),
		"the well-named row must still resolve",
	);
	assert!(
		!matches!(resolve("escape@example.org"), Resolution::Account(_)),
		"a name that would escape the data dir must not become an account",
	);
}

#[test]
fn one_bad_sql_row_does_not_take_the_whole_directory_offline() {
	// These sources are reloaded on a timer, so failing the refresh outright
	// would turn one malformed row into an outage for everyone else.
	let store = store_with(Vec::new());
	store.set_sql_accounts(vec![
		sql("Uppercase", "a@example.org", Some("secret")),
		sql("has/slash", "b@example.org", Some("secret")),
		sql("good", "good@example.org", Some("secret")),
	]);
	assert!(matches!(
		store
			.handle()
			.current()
			.resolve(&crate::smtp::address::Address::parse("good@example.org").expect("address")),
		Resolution::Account(ref name) if name == "good"
	));
}
