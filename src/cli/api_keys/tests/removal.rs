//! `epistle api-key create --account` for an account that is being removed.

use super::*;
use crate::api::ApiKeyStore;
use crate::directory_store::{AccountStore, DynamicAccount, QueuePolicy};

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\ndomains = [\"example.org\"]\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn make(config: &Config, label: &str) -> ExitCode {
	create(
		config,
		NewKey {
			label: label.to_string(),
			scopes: vec!["send".to_string()],
			account: Some("carol".to_string()),
			..NewKey::default()
		},
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
}

/// A removal that stopped half way leaves the account reserved: it can be run
/// again, and until then no new key is bound to the account.
#[tokio::test]
async fn an_account_being_removed_takes_no_new_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let config = config(&data_dir);
	let store = AccountStore::open(
		&data_dir,
		config.domains.clone(),
		Default::default(),
		Vec::new(),
	)
	.expect("store");
	store
		.add(DynamicAccount {
			name: "carol".to_string(),
			addresses: vec!["carol@example.org".to_string()],
			password_hash: crate::smtp::auth::tests::base::hash("a password"),
			..DynamicAccount::default()
		})
		.expect("add carol");
	assert_eq!(make(&config, "before"), ExitCode::SUCCESS);
	// A link where the mailbox goes stops the removal at its last step.
	std::fs::create_dir_all(data_dir.join("accounts")).expect("accounts");
	std::os::unix::fs::symlink(&data_dir, data_dir.join("accounts/carol")).expect("link");
	let spool = crate::storage::FsSpool::open(&data_dir).expect("spool");
	crate::directory_store::remove_account(
		&store,
		&spool,
		&data_dir,
		"carol",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect_err("the removal stops");

	assert_eq!(
		make(&config, "after"),
		ExitCode::from(crate::cli::exit::REFUSED)
	);
	let keys = ApiKeyStore::open(&data_dir).expect("open");
	assert!(keys.keys().is_empty(), "{:?}", keys.keys());
}
