//! A store with one dynamic account, shared by the switch tests.

use crate::config::Config;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::base::{fixture_password, hash};

pub(super) fn config(data_dir: &std::path::Path, accounts: &str) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{accounts}\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

pub(super) fn store(data_dir: &std::path::Path, config: &Config) -> AccountStore {
	AccountStore::open(
		data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open store")
}

/// A store holding the dynamic account `app`, with both switches untouched.
pub(super) fn store_with_app(dir: &tempfile::TempDir) -> AccountStore {
	let config = config(dir.path(), "");
	let store = store(dir.path(), &config);
	store
		.add(DynamicAccount {
			name: "app".to_string(),
			addresses: vec!["app@example.org".to_string()],
			password_hash: hash(fixture_password()),
			..DynamicAccount::default()
		})
		.expect("add account");
	store
}
