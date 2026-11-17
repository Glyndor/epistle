//! The store `serve` opens carries `disabled_domains` into every directory.

use super::open_account_store;
use crate::config::Config;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

fn config(data_dir: &std::path::Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {data_dir:?}\n\
		 domains = [\"example.org\", \"example.net\"]\n{extra}\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\", \"alice@example.net\"]\n"
	))
	.expect("config")
}

fn resolve(config: &Config, raw: &str) -> Resolution {
	let store = open_account_store(config).expect("open account store");
	store
		.handle()
		.current()
		.resolve(&Address::parse(raw).expect("address"))
}

#[test]
fn the_server_store_rejects_mail_for_a_disabled_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "disabled_domains = [\"example.net\"]");
	assert_eq!(
		resolve(&config, "alice@example.net"),
		Resolution::UnknownUser
	);
	assert_eq!(
		resolve(&config, "alice@example.org"),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn the_server_store_delivers_everywhere_with_no_disabled_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	assert_eq!(
		resolve(&config, "alice@example.net"),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn a_masked_limit_of_zero_is_announced_and_only_zero() {
	use super::super::masked_off_notice;
	let notice = masked_off_notice(0).expect("a notice for 0");
	assert!(notice.contains("masked_addresses_max = 0"));
	assert_eq!(masked_off_notice(1), None);
	assert_eq!(masked_off_notice(100), None);
}

#[test]
fn the_server_store_carries_the_limits_of_the_configuration() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(
		dir.path(),
		"max_message_size = 1000000\n[limits]\nmax_addresses_per_account = 2\n\
		 [[limit_scope]]\naccount = \"alice\"\nmax_message_size = 70000\n",
	);
	let store = open_account_store(&config).expect("open account store");
	let directory = store.handle().current();
	assert!(directory.admit_message("alice", 70_000).is_ok());
	assert!(directory.admit_message("alice", 70_001).is_err());
	assert!(directory.admit_message("someone", 900_000).is_ok());
	let crowded = crate::directory_store::DynamicAccount {
		name: "bob".to_string(),
		addresses: ["a", "b", "c"]
			.map(|local| format!("{local}@example.org"))
			.to_vec(),
		password_hash: "$argon2id$stub".to_string(),
		..Default::default()
	};
	assert!(matches!(
		store.add(crowded),
		Err(crate::directory_store::StoreError::Capped(_))
	));
}
