//! The config check reports addresses claimed by two owners, the same lines
//! the server logs at startup.

use super::check;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

const STATIC_ANA: &str = "[[accounts]]\nname = \"ana\"\naddresses = [\"ana@example.org\"]\n";

#[tokio::test]
async fn an_address_with_two_owners_is_a_warning_naming_both() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), STATIC_ANA);
	std::fs::write(
		dir.path().join("data/accounts.toml"),
		"[[accounts]]\nname = \"other\"\naddresses = [\"ANA@example.org\"]\npassword_hash = \"$argon2id$x\"\n",
	)
	.expect("accounts.toml");
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|item| item.name == "addresses")
		.expect("addresses item");
	assert_eq!(item.status, Level::Warn);
	assert_eq!(
		item.detail,
		"address ana@example.org is claimed by account \"ana\" (mail.toml) and by account \
		 \"other\" (accounts.toml); account \"ana\" (mail.toml) keeps it"
	);
	assert!(
		report.detail.ends_with("loads, 1 address with two owners"),
		"{}",
		report.detail
	);
}

#[tokio::test]
async fn one_owner_per_address_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), STATIC_ANA);
	let report = check(&ctx).await;
	let item = report
		.items
		.iter()
		.find(|item| item.name == "addresses")
		.expect("addresses item");
	assert_eq!(item.status, Level::Ok, "{item:?}");
}
