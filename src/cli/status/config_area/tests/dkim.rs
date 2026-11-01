//! `status` reports DKIM keys that more than one domain signs with.

use super::check;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

fn key(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let path = dir.join(name);
	std::fs::write(&path, pem).expect("write");
	path
}

/// `example.org` plus the alias `alias.example`, both signing with `[dkim]`.
fn two_signing_domains(default: &std::path::Path, extra: &str) -> String {
	format!(
		"[dkim]\nselector = \"s1\"\nkey_file = {default:?}\n{extra}\n\
		 [domain_aliases]\n\"alias.example\" = \"example.org\"\n"
	)
}

#[tokio::test]
async fn two_domains_on_the_default_key_warn() {
	let dir = tempfile::tempdir().expect("tempdir");
	let default = key(dir.path(), "default.pem");
	let ctx = ctx(dir.path(), &two_signing_domains(&default, ""));
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|item| item.name == "DKIM keys")
		.expect("a DKIM keys item");
	assert_eq!(item.status, Level::Warn);
	assert!(
		item.detail
			.contains("2 domains sign with the one [dkim] key (alias.example, example.org)"),
		"{}",
		item.detail
	);
}

#[tokio::test]
async fn a_key_of_its_own_per_domain_is_quiet() {
	let dir = tempfile::tempdir().expect("tempdir");
	let default = key(dir.path(), "default.pem");
	let own = key(dir.path(), "alias.pem");
	let entry = format!(
		"[[dkim.domain]]\nname = \"alias.example\"\nselector = \"s1\"\nkey_file = {own:?}\n"
	);
	let ctx = ctx(dir.path(), &two_signing_domains(&default, &entry));
	let report = check(&ctx).await;
	assert!(
		report.items.iter().all(|item| item.name != "DKIM keys"),
		"{report:?}"
	);
}

#[tokio::test]
async fn a_copy_of_the_default_key_fails_the_check() {
	let dir = tempfile::tempdir().expect("tempdir");
	let default = key(dir.path(), "default.pem");
	let copy = dir.path().join("copy.pem");
	std::fs::copy(&default, &copy).expect("copy");
	let entry = format!(
		"[[dkim.domain]]\nname = \"alias.example\"\nselector = \"s1\"\nkey_file = {copy:?}\n"
	);
	let ctx = ctx(dir.path(), &two_signing_domains(&default, &entry));
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert!(
		report.items.iter().any(|item| item.name == "DKIM keys"
			&& item.status == Level::Fail
			&& item.detail.contains("the same ed25519 public key")),
		"{report:?}"
	);
}
