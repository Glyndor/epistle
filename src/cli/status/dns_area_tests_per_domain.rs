//! `status` checks a domain with a `[[dkim.domain]]` override against the
//! override's key only, even when the default uses the same selector name.

use super::evaluate;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

#[tokio::test]
async fn an_override_under_the_default_selector_name_is_not_a_mismatch() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (default_pem, _) = crate::dkim::generate_key().expect("key");
	let (override_pem, override_txt) = crate::dkim::generate_key().expect("key");
	let default_key = dir.path().join("default.pem");
	let override_key = dir.path().join("override.pem");
	std::fs::write(&default_key, default_pem).expect("write");
	std::fs::write(&override_key, override_pem).expect("write");
	let extra = format!(
		"[dkim]\nselector = \"mail\"\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = \"example.org\"\nselector = \"mail\"\nkey_file = {:?}\n",
		default_key.display().to_string(),
		override_key.display().to_string(),
	);
	let config = ctx(dir.path(), &extra).config.expect("config");
	let mut dns = FakeDns::healthy();
	dns.txt.insert(
		"mail._domainkey.example.org".into(),
		vec![override_txt.clone()],
	);
	let report = evaluate(&config, &dns).await;
	assert_eq!(report.detail, "7 records ok");
	assert_eq!(report.status, Level::Ok, "{}", report.detail);
}
