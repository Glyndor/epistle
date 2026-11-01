//! `status` keeps warning that a split is incomplete while the shared key is
//! published at a domain that has a key of its own.

use super::evaluate;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

/// `example.org` has its own key `own1`; the shared `[dkim]` key is `mail`.
fn config(dir: &std::path::Path) -> crate::config::Config {
	let (shared, _) = crate::dkim::generate_key().expect("key");
	let (own, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.join("shared.pem"), shared).expect("write");
	std::fs::write(dir.join("own.pem"), own).expect("write");
	let extra = format!(
		"[dkim]\nselector = \"mail\"\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = \"example.org\"\nselector = \"own1\"\nkey_file = {:?}\n",
		dir.join("shared.pem").display().to_string(),
		dir.join("own.pem").display().to_string(),
	);
	ctx(dir, &extra).config.expect("config")
}

#[tokio::test]
async fn the_shared_key_still_published_at_a_moved_domain_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut dns = FakeDns::healthy();
	dns.txt.insert(
		"mail._domainkey.example.org".into(),
		vec!["v=DKIM1; k=ed25519; p=AAAA".into()],
	);
	let report = evaluate(&config, &dns).await;
	let item = report
		.items
		.iter()
		.find(|item| item.name == "DKIM split mail._domainkey.example.org")
		.expect("an item for the stale record");
	assert_eq!(item.status, Level::Warn);
	assert!(item.detail.contains("split incomplete"), "{}", item.detail);
	assert!(
		report.detail.contains("1 shared DKIM key still published"),
		"{}",
		report.detail
	);
}

#[tokio::test]
async fn once_the_record_is_gone_the_warning_goes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let report = evaluate(&config, &FakeDns::healthy()).await;
	assert!(
		report
			.items
			.iter()
			.all(|item| !item.name.starts_with("DKIM split")),
		"{report:?}"
	);
}
