//! What the outside will read: SPF, DKIM, DMARC, the reverse name.

use super::support::*;
use crate::cli::deliverability::checks::{Item, Level, run};
use crate::cli::deliverability::message::build;
use crate::cli::deliverability::plan::resolve;

const T: u64 = 1_800_000_000;

async fn items(
	dns: &crate::cli::status::dns_fake::FakeDns,
	sign: bool,
	tweak: impl FnOnce(&mut crate::config::Config),
) -> Vec<Item> {
	let dir = tempfile::tempdir().expect("dir");
	let mut config = config(dir.path());
	tweak(&mut config);
	let store = store(dir.path(), &config, Vec::new());
	let plan = resolve(&config, &store, "alice", DESTINATION).expect("plan");
	let signer = signer(dir.path());
	let built = build(
		&plan,
		&config.hostname,
		T,
		uuid::Uuid::now_v7(),
		sign.then_some(&signer),
	);
	run(&config, &plan, &built.data, built.signed, dns).await
}

fn level(items: &[Item], check: &str) -> Level {
	items
		.iter()
		.find(|item| item.check == check)
		.unwrap_or_else(|| panic!("no {check} item"))
		.level
}

#[tokio::test]
async fn a_server_with_everything_published_passes_every_check() {
	let items = items(&dns(), true, |_| {}).await;
	for check in ["spf", "dkim", "dmarc", "ptr"] {
		assert_eq!(level(&items, check), Level::Pass, "{check}: {items:?}");
	}
	assert_eq!(level(&items, "tls"), Level::Unknown);
}

#[tokio::test]
async fn an_unsigned_message_fails_dkim_and_says_so() {
	let items = items(&dns(), false, |_| {}).await;
	assert_eq!(level(&items, "dkim"), Level::Fail);
	let dkim = items.iter().find(|i| i.check == "dkim").expect("dkim");
	assert!(dkim.detail.contains("unsigned"), "{}", dkim.detail);
}

#[tokio::test]
async fn a_key_that_is_not_published_fails_dkim() {
	let mut dns = dns();
	dns.txt.remove("sel._domainkey.example.org");
	let items = items(&dns, true, |_| {}).await;
	assert_eq!(level(&items, "dkim"), Level::Fail);
}

#[tokio::test]
async fn an_address_the_spf_record_does_not_cover_fails_spf() {
	let items = items(&dns(), true, |config| {
		config.public_ipv4 = Some("198.51.100.7".parse().expect("ip"));
	})
	.await;
	assert_eq!(level(&items, "spf"), Level::Fail);
}

#[tokio::test]
async fn dmarc_aligns_through_dkim_when_spf_fails() {
	let items = items(&dns(), true, |config| {
		config.public_ipv4 = Some("198.51.100.7".parse().expect("ip"));
	})
	.await;
	assert_eq!(level(&items, "dmarc"), Level::Pass);
}

#[tokio::test]
async fn no_dmarc_record_is_a_warning_not_a_failure() {
	let mut dns = dns();
	dns.txt.remove("_dmarc.example.org");
	let items = items(&dns, true, |_| {}).await;
	assert_eq!(level(&items, "dmarc"), Level::Warn);
}

#[tokio::test]
async fn a_reverse_name_that_is_not_the_ehlo_name_fails() {
	let mut dns = dns();
	let ip = "203.0.113.10".parse().expect("ip");
	dns.ptr.insert(ip, vec!["static.hoster.example".into()]);
	let items = items(&dns, true, |_| {}).await;
	assert_eq!(level(&items, "ptr"), Level::Fail);
	let ptr = items.iter().find(|i| i.check == "ptr").expect("ptr");
	assert!(
		ptr.detail.contains("static.hoster.example"),
		"{}",
		ptr.detail
	);
}

#[tokio::test]
async fn a_failed_reverse_lookup_is_unknown_not_a_failure() {
	let mut dns = dns();
	dns.ptr_errors.push("203.0.113.10".parse().expect("ip"));
	let items = items(&dns, true, |_| {}).await;
	assert_eq!(level(&items, "ptr"), Level::Unknown);
}
