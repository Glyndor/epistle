//! Tests for the DNS check: record drift, resolver timeouts and the DKIM
//! public key comparison, all against a fake resolver.

use std::path::Path;
use std::time::Duration;

use super::{TimeoutDns, evaluate};
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;
use crate::config::Config;
use crate::spf::{DnsFailure, DnsLookup};

/// Write a fresh DKIM key and return its path and the TXT value it publishes.
fn dkim_key(dir: &Path, name: &str) -> (std::path::PathBuf, String) {
	let (pem, txt) = crate::dkim::generate_key().expect("key");
	let path = dir.join(name);
	std::fs::write(&path, pem).expect("write key");
	(path, txt)
}

fn config(dir: &Path, key: &Path, selector: &str) -> Config {
	let extra = format!(
		"[dkim]\nselector = {selector:?}\nkey_file = {:?}\n",
		key.display().to_string()
	);
	ctx(dir, &extra).config.expect("config")
}

fn publish(dns: &mut FakeDns, selector: &str, txt: &str) {
	dns.txt.insert(
		format!("{selector}._domainkey.example.org"),
		vec![txt.into()],
	);
}

#[tokio::test]
async fn a_fully_published_domain_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (key, txt) = dkim_key(dir.path(), "dkim.pem");
	let config = config(dir.path(), &key, "mail");
	let mut dns = FakeDns::healthy();
	publish(&mut dns, "mail", &txt);
	let report = evaluate(&config, &dns).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "7 records ok");
}

#[tokio::test]
async fn a_missing_record_is_drift_and_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (key, txt) = dkim_key(dir.path(), "dkim.pem");
	let config = config(dir.path(), &key, "mail");
	let mut dns = FakeDns::healthy();
	publish(&mut dns, "mail", &txt);
	dns.txt.remove("example.org");
	let report = evaluate(&config, &dns).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert_eq!(report.detail, "6 records ok, 1 missing");
	let item = report
		.items
		.iter()
		.find(|i| i.status == Level::Fail)
		.expect("failing item");
	assert_eq!(item.name, "SPF example.org");
	assert_eq!(item.detail, "no v=spf1 record");
}

#[tokio::test]
async fn an_inconclusive_lookup_only_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (key, txt) = dkim_key(dir.path(), "dkim.pem");
	let config = config(dir.path(), &key, "mail");
	let mut dns = FakeDns::healthy();
	publish(&mut dns, "mail", &txt);
	dns.txt_errors.push("_dmarc.example.org".into());
	let report = evaluate(&config, &dns).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.detail, "6 records ok, 1 inconclusive");
}

#[tokio::test]
async fn a_dkim_record_for_another_key_fails_even_though_a_record_exists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (key, _txt) = dkim_key(dir.path(), "dkim.pem");
	let (_other, stale) = dkim_key(dir.path(), "other.pem");
	let config = config(dir.path(), &key, "mail");
	let mut dns = FakeDns::healthy();
	publish(&mut dns, "mail", &stale);
	let report = evaluate(&config, &dns).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "DKIM key mail example.org")
		.expect("dkim item");
	assert_eq!(item.status, Level::Fail);
	assert!(
		item.detail
			.starts_with("published p= does not match the signing key"),
		"{}",
		item.detail
	);
	assert_eq!(report.detail, "7 records ok, 1 DKIM key mismatch");
}

#[tokio::test]
async fn after_a_rotation_the_rotated_key_and_selector_are_the_ones_checked() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (old_key, old_txt) = dkim_key(dir.path(), "dkim.pem");
	let (new_key, new_txt) = dkim_key(dir.path(), "dkim-ed20000.key");
	let config = config(dir.path(), &old_key, "mail");
	let state = serde_json::json!({
		"selector": "ed20000",
		"key_file": new_key,
		"rotated_at": 1,
		"previous": null,
	});
	std::fs::write(
		config.data_dir.join("dkim-rotation.json"),
		state.to_string(),
	)
	.expect("state");
	// DNS carries the rotated key under the new selector: healthy.
	let mut dns = FakeDns::healthy();
	publish(&mut dns, "ed20000", &new_txt);
	let report = evaluate(&config, &dns).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	// A stale record: the new selector still publishes the pre-rotation key.
	let mut stale = FakeDns::healthy();
	publish(&mut stale, "ed20000", &old_txt);
	let report = evaluate(&config, &stale).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert!(
		report
			.items
			.iter()
			.any(|i| i.name == "DKIM key ed20000 example.org" && i.status == Level::Fail)
	);
}

#[tokio::test]
async fn an_unreadable_rotation_state_warns_while_its_last_good_copy_signs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (configured, _) = dkim_key(dir.path(), "dkim.pem");
	let (rotated, rotated_txt) = dkim_key(dir.path(), "dkim-ed20000.key");
	let config = config(dir.path(), &configured, "mail");
	let good = serde_json::json!({
		"selector": "ed20000",
		"key_file": rotated,
		"rotated_at": 1,
		"previous": null,
	});
	std::fs::write(config.data_dir.join("dkim-rotation.json"), "{\"selector\":").expect("torn");
	let mut dns = FakeDns::healthy();
	publish(&mut dns, "ed20000", &rotated_txt);
	let without_backup = evaluate(&config, &dns).await;
	assert!(
		without_backup
			.items
			.iter()
			.any(|i| i.name == "DKIM signing key" && i.status == Level::Fail),
		"no last good copy: the state error stands {without_backup:?}"
	);
	std::fs::write(
		config.data_dir.join("dkim-rotation.json.bak"),
		good.to_string(),
	)
	.expect("backup");
	let report = evaluate(&config, &dns).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "DKIM rotation state")
		.expect("state item");
	assert_eq!(item.status, Level::Warn);
	assert!(
		item.detail.contains("dkim-rotation.json.bak") && item.detail.contains("parse"),
		"{}",
		item.detail
	);
	assert!(
		report
			.items
			.iter()
			.any(|i| i.name == "DKIM key ed20000 example.org" && i.status == Level::Ok),
		"the key from the last good state is the one compared: {report:?}"
	);
}

#[tokio::test]
async fn an_unreadable_signing_key_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let missing = dir.path().join("nope.pem");
	let config = config(dir.path(), &missing, "mail");
	let report = evaluate(&config, &FakeDns::healthy()).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert!(
		report
			.items
			.iter()
			.any(|i| i.name == "DKIM signing key" && i.status == Level::Fail)
	);
}

struct Hangs;

impl DnsLookup for Hangs {
	fn txt(
		&self,
		_name: &str,
	) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(std::future::pending())
	}
	fn addresses(
		&self,
		_name: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>,
	> {
		Box::pin(std::future::pending())
	}
	fn mx(
		&self,
		_name: &str,
	) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(std::future::pending())
	}
}

#[tokio::test(start_paused = true)]
async fn a_resolver_that_never_answers_is_cut_off_after_five_seconds() {
	let dns = TimeoutDns(Hangs);
	let began = tokio::time::Instant::now();
	assert_eq!(dns.txt("example.org").await, Err(DnsFailure::Temporary));
	assert_eq!(began.elapsed(), Duration::from_secs(5));
	assert_eq!(dns.mx("example.org").await, Err(DnsFailure::Temporary));
}

/// A Cloudflare `[dns]` section; the provider itself is handed in.
fn cloudflare_config(dir: &Path) -> Config {
	ctx(
		dir,
		"[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n",
	)
	.config
	.expect("config")
}

fn zone_with(
	records: Vec<crate::dns::provider::DnsRecord>,
) -> std::sync::Arc<dyn crate::dns::provider::DnsProvider> {
	std::sync::Arc::new(crate::dns::lockdown::tests::support::Zone::with(records))
}

#[tokio::test]
async fn a_proxied_mail_name_fails_inside_the_status_runtime() {
	// The check runs on the runtime `status` already drives; it must not
	// start one of its own.
	let dir = tempfile::tempdir().expect("tempdir");
	let config = cloudflare_config(dir.path());
	let proxied = crate::dns::provider::DnsRecord {
		proxied: Some(true),
		..crate::dns::provider::DnsRecord::new(
			"mail.example.org",
			crate::dns::provider::RecordKind::A,
			"192.0.2.10",
			300,
		)
	};
	let items = super::proxied_items(&config, Ok(Some(zone_with(vec![proxied])))).await;
	assert_eq!(items.len(), 1, "{items:?}");
	assert_eq!(items[0].name, "Cloudflare proxy mail.example.org");
	assert_eq!(items[0].status, Level::Fail);
	assert_eq!(
		items[0].detail,
		"mail.example.org is proxied by Cloudflare (orange cloud): mail clients and other servers cannot reach port 25/465/587/993 through the proxy; set it to DNS only"
	);
}

#[tokio::test]
async fn the_proxy_check_is_a_warning_when_it_cannot_read_the_zone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = cloudflare_config(dir.path());
	let items = super::proxied_items(&config, Err(())).await;
	assert_eq!(items.len(), 1, "{items:?}");
	assert_eq!(items[0].status, Level::Warn);
	assert_eq!(
		items[0].detail,
		"the Cloudflare credentials in [dns] could not be read; the proxy state was not checked"
	);
}

#[tokio::test]
async fn other_providers_get_no_proxy_check() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = ctx(
		dir.path(),
		"[dns]\nprovider = 'desec'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n",
	)
	.config
	.expect("config");
	assert!(matches!(super::proxy_provider(&config), Ok(None)));
	assert!(super::proxied_items(&config, Ok(None)).await.is_empty());
}

/// A provider whose zone listing fails.
struct UnlistableZone;

impl crate::dns::provider::DnsProvider for UnlistableZone {
	fn upsert(
		&self,
		_zone: &str,
		_record: crate::dns::provider::DnsRecord,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<(), crate::dns::provider::ProviderError>> + Send + '_>,
	> {
		Box::pin(async { Err(crate::dns::provider::ProviderError::Unsupported) })
	}
	fn delete(
		&self,
		_zone: &str,
		_record: crate::dns::provider::DnsRecord,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<(), crate::dns::provider::ProviderError>> + Send + '_>,
	> {
		Box::pin(async { Err(crate::dns::provider::ProviderError::Unsupported) })
	}
	fn list(
		&self,
		_zone: &str,
	) -> std::pin::Pin<
		Box<
			dyn Future<
					Output = Result<
						Vec<crate::dns::provider::DnsRecord>,
						crate::dns::provider::ProviderError,
					>,
				> + Send
				+ '_,
		>,
	> {
		Box::pin(async {
			Err(crate::dns::provider::ProviderError::Remote(
				"HTTP 502".into(),
			))
		})
	}
}

#[tokio::test]
async fn a_zone_listing_that_fails_leaves_the_proxy_state_unknown() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = cloudflare_config(dir.path());
	let items = super::proxied_items(&config, Ok(Some(std::sync::Arc::new(UnlistableZone)))).await;
	assert_eq!(items.len(), 1, "{items:?}");
	assert_eq!(items[0].status, Level::Warn);
	assert_eq!(
		items[0].detail,
		"listing the example.org zone failed, so the proxy state was not checked: provider error: HTTP 502"
	);
}
