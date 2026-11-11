//! `status` names the hosted-domain names that carry no null SPF and null
//! MX, against a zone in memory.

use std::sync::Arc;

use super::super::uncovered::items;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;
use crate::dns::lockdown::tests::support::{Zone, a, txt};

fn config(extra: &str) -> crate::config::Config {
	let dir = tempfile::tempdir().expect("tempdir");
	ctx(dir.path(), extra).config.expect("config")
}

#[tokio::test]
async fn names_without_the_null_records_are_reported_and_the_wildcard_with_them() {
	let config = config("");
	let zone = Zone::with(vec![a("www.example.org"), a("x.y.example.org")]);
	let found = items(&config, Some(Arc::new(zone))).await;
	assert_eq!(found.len(), 1, "{found:?}");
	assert_eq!(found[0].status, Level::Warn);
	let line = &found[0].detail;
	for name in ["www.example.org", "y.example.org", "*.example.org"] {
		assert!(line.contains(name), "{name}: {line}");
	}
	assert!(line.contains("epistle dns lockdown"), "{line}");
}

#[tokio::test]
async fn a_zone_that_is_covered_reports_nothing() {
	let config = config("");
	let zone = Zone::with(vec![
		a("www.example.org"),
		txt("www.example.org", "v=spf1 -all"),
		crate::dns::lockdown::tests::support::mx("www.example.org", "0 ."),
		txt("*.example.org", "v=spf1 -all"),
	]);
	let found = items(&config, Some(Arc::new(zone))).await;
	assert!(found.is_empty(), "{found:?}");
}

#[tokio::test]
async fn a_declared_sender_is_not_reported() {
	let config = config("[dns_publish]\nsenders = [\"www.example.org\"]\n");
	let zone = Zone::with(vec![
		a("www.example.org"),
		txt("*.example.org", "v=spf1 -all"),
	]);
	let found = items(&config, Some(Arc::new(zone))).await;
	assert!(found.is_empty(), "{found:?}");
}

#[tokio::test]
async fn without_a_provider_nothing_is_reported() {
	assert!(items(&config(""), None).await.is_empty());
}
