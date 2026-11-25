//! `epistle verify-dns --json` against `GET /api/v1/dns/verify` on the same
//! configuration and the same answers from DNS: the route reports what the
//! command prints.

use std::sync::Arc;

use super::base::FakeDns;
use crate::api::v1::dns_parity::route;
use crate::cli::verify::dns::tests::*;

fn config() -> Config {
	toml::from_str(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\n\
		 domains = ['example.org', 'example.net']\npublic_ipv4 = '192.0.2.1'\n",
	)
	.expect("config")
}

/// Some records present and some not, so the report has both kinds.
fn answers() -> FakeDns {
	let mut dns = FakeDns::default();
	dns.mx.insert(
		"example.org".to_string(),
		vec!["mail.example.org".to_string()],
	);
	dns.txt.insert(
		"example.org".to_string(),
		vec!["v=spf1 mx -all".to_string()],
	);
	dns.addresses.insert(
		"mail.example.org".to_string(),
		vec!["192.0.2.1".parse().expect("address")],
	);
	dns
}

async fn printed(config: &Config) -> serde_json::Value {
	let mut out = Vec::new();
	let code = report(
		&config.domains,
		&config.hostname,
		config.public_ipv4,
		config.public_ipv6,
		&answers(),
		config,
		(true, &mut out),
		crate::cli::style::Progress::start("checking"),
	)
	.await;
	assert_eq!(code, ExitCode::FAILURE, "the fixture has drift");
	serde_json::from_slice(&out).expect("the command prints JSON")
}

#[tokio::test]
async fn the_route_reports_what_the_command_prints() {
	let dir = tempfile::tempdir().expect("directory");
	let mut config = config();
	config.data_dir = dir.path().canonicalize().expect("canonical");
	let expected = printed(&config).await;
	let groups = expected["groups"].as_array().expect("groups");
	assert_eq!(groups.len(), 3, "the host and both domains: {expected}");
	let statuses: std::collections::BTreeSet<&str> = groups
		.iter()
		.flat_map(|group| group["checks"].as_array().unwrap())
		.map(|check| check["status"].as_str().unwrap())
		.collect();
	assert!(
		statuses.contains("ok") && statuses.contains("missing"),
		"{statuses:?}"
	);
	let (status, body) = route(&config, Arc::new(answers()), "/api/v1/dns/verify").await;
	assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	assert_eq!(body, expected);
}
