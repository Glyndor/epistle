//! `epistle dns-records --json` against `GET /api/v1/dns/records` on the
//! same configuration: the route lists the records the command prints.

use std::sync::Arc;

use super::*;
use crate::api::v1::dns_parity::{Empty, route};

fn configured(dir: &std::path::Path, extra: &str) -> Config {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.join("dkim.key"), pem).expect("key file");
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\n\
		 domains = ['example.org', 'example.net']\n\
		 public_ipv4 = '192.0.2.1'\n\
		 [dkim]\nselector = 'ed1'\nkey_file = {:?}\n{extra}",
		dir.join("dkim.key")
	))
	.expect("config")
}

fn printed(config: &Config) -> serde_json::Value {
	let mut out = Vec::new();
	assert_eq!(run(config, true, &mut out), ExitCode::SUCCESS);
	serde_json::from_slice(&out).expect("the command prints JSON")
}

#[tokio::test]
async fn the_route_lists_the_records_the_command_prints() {
	let dir = tempfile::tempdir().expect("directory");
	let data_dir = dir.path().canonicalize().expect("canonical");
	for extra in ["", "[dns_publish]\nskip = ['client-locators', 'caa']\n"] {
		let config = configured(&data_dir, extra);
		let expected = printed(&config);
		assert!(
			expected.as_array().is_some_and(|rows| rows.len() > 10),
			"{expected}"
		);
		let (status, body) = route(&config, Arc::new(Empty), "/api/v1/dns/records").await;
		assert_eq!(status, axum::http::StatusCode::OK, "{body}");
		assert_eq!(body["records"], expected, "skip list: {extra}");
		assert_eq!(body["complete"], true);
	}
}
