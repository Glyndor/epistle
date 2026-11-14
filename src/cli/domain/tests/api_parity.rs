//! `epistle domain list --json` and `epistle domain show --json` against
//! `GET /api/v1/domains` and `GET /api/v1/domains/{domain}` on the same
//! configuration file: the route answers what the command prints.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::*;
use crate::config::Config;

const TOKEN: &str = "domain-parity-token";

fn configured() -> (tempfile::TempDir, Config) {
	let dir = tempfile::tempdir().unwrap();
	let data_dir = dir.path().canonicalize().unwrap();
	let path = data_dir.join("mail.toml");
	// The server refuses a configuration file others can read.
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.unwrap();
	write!(
		file,
		"hostname = \"mail.example.org\"\n\
		 data_dir = {data_dir:?}\n\
		 domains = [\"example.org\", \"example.net\", \"example.com\"]\n\
		 disabled_domains = [\"example.net\"]\n\
		 send_only_domains = [\"example.com\"]\n\
		 \n\
		 [domain_aliases]\n\
		 \"alias.example.org\" = \"example.org\"\n\
		 \n\
		 [domain_quotas]\n\
		 'example.org' = 4096\n\
		 \n\
		 [[accounts]]\n\
		 name = \"alice\"\n\
		 addresses = [\"alice@example.org\", \"alice@example.com\"]\n\
		 password_hash = \"$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000\"\n\
		 \n\
		 [[alias]]\n\
		 address = \"team@example.org\"\n\
		 members = [\"alice@example.org\"]\n"
	)
	.unwrap();
	drop(file);
	let config = Config::load(&path).expect("config loads");
	(dir, config)
}

/// The router the server would build from `config`, as `serve` wires the
/// domain catalog.
fn router(config: &Config) -> axum::Router {
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			std::collections::HashMap::new(),
			config.accounts.clone(),
		)
		.unwrap(),
	);
	let state = crate::api::ApiState::new(
		&crate::api::api_keys::sha256_hash(TOKEN),
		config.data_dir.clone(),
		config.domains.clone(),
		store.clone(),
		crate::storage::FsSpool::open(&config.data_dir).unwrap(),
	)
	.with_directory(store.handle())
	.with_disabled_domains(config.disabled_domains.clone())
	.with_domain_catalog(crate::domain::catalog::Catalog::from_config(config));
	crate::api::router(state)
}

async fn route(app: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
	let request = Request::builder()
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
		.body(Body::empty())
		.unwrap();
	let response = app.clone().oneshot(request).await.unwrap();
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.unwrap();
	(status, serde_json::from_slice(&bytes).unwrap())
}

fn command_json(print: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> serde_json::Value {
	let mut out = Vec::new();
	print(&mut out).expect("the command prints");
	serde_json::from_slice(&out).expect("the command prints JSON")
}

#[tokio::test]
async fn the_list_route_carries_the_rows_the_command_prints() {
	let (_dir, config) = configured();
	let printed = command_json(|out| list(&config, true, out));
	let (status, body) = route(&router(&config), "/api/v1/domains").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["details"], printed);
}

#[tokio::test]
async fn the_domain_route_answers_what_the_command_shows() {
	let (_dir, config) = configured();
	let app = router(&config);
	for name in ["example.org", "example.net", "example.com", "EXAMPLE.ORG"] {
		let printed = command_json(|out| show(&config, name, true, out));
		let (status, body) = route(&app, &format!("/api/v1/domains/{name}")).await;
		assert_eq!(status, StatusCode::OK, "{name}: {body}");
		assert_eq!(body, printed, "{name}");
	}
}

#[tokio::test]
async fn a_name_the_command_refuses_is_not_found_on_the_route() {
	let (_dir, config) = configured();
	let app = router(&config);
	for name in [
		"example.org.",
		"alias.example.org",
		"nope.example",
		"xn--e1a.example",
	] {
		let mut out = Vec::new();
		let refused = show(&config, name, true, &mut out).expect_err("the command refuses");
		assert_eq!(
			refused.to_string(),
			format!("domain {name} is not configured")
		);
		let (status, body) = route(&app, &format!("/api/v1/domains/{name}")).await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{name}: {body}");
	}
}
