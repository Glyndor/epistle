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
	.with_domain_catalog(crate::domain::catalog::Catalog::from_config(config))
	.with_live_domains(crate::editable::LiveConfig::new(config.clone()));
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

async fn write_route(
	app: &axum::Router,
	method: &str,
	path: &str,
	body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	let request = Request::builder()
		.method(method)
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
		.header(header::CONTENT_TYPE, "application/json")
		.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
		.unwrap();
	let response = app.clone().oneshot(request).await.unwrap();
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.unwrap();
	(status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn domain_write_routes_and_the_real_command_produce_the_same_state() {
	use crate::domain::state::DomainsFile;
	use serde_json::json;
	let (_cli_dir, cli) = configured();
	let (_api_dir, api) = configured();
	let app = router(&api);
	let cli_path = cli.data_dir.join("mail.toml");
	let alias = |action| DomainCli::Alias(DomainAliasArgs { action });
	let steps = [
		(
			DomainCli::Add {
				domain: "new.example".into(),
				shared_dkim_key: false,
				send_only: false,
				receive_only: false,
			},
			"POST",
			"/api/v1/domains",
			Some(json!({"domain":"new.example"})),
		),
		(
			DomainCli::Set {
				domain: "example.org".into(),
				quota: Some("2K".into()),
				no_quota: false,
				submission_rate: Some("7".into()),
				no_submission_rate: false,
				send_only: true,
				receive_only: false,
				full: false,
			},
			"PUT",
			"/api/v1/domains/example.org",
			Some(json!({"quota":2048,"submission_rate":7,"role":"send-only"})),
		),
		(
			DomainCli::Disable {
				domain: "example.com".into(),
				yes: true,
			},
			"POST",
			"/api/v1/domains/example.com/disable",
			None,
		),
		(
			DomainCli::Enable {
				domain: "example.com".into(),
			},
			"POST",
			"/api/v1/domains/example.com/enable",
			None,
		),
		(
			alias(DomainAliasSubcommand::Add {
				alias: "new-alias.example".into(),
				target: "example.org".into(),
			}),
			"POST",
			"/api/v1/domains/example.org/aliases",
			Some(json!({"alias":"new-alias.example"})),
		),
		(
			alias(DomainAliasSubcommand::Remove {
				alias: "new-alias.example".into(),
				yes: true,
			}),
			"DELETE",
			"/api/v1/domains/example.org/aliases/new-alias.example",
			None,
		),
		(
			DomainCli::Set {
				domain: "example.org".into(),
				quota: None,
				no_quota: true,
				submission_rate: None,
				no_submission_rate: true,
				send_only: false,
				receive_only: false,
				full: false,
			},
			"PUT",
			"/api/v1/domains/example.org",
			Some(json!({"quota":null,"submission_rate":null})),
		),
		(
			DomainCli::Remove {
				domain: "new.example".into(),
				yes: true,
			},
			"DELETE",
			"/api/v1/domains/new.example",
			None,
		),
	];
	let read = |dir: &std::path::Path| {
		let mut file = DomainsFile::read(&crate::domain::state::path(dir))
			.unwrap()
			.unwrap();
		// Fresh secrets intentionally differ, as they do for two CLI runs.
		for domain in &mut file.domains {
			domain.srs_secret = None;
		}
		file
	};
	let before = std::fs::read(&cli_path).unwrap();
	for (command, method, path, body) in steps {
		assert_eq!(
			run(&cli_path, command, false, false),
			std::process::ExitCode::SUCCESS
		);
		let (status, body) = write_route(&app, method, path, body).await;
		assert!(status.is_success(), "{method} {path}: {body}");
		assert_eq!(read(&cli.data_dir), read(&api.data_dir), "{path}");
	}
	assert_eq!(
		std::fs::read(cli_path).unwrap(),
		before,
		"even CLI limits leave config alone"
	);
}

#[tokio::test]
async fn domain_write_refusals_preserve_the_real_commands_messages() {
	use serde_json::json;
	let (_dir, config) = configured();
	let app = router(&config);
	let path = config.data_dir.join("mail.toml");
	for (command, method, route, body) in [
		(
			DomainCli::Add {
				domain: "example.org".into(),
				shared_dkim_key: false,
				send_only: false,
				receive_only: false,
			},
			"POST",
			"/api/v1/domains",
			Some(json!({"domain":"example.org"})),
		),
		(
			DomainCli::Remove {
				domain: "ghost.example".into(),
				yes: true,
			},
			"DELETE",
			"/api/v1/domains/ghost.example",
			None,
		),
		(
			DomainCli::Remove {
				domain: "example.org".into(),
				yes: true,
			},
			"DELETE",
			"/api/v1/domains/example.org",
			None,
		),
	] {
		let message = match execute(&path, command, false, false) {
			Outcome::Error(message) | Outcome::Refusal(message) => message,
			_ => panic!("the command should refuse"),
		};
		let (status, body) = write_route(&app, method, route, body).await;
		assert!(status.is_client_error());
		assert_eq!(body["error"]["message"], message);
	}
}
