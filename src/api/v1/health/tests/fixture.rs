//! A server with a configuration file on disk, and the keys the health
//! routes are tried with.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use crate::api::ApiState;
use crate::cli::status::CheckArea;
use crate::config::Config;

/// `health`, unconfined: the key the routes are for.
pub(super) const HEALTHY: &str = "health-key-secret";
/// `health`, confined to a domain: a key the routes refuse.
pub(super) const CONFINED: &str = "health-confined-secret";
/// `health`, bound to an account.
pub(super) const BOUND: &str = "health-bound-secret";
/// Every scope but `health`.
pub(super) const OTHERS: &str = "everything-but-health-secret";

fn key(
	label: &str,
	secret: &str,
	scopes: &[&str],
	domains: &[&str],
) -> crate::api::api_keys::ApiKey {
	crate::api::api_keys::ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
		grants: Vec::new(),
		domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
		account: None,
		auto_submitted: false,
	}
}

pub(super) struct World {
	pub(super) dir: tempfile::TempDir,
	pub(super) path: std::path::PathBuf,
	pub(super) state: ApiState,
}

pub(super) fn world() -> World {
	build(true)
}

pub(super) fn build(live: bool) -> World {
	build_with(live, |state| state)
}

/// A server whose state `adjust` changes before the state is shared.
pub(super) fn build_with(live: bool, adjust: impl FnOnce(ApiState) -> ApiState) -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let path = data_dir.join("mail.toml");
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.expect("config file");
	write!(
		file,
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = {:?}\n",
		data_dir.join("data").display().to_string()
	)
	.expect("write config");
	drop(file);
	std::fs::create_dir_all(data_dir.join("data")).expect("data dir");
	let config = Config::load(&path).expect("config loads");
	let mut keys = crate::api::ApiKeyStore::open(&config.data_dir).expect("key store");
	let mut bound = key("bound", BOUND, &["health"], &[]);
	bound.account = Some("ann".to_string());
	for one in [
		key("healthy", HEALTHY, &["health"], &[]),
		key("confined", CONFINED, &["health"], &["example.org"]),
		key(
			"others",
			OTHERS,
			&["read", "write", "send", "alias", "scim", "ban"],
			&[],
		),
		bound,
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let accounts = Arc::new(
		crate::directory_store::AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(crate::api::tests::base::TOKEN.as_str()),
		config.data_dir.clone(),
		config.domains.clone(),
		accounts.clone(),
		crate::storage::FsSpool::open(&config.data_dir).expect("spool"),
	)
	.with_directory(accounts.handle())
	.with_config_path(path.clone())
	// The areas that ask the network or the host are not run by these tests.
	.with_health_areas(vec![CheckArea::Config, CheckArea::Antispam]);
	let state = adjust(state);
	let state = if live {
		state.with_live_domains(crate::editable::LiveConfig::new(config))
	} else {
		state
	};
	World { dir, path, state }
}

pub(super) fn token() -> &'static str {
	crate::api::tests::base::TOKEN.as_str()
}

pub(super) async fn get(
	state: &ApiState,
	path: &str,
	bearer: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
	let mut request = Request::builder().uri(path);
	if let Some(bearer) = bearer {
		request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
	}
	let response = crate::api::router(state.clone())
		.oneshot(request.body(Body::empty()).expect("request"))
		.await
		.expect("response");
	let (parts, body) = response.into_parts();
	let bytes = axum::body::to_bytes(body, usize::MAX).await.expect("body");
	let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
		serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
	});
	(parts.status, parts.headers, value)
}
