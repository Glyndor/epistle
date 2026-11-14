//! A server hosting three domains, one of them switched off and one an
//! A-label, read from a real configuration file, and the keys the domain
//! routes are tried with.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::api::ApiState;
use crate::config::Config;
use crate::domain::catalog::Catalog;

/// `read` and `write`, confined to `a.example`.
pub(super) const CONFINED: &str = "confined-to-a-secret";
/// `read`, unconfined.
pub(super) const READER: &str = "reader-secret";
/// `send` only, unconfined: a valid key without the scope a read needs.
pub(super) const SENDER: &str = "sender-secret";
/// `read`, confined to a domain the server does not host.
pub(super) const ELSEWHERE: &str = "confined-elsewhere-secret";

const HASH: &str = "$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000";

/// The configuration file every domain route test reads.
pub(super) fn config_text(data_dir: &std::path::Path) -> String {
	format!(
		"hostname = \"mail.a.example\"\n\
		 data_dir = {data_dir:?}\n\
		 domains = [\"a.example\", \"b.example\", \"xn--bcher-kva.example\"]\n\
		 disabled_domains = [\"b.example\"]\n\
		 send_only_domains = [\"xn--bcher-kva.example\"]\n\
		 \n\
		 [domain_aliases]\n\
		 \"alias.example\" = \"a.example\"\n\
		 \n\
		 [domain_quotas]\n\
		 'a.example' = 1000\n\
		 \n\
		 [domain_submission_limits]\n\
		 'a.example' = 7\n\
		 \n\
		 [[accounts]]\n\
		 name = \"ann\"\n\
		 addresses = [\"ann@a.example\"]\n\
		 password_hash = \"{HASH}\"\n\
		 \n\
		 [[accounts]]\n\
		 name = \"bob\"\n\
		 addresses = [\"bob@b.example\"]\n\
		 password_hash = \"{HASH}\"\n\
		 \n\
		 [[alias]]\n\
		 address = \"team@a.example\"\n\
		 members = [\"ann@a.example\"]\n"
	)
}

/// The directory holding the configuration and the API state the server
/// would build from it.
pub(super) struct World {
	pub(super) _dir: tempfile::TempDir,
	pub(super) state: ApiState,
}

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
		domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
		account: None,
	}
}

pub(super) fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let path = data_dir.join("mail.toml");
	// The server refuses a configuration file others can read.
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.expect("config file");
	file.write_all(config_text(&data_dir).as_bytes())
		.expect("write config");
	drop(file);
	let config = Config::load(&path).expect("config loads");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	for one in [
		key("confined", CONFINED, &["read", "write"], &["a.example"]),
		key("reader", READER, &["read"], &[]),
		key("sender", SENDER, &["send"], &[]),
		key("elsewhere", ELSEWHERE, &["read"], &["c.example"]),
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			&data_dir,
			config.domains.clone(),
			std::collections::HashMap::new(),
			config.accounts.clone(),
		)
		.expect("store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(crate::api::tests::base::TOKEN.as_str()),
		data_dir.clone(),
		config.domains.clone(),
		store.clone(),
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(store.handle())
	.with_disabled_domains(config.disabled_domains.clone())
	.with_domain_catalog(Catalog::from_config(&config));
	World { _dir: dir, state }
}

/// `GET path` with `token` through the whole router, middleware included.
pub(super) async fn get(
	world: &World,
	path: &str,
	token: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
	let app = crate::api::router(world.state.clone());
	crate::api::tests::base::request(&app, "GET", path, Some(token)).await
}

/// The configured token, which holds every scope and every domain.
pub(super) fn token() -> &'static str {
	crate::api::tests::base::TOKEN.as_str()
}
