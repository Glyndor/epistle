//! One state with two accounts, `app` (sending switched off) and `bob`, and
//! a key bound to each.

use axum::Router;

use super::super::base::TOKEN;
use super::super::router;
use crate::storage::FsSpool;

pub(super) const OFF: &str = "app";
pub(super) const ON: &str = "bob";

/// The secret of the key bound to `account`.
pub(super) fn secret(account: &str) -> String {
	format!("{account}-secret")
}

fn account(name: &str, send: Option<bool>) -> crate::config::Account {
	crate::config::Account {
		send,
		receive: None,
		display_name: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some(crate::smtp::auth::tests::base::hash(
			crate::test_fixtures::password(),
		)),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}
}

/// The app, with a key bound to each account holding every scope.
pub(super) fn app(dir: &std::path::Path) -> Router {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("open key store");
	for name in [OFF, ON] {
		keys.add(crate::api::api_keys::ApiKey {
			label: format!("{name}-only"),
			hash: crate::api::api_keys::sha256_hash(&secret(name)),
			expires_at: None,
			ip_cidr: None,
			scopes: ["read", "write", "send"].map(str::to_string).to_vec(),
			domains: Vec::new(),
			account: Some(name.to_string()),
		})
		.expect("add key");
	}
	drop(keys);
	let domains = vec!["example.org".to_string()];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![account(OFF, Some(false)), account(ON, None)],
		)
		.expect("open store"),
	);
	router(
		crate::api::ApiState::new(
			&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
			dir.to_path_buf(),
			domains,
			store.clone(),
			FsSpool::open(dir).expect("open spool"),
		)
		.with_directory(store.handle()),
	)
}
