//! Uploads of one tenant at the same moment share the tenant's aggregate
//! storage cap: the size is reserved before the usage is read.

use super::base::TOKEN;
use super::limits::KEY;
use super::*;
use axum::http::StatusCode;
use std::sync::Arc;
use tower::ServiceExt;

const UPLOADS: usize = 8;
const ROUNDS: usize = 12;

fn account(name: &str, address: &str) -> crate::config::Account {
	crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}
}

fn app(dir: &std::path::Path, cap: u64) -> axum::Router {
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.example".to_string()],
			quota_bytes: Some(cap),
			max_accounts: None,
			max_domains: None,
			submission_rate_limit_per_min: None,
			encryption_key_file: None,
			webhook: None,
		},
	]));
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			grants: Vec::new(),
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string()],
			domains: Vec::new(),
			account: None,
			auto_submitted: false,
		})
		.expect("add key");
	drop(key_store);
	let domains = vec!["a.example".to_string()];
	let accounts = (0..UPLOADS)
		.map(|n| account(&format!("u{n}"), &format!("u{n}@a.example")))
		.collect();
	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	router(
		ApiState::new(
			&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
			dir.to_path_buf(),
			domains,
			store.clone(),
			crate::storage::FsSpool::open(dir).expect("open spool"),
		)
		.with_directory(store.handle())
		.with_tenant_limits(limits),
	)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uploads_at_the_same_moment_stop_at_the_tenant_cap() {
	for round in 0..ROUNDS {
		let dir = tempfile::tempdir().expect("tempdir");
		// Room for one blob of 80 bytes, with its sidecars, not for two.
		let app = app(dir.path(), 150);
		let start = Arc::new(tokio::sync::Barrier::new(UPLOADS));
		let mut set = tokio::task::JoinSet::new();
		for n in 0..UPLOADS {
			let (app, start) = (app.clone(), start.clone());
			set.spawn(async move {
				let request = axum::http::Request::builder()
					.method("POST")
					.uri(format!("/jmap/upload/u{n}"))
					.header(axum::http::header::AUTHORIZATION, format!("Bearer {KEY}"))
					.header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
					.body(axum::body::Body::from(vec![1u8; 80]))
					.expect("request");
				start.wait().await;
				app.oneshot(request).await.expect("response").status()
			});
		}
		let mut stored = 0;
		while let Some(status) = set.join_next().await {
			match status.expect("upload") {
				StatusCode::OK => stored += 1,
				StatusCode::INSUFFICIENT_STORAGE => {}
				other => panic!("unexpected {other}"),
			}
		}
		assert_eq!(stored, 1, "round {round}: one blob of 80 fits a cap of 150");
	}
}
