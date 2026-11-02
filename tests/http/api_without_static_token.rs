//! HTTP router integration for submission with an account-bound send key and no static token.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use epistle::api::api_keys::sha256_hash;
use epistle::api::{ApiKey, ApiKeyStore, ApiState};
use epistle::config::{Config, ListenerKind};
use epistle::directory_store::AccountStore;
use epistle::storage::FsSpool;
use serde_json::{Value, json};

#[tokio::test]
async fn send_key_posts_mail_without_a_static_token_and_anonymous_send_is_refused() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	std::fs::write(
		&path,
		format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n\
		 [[listeners]]\nkind = 'api'\naddr = '127.0.0.1'\n[api]\n\
		 [[accounts]]\nname = 'sender'\naddresses = ['sender@example.org']\n",
			dir.path().to_str().unwrap(),
		),
	)
	.unwrap();
	#[cfg(unix)]
	std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	let config = Config::load(&path).unwrap();
	assert!(
		config
			.listeners
			.iter()
			.any(|listener| listener.kind == ListenerKind::Api)
	);
	let token_hash = config.api.unwrap().token_hash;
	assert!(token_hash.is_none());
	let secret = uuid::Uuid::now_v7().simple().to_string();
	ApiKeyStore::open(dir.path())
		.unwrap()
		.add(ApiKey {
			label: "application".into(),
			hash: sha256_hash(&secret),
			scopes: vec!["send".into()],
			account: Some("sender".into()),
			expires_at: None,
			ip_cidr: None,
			domains: Vec::new(),
		})
		.unwrap();
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			config.domains.clone(),
			config.domain_aliases,
			config.accounts,
		)
		.unwrap(),
	);
	let state = ApiState::new_with_optional_token(
		token_hash.as_deref(),
		dir.path().into(),
		config.domains,
		store.clone(),
		FsSpool::open(dir.path()).unwrap(),
	)
	.with_directory(store.handle());
	let app = epistle::api::router(state);
	let message = json!({"from": "sender@example.org", "to": ["remote@example.net"],
		"subject": "Submission", "text": "Body"});
	let send = |token: Option<&str>| {
		let mut request = Request::builder()
			.method("POST")
			.uri("/api/v1/send")
			.header("Content-Type", "application/json");
		if let Some(token) = token {
			request = request.header("Authorization", format!("Bearer {token}"));
		}
		request.body(Body::from(message.to_string())).unwrap()
	};
	let response = app.clone().oneshot(send(Some(&secret))).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	let body: Value =
		serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
			.unwrap();
	assert!(body["queued"].is_string());
	for token in [None, Some(""), Some("sha256:")] {
		let response = app.clone().oneshot(send(token)).await.unwrap();
		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
		let body: Value =
			serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
				.unwrap();
		assert_eq!(body["error"]["code"], "unauthenticated");
	}
}
