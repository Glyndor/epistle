//! Cross-protocol coverage for the per-tenant submission rate limit.
//!
//! The `SendLimiter` that backs the tenant aggregate cap is one Arc
//! shared by the SMTP listener and the JMAP router. The test in this
//! file builds both paths with the same `Arc<TenantLimits>`, spends
//! one unit on SMTP, then proves that a JMAP submission that would
//! also fit on its own limiter is refused because the SMTP side
//! already used half the budget.
//!
//! Lives in a separate file from `src/cli/serve/tests/ratelimit.rs` because
//! the line-count budget would otherwise cap the existing suite. The
//! SMTP-side helpers (`build_smtp_server`, `authenticated_submit`,
//! ...) are made `pub(super)` on the sibling module and reused here.

use std::sync::Arc;

use super::ratelimit::{
	auth_plain, authenticated_submit, build_smtp_server, build_smtp_server_with, ratelimit_config,
	spawn_smtp_listener, tls_connector, tls_session,
};
use crate::api::TenantLimits;
use crate::tls::test_support::acceptor_and_cert;

#[tokio::test]
async fn tenant_submission_limit_is_shared_between_smtp_and_jmap() {
	// The per-tenant `SendLimiter` is one Arc shared by the SMTP
	// listener and the JMAP router. A sender that spends one unit on
	// SMTP cannot top the budget up by switching to JMAP: the third
	// submission, even on a different protocol, must be deferred.
	// With `submission_rate_limit_per_min = 2` one SMTP submission
	// and one JMAP submission both fit; the next JMAP submission
	// trips the cap and returns `rateLimit`. If the SMTP and JMAP
	// paths each held their own limiter, the second JMAP submission
	// would come back with the create map populated.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut config = ratelimit_config(dir.path(), 1);
	config.submission_rate_limit_per_min = None;
	config.domain_submission_limits.clear();
	let tenant_limits = Arc::new(TenantLimits::from_config(&[crate::config::Tenant {
		name: Some("acme".to_string()),
		domains: vec!["example.org".to_string()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: Some(2),
	}]));
	let plain = auth_plain("alice", crate::smtp::auth::tests::base::fixture_password());
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server(
		&config,
		crate::tls::ReloadableAcceptor::new(acceptor),
		Some(Arc::clone(&tenant_limits)),
	);
	let (addr, task) = spawn_smtp_listener(server).await;
	let connector = tls_connector(cert);

	// SMTP submission: one unit against the tenant cap.
	let mut tls = tls_session(addr, connector).await;
	let smtp_reply =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		smtp_reply.starts_with("250 "),
		"smtp submission must be accepted: {smtp_reply:?}"
	);
	drop(tls);

	// Build a JMAP router that holds the same Arc<TenantLimits> as the
	// SMTP listener, mirroring what `cli::serve` does in production.
	let jmap_state = jmap_state_with_tenant_limits(dir.path(), Arc::clone(&tenant_limits));
	let app = crate::api::router(jmap_state);

	// JMAP submission 1: still within the shared cap (2).
	let email_id = seed_jmap_email(dir.path(), "bob@elsewhere.example");
	let req = jmap_submission_request(&email_id, "bob@elsewhere.example");
	let (status, body) = jmap_request(&app, &req).await;
	assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0][1]["notCreated"]["s1"].is_null(),
		"first jmap submission must be accepted: {body}"
	);

	// JMAP submission 2: would push the shared count to 3, over the
	// cap of 2. The `rateLimit` JMAP error is the proof that the JMAP
	// path consulted the SMTP listener's limiter, not its own.
	let email_id = seed_jmap_email(dir.path(), "carol@elsewhere.example");
	let req = jmap_submission_request(&email_id, "carol@elsewhere.example");
	let (status, body) = jmap_request(&app, &req).await;
	assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][1]["notCreated"]["s1"]["type"], "rateLimit",
		"second jmap submission must trip the shared tenant cap: {body}"
	);
	task.abort();
}

/// The per-account limit is one budget for the SMTP listener and the API
/// when both are wired the way `serve` wires them: the API gets the
/// listener's limiter through `wire_api_submission_limits`.
#[tokio::test]
async fn account_submission_limit_is_shared_between_smtp_and_jmap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = ratelimit_config(dir.path(), 2);
	let limiters = super::super::ratelimit::build_rate_limiters(&config);
	let send_limiter = limiters.send_limiter.clone();
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server_with(
		&config,
		crate::tls::ReloadableAcceptor::new(acceptor),
		None,
		limiters,
	);
	let (addr, task) = spawn_smtp_listener(server).await;
	let plain = auth_plain("alice", crate::smtp::auth::tests::base::fixture_password());
	let mut tls = tls_session(addr, tls_connector(cert)).await;
	let smtp_reply =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(smtp_reply.starts_with("250 "), "{smtp_reply:?}");
	drop(tls);

	let no_tenants = Arc::new(TenantLimits::default());
	let state = super::super::ratelimit::wire_api_submission_limits(
		jmap_state_with_tenant_limits(dir.path(), Arc::clone(&no_tenants)),
		&config,
		&send_limiter,
		&no_tenants,
	);
	let app = crate::api::router(state);
	let email_id = seed_jmap_email(dir.path(), "bob@elsewhere.example");
	let request = jmap_submission_request(&email_id, "bob@elsewhere.example");
	let (_, body) = jmap_request(&app, &request).await;
	assert!(
		body["methodResponses"][0][1]["created"]["s1"].is_object(),
		"the second unit fits: {body}"
	);
	let email_id = seed_jmap_email(dir.path(), "carol@elsewhere.example");
	let request = jmap_submission_request(&email_id, "carol@elsewhere.example");
	let (_, body) = jmap_request(&app, &request).await;
	assert_eq!(
		body["methodResponses"][0][1]["notCreated"]["s1"]["type"], "rateLimit",
		"SMTP and JMAP spent the account's two units: {body}"
	);
	task.abort();
}

/// Build a minimal `ApiState` that owns the given `tenant_limits`. Mirrors
/// what `api::tests::test_state` does but lets the test pin the token and the
/// tenant_limits instead of inheriting the global fixture token.
fn jmap_state_with_tenant_limits(
	dir: &std::path::Path,
	tenant_limits: Arc<TenantLimits>,
) -> crate::api::ApiState {
	let token_hash = crate::smtp::auth::tests::base::hash(crate::test_fixtures::api_token());
	let spool = crate::storage::FsSpool::open(dir).expect("open spool");
	let accounts = vec![crate::config::Account {
		display_name: None,
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: None,
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	crate::api::ApiState::new(
		&token_hash,
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle())
	.with_tenant_limits(tenant_limits)
}

/// Write a stored email into alice's `new/` mailbox and return its id.
fn seed_jmap_email(dir: &std::path::Path, recipient: &str) -> uuid::Uuid {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		format!("From: alice@example.org\r\nTo: {recipient}\r\nSubject: hello\r\n\r\nbody\r\n")
			.as_bytes(),
	)
	.expect("write");
	id
}

/// Build the JSON payload for an `EmailSubmission/set` against a stored
/// email and a single envelope recipient. The submission identity is
/// `alice@example.org`, matching the account the JMAP state knows about.
fn jmap_submission_request(email_id: &uuid::Uuid, recipient: &str) -> serde_json::Value {
	serde_json::json!({
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": email_id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "alice@example.org"}, "rcptTo": [{"email": recipient}]},
			} },
		}, "c1"]],
	})
}

/// Send a `POST /jmap/api` request with the bearer token the test built the
/// state with. Returns the response status and decoded JSON body.
async fn jmap_request(
	app: &axum::Router,
	body: &serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
	use tower::ServiceExt;
	let request = axum::http::Request::builder()
		.method("POST")
		.uri("/jmap/api")
		.header(
			axum::http::header::AUTHORIZATION,
			format!("Bearer {}", crate::test_fixtures::api_token()),
		)
		.header(axum::http::header::CONTENT_TYPE, "application/json")
		.body(axum::body::Body::from(body.to_string()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json = if bytes.is_empty() {
		serde_json::Value::Null
	} else {
		serde_json::from_slice(&bytes).expect("json body")
	};
	(status, json)
}
