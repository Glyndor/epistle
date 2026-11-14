//! Locally issued tokens through the real OAuth and JMAP routers; no mocks.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::base::{keys, state_with_authz};
use crate::api::{ApiState, router};

mod flows;
mod rejection;
mod revocation;
mod scopes;

fn world(dir: &std::path::Path) -> ApiState {
	let state = state_with_authz(dir, &keys());
	state
		.store()
		.add(crate::directory_store::DynamicAccount {
			name: "bob".into(),
			addresses: vec!["bob@example.org".into()],
			password_hash: crate::smtp::auth::hash_password(
				crate::test_support::fixtures::password(),
			)
			.unwrap(),
			..Default::default()
		})
		.unwrap();
	for name in ["alice", "bob"] {
		std::fs::create_dir_all(dir.join("accounts").join(name).join("new")).unwrap();
	}
	let directory = state.store().handle();
	state.with_directory(directory)
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
}

fn claims(state: &ApiState) -> Value {
	let authz = state.authz().unwrap();
	let now = now();
	json!({
		"sub": "alice", "iss": authz.issuer, "aud": authz.audience,
		"iat": now - 10, "exp": now + 3590, "scope": "read write send",
		"jti": authz.random_code().unwrap(),
	})
}

fn signed(state: &ApiState, claims: &Value) -> String {
	crate::jwt::sign(
		claims,
		crate::jwt::Algorithm::Es256,
		&state.authz().unwrap().signing_key,
	)
	.unwrap()
}

fn issued(state: &ApiState, account: &str, scopes: &str) -> String {
	state
		.authz()
		.unwrap()
		.issue_token(
			account,
			&crate::api::oauth::scopes::Scopes::parse(scopes).unwrap(),
			now(),
		)
		.unwrap()
}

async fn response(
	app: &axum::Router,
	method: &str,
	path: &str,
	token: Option<&str>,
	content_type: &str,
	body: String,
) -> axum::response::Response {
	let mut builder = Request::builder()
		.method(method)
		.uri(path)
		.header(header::CONTENT_TYPE, content_type);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let mut request = builder.body(Body::from(body)).unwrap();
	request.extensions_mut().insert(ConnectInfo(
		"203.0.113.10:4000".parse::<std::net::SocketAddr>().unwrap(),
	));
	app.clone().oneshot(request).await.unwrap()
}

async fn decoded(response: axum::response::Response) -> (StatusCode, Value) {
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.unwrap();
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(Value::Null),
	)
}

async fn form(app: &axum::Router, path: &str, fields: &str) -> (StatusCode, Value) {
	decoded(
		response(
			app,
			"POST",
			path,
			None,
			"application/x-www-form-urlencoded",
			fields.into(),
		)
		.await,
	)
	.await
}

async fn request(
	app: &axum::Router,
	method: &str,
	path: &str,
	token: &str,
	body: Value,
) -> (StatusCode, Value) {
	decoded(
		response(
			app,
			method,
			path,
			Some(token),
			"application/json",
			body.to_string(),
		)
		.await,
	)
	.await
}

async fn call(app: &axum::Router, token: &str, method: &str, args: Value) -> Value {
	let (status, body) = request(
		app,
		"POST",
		"/jmap/api",
		token,
		json!({"methodCalls": [[method, args, "c"]]}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	body["methodResponses"][0].clone()
}

async fn pkce(app: &axum::Router, scope: Option<&str>) -> String {
	let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	let mut fields = format!(
		"client_id=panel&code_challenge_method=S256&code_challenge={}&login=alice@example.org&password={}",
		super::base::CHALLENGE,
		crate::test_support::fixtures::password()
	);
	if let Some(scope) = scope {
		fields.push_str(&format!("&scope={scope}"));
	}
	let (status, body) = form(app, "/oauth/authorize", &fields).await;
	assert_eq!(status, StatusCode::OK);
	let code = body["code"].as_str().unwrap();
	let response = response(
		app,
		"POST",
		"/oauth/token",
		None,
		"application/x-www-form-urlencoded",
		format!(
			"grant_type=authorization_code&code={code}&code_verifier={verifier}&scope=read+write+send"
		),
	)
	.await;
	assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
	let (status, body) = decoded(response).await;
	assert_eq!(status, StatusCode::OK);
	body["access_token"].as_str().unwrap().to_owned()
}

async fn device(app: &axum::Router, scope: &str) -> String {
	let (status, grant) = form(
		app,
		"/oauth/device_authorization",
		&format!("client_id=panel&scope={scope}"),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let (status, _) = form(
		app,
		"/oauth/device/approve",
		&format!(
			"user_code={}&login=alice@example.org&password={}&scope={scope}",
			grant["user_code"].as_str().unwrap(),
			crate::test_support::fixtures::password()
		),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let (status, body) = form(
		app,
		"/oauth/token",
		&format!(
			"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}&scope=read+write+send",
			grant["device_code"].as_str().unwrap()
		),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	body["access_token"].as_str().unwrap().to_owned()
}
