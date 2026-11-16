//! Refresh tokens (RFC 6749 section 6): off unless configured, rotated on
//! every use, a rotated one that comes back ends its whole family, and the
//! family ends with the password, the account and the revocation endpoint.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use tower::ServiceExt;

use super::base::{keys, state_with_authz, state_with_lifetimes};
use crate::api::{ApiState, router};
use crate::test_support::fixtures;

/// A valid S256 challenge and the verifier it is the digest of (RFC 7636 appendix B).
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const MONTH: u64 = 30 * 24 * 3600;

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

async fn post(app: &axum::Router, path: &str, form: &str) -> (StatusCode, serde_json::Value) {
	let mut request = Request::builder()
		.method("POST")
		.uri(path)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.body(Body::from(form.to_string()))
		.expect("request");
	request
		.extensions_mut()
		.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			[203, 0, 113, 1],
			12345,
		))));
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("bytes");
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
	)
}

/// Sign `login` in through the authorization code grant, asking for `scope`.
async fn sign_in(app: &axum::Router, login: &str, scope: &str) -> serde_json::Value {
	let auth = format!(
		"client_id=cli&code_challenge={CHALLENGE}&code_challenge_method=S256&login={login}\
		 &password={}&scope={scope}",
		fixtures::password().replace(' ', "%20")
	);
	let (status, body) = post(app, "/oauth/authorize", &auth).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let code = body["code"].as_str().expect("code");
	let form = format!("grant_type=authorization_code&code={code}&code_verifier={VERIFIER}");
	let (status, body) = post(app, "/oauth/token", &form).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body
}

async fn refresh(app: &axum::Router, token: &str) -> (StatusCode, serde_json::Value) {
	post(
		app,
		"/oauth/token",
		&format!("grant_type=refresh_token&refresh_token={token}"),
	)
	.await
}

fn refreshing_app(dir: &std::path::Path) -> (axum::Router, ApiState) {
	let state = state_with_lifetimes(dir, &keys(), 900, Some(MONTH));
	(router(state.clone()), state)
}

/// The `exp - iat` of a JWT, read without verifying it.
fn lifetime_of(jwt: &str) -> u64 {
	let payload = jwt.split('.').nth(1).expect("payload");
	let claims: serde_json::Value =
		serde_json::from_slice(&B64URL.decode(payload).expect("base64")).expect("json");
	claims["exp"].as_u64().expect("exp") - claims["iat"].as_u64().expect("iat")
}

#[tokio::test]
async fn without_a_refresh_lifetime_no_refresh_token_is_issued_and_the_grant_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_authz(dir.path(), &keys()));
	let body = sign_in(&app, "alice@example.org", "read").await;
	assert!(body.get("refresh_token").is_none());
	assert_eq!(body["expires_in"], 3600);
	let (status, body) = refresh(&app, "anything").await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "unsupported_grant_type");
	assert_eq!(super::super::refresh::live_records(dir.path()), 0);
}

#[tokio::test]
async fn the_access_lifetime_is_the_configured_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let body = sign_in(&app, "alice@example.org", "read").await;
	assert_eq!(body["expires_in"], 900);
	assert_eq!(
		lifetime_of(body["access_token"].as_str().expect("jwt")),
		900
	);
	assert!(
		body["refresh_token"]
			.as_str()
			.is_some_and(|t| t.len() == 43)
	);
}

#[tokio::test]
async fn an_access_token_longer_lived_than_the_configured_lifetime_is_refused() {
	let keys = keys();
	let long =
		crate::api::oauth::AuthzServer::new(&keys.private_b64, "https://mail.example", "mail")
			.expect("authz");
	let short =
		crate::api::oauth::AuthzServer::new(&keys.private_b64, "https://mail.example", "mail")
			.expect("authz")
			.with_lifetimes(600, None);
	let scopes = crate::api::oauth::scopes::Scopes::requested(None).expect("scopes");
	let at = now();
	let token = long.issue_token("alice", &scopes, at).expect("token");
	assert!(long.access_claims(&token, at).is_some());
	assert!(short.access_claims(&token, at).is_none());
	let own = short.issue_token("alice", &scopes, at).expect("token");
	assert!(short.access_claims(&own, at).is_some());
	assert!(short.access_claims(&own, at + 601).is_none());
}

#[tokio::test]
async fn a_refresh_token_is_rotated_on_every_use() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let first = sign_in(&app, "alice@example.org", "read").await;
	let first_refresh = first["refresh_token"]
		.as_str()
		.expect("refresh")
		.to_string();

	let (status, second) = refresh(&app, &first_refresh).await;
	assert_eq!(status, StatusCode::OK, "{second}");
	let second_refresh = second["refresh_token"]
		.as_str()
		.expect("refresh")
		.to_string();
	assert_ne!(second_refresh, first_refresh);
	assert_ne!(second["access_token"], first["access_token"]);
	assert_eq!(second["scope"], "read");
	assert_eq!(second["expires_in"], 900);

	let (status, third) = refresh(&app, &second_refresh).await;
	assert_eq!(status, StatusCode::OK, "{third}");
	assert_ne!(third["refresh_token"], second["refresh_token"]);
}

#[tokio::test]
async fn presenting_a_rotated_token_again_revokes_the_whole_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let first = sign_in(&app, "alice@example.org", "read").await;
	let stolen = first["refresh_token"]
		.as_str()
		.expect("refresh")
		.to_string();
	let (_, second) = refresh(&app, &stolen).await;
	let current = second["refresh_token"]
		.as_str()
		.expect("refresh")
		.to_string();

	// The old token comes back, from whoever holds a copy of it.
	let (status, body) = refresh(&app, &stolen).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");

	// The legitimate holder of the current token is signed out too.
	let (status, body) = refresh(&app, &current).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");
	assert_eq!(super::super::refresh::live_records(dir.path()), 0);
}

#[tokio::test]
async fn reuse_ends_only_its_own_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let one = sign_in(&app, "alice@example.org", "read").await;
	let two = sign_in(&app, "alice@example.org", "read").await;
	let one_old = one["refresh_token"].as_str().expect("refresh").to_string();
	refresh(&app, &one_old).await;
	refresh(&app, &one_old).await;
	let (status, _) = refresh(&app, two["refresh_token"].as_str().expect("refresh")).await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn an_unknown_or_malformed_refresh_token_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let (status, body) = refresh(&app, "not-a-token").await;
	assert_eq!(
		(status, body["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_grant"))
	);
	let (status, body) = post(&app, "/oauth/token", "grant_type=refresh_token").await;
	assert_eq!(
		(status, body["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_request"))
	);
	let long = "a".repeat(4096);
	let (_, body) = refresh(&app, &long).await;
	assert_eq!(body["error"], "invalid_request");
	// Guessing costs the server no write.
	assert!(!dir.path().join("oauth_refresh.json").exists());
}

#[tokio::test]
async fn an_expired_refresh_token_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let body = sign_in(&app, "alice@example.org", "read").await;
	let path = dir.path().join("oauth_refresh.json");
	let mut store: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
	for record in store["tokens"]
		.as_object_mut()
		.expect("tokens")
		.values_mut()
	{
		record["expires_at"] = serde_json::json!(now() - 1);
	}
	std::fs::write(&path, serde_json::to_vec(&store).expect("json")).expect("write");
	let (status, body) = refresh(&app, body["refresh_token"].as_str().expect("refresh")).await;
	assert_eq!(
		(status, body["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_grant"))
	);
}

#[tokio::test]
async fn a_password_change_ends_the_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, state) = refreshing_app(dir.path());
	let body = sign_in(&app, "bob@example.org", "read").await;
	let token = body["refresh_token"].as_str().expect("refresh").to_string();
	let new_hash = crate::smtp::auth::hash_password("another example secret").expect("hash");
	state
		.store()
		.set_password_hash("bob", new_hash, None)
		.expect("change");
	let (status, body) = refresh(&app, &token).await;
	assert_eq!(
		(status, body["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_grant"))
	);
	assert_eq!(super::super::refresh::live_records(dir.path()), 0);
}

#[tokio::test]
async fn a_credential_reset_ends_the_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, state) = refreshing_app(dir.path());
	let body = sign_in(&app, "bob@example.org", "read").await;
	let token = body["refresh_token"].as_str().expect("refresh").to_string();
	crate::test_support::accounts::reset(state.store(), "bob");
	let (status, body) = refresh(&app, &token).await;
	assert_eq!(
		(status, body["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_grant"))
	);
}

#[tokio::test]
async fn disabling_the_account_ends_the_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, state) = refreshing_app(dir.path());
	let body = sign_in(&app, "bob@example.org", "read").await;
	let token = body["refresh_token"].as_str().expect("refresh").to_string();
	state.store().set_disabled("bob", true).expect("disable");
	let (status, body) = refresh(&app, &token).await;
	assert_eq!(
		(status, body["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_grant"))
	);
}

#[tokio::test]
async fn an_unrelated_account_change_keeps_the_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, state) = refreshing_app(dir.path());
	let body = sign_in(&app, "bob@example.org", "read").await;
	state.store().set_disabled("bob", false).expect("no-op");
	let (status, _) = refresh(&app, body["refresh_token"].as_str().expect("refresh")).await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_scope_can_be_narrowed_but_never_widened() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let body = sign_in(&app, "alice@example.org", "read%20write").await;
	let token = body["refresh_token"].as_str().expect("refresh").to_string();

	// Wider than granted: refused, and the token is not spent.
	let (status, refused) = post(
		&app,
		"/oauth/token",
		&format!("grant_type=refresh_token&refresh_token={token}&scope=read%20send"),
	)
	.await;
	assert_eq!(
		(status, refused["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_scope"))
	);

	let (status, narrowed) = post(
		&app,
		"/oauth/token",
		&format!("grant_type=refresh_token&refresh_token={token}&scope=read"),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{narrowed}");
	assert_eq!(narrowed["scope"], "read");

	// The family keeps what it was granted.
	let next = narrowed["refresh_token"].as_str().expect("refresh");
	let (_, again) = refresh(&app, next).await;
	assert_eq!(again["scope"], "read write");
}

#[tokio::test]
async fn revoking_the_refresh_token_ends_the_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let body = sign_in(&app, "alice@example.org", "read").await;
	let token = body["refresh_token"].as_str().expect("refresh");
	let (status, _) = post(&app, "/oauth/revoke", &format!("token={token}")).await;
	assert_eq!(status, StatusCode::OK);
	let (status, body) = refresh(&app, token).await;
	assert_eq!(
		(status, body["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_grant"))
	);

	// Revoking something unknown still answers 200 and changes nothing.
	let (status, _) = post(&app, "/oauth/revoke", "token=unknown").await;
	assert_eq!(status, StatusCode::OK);
}

#[test]
fn an_account_keeps_a_bounded_number_of_families() {
	let dir = tempfile::tempdir().expect("tempdir");
	let at = now();
	for index in 0..51u64 {
		let token = format!("token-{index}");
		let family = format!("family-{index}");
		let first = super::super::refresh::FirstToken {
			token: &token,
			family: &family,
			account: "alice",
			scope: "read",
			credential: "",
		};
		super::super::refresh::start_family(dir.path(), &first, at + 1000 + index, at)
			.expect("start");
	}
	assert_eq!(super::super::refresh::live_records(dir.path()), 50);
	// The family that would have expired first made room.
	let outcome =
		super::super::refresh::rotate(dir.path(), "token-0", "next", 10, at, |_, _| true, |_| true)
			.expect("rotate");
	assert!(matches!(outcome, super::super::refresh::Outcome::Refused));
}

/// The files the store keeps in `dir`, with their contents and modification times.
fn store_files(dir: &std::path::Path) -> Vec<(String, Vec<u8>, std::time::SystemTime)> {
	let mut files: Vec<_> = std::fs::read_dir(dir)
		.expect("dir")
		.map(|entry| entry.expect("entry"))
		.filter(|entry| {
			entry
				.file_name()
				.to_string_lossy()
				.contains("oauth_refresh")
		})
		.map(|entry| {
			(
				entry.file_name().to_string_lossy().into_owned(),
				std::fs::read(entry.path()).expect("read"),
				entry.metadata().expect("meta").modified().expect("mtime"),
			)
		})
		.collect();
	files.sort();
	files
}

#[tokio::test]
async fn revoking_what_the_store_does_not_hold_takes_no_lock_and_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());

	// No store at all: nothing is created, not even the lock file.
	for token in ["unknown", "", &"a".repeat(100_000)] {
		let (status, _) = post(&app, "/oauth/revoke", &format!("token={token}")).await;
		assert_eq!(status, StatusCode::OK);
	}
	assert!(store_files(dir.path()).is_empty());

	// A store with a family in it: unknown tokens leave it byte for byte
	// and timestamp for timestamp, and no lock file appears.
	let body = sign_in(&app, "alice@example.org", "read").await;
	let before = store_files(dir.path());
	for token in ["unknown", "", &"a".repeat(100_000)] {
		let (status, _) = post(&app, "/oauth/revoke", &format!("token={token}")).await;
		assert_eq!(status, StatusCode::OK);
		let (status, answer) = refresh(&app, token).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
	}
	assert_eq!(store_files(dir.path()), before);

	// A real token is still revoked.
	let token = body["refresh_token"].as_str().expect("refresh");
	let (status, _) = post(&app, "/oauth/revoke", &format!("token={token}")).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(super::super::refresh::live_records(dir.path()), 0);
}

#[test]
fn the_store_helpers_refuse_empty_and_oversized_tokens_without_touching_disk() {
	let dir = tempfile::tempdir().expect("tempdir");
	let at = now();
	for token in ["", &"a".repeat(129), &"a".repeat(1 << 20)] {
		super::super::refresh::revoke(dir.path(), token, at).expect("revoke");
		let outcome =
			super::super::refresh::rotate(dir.path(), token, "next", 10, at, |_, _| true, |_| true)
				.expect("rotate");
		assert!(matches!(outcome, super::super::refresh::Outcome::Refused));
	}
	assert!(store_files(dir.path()).is_empty());
}

#[tokio::test]
async fn an_unreadable_store_is_an_error_never_a_silent_success() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = refreshing_app(dir.path());
	let body = sign_in(&app, "alice@example.org", "read").await;
	let token = body["refresh_token"].as_str().expect("refresh").to_string();
	let path = dir.path().join("oauth_refresh.json");
	std::fs::write(&path, b"{ not json").expect("corrupt");

	// The endpoint reports that it could not look, instead of a 200 that
	// would tell the client its token is gone.
	let (status, answer) = post(&app, "/oauth/revoke", &format!("token={token}")).await;
	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
	assert!(super::super::refresh::revoke(dir.path(), &token, now()).is_err());
	let (status, answer) = refresh(&app, &token).await;
	assert_ne!(status, StatusCode::OK, "{answer}");
	assert_eq!(answer["error"], "temporarily_unavailable");
	assert_eq!(
		std::fs::read(&path).expect("read"),
		b"{ not json",
		"left as found"
	);

	// A store that cannot be opened as a file is the same.
	std::fs::remove_file(&path).expect("remove");
	std::fs::create_dir(&path).expect("dir in its place");
	assert!(super::super::refresh::revoke(dir.path(), &token, now()).is_err());
}

#[test]
fn a_missing_store_is_confirmed_absence() {
	let dir = tempfile::tempdir().expect("tempdir");
	super::super::refresh::revoke(dir.path(), "any-token", now()).expect("nothing to revoke");
	assert!(store_files(dir.path()).is_empty());
}

#[test]
fn a_marker_that_is_absent_or_empty_matches_nothing() {
	use super::super::refresh::matches_marker;
	assert!(matches_marker(Some("sha256:ab".into()), "sha256:ab"));
	assert!(!matches_marker(Some("sha256:ab".into()), "sha256:cd"));
	assert!(!matches_marker(None, ""), "none against empty");
	assert!(
		!matches_marker(Some(String::new()), ""),
		"empty against empty"
	);
	assert!(!matches_marker(None, "sha256:ab"), "no marker now");
	assert!(
		!matches_marker(Some("sha256:ab".into()), ""),
		"none was kept"
	);
}

#[tokio::test]
async fn an_account_without_a_credential_marker_gets_no_refresh_token_and_none_is_accepted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let state = state_with_lifetimes(dir.path(), &keys, 900, Some(MONTH));
	// An account of the LDAP directory: its password lives elsewhere.
	state
		.store()
		.set_ldap_accounts(vec![crate::directory_store::LdapAccount {
			name: "dora".to_string(),
			addresses: vec!["dora@example.org".to_string()],
		}]);
	assert!(state.store().credential_fingerprint("dora").is_none());

	let authz = state.authz().expect("authz");
	let scopes = crate::api::oauth::scopes::Scopes::requested(None).expect("scopes");
	let response = super::super::issue::grant_tokens(&state, authz, "dora", &scopes, now());
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("bytes");
	let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
	assert!(body["access_token"].is_string());
	assert!(body.get("refresh_token").is_none(), "{body}");
	assert!(!dir.path().join("oauth_refresh.json").exists());

	// Nor does a record that kept no marker survive for such an account.
	assert!(!super::super::refresh::account_unchanged(
		&state, "dora", ""
	));
	assert!(!super::super::refresh::account_unchanged(
		&state, "dora", "sha256:x"
	));
}

#[tokio::test]
async fn setting_or_removing_the_second_factor_ends_the_family() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, state) = refreshing_app(dir.path());
	let body = sign_in(&app, "bob@example.org", "read").await;
	let token = body["refresh_token"].as_str().expect("refresh").to_string();
	state
		.store()
		.set_totp("bob", Some(crate::totp::encode_base32(&[7u8; 20])))
		.expect("enrol");
	let (status, answer) = refresh(&app, &token).await;
	assert_eq!(
		(status, answer["error"].as_str()),
		(StatusCode::BAD_REQUEST, Some("invalid_grant"))
	);
}
