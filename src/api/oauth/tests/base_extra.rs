//! Additional module regressions.

use super::*;

#[tokio::test]
async fn pkce_rejects_plain_method() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	// `plain` (and an absent method) must be rejected: S256 only.
	let auth = format!(
		"client_id=cli&code_challenge=abc&code_challenge_method=plain&login={LOGIN}&password={}",
		urlenc(fixtures::password())
	);
	let (status, body) = post_form(&app, "/oauth/authorize", &auth).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn pkce_authorize_rejects_bad_credentials() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	let auth = "client_id=cli&code_challenge=abc&code_challenge_method=S256&login=alice@example.org&password=nope";
	let (status, body) = post_form(&app, "/oauth/authorize", auth).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");
}

#[test]
fn expired_device_grant_redeems_as_expired_token() {
	// Drive the store directly to age a grant past its TTL.
	let keys = keys();
	let authz =
		crate::api::oauth::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).expect("authz");
	let device_code = "dc".to_string();
	authz.devices.lock().unwrap().insert(
		device_code.clone(),
		crate::api::oauth::DeviceGrant {
			user_code: "AAAA-AAAA".to_string(),
			approved_account: Some("alice".to_string()),
			expires_at: 1, // long past
			next_poll_at: 0,
			client: None,
		},
	);
	let response = crate::api::oauth::device::redeem_device_code(&authz, &device_code);
	assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn polling_too_fast_yields_slow_down() {
	// A second poll before next_poll_at elapses gets slow_down (RFC 8628 §3.5).
	let keys = keys();
	let authz =
		crate::api::oauth::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).expect("authz");
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	authz.devices.lock().unwrap().insert(
		"dc".to_string(),
		crate::api::oauth::DeviceGrant {
			user_code: "AAAA-AAAA".to_string(),
			approved_account: None,
			expires_at: now + 600,
			next_poll_at: now + 5, // not yet allowed to poll
			client: None,
		},
	);
	let response = crate::api::oauth::device::redeem_device_code(&authz, "dc");
	assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unsupported_grant_type_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	let (status, body) = post_form(&app, "/oauth/token", "grant_type=password").await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "unsupported_grant_type");
}

#[test]
fn authz_build() {
	let keys = keys();
	assert!(crate::api::oauth::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).is_some());
	// Malformed base64 private key → no server (fail closed).
	assert!(crate::api::oauth::AuthzServer::new("not base64!!!", ISSUER, AUDIENCE).is_none());
}

/// Minimal form-value encoder for the test bodies (spaces only — the test
/// passwords/values contain no other reserved characters).

#[test]
fn parse_fields_decodes_form_escapes_and_json() {
	use axum::body::Bytes;
	use axum::http::HeaderMap;
	// Form body: %XX escapes, `+` as space, a bare key, and a malformed escape
	// that is passed through literally rather than panicking.
	let form = Bytes::from_static(b"login=a%40b.com&password=p+w%25&bare&bad=%zz");
	let fields = crate::api::oauth::parse_fields(&HeaderMap::new(), &form);
	assert_eq!(fields.get("login").map(String::as_str), Some("a@b.com"));
	// `assert_eq!` on the parsed password would Debug-print
	// the value on a mismatch, dumping the credential into
	// the CI log. The boolean form names the contract without
	// echoing the payload.
	assert!(
		fields.get("password").map(String::as_str) == Some("p w%"),
		"form percent-escapes and plus-as-space must round-trip the password"
	);
	assert_eq!(fields.get("bare").map(String::as_str), Some(""));
	assert_eq!(fields.get("bad").map(String::as_str), Some("%zz"));
	// JSON body with the JSON content-type; non-string values are dropped.
	let mut headers = HeaderMap::new();
	headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
	let json = Bytes::from_static(br#"{"login":"x@y.z","password":"s","n":1}"#);
	let fields = crate::api::oauth::parse_fields(&headers, &json);
	assert_eq!(fields.get("login").map(String::as_str), Some("x@y.z"));
	// Same reasoning: the parsed password must not surface
	// in a panic. The boolean form names the contract only.
	assert!(
		fields.get("password").map(String::as_str) == Some("s"),
		"JSON string fields must round-trip the password"
	);
	assert!(!fields.contains_key("n"));
}

#[tokio::test]
async fn device_approve_accepts_basic_auth() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	let (_, body) = post_form(&app, "/oauth/device_authorization", "client_id=cli").await;
	let user_code = body["user_code"].as_str().expect("user_code").to_string();
	// Credentials in an HTTP Basic header instead of body fields.
	let basic = B64.encode(format!("{LOGIN}:{}", fixtures::password()));
	let mut request = Request::builder()
		.method("POST")
		.uri("/oauth/device/approve")
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.header(header::AUTHORIZATION, format!("Basic {basic}"))
		.body(Body::from(format!("user_code={user_code}")))
		.expect("request");
	attach_peer(&mut request);
	let response = app.oneshot(request).await.expect("response");
	assert_eq!(response.status(), StatusCode::OK);
}

/// The 28-char `USER_CODE_ALPHABET` has `256 % 28 = 4`, so the naive
/// `byte % 28` over random bytes produces a 10/9 frequency split (the first
/// 4 chars — `B`, `C`, `D`, `F` — get 10/256 vs 9/256 for the rest, a
/// 1.111× bias). Rejection sampling under the threshold
/// `256 - (256 % 28) = 252` makes every alphabet char exactly 9/252 of the
/// valid bytes — uniform.
///
/// Pins the rejection-sampling logic directly with a deterministic byte
/// source that cycles `0..=255` in order — the worst case for the naive
/// modulo. With that source and threshold 252, every complete 256-byte cycle
/// yields exactly 9 valid hits per alphabet slot, so cumulative counts are
/// EXACTLY equal after a whole number of cycles — no statistical slack, no
/// flake risk.
#[test]
fn random_user_code_rejection_sampling_is_uniform() {
	let alphabet = crate::api::oauth::USER_CODE_ALPHABET;
	let n = alphabet.len();
	assert_eq!(n, 28, "this test pins the alphabet size");
	assert_eq!(256 % n, 4, "this test pins the bias shape");

	struct CyclingRng(u8);
	let mut rng = CyclingRng(0);
	// 396 full cycles = 99_792 valid bytes; each char gets 9 hits per cycle.
	let samples = 99_792usize;
	let chars = crate::api::oauth::random_user_code_chars_with(alphabet, samples, |buf| {
		buf[0] = rng.0;
		rng.0 = rng.0.wrapping_add(1);
		Some(())
	})
	.expect("fill never fails");

	let mut counts = vec![0usize; n];
	for &c in &chars {
		let idx = alphabet.iter().position(|&a| a == c).unwrap();
		counts[idx] += 1;
	}

	// Strict equality: a deterministic source plus a uniform map means every
	// alphabet char was used the same number of times. The biased `byte % n`
	// version would surface 3_960 hits for the first 4 chars and 3_564 for
	// the rest — a 396-hit gap that strict equality (this assertion) catches.
	let max = *counts.iter().max().unwrap();
	let min = *counts.iter().min().unwrap();
	assert_eq!(max, min, "non-uniform distribution: {counts:?}");
	assert_eq!(counts.iter().sum::<usize>(), samples);
}
