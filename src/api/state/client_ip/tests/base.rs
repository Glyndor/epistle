use super::*;
use crate::api::tests::base::{TOKEN, test_state};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

fn state(path: &std::path::Path) -> ApiState {
	test_state(path, 0).with_trusted_proxies(
		["10.0.0.0/8", "2001:db8:ffff::/48"]
			.into_iter()
			.map(|net| crate::cidr::Cidr::parse(net).unwrap())
			.collect(),
	)
}

#[test]
fn forwarded_chain_respects_the_trust_boundary_and_rejects_malformed_headers() {
	let dir = tempfile::tempdir().unwrap();
	let state = state(dir.path());
	let cases = [
		("192.0.2.1:80", Some("198.51.100.1"), "192.0.2.1"),
		("10.0.0.1:80", Some("198.51.100.1"), "198.51.100.1"),
		(
			"10.0.0.1:80",
			Some("192.0.2.99, 198.51.100.1, 10.0.0.2"),
			"198.51.100.1",
		),
		("10.0.0.1:80", Some("10.0.0.2, 10.0.0.3"), "10.0.0.1"),
		("10.0.0.1:80", None, "10.0.0.1"),
		("10.0.0.1:80", Some("garbage, 198.51.100.1"), "198.51.100.1"),
		("10.0.0.1:80", Some("198.51.100.1, garbage"), "10.0.0.1"),
		("10.0.0.1:80", Some("198.51.100.1,"), "10.0.0.1"),
		("10.0.0.1:80", Some("198.51.100.1:80"), "10.0.0.1"),
		(
			"[2001:db8:ffff::1]:80",
			Some("2001:db8:1::2, 2001:db8:ffff::2"),
			"2001:db8:1::2",
		),
		(
			"[::ffff:10.0.0.1]:80",
			Some("::ffff:198.51.100.1, 10.0.0.2"),
			"198.51.100.1",
		),
	];
	for (peer, forwarded, expected) in cases {
		let mut headers = HeaderMap::new();
		if let Some(value) = forwarded {
			headers.insert("x-forwarded-for", value.parse().unwrap());
		}
		assert_eq!(
			state.effective_client_ip(Some(peer.parse().unwrap()), &headers),
			Some(expected.parse().unwrap())
		);
	}
	let mut headers = HeaderMap::new();
	headers.append("x-forwarded-for", "192.0.2.99".parse().unwrap());
	headers.append("x-forwarded-for", "198.51.100.1, 10.0.0.2".parse().unwrap());
	assert_eq!(
		state.effective_client_ip(Some("10.0.0.1:80".parse().unwrap()), &headers),
		Some("198.51.100.1".parse().unwrap())
	);
	assert_eq!(state.effective_client_ip(None, &headers), None);
	headers.append(
		"x-forwarded-for",
		axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
	);
	assert_eq!(
		state.effective_client_ip(Some("10.0.0.1:80".parse().unwrap()), &headers),
		Some("10.0.0.1".parse().unwrap())
	);
}

#[test]
fn empty_trusted_proxies_preserves_socket_address() {
	let dir = tempfile::tempdir().unwrap();
	let state = test_state(dir.path(), 0);
	let mut headers = HeaderMap::new();
	headers.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
	assert_eq!(
		state.effective_client_ip(Some("10.0.0.1:80".parse().unwrap()), &headers),
		Some("10.0.0.1".parse().unwrap())
	);
}

async fn request(
	app: &axum::Router,
	peer: &str,
	forwarded: &str,
	token: &str,
) -> axum::response::Response {
	let mut request = Request::builder()
		.uri("/api/v1/domains")
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.header("x-forwarded-for", forwarded)
		.body(Body::empty())
		.unwrap();
	request
		.extensions_mut()
		.insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
	app.clone().oneshot(request).await.unwrap()
}

#[tokio::test]
async fn clients_behind_one_proxy_have_independent_failure_budgets_and_retry_headers() {
	let dir = tempfile::tempdir().unwrap();
	let state = state(dir.path()).with_auth_window(std::time::Duration::from_secs(3600));
	state.prime_configured_token(TOKEN.as_str());
	let app = crate::api::router(state);
	for _ in 0..20 {
		assert_eq!(
			request(&app, "10.0.0.1:80", "198.51.100.1, 10.0.0.2", "wrong")
				.await
				.status(),
			StatusCode::UNAUTHORIZED
		);
	}
	let blocked = request(&app, "10.0.0.1:80", "198.51.100.1", TOKEN.as_str()).await;
	assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
	let retry: u64 = blocked.headers()[header::RETRY_AFTER]
		.to_str()
		.unwrap()
		.parse()
		.unwrap();
	assert!((3590..=3600).contains(&retry));
	assert_eq!(
		request(&app, "10.0.0.1:80", "198.51.100.2", TOKEN.as_str())
			.await
			.status(),
		StatusCode::OK
	);
}

#[tokio::test]
async fn spoofed_forwarded_addresses_cannot_evade_an_untrusted_peers_limit() {
	let dir = tempfile::tempdir().unwrap();
	let state = state(dir.path());
	state.prime_configured_token(TOKEN.as_str());
	let app = crate::api::router(state);
	for host in 1..=20 {
		assert_eq!(
			request(&app, "192.0.2.1:80", &format!("198.51.100.{host}"), "wrong")
				.await
				.status(),
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		request(&app, "192.0.2.1:80", "198.51.100.99", TOKEN.as_str())
			.await
			.status(),
		StatusCode::TOO_MANY_REQUESTS
	);
}

#[tokio::test]
async fn forwarded_ipv6_clients_keep_the_existing_slash_64_grouping() {
	let dir = tempfile::tempdir().unwrap();
	let state = state(dir.path());
	state.prime_configured_token(TOKEN.as_str());
	let app = crate::api::router(state);
	for host in 1..=20 {
		assert_eq!(
			request(
				&app,
				"10.0.0.1:80",
				&format!("2001:db8:1:2::{host}"),
				"wrong"
			)
			.await
			.status(),
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		request(&app, "10.0.0.1:80", "2001:db8:1:2::99", TOKEN.as_str())
			.await
			.status(),
		StatusCode::TOO_MANY_REQUESTS
	);
	assert_eq!(
		request(&app, "10.0.0.1:80", "2001:db8:1:3::1", TOKEN.as_str())
			.await
			.status(),
		StatusCode::OK
	);
}

#[tokio::test]
async fn shared_failure_ceiling_responses_include_retry_after() {
	let dir = tempfile::tempdir().unwrap();
	let state = state(dir.path())
		.with_auth_window(std::time::Duration::from_secs(3600))
		.with_auth_global_max(1);
	state.prime_configured_token(TOKEN.as_str());
	let app = crate::api::router(state);
	let response = request(&app, "10.0.0.1:80", "198.51.100.1", "wrong").await;
	assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
	let seconds: u64 = response.headers()[header::RETRY_AFTER]
		.to_str()
		.unwrap()
		.parse()
		.unwrap();
	assert!((3590..=3600).contains(&seconds));
}
