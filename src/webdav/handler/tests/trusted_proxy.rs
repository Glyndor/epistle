//! Trusted-proxy resolution at the WebDAV listener: a failed Basic auth
//! behind a trusted reverse proxy must count against the proxy-reported
//! client (the address the proxy reports in `X-Forwarded-For`), not the
//! proxy's own socket peer. With no entry in `trusted_proxies` the socket
//! peer is the only thing the listener knows, and a header cannot be
//! used to claim another address.

use super::super::super::router_with_trusted;
use crate::test_fixtures as fixtures;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use tower::ServiceExt;

/// Standard base64 encode for building Basic credentials (matches the
/// encoding helper kept in `src/webdav/handler/tests/base.rs`).
fn base64_encode(input: &[u8]) -> String {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::new();
	for chunk in input.chunks(3) {
		let b = [
			chunk[0],
			*chunk.get(1).unwrap_or(&0),
			*chunk.get(2).unwrap_or(&0),
		];
		let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
		out.push(ALPHABET[(n >> 18) as usize & 63] as char);
		out.push(ALPHABET[(n >> 12) as usize & 63] as char);
		out.push(if chunk.len() > 1 {
			ALPHABET[(n >> 6) as usize & 63] as char
		} else {
			'='
		});
		out.push(ALPHABET[n as usize & 63] as char);
	}
	out
}

/// Build a router backed by a temp data dir, the ban store the test
/// inspects, and the trusted-proxy list the listener resolves
/// `X-Forwarded-For` against.
fn test_app_with_trusted_and_ban_store(
	dir: &std::path::Path,
	trusted_proxies: Vec<crate::cidr::Cidr>,
) -> (
	Router,
	std::sync::Arc<crate::antispam::bans::tests::base::FakeBanStore>,
) {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::base::FakeBanStore;
	let account = |name: &str, pw: &str| crate::config::Account {
		display_name: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some(crate::smtp::auth::hash_password(pw).expect("hash")),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let mut account_store = crate::directory_store::AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![account("alice", fixtures::password())],
	)
	.expect("store");
	account_store = account_store.with_ban_store(store.clone());
	let router = router_with_trusted(account_store.handle(), dir.to_path_buf(), trusted_proxies);
	(router, store)
}

/// Send a request with the given `ConnectInfo` extension, Basic auth,
/// and additional headers.
async fn send_with_peer(
	app: &Router,
	method: &str,
	path: &str,
	peer: std::net::SocketAddr,
	auth: Option<&str>,
	headers: &[(&str, String)],
	body: &[u8],
) -> (StatusCode, Vec<u8>, HeaderMap) {
	let mut builder = Request::builder().method(method).uri(path);
	if let Some(creds) = auth {
		let encoded = base64_encode(creds.as_bytes());
		builder = builder.header(
			axum::http::header::AUTHORIZATION,
			format!("Basic {encoded}"),
		);
	}
	for (name, value) in headers {
		builder = builder.header(*name, value);
	}
	let mut request = builder.body(Body::from(body.to_vec())).expect("request");
	request.extensions_mut().insert(ConnectInfo(peer));
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let resp_headers = response.headers().clone();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, bytes.to_vec(), resp_headers)
}

/// A failed Basic authentication reaching the WebDAV listener through a
/// trusted reverse proxy must count against the proxy-reported client,
/// not the proxy's own socket address. Without this, every client behind
/// the same NAT or reverse proxy would share one ban budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_basic_login_through_a_trusted_proxy_counts_the_real_client() {
	let dir = tempfile::tempdir().expect("tempdir");
	let trusted = ["10.0.0.0/8"]
		.into_iter()
		.map(|net| crate::cidr::Cidr::parse(net).unwrap())
		.collect();
	let (app, store) = test_app_with_trusted_and_ban_store(dir.path(), trusted);
	let peer: std::net::SocketAddr = "10.0.0.1:80".parse().expect("peer");
	let (status, _, _) = send_with_peer(
		&app,
		"PUT",
		"/probe.txt",
		peer,
		Some(&format!("alice:{}", fixtures::wrong_password())),
		&[("x-forwarded-for", "198.51.100.1".to_string())],
		b"x",
	)
	.await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"wrong password must be refused"
	);
	assert_eq!(
		store.failure_count("ip:198.51.100.1", 0),
		1,
		"the failure was attributed to the real client behind the trusted proxy"
	);
	assert_eq!(
		store.failure_count("ip:10.0.0.1", 0),
		0,
		"the proxy's socket peer must not be counted as the attacker"
	);
}

/// Without a trusted-proxy match, the socket peer is still the answer.
/// The `[api] trusted_proxies = []` default keeps the existing behaviour
/// for a listener that is not behind a reverse proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_basic_login_with_no_trusted_proxies_counts_the_socket_peer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, store) = test_app_with_trusted_and_ban_store(dir.path(), Vec::new());
	let peer: std::net::SocketAddr = "203.0.113.5:54321".parse().expect("peer");
	let (status, _, _) = send_with_peer(
		&app,
		"PUT",
		"/probe.txt",
		peer,
		Some(&format!("alice:{}", fixtures::wrong_password())),
		&[("x-forwarded-for", "198.51.100.1".to_string())],
		b"x",
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(
		store.failure_count("ip:203.0.113.5", 0),
		1,
		"the socket peer is the only thing the listener knows"
	);
	assert_eq!(
		store.failure_count("ip:198.51.100.1", 0),
		0,
		"an empty trusted_proxies list must not let a header claim another address"
	);
}
