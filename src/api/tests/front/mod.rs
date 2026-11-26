//! The core side of the channel to the HTTP fronts: the client address comes
//! from `X-Epistle-Peer` on a front socket and from nowhere else, and a socket
//! serves the routes of its own surface.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use super::base::{TOKEN, test_state};
use crate::api::api_keys::{ApiKey, sha256_hash};
use crate::api::{Surface, Surfaces, router_for, router_for_front};

const SECRET: &str = "pinned-secret";

/// A router for `surfaces` over a state that has one key, pinned to
/// `192.0.2.0/24` and holding `manage:read`; `front` picks the socket router.
fn app(dir: &std::path::Path, surfaces: &[Surface], front: bool) -> Router {
	let mut store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	store
		.add(ApiKey {
			label: "pinned".to_string(),
			hash: sha256_hash(SECRET),
			expires_at: None,
			ip_cidr: Some("192.0.2.0/24".to_string()),
			scopes: vec!["manage:read".to_string()],
			grants: Vec::new(),
			domains: Vec::new(),
			account: None,
			auto_submitted: false,
		})
		.expect("add key");
	drop(store);
	let state = test_state(dir, 0);
	let surfaces = Surfaces::only(surfaces);
	if front {
		router_for_front(state, &surfaces)
	} else {
		router_for(state, &surfaces)
	}
}

/// `GET path` with `secret`, the `X-Epistle-Peer` values given, and the TCP
/// peer `tcp` when there is one.
async fn get(
	app: &Router,
	path: &str,
	secret: &str,
	peers: &[&str],
	tcp: Option<&str>,
) -> StatusCode {
	let mut builder = Request::builder()
		.method("GET")
		.uri(path)
		.header("authorization", format!("Bearer {secret}"));
	for peer in peers {
		builder = builder.header("x-epistle-peer", *peer);
	}
	let mut request = builder.body(axum::body::Body::empty()).expect("request");
	if let Some(tcp) = tcp {
		let peer: SocketAddr = tcp.parse().expect("peer");
		request.extensions_mut().insert(ConnectInfo(peer));
	}
	app.clone()
		.oneshot(request)
		.await
		.expect("response")
		.status()
}

#[tokio::test]
async fn peer_header_feeds_ip_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path(), &[Surface::Manage], true);
	let inside = get(&app, "/api/v1/status", SECRET, &["192.0.2.7"], None).await;
	assert_eq!(inside, StatusCode::OK);
	let outside = get(&app, "/api/v1/status", SECRET, &["198.51.100.7"], None).await;
	assert_eq!(outside, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn socket_without_peer_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path(), &[Surface::Manage], true);
	let status = get(&app, "/api/v1/status", SECRET, &[], None).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	let status = get(&app, "/healthz", SECRET, &[], None).await;
	assert_eq!(
		status,
		StatusCode::BAD_REQUEST,
		"not even the liveness probe"
	);
}

#[tokio::test]
async fn repeated_or_unreadable_peer_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path(), &[Surface::Manage], true);
	for peers in [
		&["192.0.2.7", "192.0.2.8"][..],
		&["not an address"][..],
		&["192.0.2.7:443"][..],
		&[""][..],
	] {
		let status = get(&app, "/api/v1/status", SECRET, peers, None).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{peers:?}");
	}
}

#[tokio::test]
async fn tcp_ignores_peer_header() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path(), &[Surface::Manage], false);
	// The control: the address the socket really has is inside the pin.
	let status = get(&app, "/api/v1/status", SECRET, &[], Some("192.0.2.7:4000")).await;
	assert_eq!(status, StatusCode::OK);
	// A client outside the pin cannot say it is inside.
	let status = get(
		&app,
		"/api/v1/status",
		SECRET,
		&["192.0.2.7"],
		Some("198.51.100.7:4000"),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn manage_socket_has_no_jmap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path(), &[Surface::Manage], true);
	let status = get(&app, "/jmap/session", TOKEN.as_str(), &["192.0.2.7"], None).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let status = get(&app, "/api/v1/status", TOKEN.as_str(), &["192.0.2.7"], None).await;
	assert_eq!(status, StatusCode::OK, "its own surface answers");
}

#[tokio::test]
async fn trusted_proxies_apply_to_the_forwarded_peer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = crate::api::ApiKeyStore::open(dir.path()).expect("open");
	store
		.add(ApiKey {
			label: "behind".to_string(),
			hash: sha256_hash("behind-secret"),
			expires_at: None,
			ip_cidr: Some("198.51.100.0/24".to_string()),
			scopes: vec!["manage:read".to_string()],
			grants: Vec::new(),
			domains: Vec::new(),
			account: None,
			auto_submitted: false,
		})
		.expect("add");
	drop(store);
	let proxies = vec![crate::cidr::Cidr::parse("192.0.2.0/24").expect("cidr")];
	let state = test_state(dir.path(), 0).with_trusted_proxies(proxies);
	let app = router_for_front(state, &Surfaces::only(&[Surface::Manage]));
	let forwarded = |peer: &'static str, client: &'static str| {
		let app = app.clone();
		async move {
			let request = Request::builder()
				.uri("/api/v1/status")
				.header("authorization", "Bearer behind-secret")
				.header("x-epistle-peer", peer)
				.header("x-forwarded-for", client)
				.body(axum::body::Body::empty())
				.expect("request");
			app.oneshot(request).await.expect("response").status()
		}
	};
	// A TLS proxy in front of the front: its address is the peer, and it names
	// the client.
	assert_eq!(forwarded("192.0.2.7", "198.51.100.9").await, StatusCode::OK);
	// A peer that is no proxy cannot name another client.
	assert_eq!(
		forwarded("203.0.113.7", "198.51.100.9").await,
		StatusCode::UNAUTHORIZED
	);
}

#[test]
fn the_socket_of_a_front_is_in_a_directory_of_its_own() {
	use crate::api::front_socket::{dir, path};
	use crate::config::ListenerKind;
	let data = std::path::Path::new("/var/lib/glyndor/epistle/data");
	assert_eq!(
		path(data, ListenerKind::Jmap),
		std::path::Path::new("/var/lib/glyndor/epistle/fronts/jmap/core.sock")
	);
	assert_ne!(dir(data, ListenerKind::Api), dir(data, ListenerKind::Scim));
}

/// Over a real Unix socket, through the code `serve --fronts` runs: the
/// connection reports no peer, the front's header is the address, and a second
/// bind over a stale socket works.
#[tokio::test]
async fn a_unix_socket_serves_a_front_request() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let dir = tempfile::tempdir().expect("tempdir");
	use std::os::unix::fs::DirBuilderExt;
	std::fs::DirBuilder::new()
		.mode(0o700)
		.create(dir.path().join("fronts"))
		.expect("fronts");
	let socket = dir.path().join("fronts").join("api").join("core.sock");
	drop(crate::net::unix_socket::bind(&socket).expect("a first bind leaves a stale socket"));
	let listener = crate::net::unix_socket::bind(&socket).expect("a stale socket is replaced");
	let app = app(dir.path(), &[Surface::Manage], true);
	let server = tokio::spawn(crate::net::http_serve::serve_on_with(
		crate::net::accept::UnixAccept(listener),
		app,
		crate::net::http_serve::Limits {
			connections: 8,
			per_ip: 8,
		},
	));
	let mut stream = tokio::net::UnixStream::connect(&socket)
		.await
		.expect("connect");
	let request = format!(
		"GET /api/v1/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\
		 X-Epistle-Peer: 192.0.2.7\r\nConnection: close\r\n\r\n"
	);
	stream.write_all(request.as_bytes()).await.expect("write");
	let mut answer = String::new();
	stream.read_to_string(&mut answer).await.expect("read");
	assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
	let mut stream = tokio::net::UnixStream::connect(&socket)
		.await
		.expect("connect");
	stream
		.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		.await
		.expect("write");
	let mut answer = String::new();
	stream.read_to_string(&mut answer).await.expect("read");
	assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
	server.abort();
}
