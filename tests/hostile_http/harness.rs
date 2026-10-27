//! Isolated accounts, bounded requests, and the production HTTP/1 listener.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use epistle::api::api_keys::sha256_hash;
use epistle::api::{ApiKey, ApiKeyStore, ApiState};
use epistle::directory_store::AccountStore;
use epistle::storage::FsSpool;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tower::ServiceExt;

pub const ADMIN: &str = "hostile-http-admin-fixture";
pub const ALICE: &str = "hostile-http-alice-fixture";
pub const PASSWORD: &str = "Hostile-http-fixture-42!";
pub const UPLOAD_LIMIT: usize = 64 * 1024;
pub const DEADLINE: Duration = Duration::from_secs(15);
const RESPONSE_LIMIT: usize = 12 * 1024 * 1024;

static PASSWORD_HASH: LazyLock<String> =
	LazyLock::new(|| epistle::smtp::auth::hash_password(PASSWORD).expect("fixture password hash"));

pub struct Harness {
	pub api: Router,
	pub dav: Router,
	_dir: tempfile::TempDir,
}

impl Harness {
	pub fn new() -> Self {
		let dir = tempfile::Builder::new()
			.prefix(".http-fixture-")
			.tempdir_in("tests/hostile_http")
			.expect("fixture directory inside worktree");
		let domains = vec!["example.test".to_string()];
		let accounts = ["alice", "bob"].map(|name| epistle::config::Account {
			display_name: None,
			name: name.to_string(),
			addresses: vec![format!("{name}@example.test")],
			password_hash: Some(PASSWORD_HASH.clone()),
			catch_all: Vec::new(),
			quota_bytes: None,
			forward: Vec::new(),
			forward_keep_local: true,
			allowed_protocols: None,
		});
		let store = Arc::new(
			AccountStore::open(
				dir.path(),
				domains.clone(),
				Default::default(),
				accounts.to_vec(),
			)
			.expect("account store"),
		);
		let mut keys = ApiKeyStore::open(dir.path()).expect("key store");
		keys.add(ApiKey {
			label: "alice".into(),
			hash: sha256_hash(ALICE),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".into(), "write".into(), "send".into()],
			domains: Vec::new(),
			account: Some("alice".into()),
		})
		.expect("account-bound key");
		drop(keys);
		for name in ["alice", "bob"] {
			for child in ["dav", "new", "cur", "tmp"] {
				std::fs::create_dir_all(dir.path().join("accounts").join(name).join(child))
					.expect("account tree");
			}
		}
		let state = ApiState::new(
			&sha256_hash(ADMIN),
			dir.path().to_path_buf(),
			domains,
			store.clone(),
			FsSpool::open(dir.path()).expect("spool"),
		)
		.with_directory(store.handle())
		.with_max_message_size(UPLOAD_LIMIT);
		let api = epistle::api::router(state);
		let dav = epistle::webdav::router(store.handle(), dir.path().to_path_buf());
		Self {
			api,
			dav,
			_dir: dir,
		}
	}

	pub fn root(&self) -> &Path {
		self._dir.path()
	}

	pub fn dav_root(&self, account: &str) -> PathBuf {
		self.root().join("accounts").join(account).join("dav")
	}

	pub async fn healthy_api(&self) {
		let reply = call(
			&self.api,
			api_request("GET", "/api/v1/accounts", ADMIN, Body::empty()),
		)
		.await;
		assert_eq!(reply.status, StatusCode::OK);
		assert_eq!(
			reply.json()["accounts"].as_array().expect("accounts").len(),
			2
		);
		let reply = self
			.jmap(json!([["Core/echo", {"alive": true}, "health"]]))
			.await;
		assert_eq!(reply.status, StatusCode::OK);
		assert_eq!(
			reply.json()["methodResponses"][0],
			json!(["Core/echo", {"alive": true}, "health"])
		);
	}

	pub async fn healthy_dav(&self) {
		let reply = call(
			&self.dav,
			dav_request("PUT", "/health.txt", Body::from("alive")),
		)
		.await;
		assert!(matches!(
			reply.status,
			StatusCode::CREATED | StatusCode::NO_CONTENT
		));
		let reply = call(&self.dav, dav_request("GET", "/health.txt", Body::empty())).await;
		assert_eq!(reply.status, StatusCode::OK);
		assert_eq!(reply.body, b"alive");
	}

	pub async fn jmap(&self, calls: Value) -> Reply {
		call(
			&self.api,
			api_request(
				"POST",
				"/jmap/api",
				ALICE,
				Body::from(json!({"methodCalls": calls}).to_string()),
			),
		)
		.await
	}
}

pub struct Reply {
	pub status: StatusCode,
	pub headers: HeaderMap,
	pub body: Vec<u8>,
}

impl Reply {
	pub fn json(&self) -> Value {
		serde_json::from_slice(&self.body).expect("JSON response")
	}
}

pub fn api_request(method: &str, path: &str, token: &str, body: Body) -> Request<Body> {
	Request::builder()
		.method(method)
		.uri(path)
		.header("authorization", format!("Bearer {token}"))
		.header("content-type", "application/json")
		.extension(ConnectInfo(
			"192.0.2.10:1234".parse::<SocketAddr>().expect("peer"),
		))
		.body(body)
		.expect("API request")
}

pub fn dav_request(method: &str, path: &str, body: Body) -> Request<Body> {
	use base64::Engine;
	let credentials = base64::engine::general_purpose::STANDARD.encode(format!("alice:{PASSWORD}"));
	Request::builder()
		.method(method)
		.uri(path)
		.header("authorization", format!("Basic {credentials}"))
		.body(body)
		.expect("DAV request")
}

pub async fn call(app: &Router, request: Request<Body>) -> Reply {
	timeout(DEADLINE, async {
		let response = app.clone().oneshot(request).await.expect("router response");
		let status = response.status();
		let headers = response.headers().clone();
		let body = to_bytes(response.into_body(), RESPONSE_LIMIT)
			.await
			.expect("bounded response")
			.to_vec();
		Reply {
			status,
			headers,
			body,
		}
	})
	.await
	.expect("router response deadline")
}

/// An unknown-length stream, generated in chunks rather than one large allocation.
pub fn repeated_body(size: usize) -> Body {
	struct Chunks(usize);
	impl futures_core::Stream for Chunks {
		type Item = Result<axum::body::Bytes, std::io::Error>;
		fn poll_next(
			mut self: std::pin::Pin<&mut Self>,
			_cx: &mut std::task::Context<'_>,
		) -> std::task::Poll<Option<Self::Item>> {
			let n = self.0.min(64 * 1024);
			self.0 -= n;
			std::task::Poll::Ready((n != 0).then(|| Ok(axum::body::Bytes::from(vec![b'x'; n]))))
		}
	}
	Body::from_stream(Chunks(size))
}

struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

pub struct Wire {
	pub addr: SocketAddr,
	_task: AbortOnDrop,
}

impl Wire {
	pub async fn start(app: Router) -> Self {
		let listener = TcpListener::bind("127.0.0.1:0")
			.await
			.expect("loopback bind");
		let addr = listener.local_addr().expect("listener address");
		let task = tokio::spawn(epistle::net::http_serve::serve(listener, app));
		Self {
			addr,
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	/// Send a raw request, optionally half-close to expose a truncated body.
	pub async fn exchange(&self, request: &[u8], half_close: bool) -> Vec<u8> {
		timeout(DEADLINE, async {
			let mut stream = TcpStream::connect(self.addr).await.expect("connect HTTP");
			// A parser may close before an oversized head has finished writing.
			if let Err(error) = stream.write_all(request).await {
				assert!(matches!(
					error.kind(),
					std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
				));
			}
			if half_close {
				let _ = stream.shutdown().await;
			}
			let mut response = Vec::new();
			let mut chunk = [0; 4096];
			loop {
				match stream.read(&mut chunk).await {
					Ok(0) => break,
					Ok(n) => response.extend_from_slice(&chunk[..n]),
					Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
					Err(error) => panic!("HTTP read: {error}"),
				}
				assert!(response.len() <= RESPONSE_LIMIT, "unbounded wire response");
			}
			response
		})
		.await
		.expect("wire exchange deadline")
	}

	pub async fn healthy(&self) {
		let request = format!(
			"GET /api/v1/accounts HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ADMIN}\r\nConnection: close\r\n\r\n"
		);
		let bytes = self.exchange(request.as_bytes(), false).await;
		assert!(
			bytes.starts_with(b"HTTP/1.1 200 OK\r\n"),
			"{}",
			String::from_utf8_lossy(&bytes)
		);
		assert!(String::from_utf8_lossy(&bytes).contains("alice"));
	}
}
