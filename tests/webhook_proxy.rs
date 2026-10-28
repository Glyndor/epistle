//! The webhook client and the proxy of the environment.
//!
//! The proxy variables are read when the client is built, and they belong to
//! the whole process, so these checks live in their own test binary: a test
//! that sets `HTTP_PROXY` beside the other tests of another binary would
//! change the client they build.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use epistle::webhook::Webhook;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A peer that plays the proxy of the environment: it takes the
/// connections and answers them as an HTTP server would.
struct ProxyPeer {
	addr: SocketAddr,
	hits: Arc<AtomicUsize>,
	requests: Arc<Mutex<Vec<String>>>,
}

impl ProxyPeer {
	async fn start() -> Self {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind the proxy");
		let addr = listener.local_addr().expect("proxy address");
		let hits = Arc::new(AtomicUsize::new(0));
		let requests = Arc::new(Mutex::new(Vec::new()));
		let counter = hits.clone();
		let lines = requests.clone();
		tokio::spawn(async move {
			while let Ok((mut stream, _)) = listener.accept().await {
				let counter = counter.clone();
				let lines = lines.clone();
				tokio::spawn(async move {
					let mut head = Vec::new();
					while !head.ends_with(b"\r\n\r\n") {
						let mut byte = [0u8; 1];
						match stream.read(&mut byte).await {
							Ok(0) => break,
							Ok(_) => head.push(byte[0]),
							Err(_) => break,
						}
						if head.len() > 8192 {
							break;
						}
					}
					counter.fetch_add(1, Ordering::SeqCst);
					if let Ok(mut lines) = lines.lock() {
						lines.push(String::from_utf8_lossy(&head).to_string());
					}
					let _ = stream
						.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
						.await;
				});
			}
		});
		Self {
			addr,
			hits,
			requests,
		}
	}

	/// The URL the proxy of the environment points at.
	fn url(&self) -> String {
		format!("http://{}/", self.addr)
	}

	/// How many connections the proxy took.
	fn count(&self) -> usize {
		self.hits.load(Ordering::SeqCst)
	}

	/// The first request the proxy read.
	fn first_request(&self) -> String {
		self.requests
			.lock()
			.expect("the requests of the proxy")
			.first()
			.cloned()
			.unwrap_or_default()
	}
}

/// Build a client with the proxy of the environment pointing at `proxy`.
///
/// The variables are read when the client is built, and they belong to the
/// whole process, so they are set for the build and taken back right after.
fn with_proxy<T>(proxy: &str, build: impl FnOnce() -> T) -> T {
	// SAFETY: this binary holds one test, and the variables are read while
	// the client is built.
	unsafe {
		std::env::set_var("HTTP_PROXY", proxy);
		std::env::set_var("http_proxy", proxy);
		std::env::remove_var("NO_PROXY");
		std::env::remove_var("no_proxy");
	}
	let built = build();
	// SAFETY: as above.
	unsafe {
		std::env::remove_var("HTTP_PROXY");
		std::env::remove_var("http_proxy");
	}
	built
}

#[tokio::test]
async fn the_restricted_client_ignores_the_proxy_of_the_environment() {
	let proxy = ProxyPeer::start().await;

	// The control: a webhook that allows private destinations uses the
	// proxy of the environment, so the check below measures the difference
	// and not a proxy that was never in effect.
	let allowed = with_proxy(&proxy.url(), || {
		Webhook::new_allowing_private("http://webhook.invalid/hook", None).expect("client")
	});
	let status = allowed
		.send_test()
		.await
		.expect("the proxy answers the request");
	assert_eq!(status.as_u16(), 204, "{status}");
	assert_eq!(proxy.count(), 1, "the proxy did not take the request");
	let request = proxy.first_request();
	assert!(
		request.starts_with("POST http://webhook.invalid/hook "),
		"the request did not reach the proxy in the proxy form: {request}"
	);

	// The client that refuses private destinations goes to the endpoint
	// directly. The name does not resolve, so the delivery fails, and it
	// fails without the proxy taking anything.
	let restricted = with_proxy(&proxy.url(), || {
		Webhook::new("http://webhook.invalid/hook", None).expect("client")
	});
	let _ = tokio::time::timeout(Duration::from_secs(20), restricted.send_test()).await;
	assert_eq!(
		proxy.count(),
		1,
		"the restricted client went through the proxy of the environment"
	);
}
