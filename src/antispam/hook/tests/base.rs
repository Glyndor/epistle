use super::*;

#[test]
fn parses_known_actions() {
	assert_eq!(
		parse_verdict(br#"{"action":"reject"}"#),
		HookVerdict::Reject
	);
	assert_eq!(
		parse_verdict(br#"{"action":"quarantine"}"#),
		HookVerdict::Quarantine
	);
	assert_eq!(
		parse_verdict(br#"{"action":"junk"}"#),
		HookVerdict::Quarantine
	);
	assert_eq!(
		parse_verdict(br#"{"action":"accept"}"#),
		HookVerdict::Accept
	);
	// Case-insensitive.
	assert_eq!(
		parse_verdict(br#"{"action":"REJECT"}"#),
		HookVerdict::Reject
	);
}

#[test]
fn unknown_or_malformed_fails_open() {
	assert_eq!(
		parse_verdict(br#"{"action":"explode"}"#),
		HookVerdict::Accept
	);
	assert_eq!(parse_verdict(b"not json"), HookVerdict::Accept);
	assert_eq!(parse_verdict(b""), HookVerdict::Accept);
}

struct StubHook(HookVerdict);
impl MailHook for StubHook {
	fn scan(&self, _raw: &[u8]) -> ScanFuture<'_> {
		let verdict = self.0;
		Box::pin(async move { verdict })
	}
}

#[tokio::test]
async fn trait_object_returns_verdict() {
	let hook: Box<dyn MailHook> = Box::new(StubHook(HookVerdict::Quarantine));
	assert_eq!(hook.scan(b"msg").await, HookVerdict::Quarantine);
}

#[tokio::test]
async fn http_hook_posts_and_parses_verdict() {
	// A tiny in-process server stands in for the external scanner.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	let app = axum::Router::new().route(
		"/scan",
		axum::routing::post(|| async { r#"{"action":"quarantine"}"# }),
	);
	tokio::spawn(async move {
		axum::serve(listener, app).await.expect("serve");
	});

	let hook = HttpHook::new(&format!("http://{addr}/scan")).expect("hook");
	assert_eq!(hook.scan(b"raw message").await, HookVerdict::Quarantine);
}

#[tokio::test]
async fn http_hook_fails_open_when_unreachable() {
	// Port 1 on localhost refuses immediately: the hook must accept.
	let hook = HttpHook::new("http://127.0.0.1:1/scan").expect("hook");
	assert_eq!(hook.scan(b"raw message").await, HookVerdict::Accept);
}

#[tokio::test]
async fn http_hook_fails_open_on_an_answer_over_the_cap() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	// A quarantine verdict padded with spaces past the cap: if it were read and
	// parsed it would quarantine, so Accept proves it was dropped at the cap.
	let app = axum::Router::new().route(
		"/scan",
		axum::routing::post(|| async {
			format!(r#"{{"action":"quarantine"}}{}"#, " ".repeat(200 * 1024))
		}),
	);
	tokio::spawn(async move {
		axum::serve(listener, app).await.expect("serve");
	});
	let hook = HttpHook::new(&format!("http://{addr}/scan")).expect("hook");
	assert_eq!(hook.scan(b"raw message").await, HookVerdict::Accept);
}

/// A body that yields a verdict and then fifty chunks of padding, one by one.
struct Padded(usize);

impl futures_core::Stream for Padded {
	type Item = Result<axum::body::Bytes, std::convert::Infallible>;

	fn poll_next(
		mut self: std::pin::Pin<&mut Self>,
		_cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<Self::Item>> {
		let step = self.0;
		self.0 += 1;
		std::task::Poll::Ready(match step {
			0 => Some(Ok(axum::body::Bytes::from_static(
				br#"{"action":"quarantine"}"#,
			))),
			1..=50 => Some(Ok(axum::body::Bytes::from(vec![b' '; 8 * 1024]))),
			_ => None,
		})
	}
}

/// The same padded verdict, sent in chunks with no length: only the cap on what
/// is read, not the length header, can stop it.
#[tokio::test]
async fn http_hook_fails_open_on_a_chunked_answer_over_the_cap() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	let app = axum::Router::new().route(
		"/scan",
		axum::routing::post(|| async { axum::body::Body::from_stream(Padded(0)) }),
	);
	tokio::spawn(async move {
		axum::serve(listener, app).await.expect("serve");
	});
	let hook = HttpHook::new(&format!("http://{addr}/scan")).expect("hook");
	assert_eq!(hook.scan(b"raw message").await, HookVerdict::Accept);
}
