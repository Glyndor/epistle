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
