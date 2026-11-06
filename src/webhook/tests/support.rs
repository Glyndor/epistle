//! Receivers and configurations the tenant webhook tests share.

/// What a receiver got: the body and the `X-Webhook-Signature` header.
pub(crate) type Received = std::sync::Arc<std::sync::Mutex<Vec<(String, Option<String>)>>>;

/// A receiver that keeps the signature of each request next to its body.
pub(crate) async fn signed_receiver() -> (String, Received) {
	let captured: Received = Received::default();
	async fn handler(
		axum::extract::State(state): axum::extract::State<Received>,
		headers: axum::http::HeaderMap,
		body: String,
	) -> &'static str {
		let signature = headers
			.get("x-webhook-signature")
			.and_then(|value| value.to_str().ok())
			.map(str::to_string);
		state.lock().expect("lock").push((body, signature));
		"ok"
	}
	let app = axum::Router::new()
		.route("/hook", axum::routing::post(handler))
		.with_state(captured.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
	(format!("http://{addr}/hook"), captured)
}

/// Wait until `predicate` holds, or about a second has passed.
pub(crate) async fn settle(predicate: impl Fn() -> bool) {
	for _ in 0..100 {
		if predicate() {
			return;
		}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
}

/// Give a delivery that must not happen the time it would need, so an
/// assertion that nothing arrived is not simply early.
pub(crate) async fn quiet() {
	tokio::time::sleep(std::time::Duration::from_millis(250)).await;
}

/// A configuration with the server-wide `[webhook]` at `default` and two
/// tenants, `a.example` (with the alias `alias-a.example`) and `b.example`,
/// each with the `[tenant.webhook]` it is given. `c.example` belongs to no
/// tenant. A hook is `(url, secret)`.
pub(crate) fn tenant_config(
	default: Option<(&str, &str)>,
	a: Option<(&str, &str)>,
	b: Option<(&str, &str)>,
) -> crate::config::Config {
	let section = |header: &str, hook: Option<(&str, &str)>| match hook {
		Some((url, secret)) => format!(
			"{header}\nurl = \"{url}\"\nsecret = \"{secret}\"\nallow_private_webhooks = true\n"
		),
		None => String::new(),
	};
	let text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"a.example\", \"b.example\", \"c.example\"]\n\
		 [domain_aliases]\n\"alias-a.example\" = \"a.example\"\n\
		 {}\
		 [[tenant]]\nname = \"alpha\"\ndomains = [\"a.example\"]\n{}\
		 [[tenant]]\nname = \"beta\"\ndomains = [\"b.example\"]\n{}",
		section("[webhook]", default),
		section("[tenant.webhook]", a),
		section("[tenant.webhook]", b),
	);
	toml::from_str(&text).expect("the configuration parses")
}

/// The bodies a receiver got.
pub(crate) fn bodies(received: &Received) -> Vec<String> {
	received
		.lock()
		.expect("lock")
		.iter()
		.map(|(body, _)| body.clone())
		.collect()
}
