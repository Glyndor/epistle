//! A local HTTP receiver that webhook tests point at.

/// Start the HTTP receiver shared by webhook tests.
pub(crate) async fn webhook_receiver() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
	let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
	async fn handler(
		axum::extract::State(state): axum::extract::State<
			std::sync::Arc<std::sync::Mutex<Vec<String>>>,
		>,
		body: String,
	) -> &'static str {
		state.lock().expect("lock").push(body);
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
