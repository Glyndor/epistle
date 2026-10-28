use super::*;

#[test]
fn store_set_get_remove() {
	let store = ChallengeStore::new();
	assert!(store.get("tok").is_none());
	store.set("tok", "tok.thumb");
	assert_eq!(store.get("tok").as_deref(), Some("tok.thumb"));
	store.remove("tok");
	assert!(store.get("tok").is_none());
}

#[tokio::test]
async fn serves_published_token_and_404s_others() {
	let store = ChallengeStore::new();
	store.set("known", "known.auth");

	let (status, body) = serve(State(store.clone()), Path("known".to_string())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, "known.auth");

	let (status, body) = serve(State(store), Path("missing".to_string())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(body.is_empty());
}

#[tokio::test]
async fn router_serves_challenge_over_http() {
	let store = ChallengeStore::new();
	store.set("tok", "tok.thumb");
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		axum::serve(listener, router(store)).await.expect("serve");
	});

	let url = format!("http://{addr}/.well-known/acme-challenge/tok");
	let response = reqwest::get(&url).await.expect("get");
	assert_eq!(response.status(), 200);
	assert_eq!(response.text().await.expect("body"), "tok.thumb");
}
