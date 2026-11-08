use super::harness::{Peer, assert_status, exchange, request, slowloris};

const PATH: &str = "/.well-known/acme-challenge/owned-token";
const ANSWER: &str = "owned-token.fixture-key-authorization";

fn fixture() -> Peer {
	let store = crate::acme::http01::ChallengeStore::new();
	store.set("owned-token", ANSWER);
	let router = crate::acme::http01::router(store);
	Peer::start(|incoming| crate::net::http_serve::serve_on(incoming, router))
}

#[tokio::test]
async fn traversal_and_nul_tokens_are_bounded_4xx() {
	let peer = fixture();
	peer.healthy(peer.connect().await, PATH, ANSWER).await;
	// Raw HTTP targets: URL clients can normalize ../ before sending it.
	for token in [
		"../owned-token",
		"%2e%2e%2fowned-token",
		"owned-token%00",
		"%00owned-token",
	] {
		let path = format!("/.well-known/acme-challenge/{token}");
		let reply = exchange(peer.connect().await, &request(&path, "mail.example.org")).await;
		assert_status(&reply, 404);
		assert!(
			!reply.contains(ANSWER),
			"malformed token disclosed authorization"
		);
		peer.healthy(peer.connect().await, PATH, ANSWER).await;
	}
}

#[tokio::test]
async fn dripping_acme_headers_close_by_deadline() {
	let peer = fixture();
	peer.healthy(peer.connect().await, PATH, ANSWER).await;
	slowloris(peer.connect().await, PATH).await;
	peer.healthy(peer.connect().await, PATH, ANSWER).await;
}
