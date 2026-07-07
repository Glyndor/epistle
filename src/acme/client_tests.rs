//! Tests for the ACME client flow.

use super::*;
use std::collections::HashMap;

/// Transport returning canned responses keyed by URL, recording POSTs.
struct ScriptedTransport {
	directory: Vec<u8>,
	posts: Mutex<HashMap<String, PostResponse>>,
}

impl AcmeTransport for ScriptedTransport {
	fn get(&self, _url: &str) -> Fut<'_, Vec<u8>> {
		let body = self.directory.clone();
		Box::pin(async move { Ok(body) })
	}
	fn new_nonce(&self, _url: &str) -> Fut<'_, String> {
		Box::pin(async { Ok("nonce-0".to_string()) })
	}
	fn post(&self, url: &str, _jws: &str) -> Fut<'_, PostResponse> {
		let resp = self
			.posts
			.lock()
			.expect("posts")
			.get(url)
			.cloned()
			.expect("scripted response");
		Box::pin(async move { Ok(resp) })
	}
}

fn directory_json() -> Vec<u8> {
	br#"{
		"newNonce": "https://acme.example/new-nonce",
		"newAccount": "https://acme.example/new-acct",
		"newOrder": "https://acme.example/new-order"
	}"#
	.to_vec()
}

#[tokio::test]
async fn register_then_order_threads_account_and_parses_order() {
	let (key, _) = AccountKey::generate().expect("key");
	let mut posts = HashMap::new();
	posts.insert(
		"https://acme.example/new-acct".to_string(),
		PostResponse {
			nonce: "nonce-1".to_string(),
			location: Some("https://acme.example/acct/42".to_string()),
			status: 201,
			body: b"{}".to_vec(),
		},
	);
	posts.insert(
		"https://acme.example/new-order".to_string(),
		PostResponse {
			nonce: "nonce-2".to_string(),
			location: Some("https://acme.example/order/7".to_string()),
			status: 201,
			body: br#"{"status":"pending","authorizations":["https://acme.example/authz/1"],"finalize":"https://acme.example/finalize/7"}"#.to_vec(),
		},
	);
	let transport = ScriptedTransport {
		directory: directory_json(),
		posts: Mutex::new(posts),
	};

	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	assert!(!client.is_registered());
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");
	assert!(client.is_registered());

	let (order, order_url) = client
		.new_order(&["mail.example.org".to_string()])
		.await
		.expect("order");
	assert_eq!(order.finalize, "https://acme.example/finalize/7");
	assert_eq!(order.authorizations.len(), 1);
	assert_eq!(order_url, "https://acme.example/order/7");
}

/// Transport returning a queue of responses per URL (front popped each call).
struct SequencedTransport {
	directory: Vec<u8>,
	posts: Mutex<HashMap<String, std::collections::VecDeque<PostResponse>>>,
}

impl AcmeTransport for SequencedTransport {
	fn get(&self, _url: &str) -> Fut<'_, Vec<u8>> {
		let body = self.directory.clone();
		Box::pin(async move { Ok(body) })
	}
	fn new_nonce(&self, _url: &str) -> Fut<'_, String> {
		Box::pin(async { Ok("nonce-0".to_string()) })
	}
	fn post(&self, url: &str, _jws: &str) -> Fut<'_, PostResponse> {
		let mut posts = self.posts.lock().expect("posts");
		let queue = posts.get_mut(url).expect("scripted url");
		let resp = if queue.len() > 1 {
			queue.pop_front().expect("front")
		} else {
			queue.front().expect("front").clone()
		};
		Box::pin(async move { Ok(resp) })
	}
}

#[tokio::test]
async fn obtain_certificate_runs_the_full_flow() {
	let (key, _) = AccountKey::generate().expect("key");
	let mut posts: HashMap<String, std::collections::VecDeque<PostResponse>> = HashMap::new();
	let mut q = |url: &str, items: Vec<PostResponse>| {
		posts.insert(url.to_string(), items.into());
	};
	q(
		"https://acme.example/new-acct",
		vec![PostResponse {
			nonce: "n".into(),
			location: Some("https://acme.example/acct/1".into()),
			status: 201,
			body: b"{}".to_vec(),
		}],
	);
	q(
		"https://acme.example/new-order",
		vec![PostResponse {
			nonce: "n".into(),
			location: Some("https://acme.example/order/7".into()),
			status: 201,
			body: br#"{"status":"pending","authorizations":["https://acme.example/authz/1"],"finalize":"https://acme.example/finalize/7"}"#.to_vec(),
		}],
	);
	q(
		"https://acme.example/authz/1",
		vec![
			ok_body("n", br#"{"status":"pending","challenges":[{"type":"http-01","url":"https://acme.example/chal/1","token":"tok","status":"pending"}]}"#),
			ok_body("n", br#"{"status":"valid","challenges":[]}"#),
		],
	);
	q("https://acme.example/chal/1", vec![ok_body("n", b"{}")]);
	q(
		"https://acme.example/finalize/7",
		vec![ok_body("n", br#"{"status":"valid","finalize":"https://acme.example/finalize/7","certificate":"https://acme.example/cert/7"}"#)],
	);
	q(
		"https://acme.example/cert/7",
		vec![ok_body(
			"n",
			b"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n",
		)],
	);

	let transport = SequencedTransport {
		directory: directory_json(),
		posts: Mutex::new(posts),
	};
	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");

	let store = crate::acme::http01::ChallengeStore::new();
	let (chain, key_pem) = client
		.obtain_certificate(&["mail.example.org".to_string()], &store, 3)
		.await
		.expect("obtain");
	assert!(chain.starts_with("-----BEGIN CERTIFICATE-----"));
	assert!(key_pem.contains("PRIVATE KEY"));
	// Challenge tokens are cleaned up afterward.
	assert!(store.get("tok").is_none());
}

fn ok_body(nonce: &str, body: &[u8]) -> PostResponse {
	PostResponse {
		nonce: nonce.to_string(),
		location: None,
		status: 200,
		body: body.to_vec(),
	}
}

#[tokio::test]
async fn challenge_finalize_and_certificate_flow() {
	let (key, _) = AccountKey::generate().expect("key");
	let mut posts = HashMap::new();
	posts.insert(
		"https://acme.example/authz/1".to_string(),
		ok_body(
			"n1",
			br#"{"status":"pending","challenges":[{"type":"http-01","url":"https://acme.example/chal/1","token":"tok","status":"pending"}]}"#,
		),
	);
	posts.insert(
		"https://acme.example/chal/1".to_string(),
		ok_body("n2", b"{}"),
	);
	posts.insert(
		"https://acme.example/finalize/7".to_string(),
		ok_body(
			"n3",
			br#"{"status":"processing","finalize":"https://acme.example/finalize/7"}"#,
		),
	);
	posts.insert(
		"https://acme.example/order/7".to_string(),
		ok_body("n4", br#"{"status":"valid","finalize":"https://acme.example/finalize/7","certificate":"https://acme.example/cert/7"}"#),
	);
	posts.insert(
		"https://acme.example/cert/7".to_string(),
		ok_body(
			"n5",
			b"-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n",
		),
	);
	let transport = ScriptedTransport {
		directory: directory_json(),
		posts: Mutex::new(posts),
	};
	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");

	let authz = client
		.authorization("https://acme.example/authz/1")
		.await
		.expect("authz");
	let challenge = authz.challenge("http-01").expect("http-01");
	assert_eq!(challenge.token, "tok");

	client
		.respond_challenge(&challenge.url)
		.await
		.expect("respond");
	client
		.finalize("https://acme.example/finalize/7", "Q1NS")
		.await
		.expect("finalize");

	let order = client
		.order_status("https://acme.example/order/7")
		.await
		.expect("status");
	assert_eq!(order.status, protocol::OrderStatus::Valid);
	let cert_url = order.certificate.expect("cert url");
	let pem = client.download_certificate(&cert_url).await.expect("cert");
	assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
}

/// Build the account + order posts shared by the failure-path tests, with the
/// authorization queue supplied by the caller.
fn order_posts(
	authz: Vec<PostResponse>,
) -> HashMap<String, std::collections::VecDeque<PostResponse>> {
	let mut posts: HashMap<String, std::collections::VecDeque<PostResponse>> = HashMap::new();
	posts.insert(
		"https://acme.example/new-acct".to_string(),
		vec![PostResponse {
			nonce: "n".into(),
			location: Some("https://acme.example/acct/1".into()),
			status: 201,
			body: b"{}".to_vec(),
		}]
		.into(),
	);
	posts.insert(
		"https://acme.example/new-order".to_string(),
		vec![PostResponse {
			nonce: "n".into(),
			location: Some("https://acme.example/order/7".into()),
			status: 201,
			body: br#"{"status":"pending","authorizations":["https://acme.example/authz/1"],"finalize":"https://acme.example/finalize/7"}"#.to_vec(),
		}]
		.into(),
	);
	posts.insert(
		"https://acme.example/chal/1".to_string(),
		vec![ok_body("n", b"{}")].into(),
	);
	posts.insert("https://acme.example/authz/1".to_string(), authz.into());
	posts
}

async fn registered_client(
	posts: HashMap<String, std::collections::VecDeque<PostResponse>>,
) -> AcmeClient<SequencedTransport> {
	let (key, _) = AccountKey::generate().expect("key");
	let transport = SequencedTransport {
		directory: directory_json(),
		posts: Mutex::new(posts),
	};
	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");
	client
}

#[tokio::test]
async fn obtain_fails_when_authorization_invalid() {
	let authz = vec![
		ok_body("n", br#"{"status":"pending","challenges":[{"type":"http-01","url":"https://acme.example/chal/1","token":"tok","status":"pending"}]}"#),
		ok_body("n", br#"{"status":"invalid","challenges":[]}"#),
	];
	let client = registered_client(order_posts(authz)).await;
	let store = crate::acme::http01::ChallengeStore::new();
	let result = client
		.obtain_certificate(&["mail.example.org".to_string()], &store, 3)
		.await;
	assert!(result.is_err(), "invalid authorization must abort");
}

#[tokio::test]
async fn obtain_times_out_when_authorization_never_valid() {
	// Authorization stays pending forever: polling exhausts its budget.
	let authz = vec![ok_body("n", br#"{"status":"pending","challenges":[{"type":"http-01","url":"https://acme.example/chal/1","token":"tok","status":"pending"}]}"#)];
	let client = registered_client(order_posts(authz)).await;
	let store = crate::acme::http01::ChallengeStore::new();
	let result = client
		.obtain_certificate(&["mail.example.org".to_string()], &store, 2)
		.await;
	assert!(result.is_err(), "perpetual pending must time out");
}

/// An in-memory DnsProvider that records upserts and deletes.
#[derive(Default)]
struct RecordingProvider {
	upserts: Mutex<Vec<crate::dns::provider::DnsRecord>>,
	deletes: Mutex<Vec<String>>,
}

impl crate::dns::provider::DnsProvider for RecordingProvider {
	fn upsert(
		&self,
		_zone: &str,
		record: crate::dns::provider::DnsRecord,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<(), crate::dns::provider::ProviderError>> + Send + '_>,
	> {
		self.upserts.lock().unwrap().push(record);
		Box::pin(async { Ok(()) })
	}
	fn delete(
		&self,
		_zone: &str,
		record: crate::dns::provider::DnsRecord,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<(), crate::dns::provider::ProviderError>> + Send + '_>,
	> {
		self.deletes.lock().unwrap().push(record.name);
		Box::pin(async { Ok(()) })
	}
	fn list(
		&self,
		_zone: &str,
	) -> std::pin::Pin<
		Box<
			dyn Future<
					Output = Result<
						Vec<crate::dns::provider::DnsRecord>,
						crate::dns::provider::ProviderError,
					>,
				> + Send
				+ '_,
		>,
	> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn obtain_certificate_dns01_publishes_and_cleans_up() {
	let (key, _) = AccountKey::generate().expect("key");
	let mut posts: HashMap<String, std::collections::VecDeque<PostResponse>> = HashMap::new();
	let mut q = |url: &str, items: Vec<PostResponse>| {
		posts.insert(url.to_string(), items.into());
	};
	q(
		"https://acme.example/new-acct",
		vec![PostResponse {
			nonce: "n".into(),
			location: Some("https://acme.example/acct/1".into()),
			status: 201,
			body: b"{}".to_vec(),
		}],
	);
	q(
		"https://acme.example/new-order",
		vec![PostResponse {
			nonce: "n".into(),
			location: Some("https://acme.example/order/7".into()),
			status: 201,
			body: br#"{"status":"pending","authorizations":["https://acme.example/authz/1"],"finalize":"https://acme.example/finalize/7"}"#.to_vec(),
		}],
	);
	q(
		"https://acme.example/authz/1",
		vec![
			ok_body("n", br#"{"status":"pending","identifier":{"type":"dns","value":"mail.example.org"},"challenges":[{"type":"dns-01","url":"https://acme.example/chal/1","token":"tok","status":"pending"}]}"#),
			ok_body("n", br#"{"status":"valid","challenges":[]}"#),
		],
	);
	q("https://acme.example/chal/1", vec![ok_body("n", b"{}")]);
	q(
		"https://acme.example/finalize/7",
		vec![ok_body("n", br#"{"status":"valid","finalize":"https://acme.example/finalize/7","certificate":"https://acme.example/cert/7"}"#)],
	);
	q(
		"https://acme.example/cert/7",
		vec![ok_body(
			"n",
			b"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n",
		)],
	);

	let transport = SequencedTransport {
		directory: directory_json(),
		posts: Mutex::new(posts),
	};
	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");

	let provider = RecordingProvider::default();
	let (chain, key_pem) = client
		.obtain_certificate_dns01(&["mail.example.org".to_string()], &provider, 3)
		.await
		.expect("obtain");
	assert!(chain.starts_with("-----BEGIN CERTIFICATE-----"));
	assert!(key_pem.contains("PRIVATE KEY"));

	// The challenge record was published at _acme-challenge and then removed.
	let upserts = provider.upserts.lock().unwrap();
	assert_eq!(upserts.len(), 1);
	assert_eq!(upserts[0].name, "_acme-challenge.mail.example.org");
	assert_eq!(
		provider.deletes.lock().unwrap().as_slice(),
		&["_acme-challenge.mail.example.org".to_string()]
	);
}
