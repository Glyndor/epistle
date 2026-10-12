//! Challenge publishing and cleanup around an order, including the failure
//! paths: a challenge record must never outlive the order that needed it.

use super::*;
use crate::acme::challenge::{Dns01, TxtVisibility};
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};
use crate::test_fixtures as fixtures;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

/// Transport replaying a queue of responses per URL and recording every POST.
struct Recorded {
	posts: Mutex<HashMap<String, VecDeque<PostResponse>>>,
	posted: Mutex<Vec<String>>,
}

impl AcmeTransport for Recorded {
	fn get(&self, _url: &str) -> Fut<'_, Vec<u8>> {
		Box::pin(async {
			Ok(br#"{"newNonce":"https://acme.example/new-nonce","newAccount":"https://acme.example/new-acct","newOrder":"https://acme.example/new-order"}"#.to_vec())
		})
	}
	fn new_nonce(&self, _url: &str) -> Fut<'_, String> {
		Box::pin(async { Ok(fixtures::nonce().to_string()) })
	}
	fn post(&self, url: &str, _jws: &str) -> Fut<'_, PostResponse> {
		self.posted.lock().expect("posted").push(url.to_string());
		let mut posts = self.posts.lock().expect("posts");
		let response = posts.get_mut(url).and_then(|queue| {
			if queue.len() > 1 {
				queue.pop_front()
			} else {
				queue.front().cloned()
			}
		});
		Box::pin(
			async move { response.ok_or_else(|| AcmeError::Transport("unscripted url".into())) },
		)
	}
}

fn body(location: Option<&str>, body: &[u8]) -> PostResponse {
	PostResponse {
		nonce: fixtures::nonce().into(),
		location: location.map(str::to_string),
		status: 200,
		body: body.to_vec(),
	}
}

/// A registered client whose single authorization offers `kind` and then
/// reports `final_status` (`valid` or `invalid`).
async fn client_for(kind: &str, final_status: &str) -> AcmeClient<Recorded> {
	let mut posts: HashMap<String, VecDeque<PostResponse>> = HashMap::new();
	posts.insert(
		"https://acme.example/new-acct".into(),
		vec![body(Some("https://acme.example/acct/1"), b"{}")].into(),
	);
	posts.insert(
		"https://acme.example/new-order".into(),
		vec![body(
			Some("https://acme.example/order/7"),
			br#"{"status":"pending","authorizations":["https://acme.example/authz/1"],"finalize":"https://acme.example/finalize/7"}"#,
		)]
		.into(),
	);
	let challenge = serde_json::json!({"status":"pending","identifier":{"type":"dns","value":"mail.example.org"},"challenges":[{"type":kind,"url":"https://acme.example/chal/1","token":fixtures::api_token(),"status":"pending"}]});
	let done = serde_json::json!({"status": final_status, "challenges": []});
	posts.insert(
		"https://acme.example/authz/1".into(),
		vec![
			body(None, &serde_json::to_vec(&challenge).expect("json")),
			body(None, &serde_json::to_vec(&done).expect("json")),
		]
		.into(),
	);
	posts.insert(
		"https://acme.example/chal/1".into(),
		vec![body(None, b"{}")].into(),
	);
	posts.insert(
		"https://acme.example/finalize/7".into(),
		vec![body(None, br#"{"status":"valid","finalize":"https://acme.example/finalize/7","certificate":"https://acme.example/cert/7"}"#)].into(),
	);
	posts.insert(
		"https://acme.example/cert/7".into(),
		vec![body(
			None,
			b"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n",
		)]
		.into(),
	);
	let transport = Recorded {
		posts: Mutex::new(posts),
		posted: Mutex::new(Vec::new()),
	};
	let (key, _) = AccountKey::generate().expect("key");
	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");
	client
}

/// A provider recording each call as `upsert NAME` / `delete NAME`, in order.
#[derive(Default)]
struct Journal {
	calls: Mutex<Vec<String>>,
}

type Op<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> =
	std::pin::Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for Journal {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		self.calls
			.lock()
			.expect("calls")
			.push(format!("upsert {}", record.name));
		Box::pin(async { Ok(()) })
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		self.calls
			.lock()
			.expect("calls")
			.push(format!("delete {}", record.name));
		Box::pin(async { Ok(()) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// Reports a fixed visibility answer and counts how often it was asked.
struct Visibility {
	answer: bool,
	asked: Mutex<u32>,
}

impl TxtVisibility for Visibility {
	fn visible<'a>(
		&'a self,
		_name: &'a str,
		_value: &'a str,
	) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
		*self.asked.lock().expect("asked") += 1;
		let answer = self.answer;
		Box::pin(async move { answer })
	}
}

fn dns01(answer: bool) -> (Arc<Journal>, Arc<Visibility>, Dns01) {
	let provider = Arc::new(Journal::default());
	let visibility = Arc::new(Visibility {
		answer,
		asked: Mutex::new(0),
	});
	let responder = Dns01::new(provider.clone(), visibility.clone())
		.with_bounds(Duration::ZERO, Duration::ZERO);
	(provider, visibility, responder)
}

const DOMAINS: &[&str] = &["mail.example.org"];

fn domains() -> Vec<String> {
	DOMAINS.iter().map(|d| d.to_string()).collect()
}

#[tokio::test]
async fn dns01_record_is_removed_when_validation_fails() {
	let client = client_for("dns-01", "invalid").await;
	let (provider, _, responder) = dns01(true);
	let result = client.obtain_certificate(&domains(), &responder, 3).await;
	assert_eq!(
		result.err().map(|error| error.to_string()).as_deref(),
		Some("protocol error: authorization invalid")
	);
	assert_eq!(
		provider.calls.lock().expect("calls").as_slice(),
		&[
			"upsert _acme-challenge.mail.example.org".to_string(),
			"delete _acme-challenge.mail.example.org".to_string(),
		]
	);
}

#[tokio::test]
async fn dns01_record_is_removed_after_a_successful_order() {
	let client = client_for("dns-01", "valid").await;
	let (provider, visibility, responder) = dns01(true);
	let (chain, _) = client
		.obtain_certificate(&domains(), &responder, 3)
		.await
		.expect("obtain");
	assert!(chain.starts_with("-----BEGIN CERTIFICATE-----"));
	assert_eq!(*visibility.asked.lock().expect("asked"), 1);
	assert_eq!(
		provider.calls.lock().expect("calls").as_slice(),
		&[
			"upsert _acme-challenge.mail.example.org".to_string(),
			"delete _acme-challenge.mail.example.org".to_string(),
		]
	);
}

#[tokio::test]
async fn dns01_never_visible_times_out_without_asking_the_ca() {
	let client = client_for("dns-01", "valid").await;
	let (provider, _, responder) = dns01(false);
	let result = client.obtain_certificate(&domains(), &responder, 3).await;
	assert_eq!(
		result.err().map(|error| error.to_string()).as_deref(),
		Some(
			"protocol error: dns-01: _acme-challenge.mail.example.org TXT not visible on the authoritative servers after 0s"
		)
	);
	// The CA is never told to validate a record it could not see.
	let posted = client.transport.posted.lock().expect("posted").clone();
	assert!(
		!posted
			.iter()
			.any(|url| url == "https://acme.example/chal/1"),
		"challenge was posted: {posted:?}"
	);
	assert_eq!(
		provider.calls.lock().expect("calls").as_slice(),
		&[
			"upsert _acme-challenge.mail.example.org".to_string(),
			"delete _acme-challenge.mail.example.org".to_string(),
		]
	);
}

#[tokio::test]
async fn tls_alpn01_certificate_is_dropped_when_validation_fails() {
	let client = client_for("tls-alpn-01", "invalid").await;
	let store = Arc::new(crate::acme::tlsalpn::AlpnChallengeStore::new());
	let result = client.obtain_certificate(&domains(), &store, 3).await;
	assert_eq!(
		result.err().map(|error| error.to_string()).as_deref(),
		Some("protocol error: authorization invalid")
	);
	assert!(!store.has("mail.example.org"), "challenge cert left behind");
}

#[tokio::test]
async fn http01_token_is_dropped_when_validation_fails() {
	let client = client_for("http-01", "invalid").await;
	let store = crate::acme::http01::ChallengeStore::new();
	let result = client.obtain_certificate(&domains(), &store, 3).await;
	assert!(result.is_err());
	assert!(store.get(fixtures::api_token()).is_none());
}
