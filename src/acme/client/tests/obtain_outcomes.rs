//! Failed and timed-out authorizations, and the DNS-01 flow.

use super::base::{SequencedTransport, directory_json, ok_body, order_posts, registered_client};
use super::*;
use crate::test_support::fixtures;
use std::collections::HashMap;

#[tokio::test]
async fn obtain_fails_when_authorization_invalid() {
	let authz = vec![
		ok_body(fixtures::nonce(), &serde_json::to_vec(&serde_json::json!({"status":"pending","challenges":[{"type":"http-01","url":"https://acme.example/chal/1","token":fixtures::api_token(),"status":"pending"}]})).expect("challenge JSON")),
		ok_body(fixtures::nonce(), br#"{"status":"invalid","challenges":[]}"#),
	];
	let client = registered_client(order_posts(authz)).await;
	let store = crate::acme::http01::ChallengeStore::new();
	let result = client
		.obtain_certificate(
			&["mail.example.org".to_string()],
			std::sync::Arc::new(store.clone()),
			3,
		)
		.await;
	assert!(result.is_err(), "invalid authorization must abort");
}

#[tokio::test]
async fn obtain_times_out_when_authorization_never_valid() {
	// Authorization stays pending forever: polling exhausts its budget.
	let authz = vec![ok_body(fixtures::nonce(), &serde_json::to_vec(&serde_json::json!({"status":"pending","challenges":[{"type":"http-01","url":"https://acme.example/chal/1","token":fixtures::api_token(),"status":"pending"}]})).expect("challenge JSON"))];
	let client = registered_client(order_posts(authz)).await;
	let store = crate::acme::http01::ChallengeStore::new();
	let result = client
		.obtain_certificate(
			&["mail.example.org".to_string()],
			std::sync::Arc::new(store.clone()),
			2,
		)
		.await;
	assert!(result.is_err(), "perpetual pending must time out");
}

/// Every published TXT value is reported visible at once.
struct AlwaysVisible;

impl crate::acme::challenge::TxtVisibility for AlwaysVisible {
	fn visible<'a>(
		&'a self,
		_name: &'a str,
		_value: &'a str,
	) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
		Box::pin(async { true })
	}
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
			nonce: fixtures::nonce().into(),
			location: Some("https://acme.example/acct/1".into()),
			status: 201,
			body: b"{}".to_vec(),
		}],
	);
	q(
		"https://acme.example/new-order",
		vec![PostResponse {
			nonce: fixtures::nonce().into(),
			location: Some("https://acme.example/order/7".into()),
			status: 201,
			body: br#"{"status":"pending","authorizations":["https://acme.example/authz/1"],"finalize":"https://acme.example/finalize/7"}"#.to_vec(),
		}],
	);
	q(
		"https://acme.example/authz/1",
		vec![
			ok_body(fixtures::nonce(), &serde_json::to_vec(&serde_json::json!({"status":"pending","identifier":{"type":"dns","value":"mail.example.org"},"challenges":[{"type":"dns-01","url":"https://acme.example/chal/1","token":fixtures::api_token(),"status":"pending"}]})).expect("challenge JSON")),
			ok_body(fixtures::nonce(), br#"{"status":"valid","challenges":[]}"#),
		],
	);
	q(
		"https://acme.example/chal/1",
		vec![ok_body(fixtures::nonce(), b"{}")],
	);
	q(
		"https://acme.example/finalize/7",
		vec![ok_body(fixtures::nonce(), br#"{"status":"valid","finalize":"https://acme.example/finalize/7","certificate":"https://acme.example/cert/7"}"#)],
	);
	q(
		"https://acme.example/cert/7",
		vec![ok_body(
			fixtures::nonce(),
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

	let provider = std::sync::Arc::new(RecordingProvider::default());
	let responder =
		crate::acme::challenge::Dns01::new(provider.clone(), std::sync::Arc::new(AlwaysVisible));
	let (chain, key_pem) = client
		.obtain_certificate(
			&["mail.example.org".to_string()],
			std::sync::Arc::new(responder),
			3,
		)
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
