//! The URLs the ACME client may talk to: what it refuses before sending
//! anything, and what keeps working for a local CA.
//!
//! The CA chooses the URLs of its resources. A hostile CA — or whoever
//! takes its place in the path — can point them at the cloud metadata
//! address or at a service on the operator's LAN, and the client would
//! POST there a JWS signed with the account key. These tests walk the
//! places a CA URL can come from and check that nothing is sent to a
//! destination the policy refuses.

use super::*;
use crate::test_support::fixtures;
use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

/// What a transport was asked for, and what it answered.
#[derive(Clone, Default)]
struct Recorded {
	/// Every URL the transport was asked for.
	asked: Arc<Mutex<Vec<String>>>,
	/// Every signed request the transport was given.
	signed: Arc<Mutex<Vec<String>>>,
	/// The answers, keyed by URL. A URL with several answers gives the
	/// first one to the first request and the last one to the rest.
	answers: Arc<Mutex<HashMap<String, Vec<PostResponse>>>>,
}

/// A transport that records what it is asked for and answers with what the
/// test scripted.
struct RecordingTransport {
	directory: Vec<u8>,
	recorded: Recorded,
}

impl RecordingTransport {
	fn new(directory: &str) -> (Self, Recorded) {
		let recorded = Recorded::default();
		let transport = RecordingTransport {
			directory: directory.as_bytes().to_vec(),
			recorded: recorded.clone(),
		};
		(transport, recorded)
	}

	/// The answers the transport will give.
	fn answers(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<PostResponse>>> {
		self.recorded.answers.lock().expect("answers")
	}
}

/// The URLs the transport was asked for.
fn asked(recorded: &Recorded) -> Vec<String> {
	recorded.asked.lock().expect("asked").clone()
}

/// The signed requests the transport was given.
fn signed(recorded: &Recorded) -> Vec<String> {
	recorded.signed.lock().expect("signed").clone()
}

impl AcmeTransport for RecordingTransport {
	fn get(&self, url: &str) -> Fut<'_, Vec<u8>> {
		self.recorded
			.asked
			.lock()
			.expect("asked")
			.push(url.to_string());
		let body = self.directory.clone();
		Box::pin(async move { Ok(body) })
	}

	fn new_nonce(&self, url: &str) -> Fut<'_, String> {
		self.recorded
			.asked
			.lock()
			.expect("asked")
			.push(url.to_string());
		Box::pin(async { Ok(fixtures::nonce().to_string()) })
	}

	fn post(&self, url: &str, jws: &str) -> Fut<'_, PostResponse> {
		self.recorded
			.asked
			.lock()
			.expect("asked")
			.push(url.to_string());
		self.recorded
			.signed
			.lock()
			.expect("signed")
			.push(jws.to_string());
		let answer = {
			let mut answers = self.recorded.answers.lock().expect("answers");
			answers.get_mut(url).and_then(|queue| {
				if queue.len() > 1 {
					Some(queue.remove(0))
				} else {
					queue.first().cloned()
				}
			})
		};
		let url = url.to_string();
		Box::pin(async move {
			answer.ok_or_else(|| AcmeError::Transport(format!("no scripted answer for {url}")))
		})
	}
}

/// A directory that names the CA's resources on a public host.
const DIRECTORY: &str = r#"{
	"newNonce": "https://acme.example/new-nonce",
	"newAccount": "https://acme.example/new-acct",
	"newOrder": "https://acme.example/new-order"
}"#;

/// The answer of a CA that created a resource.
fn created(location: &str, body: &str) -> PostResponse {
	PostResponse {
		nonce: fixtures::nonce().to_string(),
		location: Some(location.to_string()),
		status: 201,
		body: body.as_bytes().to_vec(),
	}
}

#[tokio::test]
async fn a_hostile_directory_is_refused_before_any_request_goes_to_it() {
	// The directory points `newOrder` at the cloud metadata address. The
	// client must stop there: no request, and no signed one, goes to it.
	let (key, _) = AccountKey::generate().expect("key");
	let (transport, recorded) = RecordingTransport::new(
		r#"{
			"newNonce": "https://acme.example/new-nonce",
			"newAccount": "https://acme.example/new-acct",
			"newOrder": "https://169.254.169.254/new-order"
		}"#,
	);

	let error = match AcmeClient::connect(transport, key, "https://acme.example/dir").await {
		Ok(_) => panic!("a hostile directory must be refused"),
		Err(error) => error,
	};
	let message = error.to_string();
	assert!(
		message.contains("169.254.169.254"),
		"the refused URL must be named: {message}"
	);
	assert!(
		message.contains("link-local"),
		"the reason must be named: {message}"
	);
	assert_eq!(
		asked(&recorded),
		vec!["https://acme.example/dir".to_string()],
		"only the directory the operator configured may be asked for"
	);
	assert!(
		signed(&recorded).is_empty(),
		"nothing signed may have been sent"
	);
}

#[tokio::test]
async fn a_plain_http_url_from_an_https_directory_is_refused() {
	let (key, _) = AccountKey::generate().expect("key");
	let (transport, recorded) = RecordingTransport::new(
		r#"{
			"newNonce": "https://acme.example/new-nonce",
			"newAccount": "https://acme.example/new-acct",
			"newOrder": "http://acme.example/new-order"
		}"#,
	);

	let error = match AcmeClient::connect(transport, key, "https://acme.example/dir").await {
		Ok(_) => panic!("a plain http URL must be refused"),
		Err(error) => error,
	};
	let message = error.to_string();
	assert!(
		message.contains("http://acme.example/new-order"),
		"the refused URL must be named: {message}"
	);
	assert_eq!(
		asked(&recorded),
		vec!["https://acme.example/dir".to_string()],
		"the CA's plain http URL must not be asked for"
	);
}

#[tokio::test]
async fn a_hostile_order_url_is_refused_before_it_is_posted_to() {
	// The order names an authorization on the metadata address. The client
	// must refuse it before it POSTs there with the account key.
	let (key, _) = AccountKey::generate().expect("key");
	let (transport, recorded) = RecordingTransport::new(DIRECTORY);
	transport.answers().insert(
		"https://acme.example/new-acct".to_string(),
		vec![created("https://acme.example/acct/1", "{}")],
	);
	transport.answers().insert(
		"https://acme.example/new-order".to_string(),
		vec![created(
			"https://acme.example/order/7",
			r#"{"status":"pending","authorizations":["https://169.254.169.254/authz/1"],"finalize":"https://acme.example/finalize/7"}"#,
		)],
	);

	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");

	let error = client
		.new_order(&["mail.example.org".to_string()])
		.await
		.expect_err("a hostile order URL must be refused");
	let message = error.to_string();
	assert!(
		message.contains("169.254.169.254"),
		"the refused URL must be named: {message}"
	);
	assert!(
		!asked(&recorded)
			.iter()
			.any(|url| url.contains("169.254.169.254")),
		"the hostile URL must never be asked for: {:?}",
		asked(&recorded)
	);
}

#[tokio::test]
async fn a_hostile_account_location_is_refused() {
	// The account URL becomes the `kid` of every later request, so a
	// hostile one is refused before it is held.
	let (key, _) = AccountKey::generate().expect("key");
	let (transport, recorded) = RecordingTransport::new(DIRECTORY);
	transport.answers().insert(
		"https://acme.example/new-acct".to_string(),
		vec![created("https://169.254.169.254/acct/1", "{}")],
	);

	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	let error = client
		.register(&["admin@example.org".to_string()])
		.await
		.expect_err("a hostile account URL must be refused");
	let message = error.to_string();
	assert!(
		message.contains("169.254.169.254"),
		"the refused URL must be named: {message}"
	);
	assert!(
		!client.is_registered(),
		"no account may be held when its URL was refused"
	);
	assert!(
		!asked(&recorded)
			.iter()
			.any(|url| url.contains("169.254.169.254")),
		"the hostile URL must never be asked for: {:?}",
		asked(&recorded)
	);
}

#[tokio::test]
async fn a_refusal_names_the_url_without_repeating_the_account_key() {
	// The refusal names the URL and the reason. The account key and the
	// signed requests that prove its possession stay out of it.
	let (key, pkcs8) = AccountKey::generate().expect("key");
	let (transport, recorded) = RecordingTransport::new(DIRECTORY);
	transport.answers().insert(
		"https://acme.example/new-acct".to_string(),
		vec![created("https://169.254.169.254/acct/1", "{}")],
	);

	let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
		.await
		.expect("connect");
	let error = client
		.register(&["admin@example.org".to_string()])
		.await
		.expect_err("a hostile account URL must be refused");
	let message = error.to_string();

	let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pkcs8);
	assert!(
		!message.contains(&key_b64),
		"the account key must not be in the refusal: {message}"
	);
	for jws in signed(&recorded) {
		assert!(
			!message.contains(&jws),
			"a signed request must not be in the refusal: {message}"
		);
	}
}

#[tokio::test]
async fn a_local_ca_on_loopback_keeps_the_whole_flow_working() {
	// Pebble and the local test CAs answer over plain http on the loopback
	// interface. The policy admits that: the operator configured that
	// directory on purpose, and the CA's URLs name the same host.
	let base = "http://127.0.0.1:14000";
	let (key, _) = AccountKey::generate().expect("key");
	let (transport, recorded) = RecordingTransport::new(&format!(
		r#"{{
			"newNonce": "{base}/new-nonce",
			"newAccount": "{base}/new-acct",
			"newOrder": "{base}/new-order"
		}}"#
	));
	{
		let mut answers = transport.answers();
		answers.insert(
			format!("{base}/new-acct"),
			vec![created(&format!("{base}/acct/1"), "{}")],
		);
		answers.insert(
			format!("{base}/new-order"),
			vec![created(
				&format!("{base}/order/7"),
				&format!(
					r#"{{"status":"pending","authorizations":["{base}/authz/1"],"finalize":"{base}/finalize/7"}}"#
				),
			)],
		);
		answers.insert(
			format!("{base}/authz/1"),
			vec![
				PostResponse {
					nonce: fixtures::nonce().to_string(),
					location: None,
					status: 200,
					body: format!(
						r#"{{"status":"pending","identifier":{{"value":"mail.example.org"}},"challenges":[{{"type":"http-01","url":"{base}/chal/1","token":"token-1","status":"pending"}}]}}"#
					)
					.into_bytes(),
				},
				PostResponse {
					nonce: fixtures::nonce().to_string(),
					location: None,
					status: 200,
					body: r#"{"status":"valid","identifier":{"value":"mail.example.org"},"challenges":[]}"#
						.to_string()
						.into_bytes(),
				},
			],
		);
		answers.insert(
			format!("{base}/chal/1"),
			vec![PostResponse {
				nonce: fixtures::nonce().to_string(),
				location: None,
				status: 200,
				body: b"{}".to_vec(),
			}],
		);
		answers.insert(
			format!("{base}/finalize/7"),
			vec![PostResponse {
				nonce: fixtures::nonce().to_string(),
				location: None,
				status: 200,
				body: format!(
					r#"{{"status":"valid","finalize":"{base}/finalize/7","certificate":"{base}/cert/7"}}"#
				)
				.into_bytes(),
			}],
		);
		answers.insert(
			format!("{base}/cert/7"),
			vec![PostResponse {
				nonce: fixtures::nonce().to_string(),
				location: None,
				status: 200,
				body: b"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n".to_vec(),
			}],
		);
	}

	let client = AcmeClient::connect(transport, key, &format!("{base}/dir"))
		.await
		.expect("a local CA must connect");
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("a local CA must register");
	let store = crate::acme::http01::ChallengeStore::new();
	let (chain, key_pem) = client
		.obtain_certificate(
			&["mail.example.org".to_string()],
			std::sync::Arc::new(store),
			3,
		)
		.await
		.expect("a local CA must issue");
	assert!(chain.starts_with("-----BEGIN CERTIFICATE-----"));
	assert!(key_pem.contains("PRIVATE KEY"));
	assert!(
		asked(&recorded)
			.iter()
			.all(|url| url.starts_with(base) || url.ends_with("/dir")),
		"every request must have gone to the local CA: {:?}",
		asked(&recorded)
	);
}
