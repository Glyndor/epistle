//! A JMAP WebSocket (RFC 8887) is authenticated once, at the upgrade, but can
//! stay open for hours. These tests open a real socket over loopback, take the
//! credential away underneath it (revoke the key, disable or remove the
//! account) and check that the next request is refused and the socket is
//! closed with 1008 (policy violation) instead of still answering.

use super::tests::TOKEN;
use crate::api::{ApiState, router};
use crate::storage::FsSpool;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ANN: &str = "ann-ws-secret";
const CAROL: &str = "carol-ws-secret";

/// `ann` (static) and `carol` (dynamic, so she can be disabled or removed),
/// each with a read/write key bound to the account.
fn ws_state(
	dir: &std::path::Path,
) -> (
	ApiState,
	std::sync::Arc<crate::directory_store::AccountStore>,
) {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	for (label, secret, account) in [("ann-key", ANN, "ann"), ("carol-key", CAROL, "carol")] {
		key_store
			.add(crate::api::api_keys::ApiKey {
				label: label.to_string(),
				hash: crate::api::api_keys::sha256_hash(secret),
				expires_at: None,
				ip_cidr: None,
				scopes: vec!["read".to_string(), "write".to_string()],
				domains: Vec::new(),
				account: Some(account.to_string()),
			})
			.expect("add key");
	}
	drop(key_store);
	let domains = vec!["example.org".to_string()];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![crate::config::Account {
				display_name: None,
				name: "ann".to_string(),
				addresses: vec!["ann@example.org".to_string()],
				password_hash: Some("$argon2id$secret".to_string()),
				catch_all: Vec::new(),
				quota_bytes: None,
				forward: Vec::new(),
				forward_keep_local: true,
				allowed_protocols: None,
			}],
		)
		.expect("open store"),
	);
	store
		.add(crate::directory_store::DynamicAccount {
			display_name: None,
			name: "carol".to_string(),
			addresses: vec!["carol@example.org".to_string()],
			password_hash: "$argon2id$secret".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			forward: Vec::new(),
			catch_all: Vec::new(),
			save_sent: None,
		})
		.expect("add carol");
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle());
	(state, store)
}

/// A minimal RFC 6455 client: enough to send masked text frames and read the
/// server's unmasked frames, so the test needs no WebSocket dependency.
pub(super) struct Client {
	stream: TcpStream,
}

impl Client {
	pub(super) async fn open(state: ApiState, token: &str) -> Client {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind loopback");
		let addr = listener.local_addr().expect("local addr");
		tokio::spawn(async move {
			axum::serve(listener, router(state)).await.ok();
		});
		let mut stream = TcpStream::connect(addr).await.expect("connect");
		let handshake = format!(
			"GET /jmap/ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\n\
			 Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
			 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
			 Authorization: Bearer {token}\r\n\r\n"
		);
		stream
			.write_all(handshake.as_bytes())
			.await
			.expect("handshake");
		let mut head = Vec::new();
		while !head.ends_with(b"\r\n\r\n") {
			head.push(stream.read_u8().await.expect("handshake reply"));
		}
		let head = String::from_utf8_lossy(&head);
		assert!(head.starts_with("HTTP/1.1 101"), "upgrade refused: {head}");
		Client { stream }
	}

	pub(super) async fn send(&mut self, frame: &Value) {
		let payload = frame.to_string().into_bytes();
		let mask = [0x11u8, 0x22, 0x33, 0x44];
		let mut out = vec![0x81u8];
		match payload.len() {
			len @ 0..=125 => out.push(0x80 | len as u8),
			len => {
				out.push(0x80 | 126);
				out.extend_from_slice(&(len as u16).to_be_bytes());
			}
		}
		out.extend_from_slice(&mask);
		out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
		self.stream.write_all(&out).await.expect("send frame");
	}

	/// The next frame's opcode and payload; opcode 0 (a continuation, which
	/// this server never sends) when the connection ended without one.
	pub(super) async fn next(&mut self) -> (u8, Vec<u8>) {
		tokio::time::timeout(Duration::from_secs(5), async {
			let Ok(first) = self.stream.read_u8().await else {
				return (0, Vec::new());
			};
			let len = match self.stream.read_u8().await.expect("frame length") & 0x7f {
				126 => u64::from(self.stream.read_u16().await.expect("length")),
				127 => self.stream.read_u64().await.expect("length"),
				len => u64::from(len),
			};
			let mut payload = vec![0; len as usize];
			self.stream
				.read_exact(&mut payload)
				.await
				.expect("frame payload");
			(first & 0x0f, payload)
		})
		.await
		.expect("no frame within 5s")
	}

	pub(super) async fn next_json(&mut self) -> Value {
		let (opcode, payload) = self.next().await;
		assert_eq!(opcode, 1, "expected a text frame");
		serde_json::from_slice(&payload).expect("frame is JSON")
	}
}

fn mailbox_get(account: &str, id: &str) -> Value {
	json!({
		"@type": "Request",
		"id": id,
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/get", { "accountId": account }, "c1"]],
	})
}

/// Send a request on a socket whose credential was just taken away and check
/// it is refused, with no method response, and the socket closes with 1008.
async fn assert_refused_and_closed(client: &mut Client, account: &str) {
	client.send(&mailbox_get(account, "after")).await;
	let reply = client.next_json().await;
	assert_eq!(
		reply["@type"], "RequestError",
		"request still answered: {}",
		reply["@type"]
	);
	assert_eq!(reply["type"], "urn:ietf:params:jmap:error:forbidden");
	assert_eq!(reply["requestId"], "after");
	assert!(reply.get("methodResponses").is_none());
	let (opcode, payload) = client.next().await;
	assert_eq!(opcode, 8, "expected a close frame");
	assert_eq!(
		payload.get(..2),
		Some(&1008u16.to_be_bytes()[..]),
		"close code"
	);
}

/// Open a socket as `token` and check a first request on `account` is served.
async fn open_and_check(state: ApiState, token: &str, account: &str) -> Client {
	let mut client = Client::open(state, token).await;
	client.send(&mailbox_get(account, "before")).await;
	let reply = client.next_json().await;
	assert_eq!(reply["@type"], "Response", "{reply}");
	assert_eq!(reply["methodResponses"][0][0], "Mailbox/get", "{reply}");
	client
}

#[tokio::test]
async fn revoking_the_key_closes_an_open_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _store) = ws_state(dir.path());
	let mut client = open_and_check(state.clone(), ANN, "ann").await;

	// The CLI removes the key from the file and the watcher reloads the set.
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
	key_store.remove("ann-key").expect("remove key");
	let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");

	assert_refused_and_closed(&mut client, "ann").await;
}

#[tokio::test]
async fn disabling_the_account_closes_an_open_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, store) = ws_state(dir.path());
	let mut client = open_and_check(state, CAROL, "carol").await;

	store.set_disabled("carol", true).expect("disable carol");

	assert_refused_and_closed(&mut client, "carol").await;
}

#[tokio::test]
async fn removing_the_account_closes_an_open_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, store) = ws_state(dir.path());
	let mut client = open_and_check(state, CAROL, "carol").await;

	store.remove("carol").expect("remove carol");

	assert_refused_and_closed(&mut client, "carol").await;
}

#[tokio::test]
async fn an_unchanged_credential_keeps_its_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _store) = ws_state(dir.path());
	for (token, account) in [(ANN, "ann"), (TOKEN.as_str(), "ann")] {
		let mut client = open_and_check(state.clone(), token, account).await;
		client.send(&mailbox_get(account, "again")).await;
		let reply = client.next_json().await;
		assert_eq!(
			reply["@type"], "Response",
			"second request refused: {reply}"
		);
		assert_eq!(reply["requestId"], "again");
	}
}
