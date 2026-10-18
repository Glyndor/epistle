//! Send-as over the REST API and JMAP, for the shared table in
//! `directory_send_as_fixture.rs`: `POST /api/v1/send` and
//! `EmailSubmission/set` hold the sender and the From header to the same
//! `Directory::owns_address` as SMTP submission, for dotted addresses, any
//! case, lists and the addresses that merely deliver to the account.

use super::router;
use super::tests::{request_with_body, test_state};
use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::send_as_fixture::{CASES, directory};
use axum::Router;
use axum::http::StatusCode;

/// The only account the API test state stores; a key bound to a name the
/// store does not hold is refused before any sender is looked at. The
/// other accounts' answers are held by the directory and SMTP tests.
const ACCOUNTS: [&str; 1] = ["alice"];

/// The secret of the key bound to `account`.
fn secret(account: &str) -> String {
	format!("{account}-secret")
}

/// A router whose directory is the shared fixture, with a key bound to the
/// account: a bound key acts only for its account, so the directory is what
/// decides each case.
fn app(dir: &std::path::Path) -> Router {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("open key store");
	for account in ACCOUNTS {
		keys.add(crate::api::api_keys::ApiKey {
			label: format!("{account}-only"),
			hash: crate::api::api_keys::sha256_hash(&secret(account)),
			expires_at: None,
			ip_cidr: None,
			scopes: ["read", "write", "send"].map(str::to_string).to_vec(),
			domains: Vec::new(),
			account: Some(account.to_string()),
		})
		.expect("add key");
	}
	router(test_state(dir, 0).with_directory(DirectoryHandle::new(directory())))
}

/// The cases of `account`.
fn cases(account: &str) -> impl Iterator<Item = (&'static str, bool)> {
	let account = account.to_string();
	CASES
		.iter()
		.filter(move |case| case.0 == account)
		.map(|case| (case.1, case.2))
}

#[tokio::test]
async fn api_send_follows_the_table() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	for account in ACCOUNTS {
		for (from, allowed) in cases(account) {
			let body = serde_json::json!({
				"from": from, "to": ["dest@remote.example"],
				"subject": "hello", "text": "hi",
			});
			let (status, response) = request_with_body(
				&app,
				"POST",
				"/api/v1/send",
				Some(&secret(account)),
				Some(body),
			)
			.await;
			if allowed {
				assert_eq!(
					status,
					StatusCode::OK,
					"{account} sending as {from}: {response}"
				);
			} else {
				assert_eq!(
					status,
					StatusCode::FORBIDDEN,
					"{account} sending as {from}: {response}"
				);
				assert_eq!(response["error"]["code"], "forbidden_from", "{from}");
			}
		}
	}
}

/// Store a message from `from` in `account`'s mailbox and submit it with
/// `envelope` as the sender; the method response.
async fn submit(
	app: &Router,
	dir: &std::path::Path,
	account: &str,
	envelope: &str,
	from: &str,
) -> serde_json::Value {
	let inbox = dir.join("accounts").join(account).join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		format!("From: {from}\r\nTo: dest@remote.example\r\nSubject: hi\r\n\r\nbody\r\n"),
	)
	.expect("write");
	let request = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": account,
			"create": { "s1": {
				"emailId": id.to_string(),
				"envelope": {"mailFrom": {"email": envelope},
					"rcptTo": [{"email": "dest@remote.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(&secret(account)),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

/// Whether a submission response queued the message.
fn queued(response: &serde_json::Value) -> bool {
	response["created"]["s1"]["id"].is_string()
}

#[tokio::test]
async fn jmap_submission_from_header_follows_the_table() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	for account in ACCOUNTS {
		let envelope = format!("{account}@example.org");
		for (from, allowed) in cases(account) {
			let response = submit(&app, dir.path(), account, &envelope, from).await;
			assert_eq!(
				queued(&response),
				allowed,
				"{account} From {from}: {response}"
			);
			if !allowed {
				assert_eq!(
					response["notCreated"]["s1"]["type"], "forbiddenFrom",
					"{from}"
				);
			}
		}
	}
}

#[tokio::test]
async fn jmap_submission_envelope_follows_the_table() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	for account in ACCOUNTS {
		let own = format!("{account}@example.org");
		for (sender, allowed) in cases(account) {
			let response = submit(&app, dir.path(), account, sender, &own).await;
			assert_eq!(
				queued(&response),
				allowed,
				"{account} mailFrom {sender}: {response}"
			);
			if !allowed {
				assert_eq!(
					response["notCreated"]["s1"]["type"], "forbiddenFrom",
					"{sender}"
				);
			}
		}
	}
}
