//! A peer on an open JMAP WebSocket can send frames that are not JMAP at
//! all. A binary frame is answered with a `notJSON` error and the socket
//! stays usable for the next request; it is never read as a request.

use super::base::TOKEN;
use super::revoke::Client;
use crate::api::ApiState;
use crate::storage::FsSpool;
use serde_json::json;

fn state(dir: &std::path::Path) -> ApiState {
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("open store"),
	);
	ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle())
}

#[tokio::test]
async fn a_binary_frame_is_refused_and_never_run_as_a_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut client = Client::open(state(dir.path()), TOKEN.as_str()).await;
	// A valid request, but carried in a binary frame.
	let request = json!({
		"@type": "Request",
		"id": "bin",
		"using": ["urn:ietf:params:jmap:core"],
		"methodCalls": [["Core/echo", { "marker": "ran" }, "c1"]],
	});
	client.send_frame(0x2, request.to_string().as_bytes()).await;
	let reply = client.next_json().await;
	assert_eq!(reply["@type"], "RequestError", "{reply}");
	assert_eq!(reply["type"], "urn:ietf:params:jmap:error:notJSON");
	assert!(reply.get("methodResponses").is_none(), "{reply}");

	// The socket is still there and still answers a text request.
	let text = json!({
		"@type": "Request",
		"id": "txt",
		"using": ["urn:ietf:params:jmap:core"],
		"methodCalls": [["Core/echo", { "marker": "ran" }, "c1"]],
	});
	client.send(&text).await;
	let reply = client.next_json().await;
	assert_eq!(reply["@type"], "Response", "{reply}");
	assert_eq!(reply["requestId"], "txt");
	assert_eq!(reply["methodResponses"][0][1]["marker"], "ran");
}
