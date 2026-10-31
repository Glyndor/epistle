//! A JMAP WebSocket message is bounded by the same `maxSizeRequest` as a POST
//! body, before it is buffered whole: a peer cannot make the server hold tens
//! of megabytes per socket by sending one very large frame.

use super::base::TOKEN;
use super::jmap_ws_revoke::Client;
use crate::api::ApiState;
use crate::api::jmap::limits::MAX_SIZE_REQUEST;
use crate::storage::FsSpool;

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
async fn a_frame_over_the_request_cap_ends_the_socket_instead_of_being_buffered() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut client = Client::open(state(dir.path()), TOKEN.as_str()).await;
	client.send_text_of(MAX_SIZE_REQUEST + 1_048_576).await;
	let (opcode, _) = client.next().await;
	assert!(
		opcode == 0 || opcode == 8,
		"the oversized message was answered (opcode {opcode}) instead of refused"
	);
}
