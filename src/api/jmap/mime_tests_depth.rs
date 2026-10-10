use super::mime_tests_structure::{ID, leaf};
use crate::api::tests::{TOKEN, request_raw, test_state};
use axum::http::StatusCode;
use serde_json::{Value, json};

const LIMIT: usize = 64;

fn multipart(levels: usize) -> (Vec<u8>, Vec<u8>) {
	let mut raw = String::new();
	let mut cutoff_start = 0;
	for level in 0..levels {
		raw.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=b{level}\r\n\r\n"
		));
		if level == LIMIT {
			cutoff_start = raw.len();
		}
		raw.push_str(&format!("--b{level}\r\n"));
	}
	raw.push_str("Content-Type: text/plain\r\n\r\nInside");
	let mut cutoff_end = 0;
	for level in (0..levels).rev() {
		if level == LIMIT - 1 {
			cutoff_end = raw.len();
		}
		raw.push_str(&format!("\r\n--b{level}--"));
	}
	raw.push_str("\r\n");
	let opaque = raw.as_bytes()[cutoff_start..cutoff_end].to_vec();
	(raw.into_bytes(), opaque)
}

fn assert_multipart_shape(email: &Value, opaque_size: usize) {
	let mut node = &email["bodyStructure"];
	for _ in 0..LIMIT {
		assert_eq!(
			node["type"], "multipart/mixed",
			"ancestors must retain their MIME type"
		);
		assert_eq!(
			node["partId"],
			Value::Null,
			"multipart ancestors must have no part id"
		);
		let children = node["subParts"].as_array().expect("multipart children");
		assert_eq!(
			children.len(),
			1,
			"each ancestor must retain exactly one child"
		);
		node = &children[0];
	}
	assert_eq!(
		node["type"], "application/octet-stream",
		"the MIME depth boundary must be an opaque application/octet-stream leaf"
	);
	let expected = leaf("64", opaque_size, "application/octet-stream", Value::Null);
	assert_eq!(
		node, &expected,
		"the opaque leaf must retain its id and exact octet size without subParts"
	);
	assert_eq!(
		email["attachments"],
		json!([expected]),
		"the opaque leaf must be the only attachment"
	);
	assert_eq!(
		email["textBody"],
		json!([]),
		"hidden text must not enter textBody"
	);
	assert_eq!(
		email["htmlBody"],
		json!([]),
		"hidden text must not enter htmlBody"
	);
	assert_eq!(
		email["bodyValues"],
		json!({}),
		"fetchAllBodyValues must exclude hidden text"
	);
	assert_eq!(
		email["hasAttachment"], true,
		"opaque parts must count as attachments"
	);
	assert_eq!(
		email["preview"], "",
		"hidden text must not enter the preview"
	);
}

async fn exercise_deep_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	let state = test_state(dir.path(), 0);
	let app = crate::api::router(state.clone());
	let args = json!({"accountId":"alice","ids":[ID],
		"properties":["bodyStructure","textBody","htmlBody","attachments","bodyValues","hasAttachment","preview"],
		"fetchAllBodyValues":true});
	let (raw, opaque) = multipart(10_000);
	std::fs::write(inbox.join(format!("{ID}.eml")), &raw).expect("message");
	let response = super::super::methods::email_get(&state, &args, "c");
	assert_eq!(
		response[0], "Email/get",
		"deep messages must return Email/get"
	);
	assert_multipart_shape(&response[1]["list"][0], opaque.len());
	for part in ["65", "10000"] {
		let (status, bytes) = request_raw(
			&app,
			&format!("/jmap/download/alice/{ID}.{part}/part"),
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(
			status,
			StatusCode::NOT_FOUND,
			"parts below the MIME depth boundary must return 404"
		);
		let error: Value = serde_json::from_slice(&bytes).expect("error response");
		assert_eq!(
			error["type"], "urn:ietf:params:jmap:error:notFound",
			"hidden part downloads must report notFound"
		);
	}
	let (status, bytes) = request_raw(
		&app,
		&format!("/jmap/download/alice/{ID}.64/part"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"the opaque boundary leaf must remain downloadable"
	);
	assert!(
		bytes == opaque,
		"the opaque download must preserve exactly the boundary body octets"
	);

	let header = "Content-Type: message/rfc822\r\n\r\n";
	let raw = format!("{}Subject: inner\r\n\r\nInside", header.repeat(10_000));
	std::fs::write(inbox.join(format!("{ID}.eml")), &raw).expect("message");
	let response = super::super::methods::email_get(&state, &args, "c");
	let email = &response[1]["list"][0];
	let expected = leaf("0", raw.len() - header.len(), "message/rfc822", Value::Null);
	assert_eq!(
		email["bodyStructure"], expected,
		"nested attached messages must retain one downloadable outer leaf"
	);
	assert_eq!(
		email["attachments"],
		json!([expected]),
		"nested attached messages must remain one attachment"
	);
	for property in ["textBody", "htmlBody"] {
		assert_eq!(
			email[property],
			json!([]),
			"attached message content must not enter body lists"
		);
	}
	assert_eq!(
		email["bodyValues"],
		json!({}),
		"attached message text must not enter bodyValues"
	);
	let (status, bytes) = request_raw(
		&app,
		&format!("/jmap/download/alice/{ID}.0/part"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"deep attached messages must remain downloadable"
	);
	assert!(
		bytes == raw.as_bytes()[header.len()..],
		"attached message download must preserve all encapsulated octets"
	);
	let (status, _) = request_raw(
		&app,
		&format!("/jmap/download/alice/{ID}.10000/part"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::NOT_FOUND,
		"encapsulated part ids must return 404"
	);
}

#[test]
fn mime_bounded_nesting_truncates_structure_and_downloads_on_small_stack() {
	// Check the boundary before the stress case so regressions report a shape assertion.
	std::thread::Builder::new()
		.stack_size(16 * 1024 * 1024)
		.spawn(|| {
			let (raw, opaque) = multipart(66);
			let email = super::mime::email_body(ID, &raw, &json!({"fetchAllBodyValues":true}));
			assert_multipart_shape(&email, opaque.len());
		})
		.expect("boundary thread")
		.join()
		.expect("boundary assertion");
	std::thread::Builder::new()
		.stack_size(256 * 1024)
		.spawn(|| {
			tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.expect("runtime")
				.block_on(exercise_deep_messages());
		})
		.expect("small stack thread")
		.join()
		.expect("deep message assertions");
}
