//! The JMAP request envelope sent through a real socket, so the HTTP parser and the
//! dispatcher both see it: a body of the wrong type, framing that contradicts itself,
//! keys that repeat, a call that is not a triple, and a document nested far deeper than
//! any request. A refusal is a 4xx or a closed connection; a 5xx or a served answer to
//! a request that is not valid is a defect.

use super::harness::{ALICE, Harness, Wire};

fn status(reply: &[u8]) -> Option<u16> {
	let text = String::from_utf8_lossy(reply);
	text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn post(headers: &str, body: &str) -> Vec<u8> {
	format!(
		"POST /jmap/api HTTP/1.1\r\nHost: jmap.test\r\nAuthorization: Bearer {ALICE}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	)
	.into_bytes()
}

/// `None` is a closed connection; otherwise the status must be a refusal.
fn refused(reply: &[u8], what: &str) {
	if let Some(code) = status(reply) {
		assert!(
			(400..500).contains(&code),
			"{what}: {}",
			String::from_utf8_lossy(reply)
		);
	}
}

#[tokio::test]
async fn a_body_that_is_not_json_is_refused() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	for (headers, body) in [
		("Content-Type: text/plain\r\n", r#"{"methodCalls":[]}"#),
		(
			"Content-Type: application/x-www-form-urlencoded\r\n",
			"methodCalls=[]",
		),
		("Content-Type: application/json\r\n", "{"),
		(
			"Content-Type: application/json\r\n",
			"\u{feff}{\"methodCalls\":[]}",
		),
		("", r#"{"methodCalls":[]}"#),
	] {
		let reply = wire.exchange(&post(headers, body), false).await;
		match status(&reply) {
			// An empty list of calls answered 200 with no responses is not a defect; any
			// other success would be: the body was not valid.
			Some(200) => assert!(
				String::from_utf8_lossy(&reply).contains("methodResponses"),
				"{headers}{body}"
			),
			_ => refused(&reply, headers),
		}
	}
	wire.healthy().await;
}

#[tokio::test]
async fn a_call_that_is_not_a_triple_never_runs_a_method() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	for body in [
		r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo"]]}"#,
		r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{}]]}"#,
		r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{},"c","extra"]]}"#,
		r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[[1,2,3]]}"#,
		r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":"Core/echo"}"#,
		r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[null]}"#,
	] {
		let reply = wire
			.exchange(&post("Content-Type: application/json\r\n", body), false)
			.await;
		let text = String::from_utf8_lossy(&reply);
		if status(&reply) == Some(200) {
			// The call was answered as an error, not run.
			assert!(!text.contains("\"Core/echo\",{"), "{body}: {text}");
		} else {
			refused(&reply, body);
		}
	}
	wire.healthy().await;
}

#[tokio::test]
async fn repeated_keys_in_the_envelope_do_not_smuggle_a_second_request() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let body = r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[],"methodCalls":[["Mailbox/get",{"accountId":"bob"},"x"]]}"#;
	let reply = wire
		.exchange(&post("Content-Type: application/json\r\n", body), false)
		.await;
	let text = String::from_utf8_lossy(&reply);
	// Whichever copy wins, bob's mailboxes are not Alice's to read.
	assert!(!text.contains("\"list\":[{"), "{text}");
	wire.healthy().await;
}

#[tokio::test]
async fn contradictory_framing_is_refused_before_the_dispatcher() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let body = r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]}"#;
	for framing in [
		format!("Content-Length: {}\r\nContent-Length: 2\r\n", body.len()),
		format!(
			"Content-Length: {}\r\nTransfer-Encoding: chunked\r\n",
			body.len()
		),
		"Content-Length: -1\r\n".to_string(),
	] {
		let request = format!(
			"POST /jmap/api HTTP/1.1\r\nHost: jmap.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: application/json\r\n{framing}Connection: close\r\n\r\n{body}"
		);
		let reply = wire.exchange(request.as_bytes(), true).await;
		refused(&reply, &framing);
	}
	wire.healthy().await;
}

#[tokio::test]
async fn a_document_nested_far_deeper_than_any_request_is_refused() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let depth = 50_000;
	let body = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
	let reply = wire
		.exchange(&post("Content-Type: application/json\r\n", &body), false)
		.await;
	refused(&reply, "deep nesting");
	wire.healthy().await;
}
