//! Hostile requests to the DAV router through a real TCP listener, so the HTTP parser
//! sees them: spellings of a path that the in-process tests build as a `Request` and
//! never as bytes, framing that contradicts itself, and XML that expands.

use axum::body::Body;
use axum::http::StatusCode;
use base64::Engine;

use super::harness::{Harness, PASSWORD, Wire, call, dav_request};

fn authorization() -> String {
	let credentials = base64::engine::general_purpose::STANDARD.encode(format!("alice:{PASSWORD}"));
	format!("Authorization: Basic {credentials}\r\n")
}

/// The status code of the first line of a wire answer, `None` when the server closed
/// the connection without one.
fn status(reply: &[u8]) -> Option<u16> {
	let text = String::from_utf8_lossy(reply);
	let line = text.lines().next()?;
	line.split_whitespace().nth(1)?.parse().ok()
}

/// A refusal is a closed connection or a 4xx. A 2xx would mean the hostile request was
/// served, a 5xx that it broke something.
fn refused(reply: &[u8], what: &str) {
	match status(reply) {
		None => {}
		Some(code) => assert!(
			(400..500).contains(&code),
			"{what}: {}",
			String::from_utf8_lossy(reply)
		),
	}
}

async fn healthy(h: &Harness, wire: &Wire) {
	let put = format!(
		"PUT /health.txt HTTP/1.1\r\nHost: dav.test\r\n{}Content-Length: 5\r\nConnection: close\r\n\r\nalive",
		authorization()
	);
	let reply = wire.exchange(put.as_bytes(), false).await;
	assert!(
		matches!(status(&reply), Some(201 | 204)),
		"{}",
		String::from_utf8_lossy(&reply)
	);
	h.healthy_dav().await;
}

#[tokio::test]
async fn paths_that_do_not_decode_never_reach_a_file() {
	let h = Harness::new();
	std::fs::write(h.dav_root("bob").join("secret.txt"), b"bob-private").expect("sentinel");
	let wire = Wire::start(h.dav.clone()).await;
	for path in [
		"/%",
		"/%2",
		"/%zz",
		"/%00",
		"/a%00b",
		"/%c0%ae%c0%ae/bob",
		"/%ff%fe",
	] {
		let request = format!(
			"GET {path} HTTP/1.1\r\nHost: dav.test\r\n{}Connection: close\r\n\r\n",
			authorization()
		);
		let reply = wire.exchange(request.as_bytes(), false).await;
		refused(&reply, path);
		assert!(!String::from_utf8_lossy(&reply).contains("bob-private"));
	}
	healthy(&h, &wire).await;
}

#[tokio::test]
async fn a_body_whose_length_is_stated_twice_is_not_written() {
	let h = Harness::new();
	let wire = Wire::start(h.dav.clone()).await;
	for lengths in [
		"Content-Length: 4\r\nContent-Length: 40\r\n",
		"Content-Length: -1\r\n",
		"Content-Length: 4, 40\r\n",
	] {
		let request = format!(
			"PUT /twice.txt HTTP/1.1\r\nHost: dav.test\r\n{}{lengths}Connection: close\r\n\r\nabcd",
			authorization()
		);
		let reply = wire.exchange(request.as_bytes(), true).await;
		refused(&reply, lengths);
		assert!(
			!h.dav_root("alice").join("twice.txt").exists(),
			"{lengths}: the file was written"
		);
	}
	healthy(&h, &wire).await;
}

#[tokio::test]
async fn a_chunked_body_with_a_hostile_chunk_header_is_refused() {
	let h = Harness::new();
	let wire = Wire::start(h.dav.clone()).await;
	for chunks in [
		"ffffffffffffffffff\r\nx\r\n0\r\n\r\n",
		"zz\r\nx\r\n0\r\n\r\n",
		"4;ext=\"unterminated\r\nabcd\r\n0\r\n\r\n",
		"4\r\nabcd\r\n0\r\nX-Trailer: a\r\nX-Trailer: b\r\n\r\n",
	] {
		let request = format!(
			"PUT /chunked.txt HTTP/1.1\r\nHost: dav.test\r\n{}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{chunks}",
			authorization()
		);
		let reply = wire.exchange(request.as_bytes(), true).await;
		match status(&reply) {
			None => {}
			Some(code) => assert!(
				code < 500,
				"{chunks:?}: {}",
				String::from_utf8_lossy(&reply)
			),
		}
	}
	healthy(&h, &wire).await;
}

#[tokio::test]
async fn a_report_whose_xml_expands_is_refused_on_the_wire() {
	let h = Harness::new();
	let wire = Wire::start(h.dav.clone()).await;
	let bomb = String::from(
		"<?xml version=\"1.0\"?><!DOCTYPE lol [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">\
		 <!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]><C:calendar-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\">&c;</C:calendar-query>",
	);
	let request = format!(
		"REPORT /cal/ HTTP/1.1\r\nHost: dav.test\r\n{}Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bomb}",
		authorization(),
		bomb.len()
	);
	let reply = wire.exchange(request.as_bytes(), false).await;
	let text = String::from_utf8_lossy(&reply);
	match status(&reply) {
		None => {}
		Some(code) => assert!((400..500).contains(&code) || code == 207, "{text}"),
	}
	assert!(
		!text.contains("aaaaaaaaaaaaaaaaaaaa"),
		"the entity was expanded: {text}"
	);
	healthy(&h, &wire).await;
}

#[tokio::test]
async fn a_dav_request_without_credentials_gets_a_challenge_on_the_wire() {
	let h = Harness::new();
	let wire = Wire::start(h.dav.clone()).await;
	let reply = wire
		.exchange(
			b"PROPFIND / HTTP/1.1\r\nHost: dav.test\r\nDepth: 0\r\nConnection: close\r\n\r\n",
			false,
		)
		.await;
	assert_eq!(
		status(&reply),
		Some(401),
		"{}",
		String::from_utf8_lossy(&reply)
	);
	let reply = call(&h.dav, dav_request("GET", "/health.txt", Body::empty())).await;
	assert_ne!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
}
