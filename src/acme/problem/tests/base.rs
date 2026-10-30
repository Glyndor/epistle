//! Tests for reading a CA's refusal.

use super::*;

/// The body a CA sends when it refuses a request: the problem document of
/// RFC 8555 §6.7, indented the way Boulder indents it.
const PROBLEM: &[u8] = br#"{
  "type": "urn:ietf:params:acme:error:unauthorized",
  "detail": "No TXT record found at _acme-challenge.mail.example.org",
  "status": 400
}
"#;

#[test]
fn reads_the_type_and_the_detail_of_a_problem_document() {
	let refusal = Refusal::read(400, PROBLEM);
	assert!(refusal.is_problem());
	assert_eq!(
		refusal.kind.as_deref(),
		Some("urn:ietf:params:acme:error:unauthorized")
	);
	assert_eq!(
		refusal.detail.as_deref(),
		Some("No TXT record found at _acme-challenge.mail.example.org")
	);
	assert_eq!(refusal.status, 400);
}

#[test]
fn describes_the_problem_in_one_line() {
	let refusal = Refusal::read(400, PROBLEM);
	let described = refusal.describe();
	assert!(
		described.contains("400"),
		"the status must be named: {described}"
	);
	assert!(
		described.contains("urn:ietf:params:acme:error:unauthorized"),
		"the type must be named: {described}"
	);
	assert!(
		described.contains("No TXT record found"),
		"the detail must be named: {described}"
	);
	assert!(
		!described.contains('\n'),
		"the description must stay on one line: {described}"
	);
}

#[test]
fn a_body_that_is_not_a_problem_document_becomes_a_snippet() {
	// A proxy in front of the CA answers with HTML, not with a document.
	let body = b"<html>\n<head><title>502 Bad Gateway</title></head>\n</html>";
	let refusal = Refusal::read(502, body);
	assert!(!refusal.is_problem());
	assert!(refusal.kind.is_none());
	assert!(refusal.detail.is_none());
	let described = refusal.describe();
	assert!(
		described.contains("502"),
		"the status must be named: {described}"
	);
	assert!(
		described.contains("502 Bad Gateway"),
		"the snippet must keep what came back: {described}"
	);
}

#[test]
fn json_without_a_type_is_not_a_problem_document() {
	// A JSON body that carries no `type` names no error: it is not a
	// problem document, so it is kept as a snippet.
	let refusal = Refusal::read(400, br#"{"status": 400}"#);
	assert!(!refusal.is_problem());
	assert!(
		refusal.snippet.is_some(),
		"a body that names no error is kept as a snippet"
	);
}

#[test]
fn an_empty_body_is_described_as_empty() {
	let refusal = Refusal::read(500, b"");
	assert!(!refusal.is_problem());
	assert_eq!(refusal.describe(), "ACME answered 500 with an empty body");
}

#[test]
fn a_problem_document_without_a_detail_still_names_the_type() {
	let refusal = Refusal::read(
		429,
		br#"{"type": "urn:ietf:params:acme:error:rateLimited"}"#,
	);
	assert!(refusal.is_problem());
	assert_eq!(
		refusal.describe(),
		"ACME answered 429: urn:ietf:params:acme:error:rateLimited"
	);
}

#[test]
fn the_snippet_is_capped_and_stays_on_one_line() {
	let body = vec![b'x'; SNIPPET_LIMIT * 2];
	let refusal = Refusal::read(502, &body);
	let snippet = refusal.snippet.expect("snippet");
	assert_eq!(snippet.chars().count(), SNIPPET_LIMIT);
	assert!(!snippet.contains('\n'));
}
