use super::*;

#[test]
fn builds_request_payloads() {
	let acct = new_account_payload(&["admin@example.org".to_string()], true);
	assert_eq!(acct["termsOfServiceAgreed"], true);
	assert_eq!(acct["contact"][0], "mailto:admin@example.org");

	let order = new_order_payload(&["a.example".to_string(), "b.example".to_string()]);
	assert_eq!(order["identifiers"][0]["type"], "dns");
	assert_eq!(order["identifiers"][1]["value"], "b.example");

	assert_eq!(finalize_payload("Q1NS")["csr"], "Q1NS");
}

#[test]
fn parses_order() {
	let body = br#"{
			"status": "pending",
			"authorizations": ["https://acme.example/authz/1"],
			"finalize": "https://acme.example/finalize/1"
		}"#;
	let order: Order = serde_json::from_slice(body).expect("parse");
	assert_eq!(order.status, OrderStatus::Pending);
	assert_eq!(order.authorizations.len(), 1);
	assert!(order.certificate.is_none());
}

#[test]
fn parses_authorization_and_selects_challenge() {
	let body = br#"{
			"status": "pending",
			"identifier": {"type": "dns", "value": "a.example"},
			"challenges": [
				{"type": "http-01", "url": "https://acme.example/chal/1", "token": "tok-http", "status": "pending"},
				{"type": "dns-01", "url": "https://acme.example/chal/2", "token": "tok-dns", "status": "pending"}
			]
		}"#;
	let authz: Authorization = serde_json::from_slice(body).expect("parse");
	assert_eq!(authz.challenge("http-01").unwrap().token, "tok-http");
	assert_eq!(authz.challenge("dns-01").unwrap().token, "tok-dns");
	assert!(authz.challenge("tls-alpn-01").is_none());
}
