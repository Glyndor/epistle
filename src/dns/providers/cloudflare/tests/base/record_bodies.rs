use super::*;

#[tokio::test]
async fn mx_upsert_posts_data_object_with_priority_and_host() {
	let (provider, state) = mock(Vec::new()).await;
	let mx = DnsRecord::new("example.org", RecordKind::Mx, "10 mail.example.org", 3600);
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state
		.lock()
		.unwrap()
		.last_body
		.clone()
		.expect("post body captured");
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"priority\":10"), "{body}");
	assert!(body.contains("\"host\":\"mail.example.org\""), "{body}");
}

#[test]
fn record_body_uses_data_for_tlsa_and_content_otherwise() {
	let tlsa = DnsRecord::new(
		"_25._tcp.mail.example.org",
		RecordKind::Tlsa,
		"3 0 1 abcd",
		3600,
	);
	let body = CloudflareProvider::record_body("TLSA", &tlsa).expect("tlsa body");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"usage\":3"), "{body}");
	assert!(body.contains("\"certificate\":\"abcd\""), "{body}");

	let txt = DnsRecord::new("example.org", RecordKind::Txt, "v=spf1 -all", 3600);
	let body = CloudflareProvider::record_body("TXT", &txt).expect("txt body");
	// TXT content goes quoted, the form Cloudflare's API documents.
	assert!(body.contains(r#""content":"\"v=spf1 -all\"""#), "{body}");
}

#[test]
fn record_body_splits_srv_into_priority_weight_port_target() {
	let srv = DnsRecord::new(
		"_submissions._tcp.example.org",
		RecordKind::Srv,
		"0 1 465 mail.example.org",
		3600,
	);
	let body = CloudflareProvider::record_body("SRV", &srv).expect("srv body");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"weight\":1"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
	assert!(body.contains("\"target\":\"mail.example.org\""), "{body}");
	assert!(!body.contains("\"content\""), "{body}");
}

#[tokio::test]
async fn srv_upsert_posts_with_data_fields() {
	let (provider, state) = mock(Vec::new()).await;
	let srv = DnsRecord::new(
		"_submissions._tcp.example.org",
		RecordKind::Srv,
		"0 1 465 mail.example.org",
		3600,
	);
	provider
		.upsert("example.org", srv)
		.await
		.expect("srv upsert");
	let body = state
		.lock()
		.unwrap()
		.last_body
		.clone()
		.expect("post body captured");
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"weight\":1"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
	assert!(body.contains("\"target\":\"mail.example.org\""), "{body}");
	assert!(!body.contains("\"content\""), "{body}");
}

#[tokio::test]
async fn caa_upsert_posts_with_flags_tag_value_data() {
	let (provider, state) = mock(Vec::new()).await;
	let caa = DnsRecord::new(
		"example.org",
		RecordKind::Caa,
		"0 issue \"letsencrypt.org\"",
		3600,
	);
	provider
		.upsert("example.org", caa)
		.await
		.expect("caa upsert");
	let body = state
		.lock()
		.unwrap()
		.last_body
		.clone()
		.expect("post body captured");
	assert!(body.contains("\"type\":\"CAA\""), "{body}");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"flags\":0"), "{body}");
	assert!(body.contains("\"tag\":\"issue\""), "{body}");
	assert!(body.contains("\"value\":\"letsencrypt.org\""), "{body}");
}

#[tokio::test]
async fn create_body_carries_the_comment_field() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(state.lock().unwrap().last_body.as_deref().unwrap()).unwrap();
	assert_eq!(body["comment"], expected_description());
}

#[tokio::test]
async fn update_body_sets_the_comment_field_too() {
	let existing = vec![serde_json::json!({
		"id": "rec1", "type": "TXT", "name": "_dmarc.example.org",
		"content": "v=DMARC1; p=none", "ttl": 3600, "comment": "set by hand"
	})];
	let (provider, state) = mock(existing).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert!(
		s.calls.iter().any(|c| c.starts_with("PUT ")),
		"{:?}",
		s.calls
	);
	let body: serde_json::Value = serde_json::from_str(s.last_body.as_deref().unwrap()).unwrap();
	assert_eq!(body["comment"], expected_description());
}

#[test]
fn every_record_kind_body_carries_the_comment() {
	let rec = |kind, value: &str| DnsRecord::new("x.example.org", kind, value, 300);
	let cases = [
		(RecordKind::A, "192.0.2.1"),
		(RecordKind::Mx, "10 mail.example.org."),
		(RecordKind::Srv, "0 1 443 mail.example.org."),
		(RecordKind::Tlsa, "3 1 1 abcd"),
		(RecordKind::Caa, "0 issue \"letsencrypt.org\""),
	];
	for (kind, value) in cases {
		let r = rec(kind.clone(), value);
		let body = CloudflareProvider::record_body(kind.as_str(), &r).unwrap();
		let v: serde_json::Value = serde_json::from_str(&body).unwrap();
		assert_eq!(v["comment"], expected_description(), "{}", kind.as_str());
	}
}
