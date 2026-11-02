use super::*;

#[tokio::test]
async fn upsert_creates_txt_with_relative_subdomain_and_signed_headers() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let snapshot = {
		let s = state.lock().unwrap();
		(
			s.write_method.clone(),
			s.write_path.clone(),
			s.write_body.clone(),
			s.addr.clone(),
			s.write_headers.clone(),
			s.refresh_called,
		)
	};
	let (write_method, write_path, write_body, addr, write_headers, refresh_called) = snapshot;
	assert_eq!(write_method, "POST");
	assert_eq!(write_path, "/domain/zone/example.org/record");
	let body: serde_json::Value = serde_json::from_str(&write_body).expect("body json");
	assert_eq!(body["fieldType"], "TXT");
	assert_eq!(body["subDomain"], "_dmarc");
	assert_eq!(body["target"], "v=DMARC1; p=none");
	assert_eq!(body["ttl"], 3600);
	assert_eq!(write_headers.get("X-Ovh-Application").unwrap(), "AKID");
	assert_eq!(write_headers.get("X-Ovh-Consumer").unwrap(), "CK");
	// Reconstruct the signature independently of `OvhProvider::sign`, so a
	// bug in the implementation cannot match a buggy `expected`.
	let timestamp: u64 = write_headers
		.get("X-Ovh-Timestamp")
		.unwrap()
		.to_str()
		.unwrap()
		.parse()
		.unwrap();
	let full_url = format!("http://{addr}/domain/zone/example.org/record");
	let to_sign = format!("secret+CK+POST+{full_url}+{write_body}+{timestamp}");
	let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, to_sign.as_bytes());
	let expected = format!("$1${}", hex_lower(digest.as_ref()));
	let sig = write_headers
		.get("X-Ovh-Signature")
		.unwrap()
		.to_str()
		.unwrap()
		.to_string();
	assert_eq!(sig, expected, "X-Ovh-Signature mismatch");
	assert!(refresh_called, "POST /refresh must follow the write");
	// Round-trip through `provider.sign()` to also exercise that public
	// surface; this passes when the impl is correct and self-consistent.
	let _ = provider.sign("POST", &full_url, &write_body, timestamp);
}

#[tokio::test]
async fn upsert_at_apex_uses_empty_subdomain() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let body: serde_json::Value = serde_json::from_str(&s.write_body).expect("body json");
	assert_eq!(body["subDomain"], "");
	assert_eq!(body["fieldType"], "TXT");
	assert_eq!(s.write_path, "/domain/zone/example.org/record");
}

#[tokio::test]
async fn upsert_updates_existing_record_without_duplicating() {
	let existing = vec![StoredRecord {
		id: 42,
		field_type: "TXT".into(),
		sub_domain: "_dmarc".into(),
		target: "v=DMARC1; p=none".into(),
		ttl: 3600,
	}];
	let (provider, state) = mock_with(existing).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.write_method, "PUT");
	assert_eq!(s.write_path, "/domain/zone/example.org/record/42");
	let body: serde_json::Value = serde_json::from_str(&s.write_body).expect("body json");
	assert_eq!(body["target"], "v=DMARC1; p=reject");
	// No duplicate was created.
	let matching = s
		.records
		.iter()
		.filter(|r| r.sub_domain == "_dmarc" && r.field_type == "TXT")
		.count();
	assert_eq!(matching, 1, "expected exactly one matching record");
}

#[tokio::test]
async fn upsert_refreshes_zone_after_writing() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert!(s.refresh_called, "POST /refresh must follow the write");
}
