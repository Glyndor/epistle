use super::*;

/// A whole-set delete or first-by-name selection must fail this regression.
#[tokio::test]
async fn delete_exact_keeps_other_values_at_same_name_and_type() {
	for (kind, own, sibling) in [
		(RecordKind::A, "203.0.113.10", "203.0.113.20"),
		(RecordKind::Txt, "v=spf1 -all", "v=spf1 mx -all"),
	] {
		let records = vec![
			serde_json::json!({"id": 2, "name": "@", "type": kind.as_str(), "data": sibling, "ttl": 60,
				"priority": null, "port": null, "weight": null, "flags": null, "tag": null}),
			serde_json::json!({"id": 1, "name": "@", "type": kind.as_str(), "data": own, "ttl": 60,
				"priority": null, "port": null, "weight": null, "flags": null, "tag": null}),
		];
		let (provider, state) = mock(records, false).await;
		provider
			.delete_exact("example.org", DnsRecord::new("example.org", kind, own, 60))
			.await
			.expect("exact deletion is supported");
		let calls = state.lock().unwrap().calls.clone();
		let deletes: Vec<_> = calls
			.iter()
			.filter(|c| c.starts_with("DELETE"))
			.map(String::as_str)
			.collect();
		assert_eq!(
			deletes,
			vec!["DELETE /v2/domains/example.org/records/1"],
			"the sibling must survive"
		);
	}
}

/// Exercise the real record selector without requiring a loopback listener.
#[test]
fn selects_only_requested_value() {
	for (kind, own, sibling) in [
		(RecordKind::A, "203.0.113.10", "203.0.113.20"),
		(RecordKind::Txt, "v=spf1 -all", "v=spf1 mx -all"),
		(RecordKind::Txt, "token-own", "token-foreign"),
	] {
		let record = DnsRecord::new("example.org", kind.clone(), own, 60);
		for (value, expected) in [(own, true), (sibling, false), ("absent", false)] {
			let mut wire = serde_json::json!({"id": 1, "name": "@", "type": "A", "data": "203.0.113.10", "ttl": 60});
			wire["type"] = kind.as_str().into();
			wire["data"] = value.into();
			let stored = serde_json::from_value(wire).unwrap();
			assert_eq!(
				super::super::super::exact::matches(&stored, &record, "@"),
				expected,
				"{kind:?}: {value}"
			);
		}
	}
}
