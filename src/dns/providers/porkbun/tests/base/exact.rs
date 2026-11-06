use super::*;

/// A whole-set delete or first-by-name selection must fail this regression.
#[tokio::test]
async fn delete_exact_keeps_other_values_at_same_name_and_type() {
	for (kind, own, sibling) in [
		(RecordKind::A, "203.0.113.10", "203.0.113.20"),
		(RecordKind::Txt, "v=spf1 -all", "v=spf1 mx -all"),
	] {
		let records = serde_json::json!([
			stored("2", "example.org", kind.as_str(), sibling),
			stored("1", "example.org", kind.as_str(), own),
		]);
		let (provider, state) = mock(records).await;
		provider
			.delete_exact("example.org", DnsRecord::new("example.org", kind, own, 60))
			.await
			.expect("exact deletion is supported");
		let state = state.lock().unwrap();
		let deletes: Vec<_> = state
			.paths()
			.into_iter()
			.filter(|p| p.starts_with("/dns/delete/"))
			.collect();
		assert_eq!(
			deletes,
			vec!["/dns/delete/example.org/1"],
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
			let mut wire = serde_json::json!({"id": "1", "name": "example.org", "type": "A", "content": "203.0.113.10", "ttl": "600", "prio": ""});
			wire["type"] = kind.as_str().into();
			wire["content"] = value.into();
			let stored = serde_json::from_value(wire).unwrap();
			assert_eq!(
				super::super::super::exact::matches(&stored, &record),
				expected,
				"{kind:?}: {value}"
			);
		}
	}
}
