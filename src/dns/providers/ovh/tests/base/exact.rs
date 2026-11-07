use super::*;

/// A whole-set delete or first-by-name selection must fail this regression.
#[tokio::test]
async fn delete_exact_keeps_other_values_at_same_name_and_type() {
	for (kind, own, sibling) in [
		(RecordKind::A, "203.0.113.10", "203.0.113.20"),
		(RecordKind::Txt, "v=spf1 -all", "v=spf1 mx -all"),
	] {
		let records = vec![
			StoredRecord {
				id: 2,
				field_type: kind.as_str().into(),
				sub_domain: "".into(),
				target: sibling.into(),
				ttl: 60,
			},
			StoredRecord {
				id: 1,
				field_type: kind.as_str().into(),
				sub_domain: "".into(),
				target: own.into(),
				ttl: 60,
			},
		];
		let (provider, state) = mock_with(records).await;
		provider
			.delete_exact("example.org", DnsRecord::new("example.org", kind, own, 60))
			.await
			.expect("exact deletion is supported");
		let state = state.lock().unwrap();
		assert_eq!(state.records.len(), 1);
		assert_eq!(state.records[0].id, 2, "the sibling must survive");
		assert!(state.refresh_called, "publish the deletion");
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
			let mut wire = serde_json::json!({"fieldType": "A", "subDomain": "", "target": "203.0.113.10", "ttl": 60});
			wire["fieldType"] = kind.as_str().into();
			wire["target"] = value.into();
			let stored = serde_json::from_value(wire).unwrap();
			assert_eq!(
				super::super::super::exact::matches(&stored, &record, ""),
				expected,
				"{kind:?}: {value}"
			);
		}
	}
}
