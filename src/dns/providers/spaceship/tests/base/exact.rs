use super::*;

/// A whole-set delete or first-by-name selection must fail this regression.
#[tokio::test]
async fn delete_exact_keeps_other_values_at_same_name_and_type() {
	for (kind, own, sibling) in [
		(RecordKind::Txt, "v=spf1 -all", "v=spf1 mx -all"),
		(RecordKind::Txt, "token-own", "token-foreign"),
	] {
		let records = vec![
			serde_json::json!({"name": "@", "type": kind.as_str(), "value": sibling, "ttl": 60}),
			serde_json::json!({"name": "@", "type": kind.as_str(), "value": own, "ttl": 60}),
		];
		let (provider, state) = mock(records).await;
		provider
			.delete_exact("example.org", DnsRecord::new("example.org", kind, own, 60))
			.await
			.expect("exact deletion is supported");
		let state = state.lock().unwrap();
		assert_eq!(state.records.len(), 1);
		assert_eq!(
			state.records.values().next().unwrap()["value"],
			sibling,
			"the sibling must survive"
		);
	}
}

#[test]
fn selects_only_requested_value() {
	for (kind, value, expected) in [
		(
			RecordKind::A,
			"203.0.113.10",
			serde_json::json!({"type":"A", "name":"@", "address":"203.0.113.10"}),
		),
		(
			RecordKind::Txt,
			"v=spf1 -all",
			serde_json::json!({"type":"TXT", "name":"@", "value":"v=spf1 -all"}),
		),
		(
			RecordKind::Mx,
			"10 mx.example.org.",
			serde_json::json!({"type":"MX", "name":"@", "preference":10, "exchange":"mx.example.org"}),
		),
		(
			RecordKind::Srv,
			"0 5 443 svc.example.org.",
			serde_json::json!({"type":"SRV", "name":"@", "priority":0, "weight":5, "port":443, "target":"svc.example.org"}),
		),
	] {
		let record = DnsRecord::new("example.org", kind.clone(), value, 60);
		assert_eq!(
			super::super::super::exact::delete_item(&record, kind.as_str(), "@").unwrap(),
			expected
		);
	}
}
