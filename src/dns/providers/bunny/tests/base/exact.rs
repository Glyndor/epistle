use super::*;

/// A whole-set delete or first-by-name selection must fail this regression.
#[tokio::test]
async fn delete_exact_keeps_other_values_at_same_name_and_type() {
	for (kind, api_type, own, sibling) in [
		(RecordKind::A, 0, "203.0.113.10", "203.0.113.20"),
		(RecordKind::Txt, 3, "v=spf1 -all", "v=spf1 mx -all"),
	] {
		let (provider, state) = mock().await;
		state.lock().unwrap().zone_detail = serde_json::json!({
			"Id": 42,
			"Records": [
				{"Id": 2, "Type": api_type, "Name": "", "Value": sibling, "Ttl": 60},
				{"Id": 1, "Type": api_type, "Name": "", "Value": own, "Ttl": 60},
			]
		});
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
			vec!["DELETE /dnszone/42/records/1"],
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
			let mut wire = serde_json::json!({"Id": 1, "Type": 0, "Name": "", "Value": "203.0.113.10", "Ttl": 60});
			wire["Type"] = serde_json::json!(if kind == RecordKind::Txt { 3 } else { 0 });
			wire["Value"] = value.into();
			let stored = serde_json::from_value(wire).unwrap();
			assert_eq!(
				super::super::super::exact::matches(&stored, &record, ""),
				expected,
				"{kind:?}: {value}"
			);
		}
	}
}
