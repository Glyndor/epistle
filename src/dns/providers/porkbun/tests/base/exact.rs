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

/// An SRV record epistle wrote is read back whole, port included, and an
/// exact delete finds it; the same record as the panel holds it (the plain
/// priority in `prio`, the rest in `content`) is found too, and a sibling
/// with another port is not.
#[tokio::test]
async fn an_srv_record_round_trips_and_is_found_by_the_exact_delete() {
	let own = "0 1 465 mail.example.org";
	let name = "_submissions._tcp.example.org";
	let mut written = stored("1", name, "SRV", own);
	written["prio"] = "0".into();
	let mut panel = stored("2", name, "SRV", "1 465 mail.example.org");
	panel["prio"] = "0".into();
	let mut sibling = stored("3", name, "SRV", "0 1 587 mail.example.org");
	sibling["prio"] = "0".into();
	let (provider, state) = mock(serde_json::json!([written, panel, sibling])).await;
	let listed = provider.list("example.org").await.expect("list");
	let values: Vec<_> = listed.iter().map(|r| r.value.as_str()).collect();
	assert_eq!(
		values,
		vec![
			"0 1 465 mail.example.org",
			"0 1 465 mail.example.org",
			"0 1 587 mail.example.org"
		],
		"the port survives the listing"
	);
	provider
		.delete_exact(
			"example.org",
			DnsRecord::new(name, RecordKind::Srv, own, 60),
		)
		.await
		.expect("exact deletion");
	let state = state.lock().unwrap();
	let deletes: Vec<_> = state
		.paths()
		.into_iter()
		.filter(|p| p.starts_with("/dns/delete/"))
		.collect();
	assert_eq!(
		deletes,
		vec!["/dns/delete/example.org/1", "/dns/delete/example.org/2"],
		"both spellings of the record go, the sibling stays"
	);
}
