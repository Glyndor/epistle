//! `delete_exact` on Route 53: one batch that deletes the record set as it was
//! read and creates it again without the value, so a value that is not ours
//! stays and a change made in between makes the batch fail instead of being
//! overwritten.

use super::base::mock;
use super::*;

fn listing(name: &str, kind: &str, values: &[&str]) -> String {
	let records: String = values
		.iter()
		.map(|v| format!("<ResourceRecord><Value>{v}</Value></ResourceRecord>"))
		.collect();
	format!(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListResourceRecordSetsResult>\
<ResourceRecordSets><ResourceRecordSet><Name>{name}</Name><Type>{kind}</Type>\
<TTL>300</TTL><ResourceRecords>{records}</ResourceRecords></ResourceRecordSet>\
</ResourceRecordSets></ListResourceRecordSetsResult>"
	)
}

fn values_of(chunk: &str) -> Vec<String> {
	chunk
		.split("<Value>")
		.skip(1)
		.map(|rest| rest[..rest.find("</Value>").unwrap()].to_string())
		.collect()
}

/// The `DELETE` names every value as read; the `CREATE` carries only what must
/// stay. The sibling must be in the second and the removed value out of it.
#[tokio::test]
async fn delete_exact_keeps_other_values_at_same_name_and_type() {
	for (kind, name, own, own_wire, sibling_wire) in [
		(
			RecordKind::Txt,
			"sel._domainkey.example.org",
			"v=DKIM1; k=ed25519; p=AAAA",
			"\"v=DKIM1; k=ed25519; p=AAAA\"",
			"\"v=DKIM1; k=ed25519; p=BBBB\"",
		),
		(
			RecordKind::A,
			"mail.example.org",
			"203.0.113.10",
			"203.0.113.10",
			"203.0.113.20",
		),
	] {
		let (provider, state) = mock().await;
		state.lock().unwrap().list_response = Some(listing(
			&format!("{name}."),
			kind.as_str(),
			&[sibling_wire, own_wire],
		));
		provider
			.delete_exact("example.org", DnsRecord::new(name, kind.clone(), own, 300))
			.await
			.expect("exact deletion is supported");
		let s = state.lock().unwrap();
		assert_eq!(s.bodies.len(), 1, "one atomic batch: {:?}", s.bodies);
		let body = &s.bodies[0];
		let delete = body.find("<Action>DELETE</Action>").expect("a DELETE");
		let create = body.find("<Action>CREATE</Action>").expect("a CREATE");
		assert!(delete < create, "{body}");
		assert!(!body.contains("UPSERT"), "{body}");
		let (deleted, created) = (values_of(&body[delete..create]), values_of(&body[create..]));
		assert_eq!(deleted, vec![sibling_wire, own_wire], "the set as read");
		assert_eq!(
			created,
			vec![sibling_wire],
			"{kind:?}: the sibling must survive"
		);
		assert!(!created.iter().any(|v| v.contains(own)));
	}
}

/// The last value goes with a plain `DELETE` of the set as read.
#[tokio::test]
async fn delete_exact_of_the_only_value_deletes_the_set() {
	let (provider, state) = mock().await;
	state.lock().unwrap().list_response =
		Some(listing("mail.example.org.", "MX", &["10 mx.example.org."]));
	provider
		.delete_exact(
			"example.org",
			DnsRecord::new("mail.example.org", RecordKind::Mx, "10 mx.example.org", 300),
		)
		.await
		.expect("exact deletion is supported");
	let s = state.lock().unwrap();
	let body = &s.bodies[0];
	assert!(body.contains("<Action>DELETE</Action>"), "{body}");
	assert!(!body.contains("<Action>CREATE</Action>"), "{body}");
}

/// A value that is not in the set sends nothing.
#[tokio::test]
async fn delete_exact_of_an_absent_value_writes_nothing() {
	let (provider, state) = mock().await;
	state.lock().unwrap().list_response =
		Some(listing("mail.example.org.", "A", &["203.0.113.20"]));
	provider
		.delete_exact(
			"example.org",
			DnsRecord::new("mail.example.org", RecordKind::A, "203.0.113.10", 300),
		)
		.await
		.expect("absent is already gone");
	assert!(state.lock().unwrap().bodies.is_empty());
}

/// An empty value would mean the whole set, which is what this is not.
#[tokio::test]
async fn delete_exact_refuses_an_empty_value() {
	let (provider, state) = mock().await;
	let outcome = provider
		.delete_exact(
			"example.org",
			DnsRecord::new("mail.example.org", RecordKind::A, "", 300),
		)
		.await;
	assert!(matches!(outcome, Err(ProviderError::Unsupported)));
	assert!(state.lock().unwrap().bodies.is_empty());
}
