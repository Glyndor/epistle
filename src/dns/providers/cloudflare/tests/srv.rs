//! Cloudflare keeps the SRV priority apart from the rest of the value:
//! `content` is `weight port target`. Epistle's own SRV records must read back
//! as `priority weight port target`, or they are taken for foreign ones.

use super::*;
use crate::dns::rrset::same_record;

const SRV: &str = r#"{"id":"s1","name":"_imaps._tcp.example.org","type":"SRV","content":"1 993 mail.example.org","priority":0,"ttl":300}"#;

fn wanted() -> DnsRecord {
	DnsRecord::new(
		"_imaps._tcp.example.org",
		RecordKind::Srv,
		"0 1 993 mail.example.org.",
		300,
	)
}

/// Listed SRV keeps its priority and is the same record as the wanted one.
#[tokio::test]
async fn list_keeps_the_srv_priority_and_matches_what_was_published() {
	let page = format!(r#"{{"result":[{SRV}],"result_info":{{"page":1,"total_pages":1}}}}"#);
	let (base, _seen) = crate::dns::tests::uri_probe::probe(&[
		r#"{"result":[{"id":"zone1"}],"success":true}"#,
		&page,
	])
	.await;
	let provider = CloudflareProvider::new(ScopedSecret::new(
		"example.org",
		crate::test_support::fixtures::api_token(),
	))
	.with_base(base);
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].value, "0 1 993 mail.example.org");
	assert!(same_record(&records[0], &wanted()), "not seen as foreign");
}

/// The exact-delete selector sees the priority too.
#[test]
fn exact_selector_matches_an_srv_by_priority() {
	let stored: super::super::RecordRef = serde_json::from_str(SRV).unwrap();
	assert!(super::super::exact::matches(&stored, &wanted()));
	let mut other = wanted();
	other.value = "5 1 993 mail.example.org.".into();
	assert!(!super::super::exact::matches(&stored, &other));
}
