//! Route 53 lists record sets a page at a time. The rrset the provider
//! reads before a TXT upsert or delete can sit on a later page, and the
//! read has to follow `IsTruncated` / `NextRecordName` / `NextRecordType`
//! until it finds it or the list ends.

use super::tests::mock;
use super::*;
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

const NAME: &str = "sel._domainkey.example.org";

/// Page one: an unrelated rrset and a pointer to the TXT rrset. Page two,
/// requested from that pointer: the TXT rrset with the sibling and the old
/// DKIM key, and the end of the list.
fn two_pages() -> std::collections::HashMap<String, String> {
	let head = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListResourceRecordSetsResult>";
	let first = format!(
		"{head}<ResourceRecordSets><ResourceRecordSet><Name>example.org.</Name>\
<Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.1</Value>\
</ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets>\
<IsTruncated>true</IsTruncated><MaxItems>1</MaxItems>\
<NextRecordName>{NAME}.</NextRecordName><NextRecordType>TXT</NextRecordType>\
</ListResourceRecordSetsResult>"
	);
	let second = format!(
		"{head}<ResourceRecordSets><ResourceRecordSet><Name>{NAME}.</Name><Type>TXT</Type>\
<TTL>3600</TTL><ResourceRecords>\
<ResourceRecord><Value>\"{SIBLING}\"</Value></ResourceRecord>\
<ResourceRecord><Value>\"{OLD_DKIM}\"</Value></ResourceRecord>\
</ResourceRecords></ResourceRecordSet></ResourceRecordSets>\
<IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResult>"
	);
	[(String::new(), first), (format!("{NAME}."), second)].into()
}

fn txt(value: &str) -> DnsRecord {
	DnsRecord {
		name: NAME.into(),
		kind: RecordKind::Txt,
		value: value.into(),
		ttl: 3600,
	}
}

fn values(body: &str) -> Vec<String> {
	body.split("<Value>")
		.skip(1)
		.map(|rest| rest[..rest.find("</Value>").unwrap()].to_string())
		.collect()
}

#[tokio::test]
async fn txt_delete_finds_the_rrset_on_a_later_page() {
	let (provider, state) = mock().await;
	state.lock().unwrap().list_pages = two_pages();
	provider
		.delete("example.org", txt(OLD_DKIM))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	let body = s.bodies.last().expect("the delete sent a change");
	assert_eq!(values(body), vec![format!("\"{SIBLING}\"")]);
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_found_on_a_later_page() {
	let (provider, state) = mock().await;
	state.lock().unwrap().list_pages = two_pages();
	provider
		.upsert("example.org", txt(NEW_DKIM))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let body = s.bodies.last().expect("a change");
	assert_eq!(
		values(body),
		vec![format!("\"{SIBLING}\""), format!("\"{NEW_DKIM}\"")]
	);
}

/// The second request starts where the first page said the list goes on.
#[tokio::test]
async fn the_next_page_starts_at_next_record_name_and_type() {
	let (provider, state) = mock().await;
	state.lock().unwrap().list_pages = two_pages();
	provider
		.delete("example.org", txt(OLD_DKIM))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(s.list_queries.len(), 2, "{:?}", s.list_queries);
	assert_eq!(s.list_queries[0], "");
	assert_eq!(
		s.list_queries[1],
		format!("name={NAME}.&type=TXT"),
		"{:?}",
		s.list_queries
	);
}

/// The signature covers the query string, in the form SigV4 prescribes:
/// pairs sorted, everything but `A-Za-z0-9-_.~` percent-encoded.
#[test]
fn canonical_query_sorts_and_encodes_the_aws_way() {
	let url = reqwest::Url::parse("http://h/p?type=TXT&name=*.example.org.").unwrap();
	assert_eq!(canonical_query(&url), "name=%2A.example.org.&type=TXT");
	let bare = reqwest::Url::parse("http://h/p").unwrap();
	assert_eq!(canonical_query(&bare), "");
}
