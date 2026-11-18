//! Listing the hosted zone: every page, the apex found from the SOA, and the
//! kinds and names as epistle reads them.

use super::zone::{Set, apex, set, start};
use super::*;
use crate::dns::providers::tests::listing_contract::{
	CAA_VALUE, HOSTILE_TYPE, HTTPS_VALUE, MX_DOTTED, NAPTR_VALUE, NS_TARGET, OPAQUE_VALUE,
	SVCB_VALUE, Shape, assert_kinds_kept,
};

fn names(records: &[DnsRecord]) -> Vec<String> {
	let mut names: Vec<String> = records
		.iter()
		.map(|r| format!("{} {} {}", r.name, r.kind.as_str(), r.value))
		.collect();
	names.sort();
	names
}

#[tokio::test]
async fn the_listing_follows_every_page() {
	let mut sets = apex();
	for i in 0..5 {
		sets.push(set(&format!("h{i}.example.org."), "A", &["192.0.2.1"]));
	}
	let (provider, zone) = start(sets).await;
	zone.lock().unwrap().page = Some(2);
	let listed = provider.list("example.org").await.expect("list");
	assert_eq!(listed.len(), 7, "{:?}", names(&listed));
	assert!(listed.iter().any(|r| r.name == "h4.example.org"));
	// The SOA lookup, then four pages, each starting where the last said.
	let queries = zone.lock().unwrap().queries.clone();
	assert_eq!(queries.len(), 5, "{queries:?}");
	assert_eq!(queries[1], "");
	assert_eq!(queries[2], "name=h0.example.org.&type=A");
}

#[tokio::test]
async fn a_page_that_points_back_at_itself_is_an_error_not_a_shorter_zone() {
	let mut sets = apex();
	sets.push(set("h0.example.org.", "A", &["192.0.2.1"]));
	sets.push(set("h0.example.org.", "A", &["192.0.2.2"]));
	sets.push(set("h1.example.org.", "A", &["192.0.2.3"]));
	let (provider, zone) = start(sets).await;
	// The page from `h0 A` holds one set and says the next starts at `h0 A`.
	zone.lock().unwrap().page = Some(1);
	let error = provider.list("example.org").await.unwrap_err();
	assert!(
		matches!(&error, ProviderError::Remote(m) if m.contains("inconsistent")),
		"{error:?}"
	);
}

#[tokio::test]
async fn the_zone_is_the_name_that_holds_the_soa() {
	let (provider, _zone) = start(apex()).await;
	assert_eq!(provider.has_zone("example.org").await, Ok(true));
	assert_eq!(provider.has_zone("mail.example.org").await, Ok(false));
	assert_eq!(
		crate::dns::zone::resolve(&provider, "mail.example.org").await,
		Ok("example.org".to_string())
	);
}

#[tokio::test]
async fn a_name_that_is_not_the_apex_is_not_listed() {
	let (provider, zone) = start(apex()).await;
	assert_eq!(
		provider.list("mail.example.org").await,
		Err(ProviderError::ZoneNotFound("mail.example.org".into()))
	);
	// Only the apex lookup went out.
	assert_eq!(zone.lock().unwrap().queries.len(), 1);
}

#[tokio::test]
async fn a_txt_is_read_back_to_its_text_and_a_wildcard_to_its_star() {
	let mut sets = apex();
	sets.push(set("\\052.example.org.", "A", &["192.0.2.1"]));
	sets.push(set(
		"sel._domainkey.example.org.",
		"TXT",
		&["\"v=DKIM1; k=ed25519; \" \"p=AAAA\""],
	));
	let (provider, _zone) = start(sets).await;
	let listed = provider.list("example.org").await.expect("list");
	assert!(listed.iter().any(|r| r.name == "*.example.org"));
	let dkim = listed
		.iter()
		.find(|r| r.kind == RecordKind::Txt)
		.expect("the TXT");
	assert_eq!(dkim.value, "v=DKIM1; k=ed25519; p=AAAA");
}

#[test]
fn an_octal_escape_is_read_and_a_lone_backslash_is_kept() {
	assert_eq!(
		super::super::list::read_name("\\052.example.org."),
		"*.example.org"
	);
	assert_eq!(
		super::super::list::read_name("a\\b.example.org"),
		"a\\b.example.org"
	);
	assert_eq!(super::super::list::read_name("a\\09"), "a\\09");
}

#[tokio::test]
async fn the_listing_keeps_every_kind() {
	let mut sets: Vec<Set> = apex();
	let at = |kind: &str, value: &str| set("example.org.", kind, &[value]);
	sets.extend([
		set("sub.example.org.", "NS", &[NS_TARGET]),
		at("CAA", CAA_VALUE),
		at("MX", MX_DOTTED),
		at("HTTPS", HTTPS_VALUE),
		at("SVCB", SVCB_VALUE),
		at("NAPTR", NAPTR_VALUE),
		at(HOSTILE_TYPE, OPAQUE_VALUE),
	]);
	let (provider, _zone) = start(sets).await;
	let listed: Vec<DnsRecord> = provider
		.list("example.org")
		.await
		.expect("list")
		.into_iter()
		.filter(|r| {
			!(r.name == "example.org" && matches!(&r.kind, RecordKind::Ns)
				|| matches!(&r.kind, RecordKind::Other(t) if t == "SOA"))
		})
		.collect();
	assert_kinds_kept(
		&listed,
		&Shape {
			mx: MX_DOTTED,
			..Shape::NAMED
		},
	);
}
