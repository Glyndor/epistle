//! Exact zone discovery and refusal of writes addressed to a reduced domain.

use super::base::{mock, txt};
use crate::dns::provider::{DnsProvider, ProviderError};

#[tokio::test]
async fn a_subdomain_is_absent_without_querying_its_parent() {
	let (provider, state) = mock("", None).await;
	assert_eq!(provider.has_zone("mail.example.org").await, Ok(false));
	assert_eq!(
		provider.list("mail.example.org").await,
		Err(ProviderError::ZoneNotFound("mail.example.org".into()))
	);
	assert!(state.lock().expect("state").urls.is_empty());
}

#[tokio::test]
async fn the_registered_domain_is_confirmed_even_when_empty() {
	let (provider, state) = mock("", None).await;
	assert_eq!(provider.has_zone("example.org").await, Ok(true));
	let s = state.lock().expect("state");
	assert_eq!(s.get_hosts_calls.len(), 1);
	assert_eq!(s.get_hosts_calls[0]["SLD"], "example");
	assert_eq!(s.get_hosts_calls[0]["TLD"], "org");
}

#[tokio::test]
async fn a_real_domain_failure_stops_discovery() {
	for (xml, expected) in [
		(
			r#"<ApiResponse Status="ERROR"><Errors><Error Number="9999999">provider unavailable</Error></Errors></ApiResponse>"#,
			ProviderError::Remote("provider unavailable".into()),
		),
		(
			r#"<ApiResponse Status="ERROR"><Errors><Error Number="1012801">IP not whitelisted</Error></Errors></ApiResponse>"#,
			ProviderError::Auth,
		),
	] {
		let (provider, state) = mock(xml, None).await;
		assert_eq!(
			provider.has_zone("example.org").await,
			Err(expected.clone())
		);
		assert_eq!(
			crate::dns::zone::resolve(&provider, "mail.example.org").await,
			Err(expected)
		);
		let s = state.lock().expect("state");
		assert_eq!(s.get_hosts_calls.len(), 2);
		for call in &s.get_hosts_calls {
			assert_eq!(call["SLD"], "example");
			assert_eq!(call["TLD"], "org");
		}
		assert!(s.set_hosts_calls.is_empty());
	}
}

#[tokio::test]
async fn a_direct_write_or_delete_cannot_use_a_subdomain_as_the_zone() {
	let (provider, state) = mock("", None).await;
	let record = txt("_acme-challenge.mail.example.org", "challenge");
	let expected = Err(ProviderError::ZoneNotFound("mail.example.org".into()));
	assert_eq!(
		provider.upsert("mail.example.org", record.clone()).await,
		expected
	);
	assert_eq!(provider.delete("mail.example.org", record).await, expected);
	assert_eq!(provider.set_hosts("mail.example.org", &[]).await, expected);
	assert!(state.lock().expect("state").urls.is_empty());
}

#[test]
fn a_multi_label_suffix_does_not_make_a_subdomain_a_zone() {
	use super::super::render::zone_parts;
	assert_eq!(
		zone_parts("mail.example.co.uk"),
		Err(ProviderError::ZoneNotFound("mail.example.co.uk".into()))
	);
	assert_eq!(
		zone_parts("example.co.uk."),
		Ok(("example".into(), "co.uk".into()))
	);
}
