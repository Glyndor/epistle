//! The zone lookup of the Cloudflare provider: a name below the zone is
//! not a zone of its own, so the search for the zone that holds a record
//! name can tell them apart.

use super::*;

#[tokio::test]
async fn a_name_below_the_zone_is_not_a_zone_of_its_own() {
	let (provider, _state) = mock(Vec::new()).await;
	assert!(
		provider
			.has_zone("example.org")
			.await
			.expect("the zone lookup answers"),
		"the zone the credential covers is a zone"
	);
	assert!(
		!provider
			.has_zone("mail.example.org")
			.await
			.expect("the zone lookup answers"),
		"a name below the zone is not a zone"
	);
}

#[tokio::test]
async fn the_zone_search_stops_when_the_provider_denies_the_child_zone() {
	// The child zone only failed to answer (403) and the parent is there.
	// The search stops at the child: a zone that did not answer does not
	// say that the parent holds the name, and the record must not land in
	// a zone the operator did not ask for.
	let (provider, state) = mock(Vec::new()).await;
	state.lock().unwrap().zone_denied = Some("mail.example.org".to_string());
	assert_eq!(
		crate::dns::zone::resolve(&provider, "mail.example.org")
			.await
			.expect_err("the failure is reported"),
		ProviderError::Auth
	);
}
