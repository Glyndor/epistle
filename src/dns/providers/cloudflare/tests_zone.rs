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
