//! The upsert contract against the Porkbun mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.

use super::*;
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

const NAME: &str = "sel._domainkey.example.org";

/// A zone holding the sibling (id 1, listed first) and the old DKIM key
/// (id 2) at the same name.
async fn zone_with_sibling_and_old_key() -> (PorkbunProvider, Shared) {
	mock(serde_json::json!([
		stored("1", NAME, "TXT", SIBLING),
		stored("2", NAME, "TXT", OLD_DKIM),
	]))
	.await
}

fn writes(state: &Shared) -> Vec<String> {
	state
		.lock()
		.unwrap()
		.paths()
		.into_iter()
		.filter(|p| !p.starts_with("/dns/retrieve"))
		.map(str::to_string)
		.collect()
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let (provider, state) = zone_with_sibling_and_old_key().await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert!(
		!writes(&state).iter().any(|w| w.ends_with("/1")),
		"the sibling was edited or deleted: {:?}",
		writes(&state)
	);
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let (provider, state) = zone_with_sibling_and_old_key().await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert_eq!(writes(&state), vec!["/dns/edit/example.org/2"]);
	assert_eq!(
		state.lock().unwrap().body("/dns/edit/example.org/2")["content"],
		NEW_DKIM
	);
}

/// Two records of the same purpose are a configuration mistake the upsert
/// collapses: the first is edited, the other deleted, the sibling kept.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose_only() {
	let (provider, state) = mock(serde_json::json!([
		stored("1", NAME, "TXT", SIBLING),
		stored("2", NAME, "TXT", OLD_DKIM),
		stored("3", NAME, "TXT", "v=DKIM1; k=rsa; p=STRAY"),
	]))
	.await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert_eq!(
		writes(&state),
		vec!["/dns/edit/example.org/2", "/dns/delete/example.org/3"]
	);
}
