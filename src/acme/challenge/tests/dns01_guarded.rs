//! The dns-01 challenge through a provider that checks a precondition: the
//! challenge is added next to the TXT records already at the name, and the
//! withdrawal takes away the challenge and nothing else.

use std::sync::Arc;

use super::*;
use crate::acme::challenge::fake_zone::Visible;
use crate::dns::publish::FakeGuardedProvider;

const NAME: &str = "_acme-challenge.mail.example.org";

fn txt(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::Txt, value, 60)
}

fn values(provider: &FakeGuardedProvider) -> Vec<String> {
	let mut values: Vec<String> = provider.records().into_iter().map(|r| r.value).collect();
	values.sort();
	values
}

#[tokio::test]
async fn the_challenge_goes_next_to_a_sibling_and_leaves_it_behind() {
	let provider = Arc::new(FakeGuardedProvider::holding(vec![txt("sibling-order")]));
	let responder = Dns01::new(provider.clone(), Arc::new(Visible))
		.with_bounds(std::time::Duration::ZERO, std::time::Duration::ZERO);
	let key = AccountKey::generate().expect("key").0;
	responder
		.publish("mail.example.org", "token-aaaa", &key)
		.await
		.expect("publish");
	let ours = key.dns01_value("token-aaaa");
	let mut both = vec![ours.clone(), "sibling-order".to_string()];
	both.sort();
	assert_eq!(values(&provider), both);
	responder
		.withdraw("mail.example.org", "token-aaaa", &key)
		.await;
	assert_eq!(values(&provider), ["sibling-order"]);
}
