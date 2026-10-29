//! DNS-01 publication through the real responder and captured Namecheap forms.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::base::{Shared, mock};
use crate::acme::challenge::{ChallengeResponder, Dns01, TxtVisibility};
use crate::acme::jws::AccountKey;

/// Observe the destination represented by the captured form, without real DNS.
struct WrittenTxt(Shared);

impl TxtVisibility for WrittenTxt {
	fn visible<'a>(
		&'a self,
		name: &'a str,
		value: &'a str,
	) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
		Box::pin(async move {
			let s = self.0.lock().expect("state");
			s.set_hosts_calls.iter().any(|call| {
				call.hosts().iter().any(|host| {
					let owner = format!(
						"{}.{}.{}",
						host.name,
						call.param("SLD").expect("SLD"),
						call.param("TLD").expect("TLD")
					);
					host.kind == "TXT" && owner == name && host.address == value
				})
			})
		})
	}
}

async fn publishes(domain: &str, label: &str) {
	let (provider, state) = mock("", None).await;
	let responder = Dns01::new(Arc::new(provider), Arc::new(WrittenTxt(state.clone())))
		.with_bounds(Duration::ZERO, Duration::ZERO);
	let (key, _) = AccountKey::generate().expect("account key");
	responder
		.publish(domain, "challenge-token", &key)
		.await
		.expect("published at the requested DNS owner");
	let s = state.lock().expect("state");
	// One lookup of the registered zone, then the read before setHosts.
	assert_eq!(s.get_hosts_calls.len(), 2);
	for call in &s.get_hosts_calls {
		assert_eq!(call["SLD"], "example");
		assert_eq!(call["TLD"], "org");
	}
	assert_eq!(s.set_hosts_calls.len(), 1);
	let call = &s.set_hosts_calls[0];
	assert_eq!(call.param("SLD"), Some("example"));
	assert_eq!(call.param("TLD"), Some("org"));
	assert_eq!(call.param("HostName1"), Some(label));
	assert_eq!(call.param("RecordType1"), Some("TXT"));
	assert_eq!(
		call.param("Address1"),
		Some(key.dns01_value("challenge-token").as_str())
	);
	assert_eq!(call.param("TTL1"), Some("60"));
}

#[tokio::test]
async fn a_subdomain_challenge_keeps_its_full_relative_name() {
	publishes("mail.example.org", "_acme-challenge.mail").await;
}

#[tokio::test]
async fn a_registered_domain_challenge_still_publishes() {
	publishes("example.org", "_acme-challenge").await;
}
