//! Which providers offer `delete_exact`, and which keep the refusing default.
//!
//! A provider offers it only when removing one value cannot take a record that
//! is not ours with it, even while somebody else writes the zone. deSEC and
//! Route 53 rewrite the whole record set from what they read; DigitalOcean and
//! Porkbun delete by id without a condition on the value; Namecheap rewrites
//! the zone. A record added or changed between their read and their write would
//! be lost, so they answer `Unsupported` and the record is printed for removal
//! by hand. Google Cloud DNS (a change whose deletions must match exactly) and
//! RFC 2136 (an UPDATE that names the RDATA) are the two that stay.

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

fn record() -> DnsRecord {
	DnsRecord {
		name: "s1._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: "v=DKIM1; k=ed25519; p=AAAA".into(),
		ttl: 300,
		proxied: None,
	}
}

async fn refuses(provider: &dyn DnsProvider) -> bool {
	matches!(
		provider.delete_exact("example.org", record()).await,
		Err(ProviderError::Unsupported)
	)
}

#[tokio::test]
async fn the_providers_that_cannot_make_the_delete_atomic_refuse() {
	let secret = || ScopedSecret::new("example.org", "token");
	assert!(refuses(&crate::dns::providers::desec::DesecProvider::new(secret())).await);
	assert!(
		refuses(&crate::dns::providers::digitalocean::DigitaloceanProvider::new(secret())).await
	);
	assert!(
		refuses(&crate::dns::providers::porkbun::PorkbunProvider::new(
			ScopedSecret::new("example.org", "secret"),
			"key"
		))
		.await
	);
	assert!(
		refuses(&crate::dns::providers::route53::Route53Provider::new(
			"AKIA".into(),
			"secret".into(),
			"Z123".into()
		))
		.await
	);
}
