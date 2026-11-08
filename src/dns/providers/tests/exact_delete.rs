//! Which providers offer `delete_exact`, and which keep the refusing default.
//!
//! A provider offers it only when removing one value cannot take a record that
//! is not ours with it, even while somebody else writes the zone. deSEC and
//! Route 53 rewrite the whole record set from what they read, and Namecheap
//! rewrites the zone: a record added or changed between their read and their
//! write would be lost, so they answer `Unsupported` and the ordinary delete is
//! what remains. The providers that delete a record by its id (Cloudflare,
//! DigitalOcean, DNSimple, OVH, Porkbun, Spaceship, Bunny) match the value in
//! their own listing first and remove that one id, so a record somebody else
//! adds in between survives; only a value edited in place between the read and
//! the delete could still be hit. Google Cloud DNS (a change whose deletions
//! must match exactly) and RFC 2136 (an UPDATE that names the RDATA) were the
//! first two.

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
		refuses(&crate::dns::providers::route53::Route53Provider::new(
			"AKIA".into(),
			"secret".into(),
			"Z123".into()
		))
		.await
	);
}
