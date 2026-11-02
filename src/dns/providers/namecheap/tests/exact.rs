//! Namecheap rewrites the whole zone to remove one host, so a record added
//! meanwhile anywhere in the zone would go with it. It does not claim an
//! exact delete: a caller that must not touch a record it did not read prints
//! the record for removal by hand instead.

use super::super::NamecheapProvider;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

#[tokio::test]
async fn delete_exact_is_not_offered() {
	let provider = NamecheapProvider::new(ScopedSecret::new("example.org", "user:key")).unwrap();
	let record = DnsRecord {
		name: "s1._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: "v=DKIM1; k=ed25519; p=AAAA".into(),
		ttl: 300,
		proxied: None,
	};
	let outcome = provider.delete_exact("example.org", record).await;
	assert!(matches!(outcome, Err(ProviderError::Unsupported)));
}
