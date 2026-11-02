//! `delete_exact` is opt-in: a provider that has not been shown to match by
//! value answers `Unsupported`, so a caller never falls back to a delete that
//! matches by purpose.

use super::*;

struct ByPurposeOnly;

impl DnsProvider for ByPurposeOnly {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("delete_exact must not fall back to delete")
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn the_default_is_unsupported_and_does_not_fall_back_to_delete() {
	let record = DnsRecord {
		name: "s1._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: "v=DKIM1; k=ed25519; p=AAAA".into(),
		ttl: 300,
		proxied: None,
	};
	let outcome = ByPurposeOnly.delete_exact("example.org", record).await;
	assert!(matches!(outcome, Err(ProviderError::Unsupported)));
}
