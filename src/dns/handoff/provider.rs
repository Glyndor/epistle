//! A DNS provider that asks the other container to do the writing.
//!
//! It is the same provider the rotation takes when the split is off, with
//! the calls the hand-off carries instead of the calls to the zone: the
//! rotation does not know which of the two it is talking to.

use super::Write;
use crate::dns::provider::{DnsProvider, DnsRecord, ListOp, Op, ProviderError};

/// A provider that writes through the hand-off.
#[derive(Debug, Clone)]
pub struct HandoffProvider {
	/// The asking side of the hand-off.
	writer: super::Writer,
}

impl HandoffProvider {
	/// The provider that writes through `writer`.
	pub fn new(writer: super::Writer) -> Self {
		HandoffProvider { writer }
	}
}

impl DnsProvider for HandoffProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.writer
				.perform(Write::publish(&record))
				.await
				.map_err(ProviderError::Remote)
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			// The hand-off takes a whole record set away, the way the
			// rotation retires a selector. A removal by value is not
			// something it can ask for, and it is refused rather than
			// turned into a wider removal than was asked for.
			if !record.value.is_empty() {
				return Err(ProviderError::Remote(
					"the DNS hand-off only removes a whole record set at a name".to_string(),
				));
			}
			self.writer
				.perform(Write::withdraw(&record.name))
				.await
				.map_err(ProviderError::Remote)
		})
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		// This process holds no credential, so it cannot read the zone. The
		// caller that needed the listing is told so, and the records it
		// cannot see are left alone.
		Box::pin(async {
			Err(ProviderError::Remote(
				"this process holds no DNS credential; the certificates container reads the zone"
					.to_string(),
			))
		})
	}
}
