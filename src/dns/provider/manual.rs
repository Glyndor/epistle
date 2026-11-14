use super::{DnsProvider, DnsRecord, ListOp, Op, ProviderError};
use crate::dns::publish::provider::SnapshotOp;

/// Manual mode: no API access. Writes fail with [`ProviderError::Unsupported`]
/// so callers fall back to printing the records for the operator to add by
/// hand. Always available; needs no credentials.
pub struct ManualProvider;

impl DnsProvider for ManualProvider {
	fn check_access<'a>(
		&'a self,
		_: &'a str,
		_: &'a [String],
	) -> crate::dns::providers::check::CheckOp<'a> {
		Box::pin(async { crate::dns::providers::check::AccessReport::unknown() })
	}
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Unsupported) })
	}
	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Unsupported) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
	/// Manual mode has no zone to snapshot. Its listing is empty because
	/// there is no API behind it, not because the zone holds nothing, so
	/// the snapshot refuses instead of handing out an empty zone.
	fn publish_snapshot<'a>(&'a self, _zone: &'a str) -> SnapshotOp<'a> {
		Box::pin(async { Err(ProviderError::Unsupported) })
	}
}
