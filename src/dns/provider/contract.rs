use std::pin::Pin;

use super::{DnsRecord, ProviderError};
use crate::dns::publish::provider::{
	Change, Guard, ObservedRecord, OperationOp, OperationOutcome, Receipt, ReceiptOp, Snapshot,
	SnapshotOp,
};

pub(crate) type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
pub(crate) type ListOp<'a> =
	Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// The answer of a provider's zone lookup: whether it holds the zone.
pub type ZoneOp<'a> = Pin<Box<dyn Future<Output = Result<bool, ProviderError>> + Send + 'a>>;

/// A DNS provider that can publish and remove records in a zone. Object-safe
/// and test-injectable (mirrors the [`crate::spf::DnsLookup`] pattern).
pub trait DnsProvider: Send + Sync {
	/// Inspect credential capabilities using read operations only. Unsupported
	/// metadata stays unknown; a successful listing proves only record reading.
	fn check_access<'a>(
		&'a self,
		zone: &'a str,
		_names: &'a [String],
	) -> crate::dns::providers::check::CheckOp<'a> {
		Box::pin(async move {
			let mut report = crate::dns::providers::check::AccessReport::unknown();
			report.record_read = match self.list(zone).await {
				Ok(_) => crate::dns::providers::check::Finding::verified(
					"records can be read in the configured zone",
				),
				Err(ProviderError::Unsupported) => report.record_read,
				Err(error) => crate::dns::providers::check::Finding::failure(
					crate::dns::providers::check::failure_cause(&error),
				),
			};
			report
		})
	}
	/// Create or replace `record` in `zone`. The contract on matching is
	/// spelled out at the top of the module:
	///
	/// - For TXT, `upsert` replaces the TXT with the same purpose (version
	///   tag) at that name and leaves every other TXT at the name alone. A
	///   TXT without a known tag matches only an identical value.
	/// - For every other record kind, `upsert` replaces the whole
	///   `(name, type)` set with the one record in `record`. epistle owns
	///   those names; nothing else is supposed to be writing them.
	///
	/// Implementations are free to issue the minimum number of API calls
	/// that satisfies the contract (e.g. GoDaddy reads the current set,
	/// swaps the matching element, and PUTs the result).
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_>;
	/// Remove `record` from `zone`. Idempotent. The matching rule is the
	/// same as [`DnsProvider::upsert`]:
	///
	/// - For TXT, `delete` with a value removes only the matching record
	///   (same purpose for tagged values, identical value otherwise). An
	///   empty value removes the whole TXT set at the name, the way the
	///   DKIM rotator retires a selector.
	/// - For every other record kind, `delete` removes the whole
	///   `(name, type)` set.
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_>;
	/// Remove only the TXT record whose logical value is `record.value`
	/// ([`crate::dns::txt::same_txt_value`]: whitespace, quoting and 255-octet
	/// splitting do not count), and nothing else at the name.
	///
	/// [`DnsProvider::delete`] matches a tagged value (`v=DKIM1`, `v=spf1`) by
	/// its tag, so it can take another record with the same tag along. A
	/// caller that must not touch a record it did not read uses this method.
	/// A provider that cannot match by value, or that has not been shown to,
	/// keeps this default and answers [`ProviderError::Unsupported`]; the
	/// caller then leaves the record for the operator to remove by hand. An
	/// empty value is refused the same way: it would mean the whole set.
	fn delete_exact(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Unsupported) })
	}
	/// List the records epistle manages in `zone`.
	fn list(&self, zone: &str) -> ListOp<'_>;
	/// Whether this provider flattens a CNAME at the apex of `zone`, so that
	/// other record types (MX, TXT, CAA) may sit next to it there. RFC 1034
	/// section 3.6.2 forbids that anywhere else, and a provider that does not
	/// flatten refuses it, so the default is `false`. Only the apex is
	/// affected: a CNAME at any other name still excludes the other types.
	fn flattens_apex_cname(&self, _zone: &str) -> bool {
		false
	}
	/// Whether `zone` is a zone this provider holds.
	///
	/// A record name is not a zone: `mail.example.org` is a name inside the
	/// `example.org` zone, and a provider that names its zones looks one
	/// up by its exact name — handed the name, it answers "zone not found"
	/// and the write never happens. A caller that holds a name and not a
	/// zone asks the provider which zone holds the name, one candidate at
	/// a time (see [`crate::dns::zone::resolve`]).
	///
	/// The answer has three shapes, and the difference between the last two
	/// is the whole point of the question:
	///
	/// - `Ok(true)`: the provider holds the zone.
	/// - `Ok(false)`: the provider does not hold it, and the caller may go
	///   on to the next candidate.
	/// - `Err`: the provider could not answer. The caller stops: a zone
	///   that did not answer is not a zone that is not there, and a record
	///   written in another zone is a record in the wrong place.
	///
	/// The default answers by listing the zone: a provider that can list a
	/// zone holds it. A provider that does not name zones at all lists
	/// every name, and the caller then keeps the name as the zone, the way
	/// it wrote before. The listing tells "that zone is not there" from
	/// "the provider could not answer" only when it says so: a provider
	/// that names its zones reports the missing one as
	/// [`ProviderError::ZoneNotFound`].
	fn has_zone<'a>(&'a self, zone: &'a str) -> ZoneOp<'a> {
		Box::pin(async move {
			match self.list(zone).await {
				Ok(_) => Ok(true),
				// The provider answered: it holds no zone with that name,
				// and the search goes on to the parent.
				Err(ProviderError::ZoneNotFound(_)) => Ok(false),
				// A provider that cannot list cannot say which zone it
				// holds: it claims none, and the write decides, the way
				// it did before the search existed.
				Err(ProviderError::Unsupported) => Ok(false),
				// The provider could not answer: the search stops here.
				Err(error) => Err(error),
			}
		})
	}
	/// Take a snapshot of `zone`: every record it holds, the identities the
	/// provider gives them, its revision, and whether it applies a guarded
	/// change.
	///
	/// The default answers with the listing alone and declares the provider
	/// unchecked: a provider that says nothing about a precondition has
	/// none, and a plan built on such a snapshot is not applicable.
	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		Box::pin(async move {
			let records = self.list(zone).await?;
			Ok(Snapshot {
				zone: zone.to_string(),
				records: records
					.into_iter()
					.map(|record| ObservedRecord {
						record,
						identity: None,
					})
					.collect(),
				revision: None,
				guard: Guard::Unchecked,
			})
		})
	}
	/// Apply `change` to `zone` when its precondition still holds.
	///
	/// The default refuses and writes nothing. It never falls back to
	/// `upsert`: a write that cannot be conditioned may destroy the records
	/// of somebody else, so a provider that does not implement this cannot
	/// publish. The answer to a change whose precondition did not hold is
	/// [`Receipt::PreconditionFailed`], and a change whose answer was lost
	/// is [`Receipt::Unknown`], which the caller resolves with
	/// [`DnsProvider::lookup_operation`] before it writes anything else.
	fn apply_guarded<'a>(&'a self, _zone: &'a str, _change: Change) -> ReceiptOp<'a> {
		Box::pin(async { Receipt::Unsupported })
	}
	/// Ask the provider what became of the operation `operation_id`.
	///
	/// The default answers [`OperationOutcome::Unsupported`]: a provider
	/// that keeps no record of its operations cannot resolve a lost answer,
	/// and that is not a success.
	fn lookup_operation<'a>(&'a self, _operation_id: &'a str) -> OperationOp<'a> {
		Box::pin(async { Ok(OperationOutcome::Unsupported) })
	}
}
