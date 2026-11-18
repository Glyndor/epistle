//! One record set written under the guarded contract.
//!
//! Every writer that changes a record set goes through here: the reconcile
//! loop, the TLSA refresh, the dns-01 challenge and the per-domain DKIM
//! rotation. The change names the set at one name and type as it was read
//! and the set it must become, and the provider applies it only if the zone
//! still holds what was read; a record another account added in between is
//! never overwritten or removed.
//!
//! A provider that checks no precondition gets the ordinary write the caller
//! names instead (`upsert`, the exact removal or `delete`), as it did before:
//! there is no set to state a precondition against, and refusing would leave
//! the provider unusable.

use crate::dns::names::canonical_name;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};
use crate::dns::publish::provider::{
	Change, Guard, ObservedRecord, OperationOutcome, Precondition, Receipt,
};
use crate::dns::rrset::same_record;

/// Why a set was not written, or may not have been.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
	/// The provider could not be asked, or failed the ordinary write.
	Provider(ProviderError),
	/// The zone changed since it was read. Nothing was written.
	Changed,
	/// The provider applies no guarded change. Nothing was written.
	Unsupported,
	/// The provider refused the change, for this reason. Nothing was
	/// written.
	Rejected(String),
	/// The provider did not confirm the change and could not say what
	/// became of it. Nothing else may be written until it is resolved.
	Unconfirmed,
}

impl std::fmt::Display for WriteError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			WriteError::Provider(error) => write!(f, "{error}"),
			WriteError::Changed => {
				f.write_str("the zone changed since it was read; nothing was written")
			}
			WriteError::Unsupported => {
				f.write_str("the provider applies no guarded change; nothing was written")
			}
			WriteError::Rejected(reason) => write!(
				f,
				"the provider refused the change: {}",
				crate::cli::term::sanitize(reason)
			),
			WriteError::Unconfirmed => f.write_str(
				"the provider did not confirm the change; nothing else is written until it is resolved",
			),
		}
	}
}

impl From<ProviderError> for WriteError {
	fn from(error: ProviderError) -> Self {
		WriteError::Provider(error)
	}
}

/// What a guarded change left, as the provider confirmed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
	/// The identity the provider gave the change, when it has one.
	pub identity: Option<String>,
	/// The revision of the zone after the change, when the provider has one.
	pub revision: Option<String>,
}

/// The set at one name and type as it was read, and the set it must become.
#[derive(Debug, Clone)]
pub struct SetChange {
	/// The name of the set.
	pub name: String,
	/// The type of the set.
	pub kind: RecordKind,
	/// The set as it was read, with the identities the provider gave it.
	pub before: Vec<ObservedRecord>,
	/// The set to write.
	pub after: Vec<DnsRecord>,
}

/// The set at `name` and `kind` in `records`.
pub fn set_at(records: &[ObservedRecord], name: &str, kind: &RecordKind) -> Vec<ObservedRecord> {
	let name = canonical_name(name);
	records
		.iter()
		.filter(|o| o.record.kind == *kind && canonical_name(&o.record.name) == name)
		.cloned()
		.collect()
}

/// Apply `set` in `zone`, under the precondition that the zone is still at
/// `revision`, or, without one, that the set is still the one read.
/// `operation` names the change so a lost answer can be resolved.
///
/// The error says why nothing was written, or that the outcome is not known
/// and nothing else may be written until it is resolved.
pub async fn apply(
	provider: &dyn DnsProvider,
	zone: &str,
	set: SetChange,
	revision: Option<String>,
	operation: String,
) -> Result<Applied, WriteError> {
	let change = Change {
		name: set.name,
		kind: set.kind,
		before: set.before,
		after: set.after,
		precondition: match revision {
			Some(revision) => Precondition::Revision(revision),
			None => Precondition::Identity,
		},
		operation_id: operation.clone(),
	};
	match provider.apply_guarded(zone, change).await {
		Receipt::Applied { identity, revision } => Ok(Applied { identity, revision }),
		Receipt::Unknown => match provider.lookup_operation(&operation).await {
			Ok(OperationOutcome::Applied) => Ok(Applied::default()),
			_ => Err(WriteError::Unconfirmed),
		},
		Receipt::PreconditionFailed => Err(WriteError::Changed),
		Receipt::Unsupported => Err(WriteError::Unsupported),
		Receipt::Rejected(reason) => Err(WriteError::Rejected(reason)),
	}
}

/// The ordinary write a provider without a precondition gets instead.
#[derive(Debug, Clone)]
pub enum Unguarded {
	/// [`DnsProvider::upsert`] of the record.
	Upsert(DnsRecord),
	/// [`DnsProvider::delete_exact`] of the record, and [`DnsProvider::delete`]
	/// when the provider cannot remove one value.
	Remove(DnsRecord),
	/// [`DnsProvider::delete`] of the record: for a TXT with an empty value,
	/// the whole TXT set at the name.
	Delete(DnsRecord),
}

impl Unguarded {
	async fn run(self, provider: &dyn DnsProvider, zone: &str) -> Result<(), ProviderError> {
		match self {
			Unguarded::Upsert(record) => provider.upsert(zone, record).await,
			Unguarded::Remove(record) => match provider.delete_exact(zone, record.clone()).await {
				Err(ProviderError::Unsupported) => provider.delete(zone, record).await,
				outcome => outcome,
			},
			Unguarded::Delete(record) => provider.delete(zone, record).await,
		}
	}
}

/// Make the set at `name` and `kind` in `zone` what `plan` makes of the set
/// that is there now, under the guarded contract; a provider that checks no
/// precondition gets `unguarded`. A plan that leaves the set as it is writes
/// nothing. The caller holds the lock of the zone (see
/// [`crate::dns::zone_lock`]).
pub async fn replace_set(
	provider: &dyn DnsProvider,
	zone: &str,
	name: &str,
	kind: &RecordKind,
	plan: impl FnOnce(&[DnsRecord]) -> Vec<DnsRecord>,
	unguarded: Unguarded,
	operation: String,
) -> Result<(), WriteError> {
	let snapshot = match provider.publish_snapshot(zone).await {
		Ok(snapshot) if snapshot.guard == Guard::Checked => snapshot,
		// The provider takes no precondition, or cannot read its zone: the
		// write it offers is the ordinary one.
		Ok(_) | Err(ProviderError::Unsupported) => {
			return Ok(unguarded.run(provider, zone).await?);
		}
		Err(error) => return Err(error.into()),
	};
	let before = set_at(&snapshot.records, name, kind);
	let held: Vec<DnsRecord> = before.iter().map(|o| o.record.clone()).collect();
	let after = plan(&held);
	if same_set(&held, &after) {
		return Ok(());
	}
	let set = SetChange {
		name: name.to_string(),
		kind: kind.clone(),
		before,
		after,
	};
	apply(provider, zone, set, snapshot.revision, operation)
		.await
		.map(|_| ())
}

/// Whether two sets hold the same records, whatever the order.
fn same_set(a: &[DnsRecord], b: &[DnsRecord]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let mut used = vec![false; b.len()];
	a.iter().all(|record| {
		let found = b.iter().enumerate().position(|(i, other)| {
			!used[i] && same_record(record, other) && record.ttl == other.ttl
		});
		found.map(|i| used[i] = true).is_some()
	})
}
