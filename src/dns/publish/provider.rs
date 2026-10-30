//! The contract a provider honours to publish a record under a
//! precondition.
//!
//! Three pieces carry it: the [`Snapshot`] of a zone, the [`Change`] that
//! may be applied to it, and the [`Receipt`] that says what happened. A
//! provider that cannot check a precondition says so in the snapshot, and a
//! plan built on such a snapshot is not applicable.
//!
//! The types are opaque on purpose. The identity of a record and the
//! revision of a zone are the provider's own names for its own state: epistle
//! carries them, compares them and shows them, and never reads them.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Mutex;

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, same_txt_purpose};

/// The future of a snapshot.
pub type SnapshotOp<'a> =
	Pin<Box<dyn Future<Output = Result<Snapshot, ProviderError>> + Send + 'a>>;

/// The future of a guarded write.
pub type ReceiptOp<'a> = Pin<Box<dyn Future<Output = Receipt> + Send + 'a>>;

/// The future of an operation lookup.
pub type OperationOp<'a> =
	Pin<Box<dyn Future<Output = Result<OperationOutcome, ProviderError>> + Send + 'a>>;

/// A record as the provider holds it, with the identity it uses to address
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRecord {
	/// The record itself: name, type, value, TTL and proxy state.
	pub record: DnsRecord,
	/// The provider's own name for the record, when it has one. It is
	/// opaque: epistle carries it, compares it and shows it, and never
	/// parses it.
	pub identity: Option<String>,
}
/// Whether a provider checks a precondition before it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
	/// The provider applies a change only when the precondition holds.
	Checked,
	/// The provider writes without checking anything.
	Unchecked,
}

/// The zone as it was at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
	/// The zone the snapshot covers.
	pub zone: String,
	/// Every record the provider listed, in the order it listed them.
	pub records: Vec<ObservedRecord>,
	/// The provider's revision of the zone, when it has one.
	pub revision: Option<String>,
	/// Whether the provider applies a guarded change.
	pub guard: Guard,
}

/// The condition a provider must check before it applies a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
	/// The zone must still be at the revision the snapshot saw.
	Revision(String),
	/// The set at the name and the type of the change must still be the
	/// one the snapshot saw, with the identities it gave its records.
	Identity,
	/// Nothing may exist at the name and the type of the change: the
	/// change creates the first record of that set.
	Absent,
}

/// A change to apply to a zone under a precondition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
	/// The name the change touches.
	pub name: String,
	/// The type the change touches.
	pub kind: RecordKind,
	/// The records the provider held when the change was planned, with the
	/// identities it gave them. It is the whole set at the name, because a
	/// provider that replaces a set compares the set.
	pub before: Vec<ObservedRecord>,
	/// The records the provider must write. The delta touches only the
	/// values epistle owns; the records of somebody else stay as they are.
	pub after: Vec<DnsRecord>,
	/// The condition the provider must check before it writes.
	pub precondition: Precondition,
	/// The name of the operation, so an answer that was lost can be
	/// resolved afterwards.
	pub operation_id: String,
}

/// What a provider did with a guarded change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
	/// The change was applied and the provider confirms what it left.
	Applied {
		/// The identity the provider gave the change, when it has one.
		identity: Option<String>,
		/// The revision of the zone after the change, when the provider has
		/// one.
		revision: Option<String>,
	},
	/// The precondition did not hold. Nothing was written.
	PreconditionFailed,
	/// The provider applies no guarded change. Nothing was written.
	Unsupported,
	/// The answer was lost: the change may or may not have been applied.
	/// Nothing else may be written until the operation is resolved.
	Unknown,
	/// The provider refused the change. Nothing was written.
	Rejected(String),
}

/// What a provider knows of an operation it was asked to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationOutcome {
	/// The provider keeps no record of its operations.
	Unsupported,
	/// The provider does not know this operation.
	Unknown,
	/// The operation was applied.
	Applied,
	/// The operation was never applied.
	NotApplied,
	/// The operation is still running.
	Pending,
}

/// A provider that honours the guarded contract in memory.
///
/// It keeps the records it was given, checks the precondition of a change
/// against what it holds, refuses a change whose precondition does not
/// hold, and remembers the operation it applied, so an answer that was lost
/// can be resolved afterwards. It is the double the contract is written
/// against: a real provider has to reach the same verdicts through its own
/// API.
#[derive(Debug, Default)]
pub struct FakeGuardedProvider {
	state: Mutex<FakeState>,
}

/// The state the double keeps.
#[derive(Debug, Default)]
struct FakeState {
	/// The records it holds.
	records: Vec<ObservedRecord>,
	/// The revision of the zone, raised by every write.
	revision: u64,
	/// The operations it was asked to apply.
	operations: BTreeMap<String, OperationOutcome>,
}

impl FakeGuardedProvider {
	/// A double that holds `records`, each with an identity of its own, at
	/// revision one.
	pub fn holding(records: Vec<DnsRecord>) -> Self {
		let held = records
			.into_iter()
			.enumerate()
			.map(|(index, record)| ObservedRecord {
				record,
				identity: Some(format!("held-{index}")),
			})
			.collect();
		Self {
			state: Mutex::new(FakeState {
				records: held,
				revision: 1,
				operations: BTreeMap::new(),
			}),
		}
	}

	/// The records the double holds.
	pub fn records(&self) -> Vec<DnsRecord> {
		self.lock()
			.records
			.iter()
			.map(|observed| observed.record.clone())
			.collect()
	}

	/// The state of the double. A poisoned lock holds the state all the
	/// same, so it is taken instead of left panicking.
	fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
		self.state
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}
}

impl FakeState {
	/// Whether the precondition of `change` still holds against what the
	/// double holds.
	fn holds(&self, change: &Change) -> bool {
		match &change.precondition {
			Precondition::Revision(revision) => self.revision.to_string() == *revision,
			Precondition::Identity => {
				let held = self.set_at(&change.name, &change.kind);
				held.len() == change.before.len()
					&& held
						.iter()
						.zip(change.before.iter())
						.all(|(observed, expected)| {
							observed.record == expected.record
								&& observed.identity == expected.identity
						})
			}
			Precondition::Absent => self.set_at(&change.name, &change.kind).is_empty(),
		}
	}

	/// The records the double holds at a name and a type.
	fn set_at(&self, name: &str, kind: &RecordKind) -> Vec<&ObservedRecord> {
		self.records
			.iter()
			.filter(|observed| observed.record.name == name && observed.record.kind == *kind)
			.collect()
	}
}

impl DnsProvider for FakeGuardedProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		Box::pin(async move {
			let mut state = self.lock();
			let txt = matches!(&record.kind, RecordKind::Txt);
			state.records.retain(|observed| {
				if observed.record.name != record.name || observed.record.kind != record.kind {
					return true;
				}
				// A TXT is replaced by its purpose, every other kind by
				// the whole set at the name.
				!txt || !same_txt_purpose(&observed.record.value, &record.value)
			});
			state.records.push(ObservedRecord {
				record,
				identity: None,
			});
			state.revision += 1;
			Ok(())
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		Box::pin(async move {
			let mut state = self.lock();
			let txt = matches!(&record.kind, RecordKind::Txt);
			let empty = record.value.is_empty();
			state.records.retain(|observed| {
				if observed.record.name != record.name || observed.record.kind != record.kind {
					return true;
				}
				// An empty value removes the whole TXT set at the name,
				// every other write only the record of its purpose.
				!txt || empty || !same_txt_purpose(&observed.record.value, &record.value)
			});
			state.revision += 1;
			Ok(())
		})
	}

	fn list(&self, _zone: &str) -> crate::dns::provider::ListOp<'_> {
		Box::pin(async move { Ok(self.records()) })
	}

	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		Box::pin(async move {
			let state = self.lock();
			Ok(Snapshot {
				zone: zone.to_string(),
				records: state.records.clone(),
				revision: Some(state.revision.to_string()),
				guard: Guard::Checked,
			})
		})
	}

	fn apply_guarded<'a>(&'a self, _zone: &'a str, change: Change) -> ReceiptOp<'a> {
		Box::pin(async move {
			let mut state = self.lock();
			if !state.holds(&change) {
				return Receipt::PreconditionFailed;
			}
			state.records.retain(|observed| {
				!(observed.record.name == change.name && observed.record.kind == change.kind)
			});
			for record in change.after {
				state.records.push(ObservedRecord {
					record,
					identity: None,
				});
			}
			state.revision += 1;
			state
				.operations
				.insert(change.operation_id.clone(), OperationOutcome::Applied);
			Receipt::Applied {
				identity: None,
				revision: Some(state.revision.to_string()),
			}
		})
	}

	fn lookup_operation<'a>(&'a self, operation_id: &'a str) -> OperationOp<'a> {
		Box::pin(async move {
			Ok(self
				.lock()
				.operations
				.get(operation_id)
				.copied()
				.unwrap_or(OperationOutcome::Unknown))
		})
	}
}
