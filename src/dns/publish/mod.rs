//! The publication of DNS records under a precondition.
//!
//! A provider that publishes records one by one cannot say what it found
//! before it wrote, so a second writer's records can be destroyed by a write
//! that was planned against an older listing. The contract in [`provider`]
//! adds the three operations a guarded publication needs: the snapshot of
//! the zone, the change applied under a precondition, and the lookup of an
//! operation whose answer was lost.
//!
//! The trait methods live in [`crate::dns::provider`], and the types they
//! carry here. A provider that does not implement them refuses to publish:
//! the default answers `Unsupported` and never falls back to `upsert`.

pub mod provider;

pub use provider::{
	Change, FakeGuardedProvider, Guard, ObservedRecord, OperationOp, OperationOutcome,
	Precondition, Receipt, ReceiptOp, Snapshot, SnapshotOp,
};

#[cfg(test)]
mod tests;
