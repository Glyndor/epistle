//! Writing the TLSA value into the zone without touching records that are
//! not epistle's.
//!
//! The generic `upsert` replaces the whole `(name, type)` set, so it is used
//! only when the set holds nothing that is not epistle's own. When the set
//! holds records of somebody else, or when the new value should sit next to
//! the old one, the change goes through the guarded contract of
//! [`crate::dns::publish::provider`]: the provider applies the exact set
//! this module planned, only if the zone still holds what was read. A
//! provider that applies no guarded change never gets a write that could
//! remove a foreign record: the refresh fails closed and says why.

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};
use crate::dns::publish::provider::{
	Change, Guard, ObservedRecord, OperationOutcome, Precondition, Receipt,
};

use super::plan::{Decision, decide, normal};

/// Why a value was not written.
#[derive(Debug)]
pub(super) enum Refused {
	/// The provider cannot write at all.
	Unsupported,
	/// Not written, for this reason. Tried again later.
	Failed(String),
}

impl From<ProviderError> for Refused {
	fn from(error: ProviderError) -> Self {
		match error {
			ProviderError::Unsupported => Refused::Unsupported,
			other => Refused::Failed(other.to_string()),
		}
	}
}

/// Publish `value` at `_25._tcp.<hostname>`, leaving every record that is
/// not in `known` (the values this instance wrote, newest first) as it is.
pub(super) async fn publish(
	provider: &dyn DnsProvider,
	hostname: &str,
	value: &str,
	known: &[String],
) -> Result<(), Refused> {
	let name = format!("_25._tcp.{hostname}");
	let zone = crate::dns::zone::resolve(provider, hostname).await?;
	let record = DnsRecord::new(name.clone(), RecordKind::Tlsa, value, super::TTL);
	let snapshot = match provider.publish_snapshot(&zone).await {
		Ok(snapshot) => snapshot,
		// A provider that cannot read its zone cannot be asked who wrote
		// what; it keeps the whole-set write the operator configured.
		Err(ProviderError::Unsupported) => {
			return Ok(provider.upsert(&zone, record).await?);
		}
		Err(error) => return Err(error.into()),
	};
	let listing: Vec<DnsRecord> = snapshot.records.iter().map(|o| o.record.clone()).collect();
	crate::dns::zone::refuse_if_delegated(&zone, &name, &listing)?;
	let canonical = crate::dns::names::canonical_name(&name);
	let observed: Vec<ObservedRecord> = snapshot
		.records
		.iter()
		.filter(|o| o.record.kind == RecordKind::Tlsa)
		.filter(|o| crate::dns::names::canonical_name(&o.record.name) == canonical)
		.cloned()
		.collect();
	let set: Vec<DnsRecord> = observed.iter().map(|o| o.record.clone()).collect();
	let (foreign, overlap) = match decide(&set, value, known) {
		Decision::Present { .. } => return Ok(()),
		Decision::Write { foreign, overlap } => (foreign, overlap),
	};
	if snapshot.guard == Guard::Unchecked {
		if !foreign.is_empty() {
			return Err(Refused::Failed(foreign_refusal(&name, &foreign)));
		}
		return Ok(provider.upsert(&zone, record).await?);
	}
	let mut after = foreign;
	after.push(record);
	after.extend(overlap);
	let change = Change {
		name,
		kind: RecordKind::Tlsa,
		before: observed,
		after,
		precondition: match snapshot.revision {
			Some(revision) => Precondition::Revision(revision),
			None => Precondition::Identity,
		},
		operation_id: format!("epistle-tlsa-{}", normal(value).replace(' ', "-")),
	};
	let operation_id = change.operation_id.clone();
	let receipt = provider.apply_guarded(&zone, change).await;
	let applied = match receipt {
		Receipt::Applied { .. } => true,
		Receipt::Unknown => matches!(
			provider.lookup_operation(&operation_id).await?,
			OperationOutcome::Applied
		),
		Receipt::PreconditionFailed => {
			return Err(Refused::Failed(
				"the zone changed while the TLSA record was planned; nothing was written".into(),
			));
		}
		Receipt::Unsupported => {
			return Err(Refused::Failed(
				"the provider applies no guarded change; nothing was written".into(),
			));
		}
		Receipt::Rejected(reason) => {
			return Err(Refused::Failed(format!(
				"the provider refused the change: {}",
				crate::cli::term::sanitize(&reason)
			)));
		}
	};
	if !applied {
		return Err(Refused::Failed(
			"the provider did not confirm the change; nothing else was written until it is resolved"
				.into(),
		));
	}
	Ok(())
}

/// The refusal to replace records that are not epistle's.
fn foreign_refusal(name: &str, foreign: &[DnsRecord]) -> String {
	let values: Vec<String> = foreign
		.iter()
		.map(|record| crate::cli::term::sanitize(&record.value))
		.collect();
	format!(
		"{name} holds TLSA records this instance did not publish ({}) and the provider cannot replace one value only; they were not removed",
		values.join("; ")
	)
}
