//! The guarded write of a Route 53 hosted zone.
//!
//! A change batch is transactional: Route 53 "either makes all or none of the
//! changes", and a `DELETE` must "specify all the same values" the record set
//! holds
//! (<https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html>,
//! read 2026-11-13). So the precondition is the API's own, the way it is for
//! Google Cloud DNS: the set at the name and type is read, compared with the
//! one the plan was made against, and replaced by one batch that deletes the
//! set exactly as it was read (every value and the TTL) and creates the new
//! one. A set another account changed in between no longer matches the
//! `DELETE`; a set it created where the plan saw none collides with the
//! `CREATE`. Route 53 refuses the batch with `InvalidChangeBatch` and nothing
//! is written, so no window is left between the check and the write.
//!
//! A set that is an alias or has a routing policy is never written: a change
//! that names it without those fields would not be the set that is there.

use super::list::{Rrset, read_name, records_of};
use super::*;
use crate::dns::names::{canonical_name, in_domain};
use crate::dns::providers::guarded::{Fresh, Stop, held, within_scope};
use crate::dns::publish::provider::{Guard, ObservedRecord, Receipt, Snapshot};

/// The messages of an `InvalidChangeBatch` that say the set is not the one
/// the batch was built against. The documentation names the error and not
/// these sentences; they are what the API is known to answer for a `DELETE`
/// that does not match, a `DELETE` of a set that is gone and a `CREATE` of a
/// set that exists.
const STALE: [&str; 3] = [
	"values provided do not match the current values",
	"but it was not found",
	"but it already exists",
];

/// One `<Change>` that names the set `name`/`kind` with `ttl` and `values`.
fn change_xml(action: &str, name: &str, kind: &str, ttl: u32, values: &[String]) -> String {
	let value_xml: String = values
		.iter()
		.map(|v| {
			format!(
				"<ResourceRecord><Value>{}</Value></ResourceRecord>",
				xml_escape(v)
			)
		})
		.collect();
	format!(
		"<Change><Action>{action}</Action><ResourceRecordSet>\
<Name>{}</Name><Type>{kind}</Type><TTL>{ttl}</TTL>\
<ResourceRecords>{value_xml}</ResourceRecords>\
</ResourceRecordSet></Change>",
		xml_escape(name),
	)
}

/// A value as a change writes it: a TXT quoted and split, the rest as is.
fn wire_value(record: &DnsRecord) -> String {
	if record.kind == RecordKind::Txt {
		txt_encode(&record.value, TXT_FORM)
	} else {
		record.value.clone()
	}
}

/// What a refused change batch means, from its status and body.
pub(super) fn verdict(status: reqwest::StatusCode, body: &str) -> Stop {
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return ProviderError::Auth.into();
	}
	if status.is_server_error() {
		// The batch may or may not have been applied.
		return Stop::Unknown;
	}
	if body.contains("InvalidChangeBatch") && STALE.iter().any(|m| body.contains(m)) {
		return Stop::Changed;
	}
	Stop::Refused(format!("HTTP {status}"))
}

impl Route53Provider {
	/// The zone as Route 53 lists it. A record set has no id, so the identity
	/// is the set itself.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
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
			guard: Guard::Checked,
		})
	}

	/// Apply `change` under the operation deadline and say what happened.
	pub(super) async fn apply_inner(&self, zone: &str, change: Change) -> Receipt {
		match crate::dns::providers::within(async { Ok(self.run(zone, &change).await) }).await {
			Ok(Ok(())) => Receipt::Applied {
				identity: None,
				revision: None,
			},
			Ok(Err(Stop::Changed)) => Receipt::PreconditionFailed,
			Ok(Err(Stop::Refused(reason))) => Receipt::Rejected(reason),
			// The deadline ran out: the batch may have gone out.
			Ok(Err(Stop::Unknown)) | Err(_) => Receipt::Unknown,
		}
	}

	/// The record set at `name` and `kind`, read again now. More than one
	/// set there means a routing policy, which is never written.
	async fn read_set(&self, zone: &str, name: &str, kind: &str) -> Result<Option<Rrset>, Stop> {
		let mut sets: Vec<Rrset> = self
			.all_rrsets(zone)
			.await?
			.into_iter()
			.filter(|r| {
				r.kind.eq_ignore_ascii_case(kind) && canonical_name(&read_name(&r.name)) == name
			})
			.collect();
		if sets.len() > 1 || sets.iter().any(|r| r.routed) {
			return Err(Stop::Refused(format!(
				"{name} {kind} is an alias or has a routing policy; it is left as it is"
			)));
		}
		Ok(sets.pop())
	}

	async fn run(&self, zone: &str, change: &Change) -> Result<(), Stop> {
		within_scope(change)?;
		let kind = record_type(&change.kind)?;
		let name = canonical_name(&change.name);
		if !in_domain(&name, &canonical_name(zone)) || !self.is_apex(zone).await? {
			return Err(Stop::Refused(format!(
				"{name} is not in the hosted zone {zone}"
			)));
		}
		let existing = self.read_set(zone, &name, kind).await?;
		let fresh: Vec<Fresh> = existing
			.iter()
			.flat_map(records_of)
			.map(|record| Fresh {
				id: String::new(),
				record,
			})
			.collect();
		held(change, &fresh).ok_or(Stop::Changed)?;
		let values: Vec<String> = change.after.iter().map(wire_value).collect();
		let ttl = change.after.first().map(|r| r.ttl);
		if let (Some(old), Some(ttl)) = (&existing, ttl)
			&& old.ttl == ttl
			&& same_values(old, &change.after)
		{
			return Ok(());
		}
		let fqdn = format!("{name}.");
		let mut changes = String::new();
		if let Some(old) = &existing {
			changes.push_str(&change_xml(
				"DELETE",
				&old.name,
				&old.kind,
				old.ttl,
				&old.values,
			));
		}
		if let Some(ttl) = ttl {
			changes.push_str(&change_xml("CREATE", &fqdn, kind, ttl, &values));
		}
		if changes.is_empty() {
			return Ok(());
		}
		// A request that failed on the way may have reached Route 53.
		let response = self.send_batch(&changes).await.map_err(|_| Stop::Unknown)?;
		let status = response.status();
		if status.is_success() {
			return Ok(());
		}
		let body = crate::dns::providers::read_body(response)
			.await
			.unwrap_or_default();
		Err(verdict(status, &body))
	}
}

/// Whether the set holds exactly the records of `after`, whatever the order.
fn same_values(old: &Rrset, after: &[DnsRecord]) -> bool {
	let held = records_of(old);
	if held.len() != after.len() {
		return false;
	}
	let mut used = vec![false; held.len()];
	after.iter().all(|wanted| {
		let found = held
			.iter()
			.enumerate()
			.position(|(i, h)| !used[i] && crate::dns::rrset::same_record(h, wanted));
		found.map(|i| used[i] = true).is_some()
	})
}
