//! The guarded write of a Google Cloud DNS zone.
//!
//! Cloud DNS applies a change atomically, and the deletions of a change must
//! match the live record set exactly. So the precondition is the API's own:
//! the set at the name and type is read, compared with the one the plan was
//! made against, and then replaced by one change that deletes the set as it
//! was read and adds the new one. If another account changed the set in
//! between, the deletion no longer matches and Cloud DNS refuses the change
//! (HTTP 412); if it created a set where the plan saw none, the addition
//! collides and Cloud DNS refuses it (HTTP 409). Nothing is written in
//! either case, and no window is left between the check and the write.

use super::*;
use crate::dns::providers::guarded::{Fresh, Stop, held, within_scope};
use crate::dns::publish::provider::{Guard, ObservedRecord, Receipt, Snapshot};
use crate::dns::rrset::same_record;

impl GcloudProvider {
	/// The zone as Cloud DNS lists it. A record set has no id, so the
	/// identity is the set itself.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		let records =
			crate::dns::providers::listing(zone.to_string(), self.list_inner(zone)).await?;
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
			// The deadline ran out: the change may have gone out.
			Ok(Err(Stop::Unknown)) | Err(_) => Receipt::Unknown,
		}
	}

	async fn run(&self, zone: &str, change: &Change) -> Result<(), Stop> {
		let probe = DnsRecord::new(&change.name, change.kind.clone(), "", 0);
		self.authorize(&probe)?;
		within_scope(change)?;
		Self::api_kind(&change.kind)?;
		let managed_zone = self.managed_zone_id(zone).await?;
		let fqdn = self.fqdn(&probe);
		let kind = change.kind.as_str();
		let existing = self
			.list_rrsets(&managed_zone)
			.await?
			.into_iter()
			.find(|r| r.name == fqdn && r.kind == kind);
		let fresh: Vec<Fresh> = existing
			.iter()
			.flat_map(Self::records_of)
			.map(|record| Fresh {
				id: String::new(),
				record,
			})
			.collect();
		held(change, &fresh).ok_or(Stop::Changed)?;
		let additions = match change.after.first() {
			None => Vec::new(),
			Some(first) => vec![Rrset {
				name: fqdn,
				kind: kind.to_string(),
				ttl: first.ttl,
				rrdatas: change.after.iter().flat_map(|r| self.rrdatas(r)).collect(),
			}],
		};
		if let (Some(old), [new]) = (&existing, additions.as_slice())
			&& old.ttl == new.ttl
			&& same_rdatas(&change.after[0], old, new)
		{
			return Ok(());
		}
		let deletions: Vec<Rrset> = existing.into_iter().collect();
		let response = match self
			.send_change(&managed_zone, &additions, &deletions)
			.await
		{
			Ok(response) => response,
			Err(ProviderError::Auth) => return Err(ProviderError::Auth.into()),
			Err(_) => return Err(Stop::Unknown),
		};
		match response.status() {
			status if status.is_success() => Ok(()),
			// The deletion no longer matches, or the set appeared: the
			// precondition failed and Cloud DNS wrote nothing.
			reqwest::StatusCode::PRECONDITION_FAILED | reqwest::StatusCode::CONFLICT => {
				Err(Stop::Changed)
			}
			reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
				Err(ProviderError::Auth.into())
			}
			status => Err(Stop::Refused(format!("HTTP {status}"))),
		}
	}

	/// Remove one value from its record set, whatever the type, in one
	/// change that deletes the set as it was read: Cloud DNS refuses it when
	/// the set changed since, so a value another account added is never
	/// lost with this one.
	pub(super) async fn delete_exact_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(&record.kind)?;
		if record.value.is_empty() {
			return Err(ProviderError::Unsupported);
		}
		let managed_zone = self.managed_zone_id(zone).await?;
		let fqdn = self.fqdn(&record);
		let kind = record.kind.as_str();
		let Some(old) = self
			.list_rrsets(&managed_zone)
			.await?
			.into_iter()
			.find(|r| r.name == fqdn && r.kind == kind)
		else {
			return Ok(());
		};
		let wanted = Self::records_of(&old);
		let remainder: Vec<String> = old
			.rrdatas
			.iter()
			.zip(&wanted)
			.filter(|(_, read)| !same_record(read, &record))
			.map(|(rdata, _)| rdata.clone())
			.collect();
		if remainder.len() == old.rrdatas.len() {
			return Ok(());
		}
		let replacement = (!remainder.is_empty()).then(|| Rrset {
			name: old.name.clone(),
			kind: old.kind.clone(),
			ttl: old.ttl,
			rrdatas: remainder,
		});
		self.post_change(&managed_zone, replacement.as_slice(), &[old])
			.await
	}
}
