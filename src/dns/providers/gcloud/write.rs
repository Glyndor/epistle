//! The Google Cloud DNS upsert and delete, each one a change of a record set.

use super::*;

impl GcloudProvider {
	pub(super) async fn upsert_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(&record.kind)?;
		let managed_zone = self.managed_zone_id(zone).await?;
		let rrsets = self.list_rrsets(&managed_zone).await?;
		let kind_str = record.kind.as_str();
		let fqdn = self.fqdn(&record);
		let existing = rrsets
			.into_iter()
			.find(|r| r.name == fqdn && r.kind == kind_str);
		let mut rrdatas = self.rrdatas(&record);
		// A change replaces the whole rrset. The upsert contract in
		// `src/dns/provider/mod.rs` replaces only the TXT of the same
		// purpose, so the siblings the live rrset holds go back in.
		if record.kind == RecordKind::Txt
			&& let Some(old) = &existing
		{
			let siblings = old
				.rrdatas
				.iter()
				.filter(|r| !same_txt_purpose(r, &record.value))
				.cloned();
			rrdatas = siblings.chain(rrdatas).collect();
		}
		let new_rrset = Rrset {
			name: fqdn.clone(),
			kind: kind_str.to_string(),
			ttl: record.ttl,
			rrdatas,
		};
		match existing {
			None => self.post_change(&managed_zone, &[new_rrset], &[]).await,
			Some(old) if old.ttl == new_rrset.ttl && same_rdatas(&record, &old, &new_rrset) => {
				Ok(())
			}
			Some(old) => self.post_change(&managed_zone, &[new_rrset], &[old]).await,
		}
	}

	pub(super) async fn delete_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(&record.kind)?;
		let managed_zone = self.managed_zone_id(zone).await?;
		let rrsets = self.list_rrsets(&managed_zone).await?;
		let kind_str = record.kind.as_str();
		let fqdn = self.fqdn(&record);
		let Some(target) = rrsets
			.into_iter()
			.find(|r| r.name == fqdn && r.kind == kind_str)
		else {
			return Ok(());
		};
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the rdata
		// whose value matches (a sibling ACME challenge at the same
		// owner survives), an empty-value delete drops every rdata
		// at the rrset (the DKIM rotator's retire path). Other
		// record kinds fall through to the rrset-delete path, which
		// is the existing whole-set semantics. Google Cloud DNS
		// treats an rrset as the unit of change, so the
		// value-bearing case reads the rrdatas, drops the matching
		// one, and replaces the rrset with the remainder (a
		// wholesale delete only when the rrset is fully gone).
		//
		// The match is on the logical value, so an rdata Cloud DNS
		// lists back with its strings spaced or escaped differently
		// is still found.
		if record.kind == RecordKind::Txt && !record.value.is_empty() {
			let remainder: Vec<String> = target
				.rrdatas
				.iter()
				.filter(|r| !same_txt_value(r, &record.value))
				.cloned()
				.collect();
			if remainder.len() == target.rrdatas.len() {
				// No rdata matched: idempotent, nothing to do.
				return Ok(());
			}
			if remainder.is_empty() {
				return self.post_change(&managed_zone, &[], &[target]).await;
			}
			let target_name = target.name.clone();
			let target_kind = target.kind.clone();
			let target_ttl = target.ttl;
			let replacement = Rrset {
				name: target_name,
				kind: target_kind,
				ttl: target_ttl,
				rrdatas: remainder,
			};
			return self
				.post_change(&managed_zone, &[replacement], &[target])
				.await;
		}
		self.post_change(&managed_zone, &[], &[target]).await
	}
}
