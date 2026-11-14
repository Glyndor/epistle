//! Record-set preserving upsert and deletion.

use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};

use super::GodaddyProvider;
use super::records::{elements_match_kind, fqdn_to_relative};

impl GodaddyProvider {
	pub(super) async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = fqdn_to_relative(&record.name, &self.zone);
		let new_element = self.record_element(&record)?;
		// GoDaddy's PUT replaces the whole record set at (type, name).
		// An upsert is "publish this one record" without affecting
		// unrelated values at the same (type, name); the implementation
		// fetches the current set, swaps every matching element in
		// place (or appends the new one when nothing matches), and
		// PUTs the whole set back. A naive singleton PUT would erase
		// every other value at the owner, which is the bug a DKIM
		// publish on top of an existing SPF would otherwise trigger.
		// Two records of the same purpose at the same name are a
		// configuration mistake (SPF returns permerror, DMARC is
		// ignored): the upsert collapses them by dropping the
		// duplicates before the PUT.
		let mut set = self.fetch_set(kind, &rel).await?;
		let initial_len = set.len();
		set.retain(|element| !elements_match_kind(kind, element, &new_element));
		if set.len() < initial_len {
			// A matching element (or elements) was dropped. The new
			// value goes back as the one record of that purpose.
			set.push(new_element);
		} else {
			// No match by value: the new value is the first record
			// of this purpose at the owner.
			set.push(new_element);
		}
		let body = serde_json::Value::Array(set).to_string();
		self.put_records(kind, &rel, body).await
	}

	pub(super) async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = fqdn_to_relative(&record.name, &self.zone);
		// A TXT delete with an empty value retires the whole TXT set
		// at the owner (the DKIM rotator retires a selector this way).
		// The match-against-live-set path below would compare "" against
		// the live DKIM TXT and PUT the DKIM back as the remainder.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			return self.delete_records(kind, &rel).await;
		}
		let new_element = self.record_element(&record)?;
		// GoDaddy's DELETE removes every record at (type, name). A
		// delete is "remove this one record" without affecting other
		// values at the same (type, name); the implementation fetches
		// the current set, drops the matching element, and either PUTs
		// the remainder back or DELETEs the whole set when nothing
		// remains. A naive DELETE on a multi-value name would wipe
		// every value at the owner, which is the bug a stale ACME
		// challenge cleanup would otherwise trigger against a second
		// certificate order at the same owner.
		let set = self.fetch_set(kind, &rel).await?;
		let remainder: Vec<serde_json::Value> = set
			.into_iter()
			.filter(|element| !elements_match_kind(kind, element, &new_element))
			.collect();
		if remainder.is_empty() {
			self.delete_records(kind, &rel).await
		} else {
			let body = serde_json::Value::Array(remainder).to_string();
			self.put_records(kind, &rel, body).await
		}
	}
}
