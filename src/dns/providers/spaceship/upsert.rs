//! The Spaceship upsert and delete.

use super::*;

impl SpaceshipProvider {
	pub(super) async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = self.relative_name(&record.name);
		// Spaceship has no in-place update: remove the existing matching
		// record first, then add the new one. remove() is a 204 either way,
		// so this is also the idempotent path when the record is absent.
		if record.kind == RecordKind::Txt {
			// A TXT delete matches the exact stored value, so the record
			// to remove is the OLD one of the same purpose (the contract
			// in `src/dns/provider/mod.rs`), read from the zone; removing by
			// the new value would leave a rotated DKIM key behind. A
			// sibling of another purpose is never named.
			for old in self.txt_values_at(&rel).await? {
				if same_txt_purpose(&old, &record.value) {
					self.remove_value(kind, &rel, Some(old)).await?;
				}
			}
		} else {
			self.remove(kind, &rel, &record).await?;
		}
		self.add(kind, &rel, &record).await
	}

	/// The stored values of every TXT at the relative name `rel`, as the
	/// list returns them.
	pub(super) async fn txt_values_at(&self, rel: &str) -> Result<Vec<String>, ProviderError> {
		Ok(self
			.list_all()
			.await?
			.into_iter()
			.filter(|item| {
				item.get("type").and_then(|v| v.as_str()) == Some("TXT")
					&& item.get("name").and_then(|v| v.as_str()) == Some(rel)
			})
			.filter_map(|item| {
				item.get("value")
					.and_then(|v| v.as_str())
					.map(str::to_string)
			})
			.collect())
	}

	pub(super) async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = self.relative_name(&record.name);
		self.remove(kind, &rel, &record).await
	}
}
