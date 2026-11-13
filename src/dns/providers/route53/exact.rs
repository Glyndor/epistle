//! Removing one value from a record set without taking another one with it.
//!
//! A change batch is atomic, and a `DELETE` in it must name the record set
//! exactly as it stands: the same TTL and every value. So the removal reads
//! the set, then sends one batch that deletes the set as read and creates it
//! again without the value. A value another account added after the read makes
//! the `DELETE` mismatch, Route 53 refuses the whole batch and nothing changes;
//! the operator runs the command again. This is the precondition the plain
//! delete lacks (its `UPSERT` of the remainder overwrites whatever is there).

use super::*;
use crate::dns::rrset::canonical_value;

/// One `<Change>` for the record set `name`/`kind` with `ttl` and `values`
/// verbatim as Route 53 listed them.
fn change_xml(action: &str, rrset: &Rrset, values: &[String]) -> String {
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
<Name>{}</Name><Type>{}</Type><TTL>{}</TTL>\
<ResourceRecords>{value_xml}</ResourceRecords>\
</ResourceRecordSet></Change>",
		xml_escape(&rrset.name),
		rrset.kind,
		rrset.ttl,
	)
}

/// Whether the listed rdata `stored` is the value of `record`. A TXT compares
/// by its logical text, the other kinds by their canonical form.
fn matches(stored: &str, record: &DnsRecord) -> bool {
	if record.kind == RecordKind::Txt {
		return same_txt_value(&txt_read(stored), &record.value);
	}
	canonical_value(&record.kind, stored) == canonical_value(&record.kind, &record.value)
}

impl Route53Provider {
	pub(super) async fn delete_exact_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		let kind = record_type(&record.kind)?;
		if record.value.is_empty() {
			return Err(ProviderError::Unsupported);
		}
		let Some(rrset) = self.fetch_rrset(&record.name, kind).await? else {
			return Ok(());
		};
		let remainder: Vec<String> = rrset
			.values
			.iter()
			.filter(|v| !matches(v, &record))
			.cloned()
			.collect();
		if remainder.len() == rrset.values.len() {
			// Not there: nothing to remove.
			return Ok(());
		}
		let mut changes = change_xml("DELETE", &rrset, &rrset.values);
		if !remainder.is_empty() {
			changes.push_str(&change_xml("CREATE", &rrset, &remainder));
		}
		self.post_batch(&changes).await
	}

	/// Submit `changes` as one change batch.
	async fn post_batch(&self, changes: &str) -> Result<(), ProviderError> {
		let response = self.send_batch(changes).await?;
		let status = response.status();
		if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	/// Send `changes` as one signed change batch and hand back the answer,
	/// whatever its status.
	pub(super) async fn send_batch(
		&self,
		changes: &str,
	) -> Result<reqwest::Response, ProviderError> {
		let body = format!(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/{API_VERSION}/\">\
<ChangeBatch><Changes>{changes}</Changes></ChangeBatch>\
</ChangeResourceRecordSetsRequest>"
		);
		let url = self.rrset_url()?;
		let path = url.as_url().path().to_string();
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default();
		let (amz_date, date) = timestamps(now.as_secs());
		let auth = self.authorization(&path, &body, &amz_date, &date);
		self.client
			.post(url.into_url())
			.header("x-amz-date", &amz_date)
			.header(reqwest::header::HOST, HOST)
			.header(reqwest::header::AUTHORIZATION, auth)
			.header(reqwest::header::CONTENT_TYPE, "application/xml")
			.body(body)
			.send()
			.await
			.map_err(transport)
	}
}
