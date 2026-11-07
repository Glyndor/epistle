//! A complete value-bearing payload, never a name/type-only deletion.

use super::*;

/// Preserve listed TXT bytes; the caller first matches their logical value.
pub(super) fn delete_item(
	record: &DnsRecord,
	kind: &str,
	rel: &str,
) -> Result<serde_json::Value, ProviderError> {
	if record.value.is_empty() {
		return Err(ProviderError::Unsupported);
	}
	let mut item = serde_json::json!({"type": kind, "name": rel});
	match record.kind {
		RecordKind::Srv => {
			let (priority, weight, port, target) =
				parse_srv(&record.value).ok_or(ProviderError::Unsupported)?;
			item["priority"] = priority.into();
			item["weight"] = weight.into();
			item["port"] = port.into();
			item["target"] = target.into();
		}
		RecordKind::Mx => {
			let mut parts = record.value.split_whitespace();
			let priority = parts
				.next()
				.and_then(|p| p.parse::<u16>().ok())
				.ok_or(ProviderError::Unsupported)?;
			let target = parts.next().ok_or(ProviderError::Unsupported)?;
			if parts.next().is_some() {
				return Err(ProviderError::Unsupported);
			}
			item["preference"] = priority.into();
			item["exchange"] = crate::dns::provider::mx_target_for_api(target).into();
		}
		RecordKind::Tlsa => {
			let mut parts = record.value.split_whitespace();
			for key in ["usage", "selector", "matchingType"] {
				let value = parts
					.next()
					.and_then(|p| p.parse::<u8>().ok())
					.ok_or(ProviderError::Unsupported)?;
				item[key] = value.into();
			}
			item["associationData"] = parts.next().ok_or(ProviderError::Unsupported)?.into();
			if parts.next().is_some() {
				return Err(ProviderError::Unsupported);
			}
		}
		RecordKind::Caa => {
			let mut parts = record.value.splitn(3, ' ');
			let flag = parts
				.next()
				.and_then(|p| p.parse::<u8>().ok())
				.ok_or(ProviderError::Unsupported)?;
			item["flag"] = flag.into();
			item["tag"] = parts.next().ok_or(ProviderError::Unsupported)?.into();
			item["value"] = parts
				.next()
				.ok_or(ProviderError::Unsupported)?
				.trim_matches('"')
				.into();
		}
		RecordKind::A | RecordKind::Aaaa | RecordKind::Cname | RecordKind::Txt => {
			item[SpaceshipProvider::value_field(&record.kind)] = record.value.clone().into();
		}
		_ => return Err(ProviderError::Unsupported),
	}
	Ok(item)
}

impl SpaceshipProvider {
	pub(super) async fn delete_exact_inner(
		&self,
		mut record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		if record.value.is_empty() {
			return Err(ProviderError::Unsupported);
		}
		let relative = self.relative_name(&record.name);
		if record.kind == RecordKind::Txt {
			// Match logical text, but send the bytes the API actually stored.
			let wanted = record.value.clone();
			for old in self.txt_values_at(&relative).await? {
				if crate::dns::txt::same_txt_value(&old, &wanted) {
					record.value = old;
					self.remove_exact_item(delete_item(&record, kind, &relative)?)
						.await?;
				}
			}
			Ok(())
		} else {
			self.remove_exact_item(delete_item(&record, kind, &relative)?)
				.await
		}
	}

	async fn remove_exact_item(&self, item: serde_json::Value) -> Result<(), ProviderError> {
		let response = self
			.request(reqwest::Method::DELETE, self.records_url()?)
			.body(serde_json::json!([item]).to_string())
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}
}
