//! A recipient of `POST /api/v1/send`: a bare address, or an object that
//! also carries the display name written in front of it in the `To`, `Cc`
//! and `Reply-To` headers. A `Name <address>` string is not a third form: it
//! stays refused, because its quotes and commas are ambiguous.

use serde::Deserialize;

use crate::api::error::ApiError;

#[derive(Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum Recipient {
	/// `"ana@example.org"`: the address alone.
	Address(String),
	/// `{"name": "Ana Pérez", "address": "ana@example.org"}`.
	Named(NamedRecipient),
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct NamedRecipient {
	name: String,
	address: String,
}

impl Recipient {
	pub(super) fn address(&self) -> &str {
		match self {
			Self::Address(address) => address,
			Self::Named(named) => &named.address,
		}
	}

	pub(super) fn address_mut(&mut self) -> &mut String {
		match self {
			Self::Address(address) => address,
			Self::Named(named) => &mut named.address,
		}
	}

	/// The name as the caller wrote it, before validation.
	fn raw_name(&self) -> Option<&str> {
		match self {
			Self::Address(_) => None,
			Self::Named(named) => Some(&named.name),
		}
	}

	/// The display name when it is valid and not empty. [`check`] has
	/// refused every other name before a header is written.
	fn name(&self) -> Option<String> {
		let valid = crate::directory_store::display_name::validate(self.raw_name()?);
		valid.ok().flatten()
	}

	/// Refuse a name that cannot be written safely and a `Name <address>`
	/// string, naming the field as `to[2].name` (or `reply_to.name`).
	pub(super) fn check(&self, field: &str) -> Result<(), ApiError> {
		if let Self::Address(address) = self
			&& address.contains(['<', '>'])
		{
			return Err(ApiError::value_not_allowed_at(
				field.to_string(),
				&format!(
					"Invalid {field}: a display name goes in the object form \
					 {{\"name\": \"...\", \"address\": \"...\"}}, not as \"Name <address>\"."
				),
			));
		}
		if let Some(raw) = self.raw_name() {
			crate::directory_store::display_name::validate(raw).map_err(|why| {
				ApiError::value_not_allowed_at(
					format!("{field}.name"),
					&format!("Invalid {field}.name: {why}."),
				)
			})?;
		}
		Ok(())
	}
}

/// The `To`, `Cc` or `Reply-To` entries of `list`: each address once, in
/// order, with the first name given for it; the rest are the same recipient.
pub(super) fn header_mailboxes(list: &[Recipient]) -> Vec<String> {
	let mut seen: Vec<&str> = Vec::new();
	let mut out: Vec<(String, Option<String>)> = Vec::new();
	for recipient in list {
		let address = recipient.address();
		match seen.iter().position(|known| *known == address) {
			None => {
				seen.push(address);
				out.push((address.to_string(), recipient.name()));
			}
			Some(at) if out[at].1.is_none() => out[at].1 = recipient.name(),
			Some(_) => {}
		}
	}
	out.into_iter()
		.map(|(address, name)| crate::compose::mailbox(name.as_deref(), &address))
		.collect()
}
