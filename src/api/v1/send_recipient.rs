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

/// Most addresses in `reply_to`.
pub(super) const MAX_REPLY_TO: usize = 10;

/// The `reply_to` field: one recipient, or a list of them, since `Reply-To`
/// is an address list (RFC 5322 section 3.6.2). Absent is an empty list.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(from = "ReplyToWire")]
pub struct ReplyTo {
	list: Vec<Recipient>,
	/// Whether the request wrote a list, which decides how an error names
	/// the entry: `reply_to.name` for one recipient, `reply_to[1].name` in a list.
	listed: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReplyToWire {
	One(Recipient),
	Many(Vec<Recipient>),
}

impl From<ReplyToWire> for ReplyTo {
	fn from(wire: ReplyToWire) -> Self {
		match wire {
			ReplyToWire::One(one) => Self {
				list: vec![one],
				listed: false,
			},
			ReplyToWire::Many(list) => Self { list, listed: true },
		}
	}
}

impl ReplyTo {
	pub(super) fn is_empty(&self) -> bool {
		self.list.is_empty()
	}

	pub(super) fn recipients(&self) -> &[Recipient] {
		&self.list
	}

	pub(super) fn recipients_mut(&mut self) -> &mut [Recipient] {
		&mut self.list
	}

	/// Refuse a list over [`MAX_REPLY_TO`] and every entry [`Recipient::check`] refuses.
	pub(super) fn check(&self) -> Result<(), ApiError> {
		if self.list.len() > MAX_REPLY_TO {
			return Err(ApiError::field_out_of_range(
				"reply_to",
				&format!("Too many reply_to addresses; the maximum is {MAX_REPLY_TO}."),
			));
		}
		for (index, recipient) in self.list.iter().enumerate() {
			match self.listed {
				true => recipient.check(&format!("reply_to[{index}]"))?,
				false => recipient.check("reply_to")?,
			}
		}
		Ok(())
	}
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
