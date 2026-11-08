//! What a request says, and what the answer to it says.
//!
//! Both are JSON with no unknown field: a file that carries anything else
//! was not written by this hand-off, and the serving side refuses it rather
//! than guess what was meant.

use serde::{Deserialize, Serialize};

use crate::dns::provider::DnsRecord;

/// What the serving side is asked to do with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
	/// Put the record at the name, replacing what is there.
	Publish,
	/// Take the record at the name away.
	Withdraw,
}

/// One DNS write the serving side is asked to perform.
///
/// The zone is not part of it: the serving side resolves the name against
/// the `[dns]` configuration it holds, the same way the router and the
/// per-domain publisher do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
	/// The id of the request: the name of the request file and of the
	/// result file that answers it.
	pub id: String,
	/// What to do with the record.
	pub operation: Operation,
	/// The record name.
	pub name: String,
	/// The record type.
	pub kind: String,
	/// The record value.
	pub value: String,
	/// The time to live, in seconds.
	pub ttl: u32,
	/// When the request was made, in epoch seconds.
	pub created_at: u64,
}

/// The answer to a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
	/// The id of the request this answers.
	pub id: String,
	/// Whether the write happened.
	pub ok: bool,
	/// Why it did not, when it did not.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

impl Outcome {
	/// The answer that says the write happened.
	pub fn ok(id: &str) -> Self {
		Outcome {
			id: id.to_string(),
			ok: true,
			error: None,
		}
	}

	/// The answer that says the write did not happen, and why.
	pub fn failed(id: &str, reason: impl Into<String>) -> Self {
		Outcome {
			id: id.to_string(),
			ok: false,
			error: Some(reason.into()),
		}
	}

	/// The answer as the asking side reads it: `Ok(())` when the write
	/// happened, the reason when it did not.
	pub fn answer(&self) -> Result<(), String> {
		if self.ok {
			return Ok(());
		}
		Err(self
			.error
			.clone()
			.unwrap_or_else(|| "the write did not happen".to_string()))
	}
}

/// A write the asking side wants performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
	/// What to do with the record.
	pub operation: Operation,
	/// The record name.
	pub name: String,
	/// The record type.
	pub kind: String,
	/// The record value.
	pub value: String,
	/// The time to live, in seconds.
	pub ttl: u32,
}

impl Write {
	/// The write that puts `record` at its name.
	pub fn publish(record: &DnsRecord) -> Self {
		Write {
			operation: Operation::Publish,
			name: record.name.clone(),
			kind: record.kind.as_str().to_string(),
			value: record.value.clone(),
			ttl: record.ttl,
		}
	}

	/// The write that takes the whole TXT set at `name` away.
	pub fn withdraw(name: &str) -> Self {
		Write {
			operation: Operation::Withdraw,
			name: name.to_string(),
			kind: crate::dns::provider::RecordKind::Txt.as_str().to_string(),
			value: String::new(),
			ttl: 300,
		}
	}

	/// The write that puts a DKIM key record at `name`.
	pub fn dkim(name: &str, value: &str) -> Self {
		Write {
			operation: Operation::Publish,
			name: name.to_string(),
			kind: crate::dns::provider::RecordKind::Txt.as_str().to_string(),
			value: value.to_string(),
			ttl: 300,
		}
	}

	/// The request this write becomes, under `id` and at `now`.
	pub fn request(&self, id: &str, now: u64) -> Request {
		Request {
			id: id.to_string(),
			operation: self.operation,
			name: self.name.clone(),
			kind: self.kind.clone(),
			value: self.value.clone(),
			ttl: self.ttl,
			created_at: now,
		}
	}
}
