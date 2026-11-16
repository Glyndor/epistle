//! The bytes of one held submission: its metadata and its message, in one
//! file, so that a state change is one rename.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::Submission;

/// What is kept about a held submission besides the message bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Meta {
	id: Uuid,
	account: String,
	accepted_at: u64,
	release_at: u64,
	reverse_path: String,
	recipients: Vec<String>,
	require_tls: bool,
	mailbox: Option<String>,
	tlsrpt_verified: bool,
	sender_verified: bool,
	no_dsn: Vec<String>,
	extra: BTreeMap<String, String>,
	class: crate::evidence::MailClass,
}

/// One submission held back from delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
	/// The id the submitter was given (the queue id the message gets when
	/// it is released).
	pub id: Uuid,
	/// The account that submitted it, recorded by the server.
	pub account: String,
	/// Epoch seconds at which it was accepted.
	pub accepted_at: u64,
	/// Epoch seconds before which nothing is delivered and the sender may
	/// still cancel.
	pub release_at: u64,
	/// The message, as the submission path accepted it.
	pub message: AcceptedMessage,
	/// What the server decided about it.
	pub submission: Submission,
}

impl Held {
	/// The file content: a four-byte length, the metadata, the message.
	pub(super) fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
		let meta = Meta {
			id: self.id,
			account: self.account.clone(),
			accepted_at: self.accepted_at,
			release_at: self.release_at,
			reverse_path: self.message.reverse_path.clone(),
			recipients: self.message.recipients.clone(),
			require_tls: self.message.require_tls,
			mailbox: self.message.mailbox.clone(),
			tlsrpt_verified: self.message.tlsrpt_verified,
			sender_verified: self.message.sender_verified,
			no_dsn: self.message.no_dsn.clone(),
			extra: self.submission.extra.clone(),
			class: self.submission.class,
		};
		let meta = serde_json::to_vec(&meta).map_err(std::io::Error::other)?;
		let length = u32::try_from(meta.len()).map_err(std::io::Error::other)?;
		let mut bytes = Vec::with_capacity(4 + meta.len() + self.message.data.len());
		bytes.extend_from_slice(&length.to_be_bytes());
		bytes.extend_from_slice(&meta);
		bytes.extend_from_slice(&self.message.data);
		Ok(bytes)
	}

	/// Read what [`to_bytes`](Self::to_bytes) wrote.
	pub(super) fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
		let bad = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string());
		let (head, rest) = bytes
			.split_first_chunk::<4>()
			.ok_or_else(|| bad("held submission is truncated"))?;
		let length = usize::try_from(u32::from_be_bytes(*head)).map_err(|_| bad("bad length"))?;
		if rest.len() < length {
			return Err(bad("held submission is truncated"));
		}
		let (meta, data) = rest.split_at(length);
		let meta: Meta = serde_json::from_slice(meta).map_err(std::io::Error::other)?;
		Ok(Held {
			id: meta.id,
			account: meta.account,
			accepted_at: meta.accepted_at,
			release_at: meta.release_at,
			message: AcceptedMessage {
				reverse_path: meta.reverse_path,
				recipients: meta.recipients,
				data: data.to_vec(),
				require_tls: meta.require_tls,
				mailbox: meta.mailbox,
				tlsrpt_verified: meta.tlsrpt_verified,
				sender_verified: meta.sender_verified,
				no_dsn: meta.no_dsn,
			},
			submission: Submission {
				extra: meta.extra,
				class: meta.class,
			},
		})
	}
}
