//! Delivery routing: local recipients to mailboxes, remote to the queue.

use std::sync::Arc;

use crate::directory_store::DirectoryHandle;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use super::delivery::LocalDelivery;
use super::spool::FsSpool;

/// Splits an accepted message between local mailbox delivery and the
/// outbound spool, according to the directory.
pub struct SplitDelivery {
	directory: DirectoryHandle,
	local: LocalDelivery,
	outbound: FsSpool,
	signer: Option<Arc<crate::dkim::Signer>>,
	rules: Vec<crate::rules::Rule>,
}

impl SplitDelivery {
	/// Create the routing sink rooted at `data_dir`.
	pub fn new(data_dir: &std::path::Path, directory: DirectoryHandle) -> std::io::Result<Self> {
		Ok(SplitDelivery {
			local: LocalDelivery::new(data_dir, directory.clone())?,
			outbound: FsSpool::open(data_dir)?,
			directory,
			signer: None,
			rules: Vec::new(),
		})
	}

	/// Sign outbound messages with this DKIM signer.
	pub fn with_signer(mut self, signer: Arc<crate::dkim::Signer>) -> Self {
		self.signer = Some(signer);
		self
	}

	/// Apply these delivery rules to locally delivered mail.
	pub fn with_rules(mut self, rules: Vec<crate::rules::Rule>) -> Self {
		self.rules = rules;
		self
	}

	/// The mailbox local delivery should target for `message`, per the rules:
	/// an explicit mailbox, or `Junk` for a junk verdict, else INBOX (`None`).
	fn target_mailbox(&self, message: &AcceptedMessage) -> Option<String> {
		let sender_domain = message
			.reverse_path
			.rsplit_once('@')
			.map(|(_, domain)| domain.to_ascii_lowercase());
		let rule = crate::rules::evaluate(&self.rules, &message.data, sender_domain.as_deref())?;
		match &rule.mailbox {
			Some(mailbox) => Some(mailbox.clone()),
			None if rule.junk => Some("Junk".to_string()),
			None => None,
		}
	}
}

impl MessageSink for SplitDelivery {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		let mut local = Vec::new();
		let mut remote = Vec::new();
		for recipient in &message.recipients {
			let address = Address::parse(recipient).map_err(|_| {
				SinkError::Unavailable(format!("unparseable recipient {recipient}"))
			})?;
			match self.directory.current().resolve(&address) {
				Resolution::Account(_) => local.push(recipient.clone()),
				Resolution::NotLocal => remote.push(recipient.clone()),
				// The session rejected unknown local users; drift here is
				// a logic error and the whole delivery fails closed.
				Resolution::UnknownUser => {
					return Err(SinkError::Unavailable(format!(
						"recipient {recipient} no longer resolves"
					)));
				}
			}
		}

		if !local.is_empty() {
			// An explicit routing hint (e.g. a screening quarantine) wins over rules.
			let mailbox = message
				.mailbox
				.clone()
				.or_else(|| self.target_mailbox(&message));
			let local_message = AcceptedMessage {
				recipients: local,
				..message.clone()
			};
			self.local
				.deliver_routed(&local_message, mailbox.as_deref())?;
		}
		if !remote.is_empty() {
			let mut outbound_message = AcceptedMessage {
				recipients: remote,
				..message
			};
			// Sign relayed mail so receivers can verify our domain.
			if let Some(signer) = &self.signer
				&& let Some((_, domain)) = outbound_message.reverse_path.rsplit_once('@')
				&& let Some(header) = signer.sign(domain, &outbound_message.data)
			{
				let mut signed = header.into_bytes();
				signed.extend_from_slice(&outbound_message.data);
				outbound_message.data = signed;
			}
			self.outbound
				.store(&outbound_message)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	fn directory() -> DirectoryHandle {
		DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		))
	}

	fn message(recipients: &[&str]) -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: "alice@example.org".into(),
			recipients: recipients.iter().map(|r| r.to_string()).collect(),
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
		}
	}

	fn inbox_count(root: &std::path::Path, account: &str) -> usize {
		fs::read_dir(root.join("accounts").join(account).join("new"))
			.map(|entries| entries.count())
			.unwrap_or(0)
	}

	fn spool_count(root: &std::path::Path) -> usize {
		FsSpool::open(root)
			.expect("open spool")
			.list()
			.expect("list")
			.len()
	}

	fn folder_count(root: &std::path::Path, account: &str, mailbox: &str) -> usize {
		fs::read_dir(
			root.join("accounts")
				.join(account)
				.join("folders")
				.join(mailbox)
				.join("new"),
		)
		.map(|entries| entries.count())
		.unwrap_or(0)
	}

	#[test]
	fn junk_rule_files_into_the_junk_mailbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		let rule = crate::rules::Rule {
			sender_domain: Some("example.org".to_string()),
			header: None,
			header_contains: None,
			junk: true,
			mailbox: None,
		};
		let sink = SplitDelivery::new(dir.path(), directory())
			.expect("sink")
			.with_rules(vec![rule]);
		sink.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		// Routed to Junk, not INBOX.
		assert_eq!(folder_count(dir.path(), "alice", "Junk"), 1);
		assert_eq!(inbox_count(dir.path(), "alice"), 0);
	}

	#[test]
	fn explicit_mailbox_hint_quarantines_to_that_folder() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		let mut msg = message(&["alice@example.org"]);
		msg.mailbox = Some("Rejects".to_string());
		sink.deliver(msg).expect("deliver");
		assert_eq!(folder_count(dir.path(), "alice", "Rejects"), 1);
		assert_eq!(inbox_count(dir.path(), "alice"), 0);
	}

	#[test]
	fn local_only_message_skips_the_spool() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		assert_eq!(inbox_count(dir.path(), "alice"), 1);
		assert_eq!(spool_count(dir.path()), 0);
	}

	#[test]
	fn remote_only_message_goes_to_the_spool() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["bob@elsewhere.example"]))
			.expect("deliver");
		assert_eq!(inbox_count(dir.path(), "alice"), 0);
		assert_eq!(spool_count(dir.path()), 1);
	}

	#[test]
	fn mixed_message_is_split() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["alice@example.org", "bob@elsewhere.example"]))
			.expect("deliver");
		assert_eq!(inbox_count(dir.path(), "alice"), 1);

		let spool = FsSpool::open(dir.path()).expect("spool");
		let ids = spool.list().expect("list");
		assert_eq!(ids.len(), 1);
		let entry = spool.load(ids[0]).expect("load");
		// Only the remote recipient is queued for outbound delivery.
		assert_eq!(
			entry.envelope.recipients,
			vec!["bob@elsewhere.example".to_string()]
		);
	}

	#[test]
	fn unknown_local_user_fails_closed() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		let result = sink.deliver(message(&["stranger@example.org"]));
		assert!(result.is_err());
		assert_eq!(spool_count(dir.path()), 0);
	}
}
