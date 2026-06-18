//! Delivery routing: local recipients to mailboxes, remote to the queue.

use std::sync::Arc;

use crate::directory_store::DirectoryHandle;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use super::delivery::LocalDelivery;
use super::spool::FsSpool;

/// How long an SRS-return address stays valid (RFC-less convention).
const SRS_MAX_AGE_DAYS: u64 = 14;

/// Splits an accepted message between local mailbox delivery and the
/// outbound spool, according to the directory.
pub struct SplitDelivery {
	directory: DirectoryHandle,
	local: LocalDelivery,
	outbound: FsSpool,
	signer: Option<Arc<crate::dkim::Signer>>,
	rules: Vec<crate::rules::Rule>,
	/// SRS rewriter and our domain, for forwarded (redirected) mail.
	srs: Option<(crate::queue::srs::Srs, String)>,
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
			srs: None,
		})
	}

	/// Sign outbound messages with this DKIM signer.
	pub fn with_signer(mut self, signer: Arc<crate::dkim::Signer>) -> Self {
		self.signer = Some(signer);
		self
	}

	/// Rewrite the sender of forwarded mail via SRS at `our_domain`, so it
	/// passes SPF at the next hop.
	pub fn with_srs(mut self, srs: crate::queue::srs::Srs, our_domain: impl Into<String>) -> Self {
		self.srs = Some((srs, our_domain.into()));
		self
	}

	/// The envelope sender to use for mail forwarded to `redirect`: an SRS
	/// rewrite of the original sender when SRS is enabled, else the original.
	fn forward_sender(&self, original: &str) -> String {
		if original.is_empty() {
			return String::new();
		}
		let Some((srs, our_domain)) = &self.srs else {
			return original.to_string();
		};
		let Some((local, domain)) = original.rsplit_once('@') else {
			return original.to_string();
		};
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		srs.forward(local, domain, our_domain, now_days)
	}

	/// If `recipient` is a valid SRS-return address at our domain, the original
	/// sender it should be forwarded back to; otherwise `None`.
	fn srs_return(&self, recipient: &str) -> Option<String> {
		let (srs, our_domain) = self.srs.as_ref()?;
		let (local, domain) = recipient.rsplit_once('@')?;
		if !domain.eq_ignore_ascii_case(our_domain) {
			return None;
		}
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		let (orig_local, orig_domain) = srs.reverse(local, now_days, SRS_MAX_AGE_DAYS)?;
		Some(format!("{orig_local}@{orig_domain}"))
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
		let mut srs_returns = Vec::new();
		for recipient in &message.recipients {
			// An SRS-return address forwards the (bounce) message back to the
			// original sender it encodes.
			if let Some(original) = self.srs_return(recipient) {
				srs_returns.push(original);
				continue;
			}
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
			let mailbox = message
				.mailbox
				.clone()
				.or_else(|| self.target_mailbox(&message));
			let local_message = AcceptedMessage {
				recipients: local,
				..message.clone()
			};
			let delivered = self
				.local
				.deliver_routed(&local_message, mailbox.as_deref())?;
			if let Some(reason) = delivered.reject {
				let hostname = local_message
					.recipients
					.first()
					.and_then(|r| r.rsplit_once('@'))
					.map(|(_, domain)| domain.to_string())
					.unwrap_or_else(|| "localhost".to_string());
				if let Some(bounce) = crate::queue::bounce::build(
					&hostname,
					&message.reverse_path,
					&local_message.recipients,
					&reason,
					&message.data,
					std::time::SystemTime::now(),
				) {
					self.outbound
						.store(&bounce)
						.map_err(|error| SinkError::Unavailable(error.to_string()))?;
				}
			}
			// Queue Sieve redirects, preserving the (non-null) original sender.
			for address in delivered.redirects {
				let forwarded = AcceptedMessage {
					reverse_path: self.forward_sender(&message.reverse_path),
					recipients: vec![address],
					data: message.data.clone(),
					require_tls: false,
					mailbox: None,
				};
				self.outbound
					.store(&forwarded)
					.map_err(|error| SinkError::Unavailable(error.to_string()))?;
			}
			for reply in delivered.replies {
				self.outbound
					.store(&reply)
					.map_err(|error| SinkError::Unavailable(error.to_string()))?;
			}
		}
		// Forward SRS-return (bounce) messages back to the original senders.
		for original in srs_returns {
			let returned = AcceptedMessage {
				reverse_path: message.reverse_path.clone(),
				recipients: vec![original],
				data: message.data.clone(),
				require_tls: false,
				mailbox: None,
			};
			self.outbound
				.store(&returned)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
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
	fn sieve_reject_bounces_and_skips_delivery() {
		let dir = tempfile::tempdir().expect("tempdir");
		let account_dir = dir.path().join("accounts").join("alice");
		fs::create_dir_all(&account_dir).expect("mkdir");
		fs::write(account_dir.join("filter.sieve"), "reject \"no thanks\";").expect("filter");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		// Rejected: nothing delivered, one DSN bounce queued to the sender.
		assert_eq!(inbox_count(dir.path(), "alice"), 0);
		let spool = FsSpool::open(dir.path()).expect("spool");
		let ids = spool.list().expect("list");
		assert_eq!(ids.len(), 1);
		let entry = spool.load(ids[0]).expect("load");
		// A DSN uses the null reverse-path and goes to the original sender.
		assert!(
			entry.envelope.reverse_path.is_empty(),
			"{:?}",
			entry.envelope
		);
		assert_eq!(
			entry.envelope.recipients,
			vec!["alice@example.org".to_string()]
		);
	}

	#[test]
	fn sieve_vacation_replies_once_and_keeps() {
		let dir = tempfile::tempdir().expect("tempdir");
		let account_dir = dir.path().join("accounts").join("alice");
		fs::create_dir_all(&account_dir).expect("mkdir");
		fs::write(account_dir.join("filter.sieve"), "vacation \"I am away\";").expect("filter");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");

		let mut msg = message(&["alice@example.org"]);
		msg.reverse_path = "bob@example.net".into();
		sink.deliver(msg).expect("deliver");
		// Kept in INBOX, one null-sender autoresponse queued to the sender.
		assert_eq!(inbox_count(dir.path(), "alice"), 1);
		let spool = FsSpool::open(dir.path()).expect("spool");
		let ids = spool.list().expect("list");
		assert_eq!(ids.len(), 1);
		let reply = spool.load(ids[0]).expect("load");
		assert!(reply.envelope.reverse_path.is_empty(), "null sender");
		assert_eq!(
			reply.envelope.recipients,
			vec!["bob@example.net".to_string()]
		);

		// A second message from the same sender is deduped: no new reply.
		let mut again = message(&["alice@example.org"]);
		again.reverse_path = "bob@example.net".into();
		sink.deliver(again).expect("deliver");
		assert_eq!(spool.list().expect("list").len(), 1);
	}

	#[test]
	fn sieve_redirect_queues_to_the_spool() {
		let dir = tempfile::tempdir().expect("tempdir");
		let account_dir = dir.path().join("accounts").join("alice");
		fs::create_dir_all(&account_dir).expect("mkdir");
		fs::write(
			account_dir.join("filter.sieve"),
			"redirect \"forward@example.com\";",
		)
		.expect("filter");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		// Redirect cancels the implicit keep: nothing in INBOX, one in the spool.
		assert_eq!(inbox_count(dir.path(), "alice"), 0);
		let spool = FsSpool::open(dir.path()).expect("spool");
		let ids = spool.list().expect("list");
		assert_eq!(ids.len(), 1);
		let entry = spool.load(ids[0]).expect("load");
		assert_eq!(
			entry.envelope.recipients,
			vec!["forward@example.com".to_string()]
		);
	}

	#[test]
	fn srs_rewrites_the_forwarded_sender() {
		let dir = tempfile::tempdir().expect("tempdir");
		let account_dir = dir.path().join("accounts").join("alice");
		fs::create_dir_all(&account_dir).expect("mkdir");
		fs::write(
			account_dir.join("filter.sieve"),
			"redirect \"forward@example.com\";",
		)
		.expect("filter");
		let srs = crate::queue::srs::Srs::new(b"test secret");
		let sink = SplitDelivery::new(dir.path(), directory())
			.expect("sink")
			.with_srs(srs, "relay.example");
		sink.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		let spool = FsSpool::open(dir.path()).expect("spool");
		let ids = spool.list().expect("list");
		let entry = spool.load(ids[0]).expect("load");
		// The forwarded sender is rewritten to an SRS address at our domain.
		assert!(
			entry.envelope.reverse_path.starts_with("SRS0="),
			"{}",
			entry.envelope.reverse_path
		);
		assert!(entry.envelope.reverse_path.ends_with("@relay.example"));
	}

	#[test]
	fn srs_return_address_forwards_to_original_sender() {
		let dir = tempfile::tempdir().expect("tempdir");
		let srs = crate::queue::srs::Srs::new(b"test secret");
		// Encode an SRS-return address for the original sender at our domain.
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		let srs_local = srs
			.forward("origsender", "origin.example", "relay.example", now_days)
			.split_once('@')
			.unwrap()
			.0
			.to_string();
		let sink = SplitDelivery::new(dir.path(), directory())
			.expect("sink")
			.with_srs(crate::queue::srs::Srs::new(b"test secret"), "relay.example");

		let bounce = AcceptedMessage {
			reverse_path: String::new(),
			recipients: vec![format!("{srs_local}@relay.example")],
			data: b"Subject: bounce\r\n\r\nfailed\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
		};
		sink.deliver(bounce).expect("deliver");
		// The bounce is re-queued to the original sender it encoded.
		let spool = FsSpool::open(dir.path()).expect("spool");
		let ids = spool.list().expect("list");
		assert_eq!(ids.len(), 1);
		let entry = spool.load(ids[0]).expect("load");
		assert_eq!(
			entry.envelope.recipients,
			vec!["origsender@origin.example".to_string()]
		);
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
