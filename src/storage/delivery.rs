//! Local delivery: accepted inbound messages land in account mailboxes.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use uuid::Uuid;

use crate::directory_store::DirectoryHandle;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use super::spool::write_sync;

/// What local delivery produced: redirect addresses for the caller to queue,
/// and a Sieve reject reason to bounce (if any).
#[derive(Debug, Default)]
pub struct Delivered {
	pub redirects: Vec<String>,
	pub reject: Option<String>,
}

/// Delivers messages into `data_dir/accounts/<account>/new/`, one crash-safe
/// copy per distinct recipient account.
#[derive(Debug)]
pub struct LocalDelivery {
	accounts_root: PathBuf,
	directory: DirectoryHandle,
}

impl LocalDelivery {
	/// Create a local delivery sink rooted at `data_dir`. Creates the
	/// accounts directory eagerly so an unwritable data_dir fails at
	/// startup, not on first delivery.
	pub fn new(data_dir: &std::path::Path, directory: DirectoryHandle) -> std::io::Result<Self> {
		let accounts_root = data_dir.join("accounts");
		fs::create_dir_all(&accounts_root)?;
		Ok(LocalDelivery {
			accounts_root,
			directory,
		})
	}

	/// Resolve recipients to their distinct accounts. The session already
	/// rejected unresolvable recipients; hitting one here is a logic error
	/// and fails the whole delivery (fail closed, client retries).
	fn accounts_for(&self, message: &AcceptedMessage) -> Result<BTreeSet<String>, SinkError> {
		let mut accounts = BTreeSet::new();
		for recipient in &message.recipients {
			let address = Address::parse(recipient).map_err(|_| {
				SinkError::Unavailable(format!("unparseable recipient {recipient}"))
			})?;
			match self.directory.current().resolve(&address) {
				Resolution::Account(account) => {
					accounts.insert(account);
				}
				_ => {
					return Err(SinkError::Unavailable(format!(
						"recipient {recipient} no longer resolves to an account"
					)));
				}
			}
		}
		Ok(accounts)
	}

	fn deliver_to_account(
		&self,
		account: &str,
		mailbox: Option<&str>,
		data: &[u8],
		flags: &[String],
	) -> std::io::Result<Uuid> {
		let id = Uuid::now_v7();
		let account_dir = self.accounts_root.join(account);
		// INBOX is the account root; named mailboxes live under folders/.
		let base = match mailbox {
			Some(name) => account_dir.join("folders").join(name),
			None => account_dir,
		};
		let tmp_dir = base.join("tmp");
		let new_dir = base.join("new");
		fs::create_dir_all(&tmp_dir)?;
		fs::create_dir_all(&new_dir)?;

		let tmp_path = tmp_dir.join(format!("{id}.eml"));
		write_sync(&tmp_path, data)?;
		fs::rename(&tmp_path, new_dir.join(format!("{id}.eml")))?;
		// imap4flags: persist the Sieve-assigned flags as the IMAP sidecar.
		write_flag_sidecar(&new_dir, id, flags);
		Ok(id)
	}

	/// Deliver one copy per recipient account into `mailbox` (a named folder),
	/// or INBOX when `None`. The mailbox name must be a safe single segment.
	/// Returns the redirect addresses requested by users' Sieve filters, for
	/// the caller to queue (this sink has no outbound spool).
	pub fn deliver_routed(
		&self,
		message: &AcceptedMessage,
		mailbox: Option<&str>,
	) -> Result<Delivered, SinkError> {
		if let Some(name) = mailbox
			&& !is_safe_mailbox(name)
		{
			return Err(SinkError::Unavailable(format!(
				"unsafe mailbox name {name:?}"
			)));
		}
		let accounts = self.accounts_for(message)?;
		if accounts.is_empty() {
			return Err(SinkError::Unavailable("no recipient accounts".into()));
		}
		let mut delivered = Delivered::default();
		for account in &accounts {
			let one = self.deliver_for_account(account, message, mailbox)?;
			delivered.redirects.extend(one.redirects);
			delivered.reject = delivered.reject.or(one.reject);
		}
		Ok(delivered)
	}

	/// Deliver one message to one account. An explicit `hint` mailbox (an
	/// admin rule or a security quarantine) takes precedence; otherwise the
	/// account's Sieve filter, if any, decides. With no filter the message
	/// lands in INBOX. Returns any redirect addresses the filter requested.
	fn deliver_for_account(
		&self,
		account: &str,
		message: &AcceptedMessage,
		hint: Option<&str>,
	) -> Result<Delivered, SinkError> {
		let data = &message.data;
		if let Some(mailbox) = hint {
			self.deliver_to_account(account, Some(mailbox), data, &[])
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
			return Ok(Delivered::default());
		}
		let Some(outcome) = self.sieve_outcome(account, message) else {
			// No filter (or it failed to compile): normal INBOX delivery.
			self.deliver_to_account(account, None, data, &[])
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
			return Ok(Delivered::default());
		};
		// reject/ereject: refuse without delivering; the caller bounces the
		// reason to a non-null sender.
		if let Some(reason) = outcome.reject {
			let reject = (!message.reverse_path.is_empty()).then_some(reason);
			return Ok(Delivered {
				redirects: Vec::new(),
				reject,
			});
		}
		if outcome.keep {
			self.deliver_to_account(account, None, data, &outcome.flags)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		for folder in &outcome.fileinto {
			if is_safe_mailbox(folder) {
				self.deliver_to_account(account, Some(folder), data, &outcome.flags)
					.map_err(|error| SinkError::Unavailable(error.to_string()))?;
			}
		}
		// Never redirect a bounce (null sender): that risks mail loops.
		if message.reverse_path.is_empty() {
			return Ok(Delivered::default());
		}
		Ok(Delivered {
			redirects: outcome.redirects,
			reject: None,
		})
	}

	/// Evaluate the account's Sieve filter, if present and valid. Any read,
	/// lex or parse failure yields `None` so delivery falls back to INBOX
	/// rather than dropping mail.
	fn sieve_outcome(
		&self,
		account: &str,
		message: &AcceptedMessage,
	) -> Option<crate::sieve::interp::Outcome> {
		let path = self.accounts_root.join(account).join("filter.sieve");
		let source = fs::read_to_string(path).ok()?;
		let tokens = crate::sieve::lexer::tokenize(&source).ok()?;
		let commands = crate::sieve::parser::parse(&tokens).ok()?;
		let parsed = crate::sieve::interp::Message::parse(&message.data)
			.with_envelope(message.reverse_path.clone(), message.recipients.clone());
		Some(crate::sieve::interp::evaluate(&commands, &parsed))
	}
}

/// A mailbox name safe to use as a single path segment.
/// Persist Sieve-assigned flags as the message's IMAP `.flags` sidecar, so a
/// `setflag`/`addflag` filter is reflected when the mailbox is opened.
fn write_flag_sidecar(new_dir: &std::path::Path, id: Uuid, flag_tokens: &[String]) {
	let flags: Vec<crate::imap::mailbox::Flag> = flag_tokens
		.iter()
		.filter_map(|token| crate::imap::mailbox::Flag::parse(token))
		.collect();
	if flags.is_empty() {
		return;
	}
	if let Ok(bytes) = serde_json::to_vec(&flags) {
		let _ = write_sync(&new_dir.join(format!("{id}.flags")), &bytes);
	}
}

fn is_safe_mailbox(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= 64
		&& !name.starts_with('.')
		&& name
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
}

impl MessageSink for LocalDelivery {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		// Standalone local delivery has no outbound spool; redirects are dropped.
		self.deliver_routed(&message, None).map(|_| ())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn directory() -> DirectoryHandle {
		DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("also-alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		))
	}

	fn message(recipients: &[&str]) -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: "sender@elsewhere.example".into(),
			recipients: recipients.iter().map(|r| r.to_string()).collect(),
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
		}
	}

	fn list_inbox(root: &std::path::Path, account: &str) -> Vec<PathBuf> {
		let dir = root.join("accounts").join(account).join("new");
		match fs::read_dir(dir) {
			Ok(entries) => entries.map(|e| e.expect("entry").path()).collect(),
			Err(_) => Vec::new(),
		}
	}

	#[test]
	fn delivers_one_copy_per_account() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");

		delivery
			.deliver(message(&[
				"alice@example.org",
				"also-alice@example.org",
				"bob@example.org",
			]))
			.expect("delivery succeeds");

		// Two addresses for alice still mean one copy.
		assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
		assert_eq!(list_inbox(dir.path(), "bob").len(), 1);
	}

	#[test]
	fn delivered_file_contains_message_data() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("delivery succeeds");

		let files = list_inbox(dir.path(), "alice");
		let content = fs::read(&files[0]).expect("read delivered file");
		assert_eq!(content, b"Subject: hi\r\n\r\nbody\r\n");
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

	fn write_filter(root: &std::path::Path, account: &str, script: &str) {
		let dir = root.join("accounts").join(account);
		fs::create_dir_all(&dir).expect("mkdir");
		fs::write(dir.join("filter.sieve"), script).expect("write filter");
	}

	#[test]
	fn sieve_filter_files_into_chosen_folder() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
		write_filter(
			dir.path(),
			"alice",
			"if header :contains \"Subject\" \"hi\" { fileinto \"Filed\"; }",
		);
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		assert_eq!(folder_count(dir.path(), "alice", "Filed"), 1);
		assert!(list_inbox(dir.path(), "alice").is_empty());
	}

	#[test]
	fn sieve_imap4flags_writes_flag_sidecar() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
		write_filter(dir.path(), "alice", "addflag \"\\\\Seen\"; keep;");
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		// The delivered message carries a .flags sidecar with \Seen.
		let new_dir = dir.path().join("accounts").join("alice").join("new");
		let sidecar = fs::read_dir(&new_dir)
			.expect("new dir")
			.map(|e| e.expect("entry").path())
			.find(|p| p.extension().is_some_and(|ext| ext == "flags"))
			.expect("flags sidecar written");
		let body = fs::read_to_string(sidecar).expect("read sidecar");
		assert!(body.contains("Seen"), "{body}");
	}

	#[test]
	fn sieve_discard_drops_the_message() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
		write_filter(dir.path(), "alice", "discard;");
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		assert!(list_inbox(dir.path(), "alice").is_empty());
		assert_eq!(folder_count(dir.path(), "alice", "Filed"), 0);
	}

	#[test]
	fn invalid_filter_falls_back_to_inbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
		// A syntactically broken script must not drop mail.
		write_filter(dir.path(), "alice", "if header { oops");
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
	}

	#[test]
	fn quarantine_hint_overrides_sieve() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
		write_filter(dir.path(), "alice", "fileinto \"Filed\";");
		let mut msg = message(&["alice@example.org"]);
		msg.recipients = vec!["alice@example.org".to_string()];
		// An explicit hint (e.g. spam quarantine) wins over the user filter.
		delivery
			.deliver_routed(&msg, Some("Rejects"))
			.expect("deliver");
		assert_eq!(folder_count(dir.path(), "alice", "Rejects"), 1);
		assert_eq!(folder_count(dir.path(), "alice", "Filed"), 0);
	}

	#[test]
	fn unresolvable_recipient_fails_delivery() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		let result = delivery.deliver(message(&["stranger@example.org"]));
		assert!(result.is_err());
		assert!(list_inbox(dir.path(), "alice").is_empty());
	}

	#[test]
	fn empty_recipient_list_fails_delivery() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		assert!(delivery.deliver(message(&[])).is_err());
	}

	#[test]
	fn tmp_leftovers_are_not_visible_in_inbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("delivery succeeds");
		// Simulate a crashed write.
		fs::write(dir.path().join("accounts/alice/tmp/crash.eml"), b"partial").expect("write tmp");
		assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
	}
}
