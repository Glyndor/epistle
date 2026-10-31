//! Local delivery: accepted inbound messages land in account mailboxes.

mod io;
mod lists;
mod policy;
mod reports;
mod trace;

pub use trace::Redirect;
pub(crate) use trace::final_copy as local_delivery_copy;
pub(super) use trace::forwarded_copy;
mod vacation;

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;

use crate::directory_store::DirectoryHandle;
use crate::imap::changelog::{Change, Op};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use crate::util::path_component::{AccountName, FixedDir, MailboxName, MessageExt, message_file};
use crate::util::path_containment::{contained, contained_child};

use super::crypto::MessageCrypto;
use super::spool::write_sync;

/// Forward only while a message has crossed at most this many hops. A loop
/// re-injects the message each round, accruing `Received:` headers; stopping
/// well under RFC 5321's 100-hop ceiling breaks a forwarding loop early.
pub(super) const MAX_FORWARD_HOPS: usize = 25;

/// Count the `Received:` header lines in a raw message (its hop count).
pub(super) fn received_hops(data: &[u8]) -> usize {
	let head_end = data
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.unwrap_or(data.len());
	let head = &data[..head_end];
	head.split(|&b| b == b'\n')
		.filter(|line| {
			let line = line.strip_suffix(b"\r").unwrap_or(line);
			line.len() >= 9 && line[..9].eq_ignore_ascii_case(b"Received:")
		})
		.count()
}

/// What local delivery produced: redirects for the caller to queue, a
/// Sieve reject reason to bounce (if any), and the addresses whose delivery
/// was refused as a forwarding loop.
#[derive(Debug, Default)]
pub struct Delivered {
	pub redirects: Vec<Redirect>,
	pub reject: Option<String>,
	/// Autoresponses (e.g. Sieve vacation) to queue to the outbound spool.
	pub replies: Vec<AcceptedMessage>,
	/// Final addresses the message had already been delivered to and would
	/// have been forwarded from again: nothing was stored or forwarded for
	/// them, and the caller bounces them with 5.4.6.
	pub looped: Vec<String>,
}

/// Delivers messages into `data_dir/accounts/<account>/new/`, one crash-safe
/// copy per distinct recipient account.
#[derive(Debug)]
pub struct LocalDelivery {
	data_dir: PathBuf,
	directory: DirectoryHandle,
	crypto: MessageCrypto,
	metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
}

impl LocalDelivery {
	/// Create a local delivery sink rooted at `data_dir` with no at-rest
	/// encryption. The encrypting variant is [`LocalDelivery::new_with_crypto`].
	pub fn new(data_dir: &std::path::Path, directory: DirectoryHandle) -> std::io::Result<Self> {
		Self::new_with_crypto(data_dir, directory, MessageCrypto::disabled())
	}

	/// Create a local delivery sink rooted at `data_dir`, encrypting stored
	/// message (`.eml`) files through `crypto`. Creates the accounts directory
	/// eagerly so an unwritable data_dir fails at startup, not on first delivery.
	pub fn new_with_crypto(
		data_dir: &std::path::Path,
		directory: DirectoryHandle,
		crypto: MessageCrypto,
	) -> std::io::Result<Self> {
		fs::create_dir_all(contained(data_dir, &data_dir.join("accounts"))?)?;
		Ok(LocalDelivery {
			data_dir: data_dir.to_path_buf(),
			directory,
			crypto,
			metrics: None,
		})
	}

	/// Attach a metrics handle so the report-ingest hook can count
	/// ingested and dropped reports. Builder pattern so the default
	/// constructor stays unchanged for every existing call site.
	pub fn with_metrics(mut self, metrics: std::sync::Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Resolve recipients to their distinct accounts, each with the address
	/// its copy is delivered as (the first one when several recipients reach
	/// the same account) and the `List-*` headers of the list its delivery
	/// belongs to, when that delivery went through one.
	fn accounts_for(&self, message: &AcceptedMessage) -> Result<lists::Recipients, SinkError> {
		lists::accounts_for(&self.directory.current(), message)
	}

	fn deliver_to_account(
		&self,
		account: &str,
		mailbox: Option<&str>,
		data: &[u8],
		flags: &[String],
	) -> std::io::Result<Uuid> {
		let id = Uuid::now_v7();
		let account = AccountName::new(account)?;
		let account_dir = account.root(&self.data_dir)?;
		if !account_dir.child(FixedDir::New)?.is_dir() {
			crate::imap::mailbox::ensure_defaults(&self.data_dir, account.as_str())?;
		}
		// INBOX is the account root; named mailboxes live under folders/.
		let base = match mailbox {
			Some(name) => MailboxName::new(name)?
				.folder_dir(&account, &self.data_dir)?
				.unwrap_or_else(|| account_dir.as_path().to_path_buf()),
			None => account_dir.as_path().to_path_buf(),
		};
		let tmp_dir = contained_child(&base, "tmp")?;
		let new_dir = contained_child(&base, "new")?;
		// A Sieve `fileinto` may name a folder that does not exist yet; it is
		// created like an IMAP CREATE, with its missing superiors, and the
		// creation is journalled there.
		if let Some(name) = mailbox
			&& !new_dir.is_dir()
			&& let Err(error) = crate::imap::mailbox::create(&self.data_dir, account.as_str(), name)
			&& !new_dir.is_dir()
		{
			return Err(error);
		}
		fs::create_dir_all(&tmp_dir)?;
		fs::create_dir_all(&new_dir)?;

		let tmp_path = message_file(&tmp_dir, id, MessageExt::Eml)?;
		write_sync(&tmp_path, &self.crypto.encode(data)?)?;
		fs::rename(&tmp_path, message_file(&new_dir, id, MessageExt::Eml)?)?;
		// imap4flags: persist the Sieve-assigned flags as the IMAP sidecar.
		io::write_flag_sidecar(&new_dir, id, flags);
		let name = mailbox.unwrap_or("INBOX");
		let changes = [
			Change::email(Op::Created, id),
			Change::mailbox(Op::Updated, name),
		];
		crate::imap::changelog::note(account_dir.as_path(), &changes);
		Ok(id)
	}

	/// Deliver one copy per recipient account into `mailbox` (a named folder),
	/// or INBOX when `None`. The mailbox name must pass `is_safe_mailbox`.
	/// Returns the redirect addresses requested by users' Sieve filters, for
	/// the caller to queue (this sink has no outbound spool).
	pub fn deliver_routed(
		&self,
		message: &AcceptedMessage,
		mailbox: Option<&str>,
	) -> Result<Delivered, SinkError> {
		crate::smtp::trace::refuse_padded_headers(&message.data, self.metrics.as_deref())?;
		if let Some(name) = mailbox
			&& !io::is_safe_mailbox(name)
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
		// (Kind, domain) pairs already ingested for this message, so the report
		// hook fires once per matching report even when an alias fans out to
		// several accounts.
		let mut ingested = reports::Ingested::new();
		let mut listed = lists::ListedCopies::new(message);
		for (account, (delivered_to, list)) in &accounts {
			// Mailing list: the copies of the accounts the list reaches
			// carry that list's `List-*` headers; every other copy is the
			// message as it came.
			let one = self.deliver_for_account(
				account,
				delivered_to,
				listed.for_list(list.as_ref()),
				mailbox,
				&mut ingested,
			)?;
			delivered.redirects.extend(one.redirects);
			delivered.reject = delivered.reject.or(one.reject);
			delivered.replies.extend(one.replies);
			delivered.looped.extend(one.looped);
		}
		// Report-ingest hook: fires after normal delivery, never affects
		// outcome, and never fires twice for the same (Kind, domain).
		reports::ingest_for_recipients(
			&self.data_dir,
			&self.directory,
			self.metrics.as_ref(),
			message,
			&mut ingested,
		);
		Ok(delivered)
	}

	/// Deliver one message to one account. An explicit `hint` mailbox (an
	/// admin rule or a security quarantine) takes precedence; otherwise the
	/// account's Sieve filter, if any, decides. With no filter the message
	/// lands in INBOX. Returns any redirect addresses the filter requested.
	fn deliver_for_account(
		&self,
		account: &str,
		delivered_to: &str,
		message: &AcceptedMessage,
		hint: Option<&str>,
		_ingested: &mut reports::Ingested,
	) -> Result<Delivered, SinkError> {
		let stored = trace::final_copy(&message.reverse_path, delivered_to, &message.data);
		let data = &stored;
		if let Some(mailbox) = hint {
			self.deliver_to_account(account, Some(mailbox), data, &[])
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
			return Ok(Delivered::default());
		}
		// Admin-configured external forwarding, independent of the user filter.
		let (forwards, keep_local) = self.account_forwards(account, message);
		let Some(outcome) = self.sieve_outcome(account, message) else {
			if let Some(looped) = trace::forwarding_loop(message, delivered_to, &forwards) {
				return Ok(looped);
			}
			// No filter (or it failed to compile): normal INBOX delivery, unless
			// the account forwards with keep_local = false (pure forwarding).
			if keep_local || forwards.is_empty() {
				self.deliver_to_account(account, None, data, &[])
					.map_err(|error| SinkError::Unavailable(error.to_string()))?;
			}
			return Ok(Delivered {
				redirects: trace::redirects(forwards, delivered_to),
				replies: self
					.vacation_autoreply(account, delivered_to, message, None)
					.into_iter()
					.collect(),
				..Delivered::default()
			});
		};
		// reject/ereject: refuse without delivering; the caller bounces the
		// reason to a non-null sender.
		if let Some(reason) = outcome.reject {
			let reject = (!message.reverse_path.is_empty()).then_some(reason);
			return Ok(Delivered {
				reject,
				..Delivered::default()
			});
		}
		// Never redirect a bounce (null sender): that risks mail loops.
		// Account-level forwards are additive to the user's filter; local
		// storage follows the filter (keep_local governs only the no-filter case).
		let requested = if message.reverse_path.is_empty() {
			Vec::new()
		} else {
			outcome.redirects
		};
		let (mut redirects, unusable) = trace::deliverable(requested);
		// A `redirect` to something that is not an address fails, and a failed
		// action is a run-time error: the message is kept (RFC 5228
		// section 2.10.6) and not lost behind a redirect that never happened.
		let mut keep = outcome.keep;
		if unusable > 0 {
			if self.may_say("sieve-redirect-address", account) {
				tracing::warn!(
					account,
					unusable,
					"a Sieve redirect names something that is not an address; the message was kept"
				);
			}
			keep = true;
		}
		redirects.extend(forwards);
		if let Some(looped) = trace::forwarding_loop(message, delivered_to, &redirects) {
			return Ok(looped);
		}
		// A folder is one folder however many names reach it.
		let mut folders: Vec<Option<String>> = Vec::new();
		for folder in outcome.fileinto.iter().map(|name| io::sieve_mailbox(name)) {
			if !folders.contains(&folder) {
				folders.push(folder);
			}
		}
		// A fileinto that cannot be carried out is a run-time error, which
		// falls back to the implicit keep (RFC 5228 §2.10.6) instead of
		// dropping the message. With the `mailbox` extension (RFC 5490
		// §3.2) `:create` also creates a missing folder first; this
		// project's prior behavior already auto-creates folders, so the
		// tag is observed by the validator but the delivery path treats
		// both cases the same.
		let mut kept = keep || folders.iter().any(Option::is_none);
		if kept {
			self.deliver_to_account(account, None, data, &outcome.flags)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		for folder in folders.iter().flatten() {
			if !io::mailbox_exists(&self.data_dir, account, folder) {
				// Past the account's limit no folder is made: the message is
				// kept in INBOX instead, never lost and never filed nowhere.
				if !io::create_mailbox_within_limit(&self.data_dir, account, folder) {
					if self.may_say("sieve-folder", account) {
						tracing::warn!(
							account,
							limit = io::MAX_AUTO_FOLDERS,
							"a Sieve fileinto cannot make its folder (past the account's limit, too deep, or no lock); the message was kept"
						);
					}
					if !kept {
						self.deliver_to_account(account, None, data, &outcome.flags)
							.map_err(|error| SinkError::Unavailable(error.to_string()))?;
						kept = true;
					}
					continue;
				}
			}
			self.deliver_to_account(account, Some(folder), data, &outcome.flags)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		// vacation (RFC 5230, RFC 8621 section 8): an autoresponse alongside
		// normal delivery, from the JMAP setting or the Sieve action.
		let replies = self
			.vacation_autoreply(account, delivered_to, message, outcome.vacation.as_ref())
			.into_iter()
			.collect();
		Ok(Delivered {
			redirects: trace::redirects(redirects, delivered_to),
			reject: None,
			replies,
			looped: Vec::new(),
		})
	}
}

impl MessageSink for LocalDelivery {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		// Standalone local delivery has no outbound spool; redirects are dropped.
		self.deliver_routed(&message, None).map(|_| ())
	}
}

#[cfg(test)]
mod tests;
